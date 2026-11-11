"""Leaf-certificate inspection over a pinned, SSRF-validated connection.

Why this exists
---------------
The TLS certificate a site presents says a lot about it: a certificate issued hours
ago by a free CA for a bank lookalike, a self-signed certificate on a login page, or a
certificate whose names do not even cover the host being visited are all classic
phishing-infrastructure tells.

Security model
--------------
This is the one place in the intel layer that opens a raw TCP/TLS socket, so it applies
the same guard as :func:`uniphish.core.net.safe_fetch`:

* the host is resolved once (or the caller supplies already-resolved addresses), the
  numeric/hex/octal IP-obfuscation tricks are refused, and **every** address must be
  globally routable (:func:`uniphish.core.net.is_public_ip`) or the probe is refused;
* we connect to the *pinned* IP while sending the original host as SNI, so a
  DNS-rebinding answer between check and connect cannot redirect us;
* only the ports in :data:`ALLOWED_PORTS` are probed; the handshake is bounded by a
  timeout and we read **no application data** at all - the certificate is taken from
  the handshake and the socket is closed.

The certificate is first fetched with full verification. If verification fails (self
signed, expired, wrong host, unknown CA) we reconnect once without verification purely
to *read* the certificate; the failure reason is reported in
:attr:`TlsInfo.verify_error`. Nothing is ever trusted because of this probe.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import logging
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from uniphish.core import net

log = logging.getLogger("uniphish.intel.tls")

__all__ = ["ALLOWED_PORTS", "FREE_CA_MARKERS", "TlsInfo", "fetch_tls", "hostname_matches",
           "parse_certificate"]

ALLOWED_PORTS: frozenset[int] = frozenset({443, 8443})
#: Case-insensitive substrings of the issuer (organisation / CN) that identify free,
#: automated CAs. Free issuance is legitimate, but phishing overwhelmingly uses it.
FREE_CA_MARKERS: tuple[str, ...] = (
    "let's encrypt", "lets encrypt", "isrg", "zerossl", "buypass",
)
_MAX_SANS = 200
_MAX_DER = 64 * 1024

#: ``(ip, port, server_name, verify, timeout)`` -> leaf certificate DER bytes. Raises
#: ``ssl.SSLCertVerificationError`` when ``verify`` and verification fails.
Connector = Callable[[str, int, str, bool, float], Awaitable[bytes]]


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class TlsInfo:
    """Facts about a server's leaf certificate."""

    host: str
    ip: str | None = None
    port: int = 443
    issuer: str = ""
    issuer_org: str | None = None
    issuer_cn: str | None = None
    subject: str = ""
    subject_cn: str | None = None
    sans: tuple[str, ...] = ()
    not_before: datetime | None = None
    not_after: datetime | None = None
    age_days: int | None = None
    days_remaining: int | None = None
    is_lets_encrypt: bool = False
    free_ca: bool = False
    self_signed: bool = False
    wildcard: bool = False
    expired: bool = False
    cert_sha256: str | None = None
    san_count: int = 0
    covers_host: bool | None = None
    #: ``True`` if the chain + hostname verified against the system trust store.
    verified: bool = False
    verify_error: str | None = None
    #: Why no certificate is available (blocked, timeout, handshake failure, ...).
    error: str | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return self.error is None and self.cert_sha256 is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host, "ip": self.ip, "port": self.port, "issuer": self.issuer,
            "subject": self.subject, "sans": list(self.sans[:20]), "san_count": self.san_count,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "age_days": self.age_days, "days_remaining": self.days_remaining,
            "is_lets_encrypt": self.is_lets_encrypt, "free_ca": self.free_ca,
            "self_signed": self.self_signed, "wildcard": self.wildcard,
            "expired": self.expired, "cert_sha256": self.cert_sha256,
            "covers_host": self.covers_host, "verified": self.verified,
            "verify_error": self.verify_error, "error": self.error,
        }


# --------------------------------------------------------------------------- #
# Hostname matching (RFC 6125, SAN only)
# --------------------------------------------------------------------------- #
def hostname_matches(host: str, names: tuple[str, ...] | list[str]) -> bool:
    """Does any certificate name cover ``host``?

    DNS names match case-insensitively; a ``*`` is honoured only as the entire
    left-most label and matches exactly one label (``*.example.com`` covers
    ``a.example.com`` but neither ``example.com`` nor ``a.b.example.com``). IP-literal
    hosts match only IP SANs. The deprecated subject-CN fallback is deliberately not
    applied, as in every modern client.
    """
    h = host.strip().strip("[]").rstrip(".").lower()
    if not h:
        return False
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = None
    for raw in names:
        n = raw.strip().rstrip(".").lower()
        if not n:
            continue
        if ip is not None:
            try:
                if ipaddress.ip_address(n.strip("[]")) == ip:
                    return True
            except ValueError:
                pass
            continue
        if n == h:
            return True
        if n.startswith("*.") and "*" not in n[2:]:
            suffix = n[1:]  # ".example.com"
            if h.endswith(suffix) and h.count(".") == n.count("."):
                left = h[: -len(suffix)]
                if left and "." not in left:
                    return True
    return False


# --------------------------------------------------------------------------- #
# Certificate parsing
# --------------------------------------------------------------------------- #
def _attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    try:
        attrs = name.get_attributes_for_oid(oid)
    except Exception:
        return None
    return str(attrs[0].value) if attrs else None


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _not_before(cert: x509.Certificate) -> datetime:
    f = getattr(cert, "not_valid_before_utc", None)
    return _utc(f if f is not None else cert.not_valid_before)  # pragma: no cover - old lib


def _not_after(cert: x509.Certificate) -> datetime:
    f = getattr(cert, "not_valid_after_utc", None)
    return _utc(f if f is not None else cert.not_valid_after)  # pragma: no cover - old lib


def _sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    except Exception:
        return []
    san = ext.value
    out: list[str] = [d.lower() for d in san.get_values_for_type(x509.DNSName)]
    out.extend(str(i) for i in san.get_values_for_type(x509.IPAddress))
    return out[:_MAX_SANS]


def _is_self_signed(cert: x509.Certificate) -> bool:
    """Issuer == subject (a self-issued certificate is never a publicly trusted leaf)."""
    return cert.issuer == cert.subject


def parse_certificate(der: bytes, host: str, *, now: datetime | None = None,
                      ip: str | None = None, port: int = 443) -> TlsInfo:
    """Parse DER bytes into a :class:`TlsInfo` (never raises)."""
    now = now or datetime.now(timezone.utc)
    if not der or len(der) > _MAX_DER:
        return TlsInfo(host=host, ip=ip, port=port, error="no certificate")
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:
        return TlsInfo(host=host, ip=ip, port=port, error=f"unparseable certificate: "
                                                          f"{type(exc).__name__}")
    try:
        nb, na = _not_before(cert), _not_after(cert)
        sans = tuple(_sans(cert))
        issuer_org = _attr(cert.issuer, NameOID.ORGANIZATION_NAME)
        issuer_cn = _attr(cert.issuer, NameOID.COMMON_NAME)
        subject_cn = _attr(cert.subject, NameOID.COMMON_NAME)
        issuer_blob = f"{issuer_org or ''} {issuer_cn or ''}".lower()
        free = any(m in issuer_blob for m in FREE_CA_MARKERS)
        lets = any(m in issuer_blob for m in ("let's encrypt", "lets encrypt", "isrg"))
        wildcard = any(s.startswith("*.") for s in sans) or bool(
            subject_cn and subject_cn.startswith("*."))
        names = sans if sans else ()
        return TlsInfo(
            host=host, ip=ip, port=port,
            issuer=cert.issuer.rfc4514_string(), issuer_org=issuer_org, issuer_cn=issuer_cn,
            subject=cert.subject.rfc4514_string(), subject_cn=subject_cn, sans=sans,
            not_before=nb, not_after=na,
            age_days=max(0, (now - nb).days) if nb <= now else 0,
            days_remaining=(na - now).days,
            is_lets_encrypt=lets, free_ca=free, self_signed=_is_self_signed(cert),
            wildcard=wildcard, expired=na < now,
            cert_sha256=hashlib.sha256(der).hexdigest(), san_count=len(sans),
            covers_host=hostname_matches(host, names),
            notes=() if sans else ("certificate has no subjectAltName",),
        )
    except Exception as exc:  # defensive: malformed-but-parseable certs
        log.debug("certificate post-processing failed: %r", exc)
        return TlsInfo(host=host, ip=ip, port=port,
                       cert_sha256=hashlib.sha256(der).hexdigest(),
                       error=f"certificate fields unreadable: {type(exc).__name__}")


# --------------------------------------------------------------------------- #
# Connection
# --------------------------------------------------------------------------- #
async def _default_connector(ip: str, port: int, server_name: str, verify: bool,
                             timeout: float) -> bytes:
    """Handshake with ``ip:port`` (SNI = ``server_name``) and return the leaf DER."""
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    writer: asyncio.StreamWriter | None = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=server_name,
                                    ssl_handshake_timeout=timeout),
            timeout=timeout,
        )
        sslobj = writer.get_extra_info("ssl_object")
        der = sslobj.getpeercert(binary_form=True) if sslobj is not None else None
        if not der:
            raise ssl.SSLError("peer presented no certificate")
        return bytes(der)
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):  # best-effort close of a probe socket
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)


def _verify_reason(exc: ssl.SSLCertVerificationError) -> str:
    return (getattr(exc, "verify_message", None) or str(exc) or "verification failed")[:160]


async def fetch_tls(host: str, *, port: int = 443, ips: list[str] | None = None,
                    timeout: float = 5.0, resolver: net.Resolver | None = None,
                    connector: Connector | None = None, allow_private: bool = False,
                    allowed_ports: frozenset[int] = ALLOWED_PORTS,
                    now: datetime | None = None) -> TlsInfo:
    """Fetch and parse the leaf certificate of ``host:port``. Never raises.

    ``ips`` may carry addresses already resolved by the caller (they are re-validated
    here). On any refusal or failure the returned :class:`TlsInfo` has ``error`` set
    and no certificate fields. ``connector`` / ``resolver`` are test injection points;
    ``allow_private`` is for trusted local development targets only.
    """
    h = (host or "").strip().strip("[]").rstrip(".").lower()
    if not h:
        return TlsInfo(host=h, port=port, error="empty host")
    if port not in allowed_ports:
        return TlsInfo(host=h, port=port, error=f"blocked: port not allowed: {port}")

    candidates: list[str]
    try:
        ipaddress.ip_address(h)
        candidates = [h]
    except ValueError:
        # Refuse decimal/hex/octal obfuscation exactly like safe_fetch does.
        labels = [x for x in h.split(".") if x]
        if labels and all(x.isdigit() for x in labels):
            return TlsInfo(host=h, port=port, error="blocked: numeric host obfuscation")
        if any(x[:2] == "0x" for x in labels):
            return TlsInfo(host=h, port=port, error="blocked: hex host obfuscation")
        if ips:
            candidates = list(dict.fromkeys(ips))
        else:
            try:
                candidates = await net.resolve_ips(h, timeout=min(timeout, 4.0),
                                                   resolver=resolver)
            except Exception as exc:
                return TlsInfo(host=h, port=port, error=f"dns: {type(exc).__name__}")
    if not candidates:
        return TlsInfo(host=h, port=port, error="dns: no address")
    if not allow_private:
        for c in candidates:
            if not net.is_public_ip(c):
                return TlsInfo(host=h, port=port, error=f"blocked: non-public address {c}")

    pin = candidates[0]
    conn = connector or _default_connector
    verified = False
    verify_error: str | None = None
    try:
        try:
            der = await conn(pin, port, h, True, timeout)
            verified = True
        except ssl.SSLCertVerificationError as exc:
            verify_error = _verify_reason(exc)
            der = await conn(pin, port, h, False, timeout)
    except asyncio.CancelledError:
        raise
    except (asyncio.TimeoutError, TimeoutError):
        return TlsInfo(host=h, ip=pin, port=port, error="timeout")
    except ssl.SSLError as exc:
        return TlsInfo(host=h, ip=pin, port=port, error=f"tls: {type(exc).__name__}")
    except OSError as exc:
        return TlsInfo(host=h, ip=pin, port=port, error=f"connect: {type(exc).__name__}")
    except Exception as exc:
        log.debug("tls probe %s failed: %r", h, exc)
        return TlsInfo(host=h, ip=pin, port=port, error=f"unexpected: {type(exc).__name__}")

    info = parse_certificate(der, h, now=now, ip=pin, port=port)
    if info.error:
        return info
    # dataclass is frozen: rebuild with the verification outcome.
    return replace(info, verified=verified, verify_error=verify_error)

