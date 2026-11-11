"""SSRF-proof asynchronous network gateway — the ONLY way UniPhish touches the wire.

Every outbound request in the platform must go through :func:`safe_fetch`. Fetching a
URL that an attacker (or a phishing page we are analysing) controls is dangerous: a
hostile host can point DNS at ``169.254.169.254`` (cloud metadata), ``127.0.0.1`` (an
internal admin panel) or an RFC-1918 address and turn our scanner into a Server-Side
Request Forgery proxy. This module makes that impossible by design:

* every destination IP is checked against an exhaustive non-public blocklist
  (:func:`is_public_ip`) — private, loopback, link-local (incl. the metadata address),
  CGNAT, multicast, reserved, broadcast, and every IPv6 way of smuggling those in;
* the host is resolved **once**, each resolved IP is validated, and we then connect to
  that *pinned* IP while preserving the ``Host`` header, TLS SNI and certificate
  hostname verification — defeating DNS-rebinding / TOCTOU;
* redirects are followed manually with the same per-hop validation, so a ``302`` to
  ``http://127.0.0.1/`` is refused; numeric/hex/octal IP obfuscation in the host is
  rejected before it ever reaches a resolver;
* bodies are streamed under both a raw-wire byte cap and a decompressed-size cap, so a
  gzip/brotli bomb cannot exhaust memory;
* proxies from the environment are ignored (they would bypass the IP pin) and no
  cookies are persisted.

The gateway never raises for a network, DNS or policy problem: it always returns a
:class:`FetchResult` whose ``error`` (operational) or ``blocked_reason`` (security
refusal) says what happened.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address, ip_network
from typing import Union

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from uniphish.core.config import get_settings

log = logging.getLogger("uniphish.net")

__all__ = [
    "BlockedDestination",
    "DEFAULT_ALLOWED_PORTS",
    "FetchResult",
    "Hop",
    "Resolver",
    "is_public_ip",
    "resolve",
    "resolve_ips",
    "safe_fetch",
    "set_resolver",
]

# --------------------------------------------------------------------------- config
DEFAULT_ALLOWED_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})
_REDIRECT_CODES: frozenset[int] = frozenset({301, 302, 303, 307, 308})
_DNS_TIMEOUT = 5.0
_DEFAULT_MAX_DECOMPRESSED = 16 * 1024 * 1024
_DEADLINE_SLACK = 0.5
# Headers we always manage ourselves (never taken verbatim from the caller).
_MANAGED_REQ_HEADERS = {"host", "content-length"}
# Headers that must not leak across a cross-origin redirect.
_CROSS_ORIGIN_STRIP = {"authorization", "cookie", "proxy-authorization"}


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, "") or default))
    except ValueError:
        return default


_GLOBAL_CONCURRENCY = _env_int("UNIPHISH_HTTP_CONCURRENCY", 32)
_PER_HOST_CONCURRENCY = _env_int("UNIPHISH_HTTP_PER_HOST", 4)


# ------------------------------------------------------------------- IP classification
class BlockedDestination(Exception):
    """A destination was refused for a security-policy reason (SSRF guard)."""


class _ResolutionError(Exception):
    """DNS produced no usable address (operational, not a security refusal)."""


IPAddr = Union[IPv4Address, IPv6Address]

# Non-public IPv4 ranges. ``ipaddress`` flags differ subtly between CPython patch
# releases, so we enumerate them explicitly as well as checking the flags.
_V4_BLOCK: tuple[ipaddress.IPv4Network, ...] = (
    ip_network("0.0.0.0/8"),        # "this" network / unspecified
    ip_network("10.0.0.0/8"),       # RFC 1918 private
    ip_network("100.64.0.0/10"),    # RFC 6598 carrier-grade NAT
    ip_network("127.0.0.0/8"),      # loopback
    ip_network("169.254.0.0/16"),   # link-local incl. 169.254.169.254 metadata
    ip_network("172.16.0.0/12"),    # RFC 1918 private
    ip_network("192.0.0.0/24"),     # IETF protocol assignments
    ip_network("192.0.2.0/24"),     # TEST-NET-1
    ip_network("192.88.99.0/24"),   # 6to4 relay anycast (deprecated)
    ip_network("192.168.0.0/16"),   # RFC 1918 private
    ip_network("198.18.0.0/15"),    # benchmarking
    ip_network("198.51.100.0/24"),  # TEST-NET-2
    ip_network("203.0.113.0/24"),   # TEST-NET-3
    ip_network("224.0.0.0/4"),      # multicast
    ip_network("240.0.0.0/4"),      # reserved (future use)
    ip_network("255.255.255.255/32"),  # limited broadcast
)

# Non-public IPv6 ranges not already caught by the standard flags.
_V6_BLOCK: tuple[ipaddress.IPv6Network, ...] = (
    ip_network("::/128"),            # unspecified
    ip_network("::1/128"),           # loopback
    ip_network("64:ff9b::/96"),      # NAT64 well-known prefix
    ip_network("64:ff9b:1::/48"),    # NAT64 local-use prefix
    ip_network("100::/64"),          # discard-only
    ip_network("2001:db8::/32"),     # documentation
    ip_network("2001:20::/28"),      # ORCHIDv2
    ip_network("5f00::/16"),         # reserved
)


def _is_flagged_non_public(addr: IPAddr) -> bool:
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _to_ip(value: object) -> IPAddr | None:
    if isinstance(value, (IPv4Address, IPv6Address)):
        return value
    try:
        return ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return None


def is_public_ip(value: object) -> bool:
    """Return ``True`` only for a globally routable, externally reachable address.

    Rejects private, loopback, link-local (including the ``169.254.169.254`` cloud
    metadata address), CGNAT, multicast, reserved, unspecified, broadcast, and every
    IPv6 encoding that embeds one of those (IPv4-mapped/compatible, 6to4, Teredo,
    NAT64). Anything that cannot be parsed as an IP is not public.
    """
    addr = _to_ip(value)
    if addr is None:
        return False

    if isinstance(addr, IPv6Address):
        # Unwrap every IPv6 representation of an IPv4 address and re-check it, so a
        # private v4 cannot be smuggled through a v6 literal.
        mapped = addr.ipv4_mapped
        if mapped is not None:
            return is_public_ip(mapped)
        sixtofour = addr.sixtofour
        if sixtofour is not None:
            return is_public_ip(sixtofour)
        teredo = addr.teredo
        if teredo is not None:
            server, client = teredo
            return is_public_ip(server) and is_public_ip(client)
        if any(addr in net for net in _V6_BLOCK):
            return False
        as_int = int(addr)
        if as_int >> 32 == 0 and as_int not in (0, 1):
            # Deprecated IPv4-compatible ``::a.b.c.d`` (:: and ::1 excluded above).
            return is_public_ip(IPv4Address(as_int & 0xFFFFFFFF))
        return not _is_flagged_non_public(addr)

    if any(addr in net for net in _V4_BLOCK):
        return False
    return not _is_flagged_non_public(addr)


def _classify_host(host: str) -> tuple[str, object]:
    """Return ``("ip", IPAddr)`` or ``("name", hostname)``; refuse numeric obfuscation.

    Standard dotted-quad / bracketed IPv6 literals are returned as ``ip``. Decimal,
    hex, octal and short-form integer encodings of an IP (classic SSRF filter bypasses
    such as ``http://2130706433/`` or ``http://0x7f.0.0.1/``) are refused outright.
    """
    h = host.strip().strip("[]").rstrip(".")
    if not h:
        raise BlockedDestination("empty host")
    try:
        return ("ip", ipaddress.ip_address(h))
    except ValueError:
        pass
    labels = [lbl for lbl in h.split(".") if lbl]
    if labels and all(lbl.isdigit() for lbl in labels):
        # All-numeric labels that did not parse as a valid dotted IP (bare integer,
        # short form like 127.1, or out-of-range) — treat as an obfuscated address.
        raise BlockedDestination(f"numeric host obfuscation: {host!r}")
    for lbl in labels:
        if lbl[:2].lower() == "0x":
            raise BlockedDestination(f"hex host obfuscation: {host!r}")
    return ("name", h.lower())


# -------------------------------------------------------------------------- resolution
# A resolver takes (host, rdtype, timeout) and returns a list of IP strings. The
# default uses dnspython; tests inject a deterministic one.
Resolver = Callable[[str, str, float], Awaitable[list[str]]]

_RESOLVER: Resolver | None = None


def set_resolver(resolver: Resolver | None) -> None:
    """Install a process-wide resolver override (used by tests). ``None`` restores."""
    global _RESOLVER
    _RESOLVER = resolver


async def _default_resolver(host: str, rdtype: str, timeout: float) -> list[str]:
    try:
        answer = await dns.asyncresolver.resolve(
            host, rdtype, lifetime=timeout, raise_on_no_answer=False
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    out: list[str] = []
    rrset = getattr(answer, "rrset", None)
    if rrset is not None:
        out.extend(str(record.address) for record in rrset)
    return out


async def resolve(
    host: str,
    rdtype: str = "A",
    *,
    timeout: float | None = None,
    resolver: Resolver | None = None,
) -> list[str]:
    """Resolve ``host`` to a list of IP strings for ``rdtype`` (``A``/``AAAA``).

    The resolver is injectable: pass ``resolver=...`` or install one process-wide with
    :func:`set_resolver`. Returns ``[]`` when there is no such record.
    """
    name = host.strip().strip("[]").rstrip(".")
    fn = resolver or _RESOLVER or _default_resolver
    to = timeout if timeout is not None else _DNS_TIMEOUT
    return list(await fn(name, rdtype, to))


async def resolve_ips(
    host: str,
    *,
    timeout: float | None = None,
    resolver: Resolver | None = None,
) -> list[str]:
    """Resolve both A and AAAA records, de-duplicated, order-preserving."""
    seen: set[str] = set()
    out: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            addrs = await resolve(host, rdtype, timeout=timeout, resolver=resolver)
        except dns.exception.DNSException as exc:  # one family may fail; keep the other
            log.debug("resolve %s/%s failed: %r", host, rdtype, exc)
            continue
        for ip in addrs:
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
    return out


# ------------------------------------------------------------------------- data model
@dataclass(slots=True)
class Hop:
    """One request in a (possibly redirected) fetch chain."""

    url: str
    status: int
    ip: str | None
    location: str | None


@dataclass(slots=True)
class FetchResult:
    """Outcome of :func:`safe_fetch`. Never an exception — inspect the fields."""

    url: str
    final_url: str | None
    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool
    chain: list[Hop]
    ip: str | None
    elapsed_ms: float
    error: str | None
    blocked_reason: str | None
    content_type: str | None
    charset: str | None

    @property
    def ok(self) -> bool:
        """True when a response was received without error, block or HTTP failure."""
        return (
            self.error is None
            and self.blocked_reason is None
            and 200 <= self.status < 400
        )

    def text(self, errors: str = "replace") -> str:
        """Decode the body using the response charset (falling back to UTF-8)."""
        enc = self.charset or "utf-8"
        try:
            return self.body.decode(enc, errors=errors)
        except LookupError:
            return self.body.decode("utf-8", errors=errors)


@dataclass(slots=True)
class _Progress:
    url: str
    final_url: str | None = None
    ip: str | None = None
    chain: list[Hop] = field(default_factory=list)


# ---------------------------------------------------------------------------- limiters
class _LoopLimiters:
    __slots__ = ("global_sem", "host_sems")

    def __init__(self) -> None:
        self.global_sem = asyncio.Semaphore(_GLOBAL_CONCURRENCY)
        self.host_sems: dict[str, asyncio.Semaphore] = {}


# asyncio primitives bind to the running loop; key them by loop so each test (and each
# real event loop) gets its own limiters rather than sharing a dead loop's semaphore.
_LOOP_LIMITERS: dict[int, _LoopLimiters] = {}


def _limiters() -> _LoopLimiters:
    loop_id = id(asyncio.get_running_loop())
    state = _LOOP_LIMITERS.get(loop_id)
    if state is None:
        state = _LoopLimiters()
        _LOOP_LIMITERS[loop_id] = state
    return state


def _host_sem(state: _LoopLimiters, host: str) -> asyncio.Semaphore:
    sem = state.host_sems.get(host)
    if sem is None:
        sem = asyncio.Semaphore(_PER_HOST_CONCURRENCY)
        state.host_sems[host] = sem
    return sem


# ------------------------------------------------------------------------ fetch helpers
def _effective_port(url: httpx.URL) -> int:
    return url.port or (443 if url.scheme == "https" else 80)


def _host_header(host: str, port: int, scheme: str) -> str:
    bare = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    return bare if port == default else f"{bare}:{port}"


def _parse_content_type(value: str | None) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    parts = value.split(";")
    content_type = parts[0].strip().lower() or None
    charset: str | None = None
    for param in parts[1:]:
        param = param.strip()
        if param[:8].lower() == "charset=":
            charset = param[8:].strip().strip('"').strip("'").lower() or None
    return content_type, charset


def _lower_headers(headers: httpx.Headers) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in headers.multi_items():
        lk = key.lower()
        out[lk] = f"{out[lk]}, {value}" if lk in out else value
    return out


async def _prepare_hop(
    url_str: str,
    allowed_ports: frozenset[int],
    allow_private: bool,
    resolver: Resolver | None,
    timeout: float,
) -> tuple[httpx.URL, str, str | None, str]:
    """Validate one hop and return ``(pinned_url, host_header, sni_hostname, pin_ip)``."""
    try:
        url = httpx.URL(url_str)
    except httpx.InvalidURL as exc:
        raise BlockedDestination(f"invalid url: {exc}") from exc

    scheme = url.scheme.lower()
    if scheme not in ("http", "https"):
        raise BlockedDestination(f"scheme not allowed: {scheme or '(none)'}")
    host = url.host
    if not host:
        raise BlockedDestination("missing host")
    port = _effective_port(url)
    if port not in allowed_ports:
        raise BlockedDestination(f"port not allowed: {port}")

    kind, value = _classify_host(host)
    if kind == "ip":
        ip = value  # type: ignore[assignment]
        if not allow_private and not is_public_ip(ip):
            raise BlockedDestination(f"non-public address: {ip}")
        return url, _host_header(host, port, scheme), None, str(ip)

    hostname = str(value)
    ips = await resolve_ips(hostname, timeout=timeout, resolver=resolver)
    if not ips:
        raise _ResolutionError(f"no address for {hostname!r}")
    for ip in ips:
        if not allow_private and not is_public_ip(ip):
            raise BlockedDestination(f"{hostname} resolves to non-public address {ip}")
    pin_ip = ips[0]
    pinned = url.copy_with(host=pin_ip)
    sni = hostname if scheme == "https" else None
    return pinned, _host_header(hostname, port, scheme), sni, pin_ip


async def _read_capped(
    resp: httpx.Response, raw_cap: int, decomp_cap: int
) -> tuple[bytes, bool]:
    """Stream the body, stopping at the raw-wire cap or the decompressed-size cap.

    ``num_bytes_downloaded`` counts bytes read off the wire (compressed), while the
    accumulated length is the decoded size; enforcing both makes gzip/brotli bombs and
    oversized incompressible streams safe.
    """
    chunks: list[bytes] = []
    total = 0
    truncated = False
    async for chunk in resp.aiter_bytes():
        if chunk:
            chunks.append(chunk)
            total += len(chunk)
        if total > decomp_cap or resp.num_bytes_downloaded > raw_cap:
            truncated = True
            break
    body = b"".join(chunks)
    if len(body) > decomp_cap:
        body = body[:decomp_cap]
    return body, truncated


def _build(
    prog: _Progress,
    start: float,
    *,
    status: int = 0,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    truncated: bool = False,
    content_type: str | None = None,
    charset: str | None = None,
    error: str | None = None,
    blocked_reason: str | None = None,
) -> FetchResult:
    return FetchResult(
        url=prog.url,
        final_url=prog.final_url,
        status=status,
        headers=headers or {},
        body=body,
        truncated=truncated,
        chain=list(prog.chain),
        ip=prog.ip,
        elapsed_ms=round((time.monotonic() - start) * 1000, 2),
        error=error,
        blocked_reason=blocked_reason,
        content_type=content_type,
        charset=charset,
    )


async def safe_fetch(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    max_bytes: int | None = None,
    timeout: float | None = None,
    follow_redirects: bool = True,
    max_redirects: int = 5,
    allowed_ports: frozenset[int] = DEFAULT_ALLOWED_PORTS,
    allow_private: bool = False,
    transport: httpx.AsyncBaseTransport | None = None,
    resolver: Resolver | None = None,
    max_decompressed_bytes: int | None = None,
) -> FetchResult:
    """Fetch ``url`` safely, following redirects with full per-hop SSRF validation.

    Resolves each host once, verifies every resolved IP is public, and connects to the
    pinned IP while preserving the ``Host`` header, TLS SNI and certificate hostname
    verification (defeating DNS rebinding). Streams the body under a raw-wire cap
    (``max_bytes``) and a decompressed-size cap (``max_decompressed_bytes``). Never
    raises: a security refusal sets ``blocked_reason``, an operational failure sets
    ``error``.

    ``transport`` and ``resolver`` are injection points for tests. ``allow_private``
    (default ``False``) permits private/loopback destinations — use only for trusted
    local development targets.
    """
    settings = get_settings()
    deadline = timeout if timeout is not None else settings.http_timeout_s
    raw_cap = max_bytes if max_bytes is not None else settings.http_max_bytes
    decomp_cap = (
        max_decompressed_bytes
        if max_decompressed_bytes is not None
        else max(raw_cap, _DEFAULT_MAX_DECOMPRESSED)
    )
    start = time.monotonic()
    prog = _Progress(url=str(url), final_url=str(url))
    base_headers = {
        key.lower(): val
        for key, val in (headers or {}).items()
        if key.lower() not in _MANAGED_REQ_HEADERS
    }

    try:
        return await asyncio.wait_for(
            _run(
                prog=prog,
                start=start,
                method=method,
                base_headers=base_headers,
                raw_cap=raw_cap,
                decomp_cap=decomp_cap,
                deadline=deadline,
                follow_redirects=follow_redirects,
                max_redirects=max_redirects,
                allowed_ports=frozenset(allowed_ports),
                allow_private=allow_private,
                transport=transport,
                resolver=resolver,
                settings=settings,
            ),
            timeout=deadline + _DEADLINE_SLACK,
        )
    except (asyncio.TimeoutError, TimeoutError):
        return _build(prog, start, error="timeout")
    except Exception as exc:  # the gateway must never propagate — report, don't raise
        log.warning("safe_fetch(%s) unexpected error: %r", url, exc)
        return _build(prog, start, error=f"unexpected: {type(exc).__name__}")


async def _run(
    *,
    prog: _Progress,
    start: float,
    method: str,
    base_headers: dict[str, str],
    raw_cap: int,
    decomp_cap: int,
    deadline: float,
    follow_redirects: bool,
    max_redirects: int,
    allowed_ports: frozenset[int],
    allow_private: bool,
    transport: httpx.AsyncBaseTransport | None,
    resolver: Resolver | None,
    settings: object,
) -> FetchResult:
    current = prog.url
    cur_method = method.upper()
    hop_headers = dict(base_headers)
    origin_host: str | None = None
    visited: set[str] = set()

    client_kwargs: dict[str, object] = {
        "follow_redirects": False,
        "timeout": httpx.Timeout(deadline),
    }
    if transport is not None:
        client_kwargs["transport"] = transport
    else:
        client_kwargs.update(
            verify=True,
            trust_env=False,  # ignore *_PROXY env — a proxy would bypass the IP pin
            limits=httpx.Limits(max_connections=_GLOBAL_CONCURRENCY),
        )

    user_agent = getattr(settings, "user_agent", "UniPhish/2.0")
    limiters = _limiters()

    async with httpx.AsyncClient(**client_kwargs) as client:
        for hop_index in range(max_redirects + 1):
            remaining = deadline - (time.monotonic() - start)
            if remaining <= 0:
                return _build(prog, start, error="timeout")
            if current in visited:
                return _build(prog, start, error="redirect loop")
            visited.add(current)

            try:
                pinned, host_header, sni, pin_ip = await _prepare_hop(
                    current, allowed_ports, allow_private, resolver,
                    min(remaining, _DNS_TIMEOUT),
                )
            except BlockedDestination as exc:
                prog.chain.append(Hop(url=current, status=0, ip=None, location=None))
                return _build(prog, start, blocked_reason=str(exc))
            except _ResolutionError as exc:
                return _build(prog, start, error=f"dns: {exc}")
            except dns.exception.DNSException as exc:
                return _build(prog, start, error=f"dns: {type(exc).__name__}")

            # Strip credential headers once we leave the original origin.
            host_only = host_header
            if host_only.startswith("["):
                host_only = host_only[1:].split("]", 1)[0]
            elif host_only.count(":") == 1:
                host_only = host_only.rsplit(":", 1)[0]
            if origin_host is None:
                origin_host = host_only
            elif host_only != origin_host:
                for sensitive in _CROSS_ORIGIN_STRIP:
                    hop_headers.pop(sensitive, None)

            prog.ip = pin_ip
            prog.final_url = current

            # No persisted cookies: httpx's client jar would otherwise absorb a
            # Set-Cookie from one hop and replay it as a Cookie header on the next
            # (even cross-origin). Clear it before building every request so a hop
            # never carries session state forward.
            client.cookies.clear()

            request_headers = {
                "user-agent": user_agent,
                "accept": "*/*",
                **hop_headers,
                "host": host_header,
            }
            request = client.build_request(cur_method, pinned, headers=request_headers)
            if sni:
                request.extensions["sni_hostname"] = sni
            request.extensions["timeout"] = {
                "connect": remaining, "read": remaining,
                "write": remaining, "pool": remaining,
            }

            host_semaphore = _host_sem(limiters, host_header)
            try:
                async with limiters.global_sem, host_semaphore:
                    resp = await client.send(request, stream=True)
            except httpx.TimeoutException:
                return _build(prog, start, error="timeout")
            except httpx.HTTPError as exc:
                return _build(prog, start, error=f"connect: {type(exc).__name__}")

            try:
                status = resp.status_code
                location = resp.headers.get("location")
                prog.chain.append(Hop(url=current, status=status, ip=pin_ip, location=location))

                if follow_redirects and status in _REDIRECT_CODES and location:
                    if hop_index >= max_redirects:
                        return _build(prog, start, error="too many redirects")
                    next_url = str(httpx.URL(current).join(location))
                    downgrade = status in (301, 302) and cur_method not in ("GET", "HEAD")
                    if status == 303 or downgrade:
                        cur_method = "GET"
                    current = next_url
                    continue

                body, truncated = await _read_capped(resp, raw_cap, decomp_cap)
                content_type, charset = _parse_content_type(resp.headers.get("content-type"))
                return _build(
                    prog, start,
                    status=status,
                    headers=_lower_headers(resp.headers),
                    body=body,
                    truncated=truncated,
                    content_type=content_type,
                    charset=charset,
                )
            finally:
                await resp.aclose()

        return _build(prog, start, error="too many redirects")
