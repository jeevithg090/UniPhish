"""Domain registration age via RDAP.

Why this exists
---------------
Domain age is one of the strongest cheap phishing signals: the large majority of
phishing domains are used within days of registration, while legitimate brands have
been registered for years. RDAP (RFC 7480-7484) is the structured, JSON, rate-limit
friendly successor to WHOIS and exposes the registration event.

Lookup strategy
---------------
1. ``https://rdap.org/domain/<name>`` (a public redirector to the authoritative
   registry; ``safe_fetch`` follows the redirect with per-hop SSRF validation).
2. If that fails operationally, the IANA RDAP bootstrap file
   (``https://data.iana.org/rdap/dns.json``) is consulted to find the TLD's registry
   service directly.

Every request goes through :func:`uniphish.core.net.safe_fetch`. Results are cached on
disk (24 h for hits, 15 min for "not found" so a just-registered name is re-checked
soon). A failed lookup returns ``None`` and never raises.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from uniphish.core.cache import DiskCache
from uniphish.core.net import FetchResult, safe_fetch

log = logging.getLogger("uniphish.intel.rdap")

__all__ = ["RdapInfo", "domain_age", "parse_rdap"]

RDAP_REDIRECTOR = "https://rdap.org/"
IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
#: RDAP documents are small; refuse anything bigger than this.
MAX_RDAP_BYTES = 512_000
HIT_TTL_S = 86_400.0
MISS_TTL_S = 900.0
BOOTSTRAP_TTL_S = 86_400.0

Fetcher = Callable[..., Awaitable[FetchResult]]

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
                        r"(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$")


@dataclass(frozen=True)
class RdapInfo:
    """Registration facts for one domain."""

    domain: str
    registered: datetime | None
    age_days: int | None
    expires: datetime | None = None
    last_changed: datetime | None = None
    registrar: str | None = None
    nameservers: tuple[str, ...] = ()
    status: tuple[str, ...] = ()
    source: str = "rdap"
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "registered": self.registered.isoformat() if self.registered else None,
            "age_days": self.age_days,
            "expires": self.expires.isoformat() if self.expires else None,
            "registrar": self.registrar,
            "nameservers": list(self.nameservers),
            "status": list(self.status),
            "source": self.source,
        }


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def _parse_dt(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    s = value.strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        # Some registries emit ``2020-01-02 03:04:05`` or date-only strings.
        try:
            dt = datetime.strptime(s[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _vcard_fn(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                val = item[3]
                if isinstance(val, str) and val.strip():
                    return val.strip()[:200]
    return None


def _registrar(doc: dict[str, Any]) -> str | None:
    def walk(entities: object, depth: int = 0) -> str | None:
        if not isinstance(entities, list) or depth > 3:
            return None
        for ent in entities:
            if not isinstance(ent, dict):
                continue
            roles = ent.get("roles")
            if isinstance(roles, list) and "registrar" in roles:
                name = _vcard_fn(ent)
                if name:
                    return name
            nested = walk(ent.get("entities"), depth + 1)
            if nested:
                return nested
        return None

    return walk(doc.get("entities"))


def parse_rdap(doc: object, domain: str, *, now: datetime | None = None,
               source: str = "rdap") -> RdapInfo | None:
    """Turn an RDAP domain object into :class:`RdapInfo` (``None`` if not a domain)."""
    if not isinstance(doc, dict):
        return None
    if doc.get("objectClassName") not in (None, "domain"):
        return None
    now = now or datetime.now(timezone.utc)
    registered = expires = changed = None
    events = doc.get("events")
    if isinstance(events, list):
        for ev in events:
            if not isinstance(ev, dict):
                continue
            action = str(ev.get("eventAction", "")).lower()
            dt = _parse_dt(ev.get("eventDate"))
            if dt is None:
                continue
            if action == "registration":
                # Keep the earliest registration event if several are reported.
                registered = dt if registered is None or dt < registered else registered
            elif action == "expiration":
                expires = dt
            elif action == "last changed":
                changed = dt
    notes: list[str] = []
    age: int | None = None
    if registered is not None:
        delta = now - registered
        if delta.total_seconds() < -86_400:
            notes.append("registration date is in the future; ignored")
            registered = None
        else:
            age = max(0, delta.days)
    else:
        notes.append("no registration event")
    ns: list[str] = []
    nss = doc.get("nameservers")
    if isinstance(nss, list):
        for n in nss[:16]:
            if isinstance(n, dict):
                name = n.get("ldhName") or n.get("unicodeName")
                if isinstance(name, str) and name:
                    ns.append(name.lower().rstrip("."))
    status = tuple(s for s in (doc.get("status") or []) if isinstance(s, str))[:12]
    return RdapInfo(domain=domain, registered=registered, age_days=age, expires=expires,
                    last_changed=changed, registrar=_registrar(doc),
                    nameservers=tuple(ns), status=status, source=source, notes=tuple(notes))


# --------------------------------------------------------------------------- #
# Caching helpers (disk; never fatal)
# --------------------------------------------------------------------------- #
def _cache(ns: str, ttl: float) -> DiskCache | None:
    try:
        return DiskCache(ns, ttl=ttl)
    except Exception as exc:  # unwritable data dir etc. -> run uncached
        log.debug("rdap cache unavailable: %r", exc)
        return None


def _cache_get(ns: str, ttl: float, key: str) -> Any:
    c = _cache(ns, ttl)
    # NB: DiskCache defines __len__, so an empty cache is falsy -> compare to None.
    return c.get(key) if c is not None else None


def _cache_set(ns: str, ttl: float, key: str, value: Any) -> None:
    c = _cache(ns, ttl)
    if c is not None:
        c.set(key, value)


def _info_from_cache(raw: dict[str, Any], domain: str, now: datetime) -> RdapInfo | None:
    registered = _parse_dt(raw.get("registered"))
    age = None
    if registered is not None:
        age = max(0, (now - registered).days)
    return RdapInfo(
        domain=domain, registered=registered, age_days=age,
        expires=_parse_dt(raw.get("expires")), registrar=raw.get("registrar"),
        nameservers=tuple(raw.get("nameservers") or ()), status=tuple(raw.get("status") or ()),
        source=str(raw.get("source") or "rdap"),
    )


# --------------------------------------------------------------------------- #
# Fetching
# --------------------------------------------------------------------------- #
async def _get_json(url: str, fetch: Fetcher, timeout: float) -> tuple[Any, int, str | None]:
    res = await fetch(url, headers={"accept": "application/rdap+json, application/json"},
                      max_bytes=MAX_RDAP_BYTES, timeout=timeout, max_redirects=4)
    if res.blocked_reason or res.error:
        return None, res.status, res.blocked_reason or res.error
    if res.status == 404:
        return None, 404, None
    if not 200 <= res.status < 300:
        return None, res.status, f"http {res.status}"
    if res.truncated:
        return None, res.status, "response too large"
    try:
        return json.loads(res.body.decode("utf-8", "replace")), res.status, None
    except ValueError:
        return None, res.status, "invalid json"


async def _bootstrap_service(tld: str, fetch: Fetcher, timeout: float) -> str | None:
    cached = _cache_get("rdap_bootstrap", BOOTSTRAP_TTL_S, "dns")
    doc = cached
    if doc is None:
        doc, _, err = await _get_json(IANA_BOOTSTRAP_URL, fetch, timeout)
        if doc is None:
            log.debug("rdap bootstrap unavailable: %s", err)
            return None
        _cache_set("rdap_bootstrap", BOOTSTRAP_TTL_S, "dns", doc)
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, list):
        return None
    for entry in services:
        try:
            tlds, urls = entry[0], entry[1]
        except (TypeError, IndexError):
            continue
        if isinstance(tlds, list) and tld in [str(t).lower() for t in tlds] \
                and isinstance(urls, list):
            https = [u for u in urls if isinstance(u, str) and u.startswith("https://")]
            if https:
                return https[0]
    return None


async def domain_age(domain: str, *, timeout: float = 6.0, now: datetime | None = None,
                     fetch: Fetcher | None = None, use_cache: bool = True) -> RdapInfo | None:
    """Look up registration data for ``domain`` (a registrable domain, e.g. ``a.co.uk``).

    Returns ``None`` when the domain is malformed, not registered (RDAP 404), or the
    registry could not be reached. ``fetch`` defaults to
    :func:`uniphish.core.net.safe_fetch` (looked up at call time) and exists for tests.
    """
    name = (domain or "").strip().rstrip(".").lower()
    if not _DOMAIN_RE.match(name):
        return None
    now = now or datetime.now(timezone.utc)
    fetcher: Fetcher = fetch or safe_fetch

    if use_cache:
        hit = _cache_get("rdap", HIT_TTL_S, name)
        if isinstance(hit, dict):
            return _info_from_cache(hit, name, now)
        if _cache_get("rdap_miss", MISS_TTL_S, name):
            return None

    path = "domain/" + quote(name, safe="")
    tld = name.rsplit(".", 1)[-1]
    attempts: list[str] = [RDAP_REDIRECTOR + path]
    doc: Any = None
    source = "rdap.org"
    not_found = False
    for i, url in enumerate(attempts):
        try:
            doc, status, err = await _get_json(url, fetcher, timeout)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.debug("rdap fetch %s failed: %r", url, exc)
            doc, status, err = None, 0, type(exc).__name__
        if doc is not None:
            break
        if status == 404:
            not_found = True
            break
        log.debug("rdap %s -> %s", url, err)
        if i == 0:
            try:
                service = await _bootstrap_service(tld, fetcher, timeout)
            except asyncio.CancelledError:
                raise
            except Exception:
                service = None
            if service:
                attempts.append(service.rstrip("/") + "/" + path)
                source = "iana-bootstrap"

    if doc is None:
        if not_found and use_cache:
            _cache_set("rdap_miss", MISS_TTL_S, name, True)
        return None
    info = parse_rdap(doc, name, now=now, source=source)
    if info is not None and use_cache:
        _cache_set("rdap", HIT_TTL_S, name, info.to_dict())
    return info
