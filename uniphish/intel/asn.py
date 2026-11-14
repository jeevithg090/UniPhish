"""IP -> ASN / organisation mapping through Team Cymru's DNS interface.

Why this exists
---------------
Where a site is hosted is context for a brand-impersonation verdict: a "bank" login
page served from a consumer broadband line, or from a hoster known for ignoring abuse
reports, is far more suspicious than the same page on a mainstream cloud. Team Cymru's
IP-to-ASN mapping is published over plain DNS TXT records, so it needs no API key and
no HTTP: only DNS queries (via :func:`uniphish.intel.dns.query_rr`).

* IPv4 ``a.b.c.d``   -> ``d.c.b.a.origin.asn.cymru.com``   TXT
  ``"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"``
* IPv6               -> nibble-reversed ``....origin6.asn.cymru.com`` TXT
* AS name            -> ``AS<n>.asn.cymru.com`` TXT
  ``"15169 | US | arin | 2000-03-30 | GOOGLE, US"``

Only globally routable addresses are looked up (a private address has no origin AS and
we never want to leak internal addressing into DNS queries). Results are cached on disk
for 24 hours. The provider lists below are a *small, conservative heuristic*, not a
reputation database.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from dataclasses import dataclass
from typing import Any

from uniphish.core.cache import DiskCache
from uniphish.core.net import is_public_ip
from uniphish.intel.dns import RRResolver, query_rr

log = logging.getLogger("uniphish.intel.asn")

__all__ = ["AsnInfo", "HOSTING_ASNS", "ABUSE_PRONE_ASNS", "classify_asn", "lookup_asn"]

CACHE_TTL_S = 86_400.0
_ORIGIN4 = "origin.asn.cymru.com"
_ORIGIN6 = "origin6.asn.cymru.com"
_ASNAME = "asn.cymru.com"

#: Well-known mainstream hosting / cloud / CDN autonomous systems.
HOSTING_ASNS: dict[int, str] = {
    13335: "Cloudflare",
    16509: "Amazon AWS",
    14618: "Amazon AWS",
    15169: "Google",
    396982: "Google Cloud",
    8075: "Microsoft Azure",
    14061: "DigitalOcean",
    16276: "OVHcloud",
    24940: "Hetzner",
    63949: "Akamai Connected Cloud (Linode)",
    20473: "Vultr",
    22612: "Namecheap",
    51167: "Contabo",
    47583: "Hostinger",
    26496: "GoDaddy",
    54113: "Fastly",
    45102: "Alibaba Cloud",
    132203: "Tencent Cloud",
    46606: "Unified Layer (Bluehost/HostGator)",
    36351: "IBM SoftLayer",
    8560: "IONOS",
    197540: "netcup",
    12876: "Scaleway",
    53667: "FranTech / BuyVM",
}
#: A few autonomous systems widely reported as abuse-tolerant ("bulletproof-ish")
#: hosters. Heuristic only; membership is a weak signal, never proof.
ABUSE_PRONE_ASNS: dict[int, str] = {
    44477: "Stark Industries Solutions",
    200593: "Prospero OOO",
    210644: "Aeza International",
}

_HOSTING_ORG_RE = re.compile(
    r"\b(?:hosting|hoster|host|cloud|datacenter|data[ -]center|vps|servers?|colo(?:cation)?|"
    r"dedicated|vserver|webhost\w*)\b"
)
_RESIDENTIAL_ORG_RE = re.compile(
    r"\b(?:telecom\w*|telekom\w*|broadband|cable|dsl|adsl|fib(?:er|re)|ftth|mobile|wireless|"
    r"cellular|residential|comcast|charter|verizon|spectrum|rogers|virgin media|vodafone|"
    r"telefonica|bsnl|jio|airtel|at&t|internet service)\b"
)


@dataclass(frozen=True)
class AsnInfo:
    """Autonomous-system context for one IP address."""

    ip: str
    asn: int
    prefix: str | None = None
    country: str | None = None
    registry: str | None = None
    org: str | None = None
    is_hosting: bool = False
    hosting_provider: str | None = None
    is_abuse_prone: bool = False
    is_residential_like: bool = False
    note: str | None = None

    @property
    def label(self) -> str:
        return f"AS{self.asn}" + (f" {self.org}" if self.org else "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "asn": self.asn,
            "prefix": self.prefix,
            "country": self.country,
            "registry": self.registry,
            "org": self.org,
            "is_hosting": self.is_hosting,
            "hosting_provider": self.hosting_provider,
            "is_abuse_prone": self.is_abuse_prone,
            "is_residential_like": self.is_residential_like,
            "note": self.note,
        }


def classify_asn(asn: int, org: str | None) -> tuple[bool, str | None, bool, bool, str | None]:
    """Classify an AS: ``(is_hosting, provider, abuse_prone, residential_like, note)``."""
    provider = HOSTING_ASNS.get(asn)
    abuse = asn in ABUSE_PRONE_ASNS
    if abuse:
        provider = provider or ABUSE_PRONE_ASNS[asn]
    low = (org or "").lower()
    hosting = provider is not None or bool(_HOSTING_ORG_RE.search(low))
    residential = (not hosting) and bool(_RESIDENTIAL_ORG_RE.search(low))
    note: str | None = None
    if abuse:
        note = "autonomous system widely reported as abuse-tolerant hosting"
    elif residential:
        note = "organisation name looks like a consumer / mobile ISP"
    elif hosting:
        note = "mainstream hosting provider" if asn in HOSTING_ASNS else "hosting-like name"
    return hosting, provider, abuse, residential, note


def _reverse_name(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        return ".".join(reversed(str(addr).split("."))) + "." + _ORIGIN4
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + "." + _ORIGIN6


def _fields(txt: str) -> list[str]:
    return [f.strip() for f in txt.strip().strip('"').split("|")]


def _parse_origin(values: tuple[str, ...]) -> tuple[int, str | None, str | None, str | None] | None:
    for v in values:
        f = _fields(v)
        if len(f) < 3:
            continue
        # The origin field may list several ASNs ("15169 36040"); take the first.
        m = re.match(r"\s*(?:AS)?(\d{1,10})", f[0])
        if not m:
            continue
        asn = int(m.group(1))
        prefix = f[1] or None
        country = f[2] or None
        registry = f[3] if len(f) > 3 and f[3] else None
        return asn, prefix, country, registry
    return None


def _parse_asname(values: tuple[str, ...]) -> str | None:
    for v in values:
        f = _fields(v)
        if len(f) >= 5 and f[4]:
            return f[4][:200]
    return None


def _cache(ns: str) -> DiskCache | None:
    try:
        return DiskCache(ns, ttl=CACHE_TTL_S)
    except Exception as exc:
        log.debug("asn cache unavailable: %r", exc)
        return None


def _from_dict(d: dict[str, Any]) -> AsnInfo | None:
    try:
        asn = int(d["asn"])
        ip = str(d["ip"])
    except (KeyError, TypeError, ValueError):
        return None
    org = d.get("org")
    hosting, provider, abuse, resid, note = classify_asn(asn, org)
    return AsnInfo(
        ip=ip,
        asn=asn,
        prefix=d.get("prefix"),
        country=d.get("country"),
        registry=d.get("registry"),
        org=org,
        is_hosting=hosting,
        hosting_provider=provider,
        is_abuse_prone=abuse,
        is_residential_like=resid,
        note=note,
    )


async def lookup_asn(
    ip: str, *, timeout: float = 4.0, rr_resolver: RRResolver | None = None, use_cache: bool = True
) -> AsnInfo | None:
    """Map ``ip`` to its origin AS. ``None`` if non-public, unmapped or lookup failed."""
    ip = (ip or "").strip().strip("[]")
    if not is_public_ip(ip):
        return None
    ip = str(ipaddress.ip_address(ip))
    name = _reverse_name(ip)
    if name is None:
        return None
    cache = _cache("asn") if use_cache else None
    if cache is not None:
        hit = cache.get(ip)
        if isinstance(hit, dict):
            return _from_dict(hit)
    try:
        origin = await query_rr(name, "TXT", timeout=timeout, resolver=rr_resolver)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log.debug("cymru origin lookup for %s failed: %r", ip, exc)
        return None
    parsed = _parse_origin(origin.values)
    if parsed is None:
        return None
    asn, prefix, country, registry = parsed
    org: str | None = None
    try:
        nm = await query_rr(f"AS{asn}.{_ASNAME}", "TXT", timeout=timeout, resolver=rr_resolver)
        org = _parse_asname(nm.values)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # org name is optional
        log.debug("cymru AS name lookup for AS%s failed: %r", asn, exc)
    record = {
        "ip": ip,
        "asn": asn,
        "prefix": prefix,
        "country": country,
        "registry": registry,
        "org": org,
    }
    if cache is not None and org is not None:
        cache.set(ip, record)
    return _from_dict(record)
