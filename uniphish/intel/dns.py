"""DNS reconnaissance for the infrastructure analyzer.

Why this exists
---------------
Phishing infrastructure leaves a recognisable DNS footprint: a lookalike domain that
has no mail exchanger (it was registered to host a page, not to receive mail), a
parking-service name-server on a freshly parked name, or a "fast-flux" A set (many
addresses, very short TTL, scattered across unrelated networks) used to keep a
takedown-resistant landing page alive. This module collects that footprint for one
host and distils it into a :class:`DNSResult`.

Design
------
* **A/AAAA go through** :func:`uniphish.core.net.resolve` so the platform's resolver
  override (:func:`uniphish.core.net.set_resolver`) and its SSRF-aware conventions are
  honoured. The other record types (CNAME/MX/NS/TXT) and the A-record TTL need
  record-type-aware answers that ``core.net`` does not expose, so they come from a
  small injectable :data:`RRResolver` (default: dnspython, async). Tests install a
  deterministic one with :func:`set_rr_resolver`.
* **A failed query is not an empty answer.** Every query records whether it
  *succeeded*; ``no_mx`` is only ever ``True`` when the MX query succeeded and was
  empty. Timeouts and SERVFAILs degrade to ``errors`` entries, never to evidence.
* The module only ever issues DNS queries (no connections to the answers), so it
  cannot be turned into an SSRF primitive. Whether the answers are *connectable* is
  decided later by the TLS probe, which re-validates every address.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from uniphish.core import net
from uniphish.core.cache import TTLCache

log = logging.getLogger("uniphish.intel.dns")

__all__ = [
    "DNSResult",
    "PARKING_NS_SUFFIXES",
    "RRResolver",
    "RRSet",
    "clear_cache",
    "lookup_dns",
    "query_rr",
    "set_rr_resolver",
]

#: Default per-query timeout (seconds).
DEFAULT_TIMEOUT = 4.0
#: Fast-flux heuristics: at least this many A records ...
FLUX_MIN_A = 4
#: ... with a TTL at or below this many seconds ...
FLUX_MAX_TTL = 300
#: ... spanning at least this many distinct /16 networks.
FLUX_MIN_NETWORKS = 3
#: Cap on records kept per type (hostile zones can return thousands).
MAX_RECORDS = 64

#: Name-server suffixes of well-known domain-parking / for-sale services. A parked
#: name carries no phishing content *yet*, but is a useful context note.
PARKING_NS_SUFFIXES: tuple[str, ...] = (
    "sedoparking.com",
    "parkingcrew.net",
    "bodis.com",
    "above.com",
    "domainsponsor.com",
    "fabulous.com",
    "parklogic.com",
    "dan.com",
    "afternic.com",
    "hugedomains.com",
    "namebrightdns.com",
    "voodoo.com",
    "trafficz.com",
)


# --------------------------------------------------------------------------- #
# Record-set resolver (injectable)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RRSet:
    """Textual records of one type plus the RRset TTL (``None`` if unknown)."""

    values: tuple[str, ...] = ()
    ttl: int | None = None


RRResolver = Callable[[str, str, float], Awaitable[RRSet]]

_RR_RESOLVER: RRResolver | None = None


def set_rr_resolver(resolver: RRResolver | None) -> None:
    """Install a process-wide record resolver (tests). ``None`` restores dnspython."""
    global _RR_RESOLVER
    _RR_RESOLVER = resolver


def _clean_name(name: str) -> str:
    return name.strip().rstrip(".").lower()


def _render(rdtype: str, rdata: Any) -> str:
    if rdtype == "MX":
        return f"{int(rdata.preference)} {_clean_name(str(rdata.exchange))}"
    if rdtype in ("NS", "CNAME"):
        return _clean_name(str(rdata.target))
    if rdtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", "replace")
    if rdtype in ("A", "AAAA"):
        return str(rdata.address)
    return str(rdata)


async def _dnspython_rr(host: str, rdtype: str, timeout: float) -> RRSet:
    """Default :data:`RRResolver`. Empty set for NXDOMAIN / NODATA; raises on failure."""
    try:
        answer = await dns.asyncresolver.resolve(
            host, rdtype, lifetime=timeout, raise_on_no_answer=False
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return RRSet()
    rrset = getattr(answer, "rrset", None)
    if rrset is None:
        return RRSet()
    values = tuple(_render(rdtype, r) for r in list(rrset)[:MAX_RECORDS])
    return RRSet(values=values, ttl=int(rrset.ttl))


async def query_rr(host: str, rdtype: str, *, timeout: float = DEFAULT_TIMEOUT,
                   resolver: RRResolver | None = None) -> RRSet:
    """Resolve ``rdtype`` for ``host`` through the (injectable) record resolver.

    Raises ``dns.exception.DNSException`` (or the resolver's own error) when the query
    itself fails, so callers can tell *failure* from *empty answer*.
    """
    fn = resolver or _RR_RESOLVER or _dnspython_rr
    return await fn(_clean_name(host), rdtype, timeout)


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #
@dataclass
class DNSResult:
    """What DNS says about a host (and its registrable domain)."""

    host: str
    domain: str
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    a_ttl: int | None = None
    #: record type -> short error code for queries that *failed* (not merely empty).
    errors: dict[str, str] = field(default_factory=dict)

    # ---- derived ---------------------------------------------------------- #
    @property
    def ips(self) -> list[str]:
        """All resolved addresses (A then AAAA), de-duplicated, order preserved."""
        return list(dict.fromkeys([*self.a, *self.aaaa]))

    @property
    def resolves(self) -> bool:
        return bool(self.a or self.aaaa)

    @property
    def mx_checked(self) -> bool:
        return "MX" not in self.errors

    @property
    def no_mx(self) -> bool:
        """``True`` only when the MX query *succeeded* and returned nothing.

        A null MX (RFC 7505, ``0 .``) also counts: the owner explicitly declared the
        domain mail-less.
        """
        if not self.mx_checked:
            return False
        real = [m for m in self.mx if m.split(" ", 1)[-1].strip(". ")]
        return not real

    @property
    def distinct_networks(self) -> int:
        """Number of distinct /16 (IPv4) or /32 (IPv6) networks among the A/AAAA set."""
        nets: set[str] = set()
        for ip in self.ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            prefix = 16 if addr.version == 4 else 32
            nets.add(str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False)))
        return len(nets)

    @property
    def fast_flux(self) -> bool:
        """Fast-flux-ish: many addresses, very low TTL, spread over unrelated networks.

        Large CDNs also publish many low-TTL addresses, so the spread across
        :data:`FLUX_MIN_NETWORKS` distinct networks is required as well; callers should
        additionally suppress this for top-ranked / official domains.
        """
        return (
            len(self.a) >= FLUX_MIN_A
            and self.a_ttl is not None
            and self.a_ttl <= FLUX_MAX_TTL
            and self.distinct_networks >= FLUX_MIN_NETWORKS
        )

    @property
    def parked(self) -> list[str]:
        """Parking indicators: parking-service name-servers (one entry per match)."""
        out: list[str] = []
        for ns in self.ns:
            for suf in PARKING_NS_SUFFIXES:
                if ns == suf or ns.endswith("." + suf):
                    out.append(f"ns:{ns}")
                    break
        return out

    @property
    def is_parked(self) -> bool:
        return bool(self.parked)

    @property
    def spf_present(self) -> bool:
        return any(t.lower().startswith("v=spf1") for t in self.txt)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe summary for ``Verdict.meta``."""
        return {
            "host": self.host, "domain": self.domain,
            "a": self.a[:16], "aaaa": self.aaaa[:16], "cname": self.cname[:8],
            "mx": self.mx[:8], "ns": self.ns[:8], "a_ttl": self.a_ttl,
            "a_count": len(self.a), "distinct_networks": self.distinct_networks,
            "no_mx": self.no_mx, "fast_flux": self.fast_flux, "parked": self.parked,
            "errors": dict(self.errors),
        }


# --------------------------------------------------------------------------- #
# Lookup
# --------------------------------------------------------------------------- #
_CACHE: TTLCache = TTLCache(maxsize=2048, ttl=300.0)


def clear_cache() -> None:
    """Drop cached lookups (tests, or after changing resolvers)."""
    _CACHE.clear()


def _err_code(exc: BaseException) -> str:
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError, dns.exception.Timeout)):
        return "timeout"
    return type(exc).__name__


async def _safe_rr(host: str, rdtype: str, timeout: float,
                   resolver: RRResolver | None) -> tuple[RRSet | None, str | None]:
    try:
        return await query_rr(host, rdtype, timeout=timeout, resolver=resolver), None
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # dns errors, injected-resolver errors, blocked sockets
        log.debug("rr %s/%s failed: %r", host, rdtype, exc)
        return None, _err_code(exc)


async def _safe_addrs(host: str, rdtype: str, timeout: float,
                      resolver: net.Resolver | None) -> tuple[list[str], str | None]:
    try:
        addrs = await net.resolve(host, rdtype, timeout=timeout, resolver=resolver)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log.debug("resolve %s/%s failed: %r", host, rdtype, exc)
        return [], _err_code(exc)
    return list(dict.fromkeys(addrs))[:MAX_RECORDS], None


async def lookup_dns(host: str, *, domain: str | None = None,
                     timeout: float = DEFAULT_TIMEOUT,
                     resolver: net.Resolver | None = None,
                     rr_resolver: RRResolver | None = None) -> DNSResult:
    """Collect the DNS footprint of ``host``.

    ``host`` is queried for A/AAAA/CNAME (where the page is served from);
    ``domain`` (default: ``host``) is queried for MX/NS/TXT (the registrable domain
    that owns mail and delegation). Queries run concurrently and never raise: a failed
    query is recorded in :attr:`DNSResult.errors`.

    Results are cached for five minutes unless an explicit ``resolver`` /
    ``rr_resolver`` is passed.
    """
    h = _clean_name(host)
    d = _clean_name(domain or host)
    cacheable = resolver is None and rr_resolver is None
    key = (h, d)
    if cacheable:
        hit = _CACHE.get(key)
        if hit is not None:
            return hit

    ip_literal = False
    try:
        ipaddress.ip_address(h.strip("[]"))
        ip_literal = True
    except ValueError:
        pass

    result = DNSResult(host=h, domain=d)
    if ip_literal:
        # Nothing to resolve: the "host" is already an address.
        bare = h.strip("[]")
        (result.aaaa if ":" in bare else result.a).append(bare)
        return result

    (a_res, a_err), (aaaa_res, aaaa_err), cname, ttl_a, mx, ns, txt = await asyncio.gather(
        _safe_addrs(h, "A", timeout, resolver),
        _safe_addrs(h, "AAAA", timeout, resolver),
        _safe_rr(h, "CNAME", timeout, rr_resolver),
        _safe_rr(h, "A", timeout, rr_resolver),
        _safe_rr(d, "MX", timeout, rr_resolver),
        _safe_rr(d, "NS", timeout, rr_resolver),
        _safe_rr(d, "TXT", timeout, rr_resolver),
    )
    result.a = a_res
    result.aaaa = aaaa_res
    if a_err:
        result.errors["A"] = a_err
    if aaaa_err:
        result.errors["AAAA"] = aaaa_err
    for rdtype, (_rs, err) in (("CNAME", cname), ("A-ttl", ttl_a), ("MX", mx),
                              ("NS", ns), ("TXT", txt)):
        if err:
            result.errors[rdtype] = err
    if cname[0]:
        result.cname = list(cname[0].values)[:MAX_RECORDS]
    if ttl_a[0]:
        result.a_ttl = ttl_a[0].ttl
    if mx[0]:
        result.mx = list(mx[0].values)[:MAX_RECORDS]
    if ns[0]:
        result.ns = list(ns[0].values)[:MAX_RECORDS]
    if txt[0]:
        result.txt = [t[:512] for t in txt[0].values[:MAX_RECORDS]]

    # Only cache answers that were not degraded by failures.
    if cacheable and not result.errors:
        _CACHE.set(key, result)
    return result
