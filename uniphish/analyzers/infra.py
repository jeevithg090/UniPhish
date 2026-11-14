"""Infrastructure analyzer: DNS, RDAP domain age, TLS certificate and ASN (online).

Why this exists
---------------
URL *form* tells you how a link is built; infrastructure tells you how it was stood
up. Phishing sites are overwhelmingly hosted on domains registered days earlier, behind
brand-new free certificates, on name servers or networks that legitimate brands do not
use. None of this is visible offline, so this analyzer runs only when the request is
online (``requires_online``) and at stage 20, after the URL/brand analyzers, so it can
condition its evidence on whether the URL impersonates a brand.

Evidence (category ``infra`` - correlated, so the scorer damps repeated hits)
-----------------------------------------------------------------------------
* domain age: < 7 d +2.5, < 30 d +1.5, < 90 d +0.5, > 2 y -1.0;
* certificate: issued < 7 d ago +1.0, free CA while impersonating a brand +0.5,
  self-signed on a credential-looking page +1.0, names not covering the host +2.0;
* DNS: no MX on a login / brand domain +0.5, low-TTL multi-network fast-flux +1.0;
* ASN: a brand lookalike hosted on a consumer-ISP-like or abuse-prone network +1.0.

Guard rails
-----------
* **No legitimacy for shared hosting.** Domain age is not assessed (and the "old domain"
  bonus is never granted) for living-off-trusted-sites hosts, private-suffix hosts such
  as ``x.pages.dev``, dynamic-DNS names and URL shorteners: the registrable parent is
  old, the attacker's page is not.
* **Degrade, never block.** Every lookup runs concurrently under a shared time budget,
  is individually fault-isolated, and failures become ``meta["infra"]["unavailable"]``
  notes - never exceptions and never evidence.
* **No leaking internal names.** Single-label and ``.local`` / ``.internal`` /
  ``.localhost`` hosts are never sent to public resolvers or registries.
* The TLS probe connects only to validated public addresses (see
  :mod:`uniphish.intel.tls`); ASN lookups are DNS-only.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from uniphish.assets.lists import is_dyndns, is_shortener, is_top_site, lots_match
from uniphish.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult, register
from uniphish.core.net import is_public_ip
from uniphish.core.types import (
    Artifact,
    ArtifactKind,
    BrandMatch,
    Indicator,
    IndicatorType,
    Signal,
)
from uniphish.intel import tls as tls_mod
from uniphish.intel.asn import AsnInfo, lookup_asn
from uniphish.intel.dns import DNSResult, lookup_dns
from uniphish.intel.rdap import RdapInfo, domain_age
from uniphish.intel.tls import TlsInfo, fetch_tls
from uniphish.url.parse import ParsedURL, parse_url

log = logging.getLogger("uniphish.analyzers.infra")

#: Addresses probed for ASN / included as indicators per host.
MAX_IPS = 3
#: Minimum brand confidence for "this URL impersonates a brand" conclusions.
BRAND_MIN_CONFIDENCE = 0.5
_INTERNAL_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".home.arpa",
    ".intranet",
    ".corp",
    ".private",
)

# Weights (signed log-odds) from the spec.
W_AGE_LT_7 = 2.5
W_AGE_LT_30 = 1.5
W_AGE_LT_90 = 0.5
W_AGE_OLD = -1.0
W_CERT_FRESH = 1.0
W_CERT_FREE_BRAND = 0.5
W_CERT_SELF_SIGNED = 1.0
W_CERT_SAN_MISMATCH = 2.0
W_NO_MX = 0.5
W_FAST_FLUX = 1.0
W_ASN_RESIDENTIAL = 1.0
W_ASN_ABUSE = 1.0

DnsFn = Callable[..., Awaitable[DNSResult]]
RdapFn = Callable[..., Awaitable["RdapInfo | None"]]
TlsFn = Callable[..., Awaitable[TlsInfo]]
AsnFn = Callable[..., Awaitable["AsnInfo | None"]]


def _round(x: float) -> float:
    return round(x, 2)


def _is_internal_name(host: str) -> bool:
    if "." not in host:
        return True
    return host.endswith(_INTERNAL_SUFFIXES)


def _registrable(parsed: ParsedURL, *, icann: bool) -> str:
    """ASCII registrable domain (PSL-aware; falls back to the last two labels)."""
    labels = parsed.host_ascii.split(".")
    reg = parsed.icann_registrable if icann else parsed.registrable_domain
    n = len(reg.split(".")) if reg else 0
    if n == 0:
        n = min(2, len(labels))
    return ".".join(labels[-n:])


@register
class InfraAnalyzer(Analyzer):
    """DNS / RDAP / TLS / ASN evidence for URL artifacts (online only)."""

    name = "infra"
    kinds = frozenset({ArtifactKind.URL})
    stage = 20
    requires_online = True
    blocking = False
    description = "Infrastructure: domain age (RDAP), TLS certificate, DNS and hosting ASN"
    signals = {
        "infra.domain.age_lt_7d": "Domain registered less than 7 days ago",
        "infra.domain.age_lt_30d": "Domain registered less than 30 days ago",
        "infra.domain.age_lt_90d": "Domain registered less than 90 days ago",
        "infra.domain.age_gt_2y": "Domain registered more than two years ago",
        "infra.cert.fresh": "TLS certificate issued less than 7 days ago",
        "infra.cert.free_ca_brand": "Free-CA certificate on a brand-impersonating site",
        "infra.cert.self_signed": "Self-signed certificate on a login-style page",
        "infra.cert.san_mismatch": "TLS certificate does not cover this host name",
        "infra.dns.no_mx": "Login/brand-style domain has no mail exchanger",
        "infra.dns.fast_flux": "Many low-TTL addresses across unrelated networks (fast-flux)",
        "infra.asn.brand_on_residential": "Brand lookalike hosted on a consumer-ISP-like network",
        "infra.asn.brand_on_abuse_hosting": "Brand lookalike hosted on an abuse-prone network",
    }

    def __init__(
        self,
        *,
        dns: DnsFn | None = None,
        rdap: RdapFn | None = None,
        tls: TlsFn | None = None,
        asn: AsnFn | None = None,
        max_ips: int = MAX_IPS,
    ) -> None:
        self._dns = dns
        self._rdap = rdap
        self._tls = tls
        self._asn = asn
        self.max_ips = max(1, max_ips)

    # ------------------------------------------------------------------ plumbing #
    def applies(self, artifact: Artifact, ctx: AnalysisContext) -> bool:
        return bool(artifact.url)

    @staticmethod
    async def _guard(
        label: str, coro: Awaitable[Any], timeout: float, unavailable: dict[str, str]
    ) -> Any:
        """Await ``coro`` with a timeout; failures are recorded, never raised."""
        try:
            return await asyncio.wait_for(coro, timeout=max(0.2, timeout))
        except asyncio.CancelledError:
            raise
        except (asyncio.TimeoutError, TimeoutError):
            unavailable[label] = "timeout"
        except Exception as exc:
            log.debug("infra %s failed: %r", label, exc)
            unavailable[label] = type(exc).__name__
        return None

    @staticmethod
    def _brand_for(parsed: ParsedURL, ctx: AnalysisContext) -> BrandMatch | None:
        brand = ctx.brand()
        if brand is not None:
            return brand
        try:  # URL analyzer may be disabled; the check is offline and cheap.
            from uniphish.url.brands import brand_impersonation

            return brand_impersonation(parsed)
        except Exception as exc:
            log.debug("brand_impersonation failed: %r", exc)
            return None

    @staticmethod
    def _credential_like(parsed: ParsedURL, ctx: AnalysisContext) -> bool:
        """Does the URL (or an earlier analyzer) suggest a credential-harvesting page?"""
        for res in ctx.results.values():
            for s in res.signals:
                sid = s.id.lower()
                if "password" in sid or "credential" in sid:
                    return True
        try:
            from uniphish.url.lexical import features

            f = features(parsed)
            return bool(f.sensitive_words_in_host or f.sensitive_words_in_path)
        except Exception as exc:
            log.debug("lexical features failed: %r", exc)
            return False

    # ------------------------------------------------------------------- analyze #
    async def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        started = time.monotonic()
        parsed = parse_url(artifact.url or "")
        meta: dict[str, Any] = {}
        unavailable: dict[str, str] = {}
        if not parsed.valid or not parsed.host_ascii:
            return AnalyzerResult(meta={"infra": {"skipped": "invalid url"}})

        is_ip = bool(parsed.is_ip and parsed.ip is not None)
        host = str(parsed.ip) if is_ip else parsed.host_ascii
        if not is_ip and _is_internal_name(host):
            return AnalyzerResult(meta={"infra": {"skipped": "internal host name"}})

        budget = max(1.0, ctx.options.analyzer_timeout_s * 0.85)

        def remaining() -> float:
            return budget - (time.monotonic() - started)

        reg_dns = _registrable(parsed, icann=False)
        reg_icann = _registrable(parsed, icann=True)
        private_suffix = bool(
            parsed.registrable_domain
            and parsed.icann_registrable
            and parsed.registrable_domain != parsed.icann_registrable
        )
        lots = lots_match(parsed.host_ascii, parsed.path) if not is_ip else None
        shared_hosting = bool(
            lots or private_suffix or (not is_ip and (is_dyndns(host) or is_shortener(host)))
        )
        brand = self._brand_for(parsed, ctx)
        official = bool(brand and brand.official)
        impersonating = bool(
            brand
            and not brand.official
            and brand.technique != "official"
            and brand.confidence >= BRAND_MIN_CONFIDENCE
        )
        creds_like = impersonating or self._credential_like(parsed, ctx)
        top_site = bool(not is_ip and not shared_hosting and is_top_site(reg_icann))

        # ---- stage A: DNS and RDAP concurrently ---------------------------- #
        dns_fn = self._dns or lookup_dns
        rdap_fn = self._rdap or domain_age
        tls_fn = self._tls or fetch_tls
        asn_fn = self._asn or lookup_asn

        want_rdap = not is_ip and not shared_hosting
        if not is_ip and shared_hosting:
            meta["age_skipped"] = (
                "living-off-trusted-sites / shared hosting: the registrable "
                "parent's age says nothing about this page"
            )
        t_a = min(6.0, remaining())
        dns_task = (
            self._guard(
                "dns", dns_fn(host, domain=reg_dns, timeout=min(4.0, t_a)), t_a, unavailable
            )
            if not is_ip
            else None
        )
        rdap_task = (
            self._guard("rdap", rdap_fn(reg_icann, timeout=min(5.0, t_a)), t_a, unavailable)
            if want_rdap
            else None
        )
        dns_res: DNSResult | None
        rdap_res: RdapInfo | None
        if dns_task is not None or rdap_task is not None:
            out = await asyncio.gather(dns_task or _none(), rdap_task or _none())
            dns_res, rdap_res = out[0], out[1]
        else:
            dns_res, rdap_res = None, None
        if is_ip:
            dns_res = DNSResult(host=host, domain=host)
            (dns_res.aaaa if ":" in host else dns_res.a).append(host)
        if dns_res is not None and not dns_res.resolves and "dns" not in unavailable and not is_ip:
            unavailable["dns"] = "host does not resolve"

        ips = [i for i in (dns_res.ips if dns_res else []) if is_public_ip(i)]
        public_ips = ips[: self.max_ips]

        # ---- stage B: TLS and ASN (need the addresses) ---------------------- #
        tls_res: TlsInfo | None = None
        asn_infos: list[AsnInfo] = []
        t_b = min(6.0, remaining())
        tasks: list[Awaitable[Any]] = []
        port = parsed.effective_port or 443
        probe_tls = parsed.scheme == "https" and bool(ips) and port in tls_mod.ALLOWED_PORTS
        if parsed.scheme == "https" and not probe_tls:
            unavailable["tls"] = "no public address" if not ips else f"port {port} not probed"
        if probe_tls and t_b > 0.3:
            tasks.append(
                self._guard(
                    "tls", tls_fn(host, port=port, ips=ips, timeout=min(5.0, t_b)), t_b, unavailable
                )
            )
        else:
            tasks.append(_none())
        asn_tasks = []
        if t_b > 0.3:
            for ip in public_ips:
                asn_tasks.append(
                    self._guard(f"asn:{ip}", asn_fn(ip, timeout=min(4.0, t_b)), t_b, unavailable)
                )
        gathered = await asyncio.gather(*tasks, *asn_tasks)
        tls_res = gathered[0]
        asn_infos = [a for a in gathered[1:] if a is not None]
        if public_ips and not asn_infos and not any(k.startswith("asn:") for k in unavailable):
            unavailable["asn"] = "no mapping returned"
        if isinstance(tls_res, TlsInfo) and tls_res.error:
            unavailable["tls"] = tls_res.error
            tls_res = None

        # ---- evidence -------------------------------------------------------- #
        signals: list[Signal] = []
        ev_ctx = {"host": host, "domain": reg_icann}

        if rdap_res is not None and rdap_res.age_days is not None:
            signals.extend(self._age_signals(rdap_res, reg_icann, shared_hosting))
        elif want_rdap and "rdap" not in unavailable:
            unavailable["rdap"] = "no registration data"

        if tls_res is not None:
            signals.extend(self._cert_signals(tls_res, host, impersonating, creds_like, brand))
        if dns_res is not None:
            signals.extend(
                self._dns_signals(
                    dns_res, reg_dns, creds_like, official, shared_hosting, top_site, is_ip
                )
            )
        signals.extend(self._asn_signals(asn_infos, impersonating, brand))

        # ---- indicators ------------------------------------------------------ #
        indicators: list[Indicator] = []
        for ip in ips[:16]:
            version = ipaddress.ip_address(ip).version
            indicators.append(
                Indicator(
                    type=IndicatorType.IPV6 if version == 6 else IndicatorType.IPV4,
                    value=ip,
                    role="resolved",
                    context=f"resolved address of {host}",
                )
            )
        if tls_res is not None and tls_res.cert_sha256:
            indicators.append(
                Indicator(
                    type=IndicatorType.CERT_SHA256,
                    value=tls_res.cert_sha256,
                    role="tls-leaf",
                    context=f"leaf certificate presented by {host}",
                )
            )
        seen_asn: set[int] = set()
        for a in asn_infos:
            if a.asn in seen_asn:
                continue
            seen_asn.add(a.asn)
            indicators.append(
                Indicator(
                    type=IndicatorType.ASN, value=f"AS{a.asn}", role="hosting", context=a.label
                )
            )

        # ---- meta ------------------------------------------------------------ #
        infra_meta: dict[str, Any] = {
            **ev_ctx,
            "dns": dns_res.to_dict() if dns_res else None,
            "rdap": rdap_res.to_dict() if rdap_res else None,
            "tls": tls_res.to_dict() if tls_res else None,
            "asn": [a.to_dict() for a in asn_infos],
            "unavailable": dict(unavailable),
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        }
        infra_meta.update(meta)
        if dns_res is not None and dns_res.parked:
            infra_meta["parked"] = dns_res.parked
        if official and asn_infos:
            infra_meta["expected_infra_note"] = (
                f"official {brand.name if brand else 'brand'} domain served from "
                + ", ".join(sorted({a.label for a in asn_infos}))
                + "; recorded as the brand's expected infrastructure baseline"
            )
        return AnalyzerResult(signals=signals, indicators=indicators, meta={"infra": infra_meta})

    # ------------------------------------------------------------------ signals #
    @staticmethod
    def _age_signals(info: RdapInfo, domain: str, shared_hosting: bool) -> list[Signal]:
        age = info.age_days
        if age is None:
            return []
        when = info.registered.date().isoformat() if info.registered else "unknown date"
        ev = {"domain": domain, "age_days": age, "registered": when, "registrar": info.registrar}
        reg = f" via {info.registrar}" if info.registrar else ""
        if age < 7:
            sid, w, label = "infra.domain.age_lt_7d", W_AGE_LT_7, "less than 7 days"
        elif age < 30:
            sid, w, label = "infra.domain.age_lt_30d", W_AGE_LT_30, "less than 30 days"
        elif age < 90:
            sid, w, label = "infra.domain.age_lt_90d", W_AGE_LT_90, "less than 90 days"
        elif age > 730 and not shared_hosting:
            return [
                Signal(
                    id="infra.domain.age_gt_2y",
                    title="Domain has been registered for more than two years",
                    detail=f"{domain} was registered on {when} ({age // 365} years ago){reg}; "
                    "long-lived domains are rarely throwaway phishing infrastructure.",
                    weight=W_AGE_OLD,
                    category="infra",
                    evidence=ev,
                )
            ]
        else:
            return []
        return [
            Signal(
                id=sid,
                title=f"Domain registered {label} ago",
                detail=f"{domain} was registered on {when} ({age} day{'s' if age != 1 else ''} "
                f"ago){reg}. Phishing domains are typically used within days of "
                "registration.",
                weight=w,
                category="infra",
                evidence=ev,
                mitre=["T1583.001"],
            )
        ]

    @staticmethod
    def _cert_signals(
        t: TlsInfo, host: str, impersonating: bool, creds_like: bool, brand: BrandMatch | None
    ) -> list[Signal]:
        out: list[Signal] = []
        issuer = t.issuer_org or t.issuer_cn or t.issuer or "unknown issuer"
        base_ev = {"cert_sha256": t.cert_sha256, "issuer": issuer, "host": host}
        if t.age_days is not None and t.age_days < 7 and not t.self_signed:
            out.append(
                Signal(
                    id="infra.cert.fresh",
                    title="TLS certificate issued less than 7 days ago",
                    detail=f"The certificate for {host} was issued by {issuer} "
                    f"{t.age_days} day{'s' if t.age_days != 1 else ''} ago, consistent "
                    "with newly stood-up infrastructure.",
                    weight=W_CERT_FRESH,
                    category="infra",
                    evidence={**base_ev, "age_days": t.age_days},
                    mitre=["T1583.001"],
                )
            )
        if t.free_ca and impersonating:
            name = brand.name if brand else "a brand"
            out.append(
                Signal(
                    id="infra.cert.free_ca_brand",
                    title="Free-CA certificate on a brand-impersonating site",
                    detail=f"{host} impersonates {name} but presents a certificate from the free "
                    f"CA {issuer}; brands normally use organisation-validated certificates.",
                    weight=W_CERT_FREE_BRAND,
                    category="infra",
                    evidence={**base_ev, "brand": brand.brand if brand else None},
                )
            )
        if t.self_signed and creds_like:
            out.append(
                Signal(
                    id="infra.cert.self_signed",
                    title="Self-signed certificate on a login-style page",
                    detail=f"{host} looks like a sign-in page but its certificate is "
                    "self-signed, so no CA vouches for the site.",
                    weight=W_CERT_SELF_SIGNED,
                    category="infra",
                    evidence=base_ev,
                )
            )
        if t.covers_host is False:
            names = ", ".join(t.sans[:5]) or (t.subject_cn or "no names")
            out.append(
                Signal(
                    id="infra.cert.san_mismatch",
                    title="TLS certificate does not cover this host name",
                    detail=f"The certificate served for {host} lists {names}"
                    f"{' ...' if len(t.sans) > 5 else ''}, none of which match the "
                    "host being visited.",
                    weight=W_CERT_SAN_MISMATCH,
                    category="infra",
                    evidence={**base_ev, "sans": list(t.sans[:20]), "san_count": t.san_count},
                )
            )
        return out

    @staticmethod
    def _dns_signals(
        d: DNSResult,
        domain: str,
        creds_like: bool,
        official: bool,
        shared_hosting: bool,
        top_site: bool,
        is_ip: bool,
    ) -> list[Signal]:
        out: list[Signal] = []
        if (
            not is_ip
            and creds_like
            and not official
            and not shared_hosting
            and not top_site
            and d.resolves
            and d.no_mx
        ):
            out.append(
                Signal(
                    id="infra.dns.no_mx",
                    title="Login/brand-style domain has no mail exchanger",
                    detail=f"{domain} looks like an account or brand domain but publishes no MX "
                    "record: it was set up to serve a page, not to run a real service.",
                    weight=W_NO_MX,
                    category="infra",
                    evidence={"domain": domain, "mx": d.mx, "ns": d.ns[:4]},
                )
            )
        if d.fast_flux and not official and not top_site:
            out.append(
                Signal(
                    id="infra.dns.fast_flux",
                    title="Many low-TTL addresses across unrelated networks (fast-flux)",
                    detail=f"{d.host} resolves to {len(d.a)} IPv4 addresses with a {d.a_ttl}s TTL "
                    f"spread over {d.distinct_networks} networks, a pattern used to "
                    "keep phishing pages alive despite takedowns.",
                    weight=W_FAST_FLUX,
                    category="infra",
                    evidence={"a_count": len(d.a), "ttl": d.a_ttl, "networks": d.distinct_networks},
                )
            )
        return out

    @staticmethod
    def _asn_signals(
        infos: list[AsnInfo], impersonating: bool, brand: BrandMatch | None
    ) -> list[Signal]:
        if not impersonating or not infos:
            return []
        name = brand.name if brand else "a brand"
        out: list[Signal] = []
        resid = [a for a in infos if a.is_residential_like]
        abuse = [a for a in infos if a.is_abuse_prone]
        if resid:
            a = resid[0]
            out.append(
                Signal(
                    id="infra.asn.brand_on_residential",
                    title="Brand lookalike hosted on a consumer-ISP-like network",
                    detail=f"The site imitating {name} is served from {a.ip} in {a.label}"
                    f"{' (' + a.country + ')' if a.country else ''}, which looks like a "
                    "consumer or mobile ISP rather than a business hoster.",
                    weight=W_ASN_RESIDENTIAL,
                    category="infra",
                    evidence={
                        "asn": a.asn,
                        "org": a.org,
                        "ip": a.ip,
                        "brand": brand.brand if brand else None,
                    },
                )
            )
        if abuse:
            a = abuse[0]
            out.append(
                Signal(
                    id="infra.asn.brand_on_abuse_hosting",
                    title="Brand lookalike hosted on an abuse-prone network",
                    detail=f"The site imitating {name} is served from {a.ip} in {a.label}, a "
                    "network widely reported as tolerant of abusive content.",
                    weight=W_ASN_ABUSE,
                    category="infra",
                    evidence={
                        "asn": a.asn,
                        "org": a.org,
                        "ip": a.ip,
                        "brand": brand.brand if brand else None,
                    },
                )
            )
        return out


async def _none() -> None:
    return None
