"""Offline tests for uniphish.analyzers.infra (all lookups mocked)."""

from __future__ import annotations

import asyncio
import datetime as dt
import importlib.util
import json
from pathlib import Path

import pytest

from uniphish.analyzers.infra import InfraAnalyzer
from uniphish.core import net
from uniphish.core.analyzer import AnalysisContext, AnalysisOptions, AnalyzerResult
from uniphish.core.engine import Engine
from uniphish.core.net import FetchResult
from uniphish.core.types import Artifact, BrandMatch, IndicatorType
from uniphish.intel import dns as dns_mod
from uniphish.intel import tls as tls_mod
from uniphish.intel.asn import AsnInfo, classify_asn
from uniphish.intel.dns import DNSResult, RRSet
from uniphish.intel.rdap import RdapInfo
from uniphish.intel.tls import TlsInfo

_spec = importlib.util.spec_from_file_location(
    "infra_analyzer_test_certs",
    Path(__file__).resolve().parents[1] / "intel" / "certs.py")
certs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(certs)  # type: ignore[union-attr]

PUB1, PUB2 = "93.184.216.34", "1.1.1.1"
LOGIN_URL = "https://secure-login.evil-shop.test/account/verify"


@pytest.fixture(autouse=True)
def _clean():
    dns_mod.clear_cache()
    net.set_resolver(None)
    dns_mod.set_rr_resolver(None)
    yield
    dns_mod.clear_cache()
    net.set_resolver(None)
    dns_mod.set_rr_resolver(None)


# ----------------------------------------------------------------------- builders
def ctx(online: bool = True, **opt) -> AnalysisContext:
    return AnalysisContext(options=AnalysisOptions(online=online, **opt))


def brand_ctx(brand: BrandMatch | None) -> AnalysisContext:
    c = ctx()
    if brand is not None:
        c.results["url"] = AnalyzerResult(brand=brand)
    return c


def paypal_lookalike(official: bool = False) -> BrandMatch:
    return BrandMatch(brand="paypal", name="PayPal", technique="official" if official
                      else "homoglyph", confidence=0.9, official=official,
                      legit_domains=["paypal.com"])


def dns_result(host="secure-login.evil-shop.test", ips=(PUB1,), mx=(), ttl=3600,
               ns=("ns1.cheap-dns.test",), a_count=None, errors=None) -> DNSResult:
    a = list(ips) if a_count is None else [f"{20 + i * 7}.9.9.{i + 1}" for i in range(a_count)]
    return DNSResult(host=host, domain=host.split(".", 1)[-1], a=a, mx=list(mx), ns=list(ns),
                     a_ttl=ttl, errors=dict(errors or {}))


def rdap_info(age: int | None, domain="evil-shop.test") -> RdapInfo:
    now = dt.datetime.now(dt.timezone.utc)
    return RdapInfo(domain=domain,
                    registered=None if age is None else now - dt.timedelta(days=age),
                    age_days=age, registrar="Example Registrar LLC")


def tls_info(**kw) -> TlsInfo:
    base = dict(host="secure-login.evil-shop.test", ip=PUB1, issuer_org="Some CA",
                issuer="O=Some CA", sans=("secure-login.evil-shop.test",), san_count=1,
                age_days=200, covers_host=True, cert_sha256="ab" * 32, verified=True)
    base.update(kw)
    return TlsInfo(**base)


def asn_info(asn=64500, org="Example Cloud Hosting, US", ip=PUB1) -> AsnInfo:
    hosting, provider, abuse, resid, note = classify_asn(asn, org)
    return AsnInfo(ip=ip, asn=asn, prefix="93.184.216.0/24", country="US", registry="arin",
                   org=org, is_hosting=hosting, hosting_provider=provider,
                   is_abuse_prone=abuse, is_residential_like=resid, note=note)


def analyzer(*, dns=None, rdap=None, tls=None, asn=None) -> InfraAnalyzer:
    async def _dns(host, **kw):
        return dns if isinstance(dns, DNSResult) else dns_result(host=host)

    async def _rdap(domain, **kw):
        return rdap

    async def _tls(host, **kw):
        return tls if tls is not None else TlsInfo(host=host, error="no cert in test")

    async def _asn(ip, **kw):
        return asn
    return InfraAnalyzer(dns=_dns, rdap=_rdap, tls=_tls, asn=_asn)


def sig(res, sid):
    return next((s for s in res.signals if s.id == sid), None)


def ids(res):
    return {s.id for s in res.signals}


async def run(an, url=LOGIN_URL, c=None):
    return await an.analyze(Artifact.from_url(url), c or ctx())


# ============================================================================ age
class TestDomainAge:
    @pytest.mark.parametrize("age,sid,weight", [
        (0, "infra.domain.age_lt_7d", 2.5),
        (6, "infra.domain.age_lt_7d", 2.5),
        (7, "infra.domain.age_lt_30d", 1.5),
        (29, "infra.domain.age_lt_30d", 1.5),
        (30, "infra.domain.age_lt_90d", 0.5),
        (89, "infra.domain.age_lt_90d", 0.5),
    ])
    async def test_young_domain_buckets(self, age, sid, weight):
        res = await run(analyzer(rdap=rdap_info(age)))
        s = sig(res, sid)
        assert s is not None and s.weight == weight and s.category == "infra"
        assert "T1583.001" in s.mitre and s.evidence["age_days"] == age
        assert str(age) in s.detail or age == 0
        assert len([x for x in res.signals if x.id.startswith("infra.domain.")]) == 1

    @pytest.mark.parametrize("age", [90, 365, 730])
    async def test_middle_age_is_neutral(self, age):
        res = await run(analyzer(rdap=rdap_info(age)))
        assert not [s for s in res.signals if s.id.startswith("infra.domain.")]

    async def test_old_domain_is_negative_evidence(self):
        res = await run(analyzer(rdap=rdap_info(4000)))
        s = sig(res, "infra.domain.age_gt_2y")
        assert s is not None and s.weight == -1.0 and s.mitre == []
        assert "10 years" in s.detail

    @pytest.mark.parametrize("url", [
        "https://evil-shop.pages.dev/login",          # LOTS / private suffix
        "https://phish.web.app/",
        "https://bit.ly/abc123",                      # shortener
    ])
    async def test_shared_hosting_never_gets_age_credit_or_lookup(self, url):
        called = []

        async def rdap(domain, **kw):
            called.append(domain)
            return rdap_info(5000)
        an = InfraAnalyzer(dns=lambda h, **k: _async(dns_result(host=h)), rdap=rdap,
                           tls=lambda h, **k: _async(TlsInfo(host=h, error="x")),
                           asn=lambda i, **k: _async(None))
        res = await an.analyze(Artifact.from_url(url), ctx())
        assert called == []
        assert not [s for s in res.signals if s.id.startswith("infra.domain.")]
        assert "age_skipped" in res.meta["infra"]

    async def test_rdap_unavailable_degrades_to_note(self):
        res = await run(analyzer(rdap=None))
        assert not [s for s in res.signals if s.id.startswith("infra.domain.")]
        assert res.meta["infra"]["unavailable"]["rdap"] == "no registration data"

    async def test_rdap_without_registration_date(self):
        res = await run(analyzer(rdap=rdap_info(None)))
        assert not [s for s in res.signals if s.id.startswith("infra.domain.")]


async def _async(v):
    return v


# ============================================================================ TLS
class TestCertificates:
    async def test_fresh_cert(self):
        res = await run(analyzer(tls=tls_info(age_days=2, issuer_org="Let's Encrypt")))
        s = sig(res, "infra.cert.fresh")
        assert s and s.weight == 1.0 and s.evidence["age_days"] == 2

    async def test_old_cert_not_flagged(self):
        res = await run(analyzer(tls=tls_info(age_days=7)))
        assert sig(res, "infra.cert.fresh") is None

    async def test_free_ca_with_brand_impersonation(self):
        t = tls_info(age_days=60, free_ca=True, is_lets_encrypt=True,
                     issuer_org="Let's Encrypt")
        res = await run(analyzer(tls=t), c=brand_ctx(paypal_lookalike()))
        s = sig(res, "infra.cert.free_ca_brand")
        assert s and s.weight == 0.5 and "PayPal" in s.detail

    async def test_free_ca_without_brand_is_not_flagged(self):
        t = tls_info(age_days=60, free_ca=True)
        res = await run(analyzer(tls=t), url="https://plain-site.test/")
        assert sig(res, "infra.cert.free_ca_brand") is None

    async def test_self_signed_on_credentials_page(self):
        res = await run(analyzer(tls=tls_info(self_signed=True, age_days=300)))
        s = sig(res, "infra.cert.self_signed")
        assert s and s.weight == 1.0

    async def test_self_signed_on_non_credential_url_is_not_flagged(self):
        res = await run(analyzer(tls=tls_info(self_signed=True, age_days=300)),
                        url="https://homelab-gadgets.test/")
        assert sig(res, "infra.cert.self_signed") is None

    async def test_san_mismatch(self):
        t = tls_info(covers_host=False, sans=("other.example.test", "www.other.example.test"),
                     san_count=2, age_days=300)
        res = await run(analyzer(tls=t))
        s = sig(res, "infra.cert.san_mismatch")
        assert s and s.weight == 2.0 and "other.example.test" in s.detail
        assert s.evidence["san_count"] == 2

    async def test_tls_error_becomes_unavailable_note(self):
        res = await run(analyzer(tls=TlsInfo(host="x", error="timeout")))
        assert res.meta["infra"]["unavailable"]["tls"] == "timeout"
        assert not [s for s in res.signals if s.id.startswith("infra.cert.")]
        assert not [i for i in res.indicators if i.type is IndicatorType.CERT_SHA256]

    async def test_http_url_is_not_probed(self):
        called = []

        async def tls(host, **kw):
            called.append(host)
            return tls_info()
        an = InfraAnalyzer(dns=lambda h, **k: _async(dns_result(host=h)),
                           rdap=lambda d, **k: _async(None), tls=tls,
                           asn=lambda i, **k: _async(None))
        await an.analyze(Artifact.from_url("http://secure-login.evil-shop.test/"), ctx())
        assert called == []

    async def test_odd_port_not_probed(self):
        called = []

        async def tls(host, **kw):
            called.append(host)
            return tls_info()
        an = InfraAnalyzer(dns=lambda h, **k: _async(dns_result(host=h)),
                           rdap=lambda d, **k: _async(None), tls=tls,
                           asn=lambda i, **k: _async(None))
        res = await an.analyze(Artifact.from_url("https://secure-login.evil-shop.test:2222/"),
                               ctx())
        assert called == [] and "not probed" in res.meta["infra"]["unavailable"]["tls"]


# ============================================================================ DNS
class TestDnsSignals:
    async def test_no_mx_on_login_domain(self):
        res = await run(analyzer(dns=dns_result(mx=())))
        s = sig(res, "infra.dns.no_mx")
        assert s and s.weight == 0.5

    async def test_mx_present_no_signal(self):
        res = await run(analyzer(dns=dns_result(mx=("10 mx.evil-shop.test",))))
        assert sig(res, "infra.dns.no_mx") is None

    async def test_mx_query_failure_is_not_no_mx(self):
        res = await run(analyzer(dns=dns_result(mx=(), errors={"MX": "timeout"})))
        assert sig(res, "infra.dns.no_mx") is None

    async def test_no_mx_needs_login_or_brand_context(self):
        res = await run(analyzer(dns=dns_result(mx=())), url="https://garden-tools.test/")
        assert sig(res, "infra.dns.no_mx") is None

    async def test_no_mx_not_for_official_brand(self):
        res = await run(analyzer(dns=dns_result(mx=())), c=brand_ctx(paypal_lookalike(True)))
        assert sig(res, "infra.dns.no_mx") is None

    async def test_fast_flux(self):
        d = dns_result(ttl=60, a_count=6)
        assert d.fast_flux
        res = await run(analyzer(dns=d, asn=None))
        s = sig(res, "infra.dns.fast_flux")
        assert s and s.weight == 1.0 and s.evidence["ttl"] == 60

    async def test_high_ttl_many_a_is_not_flux(self):
        res = await run(analyzer(dns=dns_result(ttl=3600, a_count=6)))
        assert sig(res, "infra.dns.fast_flux") is None

    async def test_unresolvable_host_noted(self):
        res = await run(analyzer(dns=dns_result(ips=())))
        assert res.meta["infra"]["unavailable"]["dns"] == "host does not resolve"
        assert res.meta["infra"]["unavailable"]["tls"] == "no public address"


# ============================================================================ ASN
class TestAsnSignals:
    async def test_brand_on_residential_asn(self):
        a = asn_info(64500, "Example Broadband Telecom, XX")
        assert a.is_residential_like
        res = await run(analyzer(asn=a), c=brand_ctx(paypal_lookalike()))
        s = sig(res, "infra.asn.brand_on_residential")
        assert s and s.weight == 1.0 and s.evidence["asn"] == 64500

    async def test_brand_on_abuse_prone_asn(self):
        a = asn_info(44477, "STARK-INDUSTRIES, GB")
        res = await run(analyzer(asn=a), c=brand_ctx(paypal_lookalike()))
        s = sig(res, "infra.asn.brand_on_abuse_hosting")
        assert s and s.weight == 1.0

    async def test_residential_asn_without_brand_is_not_flagged(self):
        a = asn_info(64500, "Example Broadband Telecom, XX")
        res = await run(analyzer(asn=a), url="https://garden-tools.test/")
        assert not [s for s in res.signals if s.id.startswith("infra.asn.")]

    async def test_mainstream_cloud_not_flagged_for_brand(self):
        a = asn_info(13335, "CLOUDFLARENET, US")
        res = await run(analyzer(asn=a), c=brand_ctx(paypal_lookalike()))
        assert not [s for s in res.signals if s.id.startswith("infra.asn.")]

    async def test_official_brand_records_baseline_note_without_signals(self):
        a = asn_info(13335, "CLOUDFLARENET, US")
        res = await run(analyzer(asn=a, dns=dns_result(host="www.paypal.com")),
                        url="https://www.paypal.com/signin", c=brand_ctx(paypal_lookalike(True)))
        assert "expected_infra_note" in res.meta["infra"]
        assert not [s for s in res.signals if s.id.startswith("infra.asn.")]

    async def test_asn_indicator_deduplicated(self):
        a1, a2 = asn_info(64500, ip=PUB1), asn_info(64500, ip=PUB2)
        n = {PUB1: a1, PUB2: a2}

        async def _asn(ip, **kw):
            return n[ip]
        an = InfraAnalyzer(dns=lambda h, **k: _async(dns_result(host=h, ips=(PUB1, PUB2))),
                           rdap=lambda d, **k: _async(None),
                           tls=lambda h, **k: _async(TlsInfo(host=h, error="x")), asn=_asn)
        res = await an.analyze(Artifact.from_url(LOGIN_URL), ctx())
        asns = [i for i in res.indicators if i.type is IndicatorType.ASN]
        assert [i.value for i in asns] == ["AS64500"]


# ===================================================================== indicators
class TestIndicators:
    async def test_ips_cert_and_asn_indicators(self):
        d = dns_result(ips=(PUB1,))
        d.aaaa = ["2606:4700:4700::1111"]
        res = await run(analyzer(dns=d, tls=tls_info(), asn=asn_info()))
        by_type = {(i.type, i.value): i for i in res.indicators}
        assert by_type[(IndicatorType.IPV4, PUB1)].role == "resolved"
        assert by_type[(IndicatorType.IPV6, "2606:4700:4700::1111")].role == "resolved"
        assert by_type[(IndicatorType.CERT_SHA256, "ab" * 32)].role == "tls-leaf"
        assert (IndicatorType.ASN, "AS64500") in by_type

    async def test_non_public_addresses_are_not_indicators_or_probed(self):
        seen = {"tls": None, "asn": []}

        async def tls(host, *, ips, **kw):
            seen["tls"] = ips
            return TlsInfo(host=host, error="x")

        async def asn(ip, **kw):
            seen["asn"].append(ip)
        an = InfraAnalyzer(dns=lambda h, **k: _async(dns_result(host=h, ips=("10.0.0.5",))),
                           rdap=lambda d, **k: _async(None), tls=tls, asn=asn)
        res = await an.analyze(Artifact.from_url(LOGIN_URL), ctx())
        assert not res.indicators and seen["asn"] == []
        assert seen["tls"] is None  # never probed: no public address


# =================================================================== robustness
class TestRobustness:
    async def test_every_lookup_raising_never_breaks_analysis(self):
        async def boom(*a, **k):
            raise RuntimeError("lookup exploded")
        res = await InfraAnalyzer(dns=boom, rdap=boom, tls=boom, asn=boom).analyze(
            Artifact.from_url(LOGIN_URL), ctx())
        assert res.signals == []
        un = res.meta["infra"]["unavailable"]
        assert un["dns"] == "RuntimeError" and un["rdap"] == "RuntimeError"

    async def test_slow_lookups_are_bounded_by_budget(self):
        async def slow(*a, **k):
            await asyncio.sleep(30)
        an = InfraAnalyzer(dns=slow, rdap=slow, tls=slow, asn=slow)
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        res = await an.analyze(Artifact.from_url(LOGIN_URL), ctx(analyzer_timeout_s=1.5))
        assert loop.time() - t0 < 4.0
        assert res.meta["infra"]["unavailable"]["dns"] == "timeout"

    async def test_partial_results_survive_other_failures(self):
        async def boom(*a, **k):
            raise RuntimeError
        an = InfraAnalyzer(dns=lambda h, **k: _async(dns_result(host=h)),
                           rdap=lambda d, **k: _async(rdap_info(2)), tls=boom, asn=boom)
        res = await an.analyze(Artifact.from_url(LOGIN_URL), ctx())
        assert "infra.domain.age_lt_7d" in ids(res)

    @pytest.mark.parametrize("url", ["http://localhost/", "https://intranet/login",
                                     "https://printer.local/", "https://db.internal/x"])
    async def test_internal_names_are_never_looked_up(self, url):
        async def boom(*a, **k):  # pragma: no cover - must not run
            raise AssertionError("looked up an internal name")
        res = await InfraAnalyzer(dns=boom, rdap=boom, tls=boom, asn=boom).analyze(
            Artifact.from_url(url), ctx())
        assert res.meta["infra"]["skipped"] == "internal host name" and not res.signals

    async def test_ip_literal_host_skips_dns_and_rdap(self):
        calls = {"dns": 0, "rdap": 0}

        async def dns(*a, **k):
            calls["dns"] += 1

        async def rdap(*a, **k):
            calls["rdap"] += 1
        tls_calls = []

        async def tls(host, *, ips, **kw):
            tls_calls.append((host, ips))
            return tls_info(host=host, covers_host=False, sans=("x.test",), age_days=300)
        an = InfraAnalyzer(dns=dns, rdap=rdap, tls=tls, asn=lambda i, **k: _async(None))
        res = await an.analyze(Artifact.from_url("https://93.184.216.34/login"), ctx())
        assert calls == {"dns": 0, "rdap": 0} and tls_calls == [(PUB1, [PUB1])]
        assert "infra.cert.san_mismatch" in ids(res)

    async def test_private_ip_literal_is_not_connected_to(self):
        async def boom(*a, **k):  # pragma: no cover
            raise AssertionError("contacted a private address")
        res = await InfraAnalyzer(dns=boom, rdap=boom, tls=boom, asn=boom).analyze(
            Artifact.from_url("https://169.254.169.254/latest/meta-data"), ctx())
        assert not res.indicators and not res.signals

    def test_applies_and_declares_signals(self):
        a = InfraAnalyzer()
        assert a.requires_online and a.stage == 20 and a.name == "infra"
        assert a.applies(Artifact.from_url("https://a.test"), ctx())
        assert all(k.startswith("infra.") for k in a.signals)

    async def test_every_emitted_signal_is_declared(self):
        a = analyzer(
            dns=dns_result(ttl=30, a_count=6),
            rdap=rdap_info(1),
            tls=tls_info(age_days=1, free_ca=True, self_signed=True, covers_host=False),
            asn=asn_info(44477, "STARK-INDUSTRIES, GB"))
        res = await run(a, c=brand_ctx(paypal_lookalike()))
        assert ids(res) and ids(res) <= set(InfraAnalyzer.signals)
        assert all(s.category == "infra" for s in res.signals)
        # (a self-signed cert is never also "fresh": its age carries no CA information)
        assert {"infra.domain.age_lt_7d", "infra.cert.free_ca_brand",
                "infra.cert.self_signed", "infra.cert.san_mismatch", "infra.dns.fast_flux",
                "infra.asn.brand_on_abuse_hosting"} <= ids(res)

    async def test_meta_is_json_serialisable(self):
        res = await run(analyzer(dns=dns_result(), rdap=rdap_info(3), tls=tls_info(),
                                 asn=asn_info()))
        json.dumps(res.meta)


# ================================================== low-level mocks, real functions
class TestEndToEndWithLowLevelMocks:
    """Real intel code paths; only the wire (resolver, RDAP fetch, handshake) is faked."""

    async def test_brand_new_phish_domain(self, monkeypatch):
        host = "paypal-secure.evil-shop.test"
        now = dt.datetime.now(dt.timezone.utc)
        der, _ = certs.make_cert(host, [host], issuer_cn="R11", issuer_org="Let's Encrypt",
                                 age_days=1)

        async def addr(h, rdtype, timeout):
            return [PUB1] if (h == host and rdtype == "A") else []
        net.set_resolver(addr)

        async def rr(h, rdtype, timeout):
            table = {
                (host, "A"): RRSet((PUB1,), 300),
                ("34.216.184.93.origin.asn.cymru.com", "TXT"):
                    RRSet(('"64500 | 93.184.216.0/24 | NL | ripencc | 2020-01-01"',)),
                ("as64500.asn.cymru.com", "TXT"):
                    RRSet(('"64500 | NL | ripencc | 2010-01-01 | EXAMPLE-NET Telecom, NL"',)),
            }
            return table.get((h, rdtype), RRSet())
        dns_mod.set_rr_resolver(rr)

        reg = (now - dt.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        fetched = []

        async def fake_fetch(url, **kw):
            fetched.append(url)
            body = json.dumps({"objectClassName": "domain", "events": [
                {"eventAction": "registration", "eventDate": reg}]}).encode()
            return FetchResult(url, url, 200, {}, body, False, [], None, 1.0, None, None,
                               "application/rdap+json", None)
        monkeypatch.setattr("uniphish.intel.rdap.safe_fetch", fake_fetch)

        async def connector(ip, port, name, verify, timeout):
            assert (ip, port, name) == (PUB1, 443, host)
            return der
        monkeypatch.setattr(tls_mod, "_default_connector", connector)

        res = await InfraAnalyzer().analyze(
            Artifact.from_url(f"https://{host}/signin"), brand_ctx(paypal_lookalike()))
        got = ids(res)
        assert {"infra.domain.age_lt_7d", "infra.cert.fresh", "infra.cert.free_ca_brand",
                "infra.dns.no_mx", "infra.asn.brand_on_residential"} <= got
        assert fetched == ["https://rdap.org/domain/evil-shop.test"]
        types = {i.type for i in res.indicators}
        assert {IndicatorType.IPV4, IndicatorType.CERT_SHA256, IndicatorType.ASN} <= types
        assert res.meta["infra"]["unavailable"] == {}

    async def test_established_domain_gets_legitimacy(self, monkeypatch):
        host = "www.old-shop.test"
        der, _ = certs.make_cert(host, [host], issuer_cn="Some CA", age_days=100)

        async def addr(h, rdtype, timeout):
            return [PUB1] if rdtype == "A" else []
        net.set_resolver(addr)

        async def rr(h, rdtype, timeout):
            if rdtype == "MX":
                return RRSet(("10 mx.old-shop.test",))
            return RRSet()
        dns_mod.set_rr_resolver(rr)

        async def fake_fetch(url, **kw):
            body = json.dumps({"objectClassName": "domain", "events": [
                {"eventAction": "registration", "eventDate": "2012-03-04T00:00:00Z"}]}).encode()
            return FetchResult(url, url, 200, {}, body, False, [], None, 1.0, None, None,
                               "application/rdap+json", None)
        monkeypatch.setattr("uniphish.intel.rdap.safe_fetch", fake_fetch)

        async def connector(*a):
            return der
        monkeypatch.setattr(tls_mod, "_default_connector", connector)

        res = await InfraAnalyzer().analyze(Artifact.from_url(f"https://{host}/"), ctx())
        assert ids(res) == {"infra.domain.age_gt_2y"}
        assert sum(s.weight for s in res.signals) == -1.0


# ================================================================ engine plumbing
class TestEngineIntegration:
    def _engine(self, **kw) -> Engine:
        return Engine(analyzers=[analyzer(**kw)])

    async def test_skipped_offline(self):
        v = await self._engine(rdap=rdap_info(1)).analyze_url(LOGIN_URL, online=False)
        assert v.signals == []
        assert v.analyzers == []  # requires_online: the engine never selects it

    async def test_online_contributes_signals_and_meta(self):
        v = await self._engine(rdap=rdap_info(1), tls=tls_info(age_days=1)).analyze_url(
            LOGIN_URL, online=True)
        got = {s.id for s in v.signals}
        assert {"infra.domain.age_lt_7d", "infra.cert.fresh"} <= got
        assert all(s.analyzer == "infra" for s in v.signals)
        assert "infra" in v.meta and v.analyzers[0].status == "ok"
        assert any(m.id == "T1583.001" for m in v.mitre)
        # age signal outweighs the cert signal and is damped within the 'infra' category
        assert v.logit > -2.0

    async def test_registered_in_global_registry(self):
        from uniphish.core.analyzer import REGISTRY, signal_catalog
        assert REGISTRY["infra"] is InfraAnalyzer
        cat = signal_catalog()
        assert cat["infra.domain.age_lt_7d"]["analyzer"] == "infra"
