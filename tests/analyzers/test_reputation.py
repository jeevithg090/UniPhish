"""Offline tests for the reputation analyzer (local DB, top sites, novelty, feeds)."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from uniphish.analyzers import reputation as rep
from uniphish.analyzers.reputation import ReputationAnalyzer, top_site_weight
from uniphish.core.analyzer import AnalysisContext, AnalysisOptions, AnalyzerResult
from uniphish.core.config import get_settings
from uniphish.core.types import Artifact, BrandMatch, Signal
from uniphish.store import get_store, reset_store


@pytest.fixture(autouse=True)
def _fresh():
    reset_store()
    for fn in (rep._safebrowsing, rep._virustotal, rep._urlscan):
        fn.cache_clear()
    yield
    reset_store()


def run(
    url: str,
    *,
    results: dict | None = None,
    online: bool = False,
    analyzer: ReputationAnalyzer | None = None,
    settings=None,
) -> AnalyzerResult:
    a = analyzer or ReputationAnalyzer()
    ctx = AnalysisContext(
        options=AnalysisOptions(online=online),
        settings=settings or get_settings(),
        results=results or {},
    )
    return asyncio.run(a.analyze(Artifact.from_url(url), ctx))


def ids(res: AnalyzerResult) -> list[str]:
    return [s.id for s in res.signals]


def sig(res: AnalyzerResult, sid: str) -> Signal:
    return next(s for s in res.signals if s.id == sid)


# ----------------------------------------------------------------- top sites
def test_top_site_weight_tiers():
    assert top_site_weight(1) == -3.0
    assert top_site_weight(1000) == -3.0
    assert top_site_weight(1001) == -2.0
    assert top_site_weight(10_000) == -2.0
    assert top_site_weight(10_001) == -1.0


def test_top_site_negative():
    res = run("https://www.google.com/search?q=cats")
    s = sig(res, "rep.top_site")
    assert s.weight == -3.0 and s.category == "reputation"
    assert s.evidence["rank"] == 1


def test_top_site_mid_rank_is_weaker():
    from uniphish.assets.lists import top_rank

    assert top_rank("utexas.edu") and 1000 < top_rank("utexas.edu") <= 10_000
    assert sig(run("https://www.utexas.edu/"), "rep.top_site").weight == -2.0


def test_top_site_low_rank_is_weakest():
    from uniphish.assets.lists import top_rank

    assert 10_000 < top_rank("fnal.gov") <= 100_000
    assert sig(run("https://www.fnal.gov/"), "rep.top_site").weight == -1.0


def test_unranked_domain_gets_no_credit():
    assert "rep.top_site" not in ids(run("https://zq-unranked-site.example/login"))


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.pages.dev/login",  # LOTS host of a top-ranked parent
        "https://someone.github.io/paypal",
        "https://bit.ly/abc",  # popular shortener
        "https://google.com@evil.example/login",  # user@host trick
        "http://93.184.216.34/x",
    ],
)
def test_no_top_site_bonus_for_lots_shortener_userinfo_ip(url):
    assert "rep.top_site" not in ids(run(url))


def test_lots_parent_domain_itself_gets_no_bonus():
    from uniphish.assets.lists import top_rank

    assert top_rank("pages.dev") is not None  # popular, yet a hosting platform
    assert "rep.top_site" not in ids(run("https://pages.dev/"))


def test_open_redirect_on_top_site_gets_no_bonus():
    res = run("https://www.google.com/url?q=https%3A%2F%2Fevil.example%2Fx")
    assert "rep.top_site" not in ids(res)


def test_brand_impersonation_suppresses_top_site_bonus():
    prior = AnalyzerResult(
        brand=BrandMatch(brand="x", name="X", technique="homoglyph", confidence=0.9)
    )
    assert "rep.top_site" not in ids(run("https://www.google.com/", results={"url": prior}))


def test_brand_signal_suppresses_top_site_bonus():
    prior = AnalyzerResult(
        signals=[Signal(id="url.brand.combosquat", title="t", weight=2.0, category="brand")]
    )
    assert "rep.top_site" not in ids(run("https://www.google.com/", results={"url": prior}))


def test_strong_foreign_evidence_suppresses_bonus():
    prior = AnalyzerResult(signals=[Signal(id="ml.cnn", title="t", weight=4.5, category="ml")])
    assert "rep.top_site" not in ids(run("https://www.google.com/", results={"ml": prior}))


def test_official_brand_result_does_not_suppress_bonus():
    prior = AnalyzerResult(
        brand=BrandMatch(
            brand="google", name="Google", technique="official", confidence=1.0, official=True
        )
    )
    assert "rep.top_site" in ids(run("https://www.google.com/", results={"url": prior}))


# ------------------------------------------------------------- local reputation
def test_denylist_positive_and_indicator():
    get_store().set_reputation(
        "domain", "bad.example", "deny", weight=7.0, reason="campaign 12", source="soc"
    )
    res = run("https://login.bad.example/a")
    s = sig(res, "rep.local_denylist")
    assert s.weight == 7.0 and "campaign 12" in s.detail and s.evidence["source"] == "soc"
    assert any(i.malicious and i.value == "bad.example" for i in res.indicators)


def test_denylist_default_and_clamped_weight():
    st = get_store()
    st.set_reputation("domain", "a.example", "deny")
    st.set_reputation("domain", "b.example", "deny", weight=99)
    assert sig(run("https://a.example/"), "rep.local_denylist").weight == 6.0
    assert sig(run("https://b.example/"), "rep.local_denylist").weight == 8.0


def test_deny_by_exact_url_and_ip():
    st = get_store()
    st.set_reputation("url", "https://x.example/p?a=1", "deny")
    st.set_reputation("ipv4", "203.0.113.9", "deny")
    assert "rep.local_denylist" in ids(run("https://x.example/p?a=1#frag"))
    assert "rep.local_denylist" not in ids(run("https://x.example/other"))
    assert "rep.local_denylist" in ids(run("http://203.0.113.9/login"))


def test_allowlist_negative_and_blocks_other_credit():
    get_store().set_reputation("domain", "partner.example", "allow", reason="vendor")
    res = run("https://portal.partner.example/")
    assert sig(res, "rep.local_allowlist").weight == -3.0
    assert "rep.never_seen" not in ids(res)


def test_allowlist_weight_sign_is_normalised():
    get_store().set_reputation("domain", "p.example", "allow", weight=2.0)
    assert sig(run("https://p.example/"), "rep.local_allowlist").weight == -2.0


def test_deny_beats_allow():
    st = get_store()
    st.set_reputation("domain", "mix.example", "allow")
    st.set_reputation("url", "https://sub.mix.example/evil", "deny")
    res = run("https://sub.mix.example/evil")
    assert ids(res) == ["rep.local_denylist"]


def test_parent_domain_above_registrable_is_not_consulted():
    get_store().set_reputation("domain", "example", "deny")
    assert not run("https://a.example.com/").signals or "rep.local_denylist" not in ids(
        run("https://a.example.com/")
    )


def test_expired_and_unknown_entries_ignored():
    st = get_store()
    st.set_reputation("domain", "old.example", "deny", ttl=-5)
    st.set_reputation("domain", "meh.example", "unknown")
    assert "rep.local_denylist" not in ids(run("https://old.example/"))
    assert not ids(run("https://meh.example/")) or "rep.local_allowlist" not in ids(
        run("https://meh.example/")
    )


def test_denylist_on_top_site_domain_wins_over_bonus():
    get_store().set_reputation("domain", "google.com", "deny")
    res = run("https://www.google.com/")
    assert ids(res) == ["rep.local_denylist"]


def test_store_failure_never_raises(monkeypatch):
    def boom():
        raise RuntimeError("db down")

    monkeypatch.setattr(ReputationAnalyzer, "_store", staticmethod(boom))
    res = run("https://www.google.com/")
    assert "rep.top_site" in ids(res)


# ------------------------------------------------------------------- novelty
def _seed_history(n: int) -> None:
    from uniphish.core.types import (
        Action,
        ArtifactKind,
        Indicator,
        IndicatorType,
        Level,
        Verdict,
    )

    st = get_store()
    for i in range(n):
        st.save_verdict(
            Verdict(
                kind=ArtifactKind.URL,
                target=f"https://seed{i}.example/",
                artifact_id=f"a{i}",
                risk=0.1,
                score=10,
                confidence=0.9,
                logit=-2.0,
                level=Level.BENIGN,
                action=Action.ALLOW,
                indicators=[Indicator(type=IndicatorType.DOMAIN, value=f"seed{i}.example")],
            )
        )


def test_novelty_requires_history():
    assert "rep.never_seen" not in ids(run("https://fresh-site.example/"))


def test_novelty_fires_for_unseen_domain_with_history():
    _seed_history(ReputationAnalyzer.novelty_min_history)
    res = run("https://fresh-site.example/")
    s = sig(res, "rep.never_seen")
    assert s.weight == pytest.approx(0.3)


def test_novelty_skipped_for_seen_domain():
    _seed_history(ReputationAnalyzer.novelty_min_history)
    assert "rep.never_seen" not in ids(run("https://seed3.example/other"))


def test_novelty_skipped_for_top_site():
    _seed_history(ReputationAnalyzer.novelty_min_history)
    assert "rep.never_seen" not in ids(run("https://www.google.com/"))


def test_domain_indicator_emitted_once_per_registrable():
    res = run("https://a.b.fresh-site.example/")
    assert [i.value for i in res.indicators if i.type.value == "domain"] == ["fresh-site.example"]


# --------------------------------------------------------------------- email
EML = (
    "{auth}From: Billing <alerts@vendor.example>\r\nTo: me@example.net\r\n"
    "Subject: Invoice\r\nDate: Mon, 1 Jan 2026 10:00:00 +0000\r\n"
    "Message-ID: <1@vendor.example>\r\n\r\nhello\r\n"
)
AUTH_PASS = (
    "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=vendor.example; "
    "dkim=pass header.d=vendor.example; dmarc=pass header.from=vendor.example\r\n"
)


def run_email(raw: str) -> AnalyzerResult:
    ctx = AnalysisContext(options=AnalysisOptions(online=False), settings=get_settings())
    return asyncio.run(ReputationAnalyzer().analyze(Artifact.from_email(raw), ctx))


def test_email_denylisted_sender_domain():
    get_store().set_reputation("domain", "vendor.example", "deny")
    res = run_email(EML.format(auth=""))
    assert sig(res, "rep.local_denylist").weight == 6.0
    assert any(i.malicious and i.type.value == "domain" for i in res.indicators)


def test_email_allowlist_requires_authenticated_sender():
    get_store().set_reputation("domain", "vendor.example", "allow")
    forged = run_email(EML.format(auth=""))
    assert "rep.local_allowlist" not in ids(forged)
    assert forged.meta["reputation_allow_ignored"]
    assert "rep.local_allowlist" in ids(run_email(EML.format(auth=AUTH_PASS)))


def test_email_denylisted_sender_address():
    get_store().set_reputation("email", "Alerts@Vendor.example", "deny")
    assert "rep.local_denylist" in ids(run_email(EML.format(auth="")))


def test_email_has_no_top_site_credit():
    raw = EML.replace("vendor.example", "google.com").format(auth="")
    assert "rep.top_site" not in ids(run_email(raw))


# --------------------------------------------------------------------- feeds
class Calls:
    def __init__(self, handler):
        self.requests: list[httpx.Request] = []
        self._handler = handler

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._handler(request)


def feed_run(url: str, handler, monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    from uniphish.core.config import reset_settings

    reset_settings()
    calls = Calls(handler)

    # Public-looking resolution without touching DNS.
    async def fake_resolver(host, rdtype, timeout):
        return ["93.184.216.34"] if rdtype == "A" else []

    from uniphish.core.net import set_resolver

    set_resolver(fake_resolver)
    try:
        res = run(
            url,
            online=True,
            analyzer=ReputationAnalyzer(transport=httpx.MockTransport(calls)),
            settings=get_settings(),
        )
    finally:
        set_resolver(None)
    return res, calls


def test_feeds_noop_without_keys_or_when_offline(monkeypatch):
    res, calls = feed_run(
        "https://shady-site.zqtest-lab.net/", lambda r: httpx.Response(500), monkeypatch
    )
    assert not calls.requests and not res.signals


def test_feeds_not_called_when_offline_even_with_keys(monkeypatch):
    monkeypatch.setenv("GSB_API_KEY", "k")
    from uniphish.core.config import reset_settings

    reset_settings()
    calls = Calls(lambda r: httpx.Response(200, json={}))
    res = run(
        "https://shady-site.zqtest-lab.net/",
        online=False,
        analyzer=ReputationAnalyzer(transport=httpx.MockTransport(calls)),
    )
    assert not calls.requests and "rep.safebrowsing" not in ids(res)


def test_safebrowsing_hit(monkeypatch):
    def h(req):
        assert req.headers["x-goog-api-key"] == "secret"
        assert "secret" not in str(req.url)
        return httpx.Response(
            200, json={"threats": [{"url": "x", "threatTypes": ["SOCIAL_ENGINEERING"]}]}
        )

    res, calls = feed_run(
        "https://shady-site.zqtest-lab.net/p", h, monkeypatch, GSB_API_KEY="secret"
    )
    assert sig(res, "rep.safebrowsing").weight == 6.0
    assert any(i.malicious and i.value == "zqtest-lab.net" for i in res.indicators)


def test_safebrowsing_clean_and_error_never_raise(monkeypatch):
    res, _ = feed_run(
        "https://clean-site.zqtest-lab.net/",
        lambda r: httpx.Response(200, json={}),
        monkeypatch,
        GSB_API_KEY="k",
    )
    assert "rep.safebrowsing" not in ids(res)
    res, _ = feed_run(
        "https://err-site.zqtest-lab.net/",
        lambda r: httpx.Response(500),
        monkeypatch,
        GSB_API_KEY="k",
    )
    assert "rep.safebrowsing" not in ids(res)


def test_errors_are_not_cached(monkeypatch):
    state = {"n": 0}

    def h(req):
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(503)
        return httpx.Response(200, json={"threats": [{"threatTypes": ["MALWARE"]}]})

    r1, _ = feed_run("https://flaky.zqtest-lab.net/", h, monkeypatch, GSB_API_KEY="k")
    r2, _ = feed_run("https://flaky.zqtest-lab.net/", h, monkeypatch, GSB_API_KEY="k")
    assert "rep.safebrowsing" not in ids(r1) and "rep.safebrowsing" in ids(r2)


def test_feed_results_are_cached(monkeypatch):
    h = lambda r: httpx.Response(200, json={"threats": [{"threatTypes": ["MALWARE"]}]})  # noqa: E731
    _, c1 = feed_run("https://cached.zqtest-lab.net/", h, monkeypatch, GSB_API_KEY="k")
    _, c2 = feed_run("https://cached.zqtest-lab.net/", h, monkeypatch, GSB_API_KEY="k")
    assert len(c1.requests) == 1 and len(c2.requests) == 0


@pytest.mark.parametrize(
    "mal,sus,expected", [(0, 0, None), (0, 3, 0.8), (1, 0, 1.5), (3, 0, 3.5), (9, 0, 6.0)]
)
def test_virustotal_mapping(monkeypatch, mal, sus, expected):
    body = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": mal, "suspicious": sus, "harmless": 50}
            }
        }
    }

    def h(req):
        assert req.headers["x-apikey"] == "vt" and "/domains/zqtest-lab.net" in str(req.url)
        return httpx.Response(200, json=body)

    res, _ = feed_run("https://www.zqtest-lab.net/", h, monkeypatch, VT_API_KEY="vt")
    if expected is None:
        assert "rep.virustotal" not in ids(res)
    else:
        assert sig(res, "rep.virustotal").weight == expected


def test_virustotal_404_is_clean(monkeypatch):
    res, _ = feed_run(
        "https://nf.zqtest-lab.net/", lambda r: httpx.Response(404), monkeypatch, VT_API_KEY="vt"
    )
    assert "rep.virustotal" not in ids(res)


SCAN_ID = "0123abcd-0123-4abc-8def-0123456789ab"


def test_urlscan_malicious(monkeypatch):
    def h(req):
        if "/search/" in str(req.url):
            return httpx.Response(200, json={"results": [{"_id": SCAN_ID}]})
        assert SCAN_ID in str(req.url)
        return httpx.Response(
            200, json={"verdicts": {"overall": {"malicious": True, "score": 100}}}
        )

    res, calls = feed_run("https://scan.zqtest-lab.net/", h, monkeypatch, URLSCAN_API_KEY="us")
    assert sig(res, "rep.urlscan").weight == 5.0
    assert len(calls.requests) == 2
    assert calls.requests[0].headers["api-key"] == "us"


def test_urlscan_ignores_malformed_scan_id(monkeypatch):
    def h(req):
        return httpx.Response(200, json={"results": [{"_id": "../../etc/passwd"}]})

    res, calls = feed_run("https://scan2.zqtest-lab.net/", h, monkeypatch, URLSCAN_API_KEY="us")
    assert "rep.urlscan" not in ids(res) and len(calls.requests) == 1


def test_non_public_hosts_never_sent_to_feeds(monkeypatch):
    h = lambda r: httpx.Response(200, json={"threats": [{"threatTypes": ["MALWARE"]}]})  # noqa: E731
    for url in (
        "https://intranet.corp/x",
        "http://192.168.1.5/x",
        "https://phish.test/login",
        "https://singlelabel/",
    ):
        res, calls = feed_run(
            url, h, monkeypatch, GSB_API_KEY="k", VT_API_KEY="v", URLSCAN_API_KEY="u"
        )
        assert not calls.requests, url
        assert "rep.safebrowsing" not in ids(res)


def test_garbage_json_is_ignored(monkeypatch):
    bad = lambda r: httpx.Response(200, content=b"{not")  # noqa: E731
    res, _ = feed_run(
        "https://junk.zqtest-lab.net/",
        bad,
        monkeypatch,
        GSB_API_KEY="k",
        VT_API_KEY="v",
        URLSCAN_API_KEY="u",
    )
    assert not any(s.id.startswith("rep.") and s.id != "rep.never_seen" for s in res.signals)


# ---------------------------------------------------------------- robustness
@pytest.mark.parametrize(
    "url",
    [
        "http://",
        "https://[::1",
        "javascript:alert(1)",
        "data:text/html,x",
        "https://" + "a." * 120 + "example",
        "http://%00/",
        "ftp://x.example/",
    ],
)
def test_hostile_urls_never_raise(url):
    run(url)


def test_catalog_declares_every_emitted_id():
    declared = set(ReputationAnalyzer.signals)
    assert {
        "rep.top_site",
        "rep.local_denylist",
        "rep.local_allowlist",
        "rep.never_seen",
        "rep.safebrowsing",
        "rep.virustotal",
        "rep.urlscan",
    } == declared
    assert set(rep._FEED_META[k][0] for k in rep._FEED_META) <= declared


def test_registered_and_json_safe():
    from uniphish.core.analyzer import REGISTRY

    assert REGISTRY["reputation"] is ReputationAnalyzer
    get_store().set_reputation("domain", "j.example", "deny")
    for s in run("https://j.example/").signals:
        json.dumps(s.model_dump(mode="json"))
