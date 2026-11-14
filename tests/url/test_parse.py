"""Tests for the hostile-input URL parser."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from uniphish.url.parse import (
    defang,
    extract_urls,
    host_is_under,
    normalize_url,
    parse_url,
    refang,
    same_site,
)


@pytest.mark.parametrize(
    "url,host,ascii_host,reg,is_ip",
    [
        ("https://pаypal.com/login", "pаypal.com", "xn--pypal-4ve.com", "pаypal.com", False),
        ("http://paypal.com@evil.test/verify", "evil.test", "evil.test", "evil.test", False),
        ("https://xn--80ak6aa92e.com/", "аррӏе.com", "xn--80ak6aa92e.com", "аррӏе.com", False),
        ("http://3232235777/admin", "192.168.1.1", "192.168.1.1", "", True),
        ("http://0xC0.0xA8.0.1/", "192.168.0.1", "192.168.0.1", "", True),
        ("http://192.168.257/", "192.168.1.1", "192.168.1.1", "", True),
        (
            "https://a.evil.pages.dev/x",
            "a.evil.pages.dev",
            "a.evil.pages.dev",
            "evil.pages.dev",
            False,
        ),
        ("paypal.co.uk/login", "paypal.co.uk", "paypal.co.uk", "paypal.co.uk", False),
        (
            "https://sub.münchen.de./p",
            "sub.münchen.de",
            "sub.xn--mnchen-3ya.de",
            "münchen.de",
            False,
        ),
        ("https://[2001:db8::1]:443/", "[2001:db8::1]", "[2001:db8::1]", "", True),
    ],
)
def test_host_resolution(url, host, ascii_host, reg, is_ip):
    p = parse_url(url)
    assert p.host == host
    assert p.host_ascii == ascii_host
    assert p.registrable_domain == reg
    assert p.is_ip is is_ip


def test_userinfo_at_trick_does_not_leak_brand_into_host():
    p = parse_url("https://accounts.google.com@phish.test/signin")
    assert p.host == "phish.test"
    assert p.has_userinfo and p.userinfo == "accounts.google.com"


def test_ipv4_obfuscation_flagged():
    assert parse_url("http://3232235777/").ip_obfuscated
    assert not parse_url("http://192.168.1.1/").ip_obfuscated


def test_backslash_is_slash_for_special_scheme():
    assert parse_url("https:\\\\evil.test\\path").host == "evil.test"


def test_control_characters_stripped():
    assert parse_url("https://ev\til\n.test/").host == "evil.test"


def test_sld_strips_multilevel_suffix():
    assert parse_url("https://paypal.co.uk/").sld == "paypal"
    assert parse_url("https://login.paypal.co.uk/").subdomain == "login"


def test_icann_vs_private_registrable():
    p = parse_url("https://a.evil.pages.dev/")
    assert p.registrable_domain == "evil.pages.dev"  # private PSL
    assert p.icann_registrable == "pages.dev"  # ICANN section


def test_no_authority_schemes_do_not_crash():
    for u in (
        "data:text/html,<b>x</b>",
        "javascript:alert(1)",
        "mailto:a@b.test",
        "tel:+1234",
        "about:blank",
    ):
        p = parse_url(u)
        assert p.host == ""


def test_port_parsing():
    assert parse_url("https://x.test:8443/").port == 8443
    assert parse_url("https://x.test:443/").effective_port == 443
    assert "invalid-port" in parse_url("https://x.test:99999/").errors


def test_normalize_idempotent_and_drops_default_port():
    once = normalize_url("HTTPS://Example.COM:443/a/./b/../c")
    assert once == normalize_url(once)
    assert "443" not in once and once == "https://example.com/a/c"


def test_host_relationships():
    assert host_is_under("a.paypal.com", "paypal.com")
    assert not host_is_under("notpaypal.com", "paypal.com")
    assert same_site("https://a.evil.pages.dev", "https://b.evil.pages.dev")
    assert not same_site("https://evil.pages.dev", "https://other.pages.dev")


def test_refang_defang_roundtrip_ioc():
    assert refang("hxxps://paypal[.]com/a") == "https://paypal.com/a"
    assert refang("evil(dot)test") == "evil.test"
    d = defang("https://paypal.com/login")
    assert "hxxps" in d and "[.]" in d


def test_extract_urls_spans_and_filters():
    text = "visit www.google.com and example.com/path but not file.txt or v1.2.3 ok"
    got = extract_urls(text)
    urls = {e.url for e in got}
    assert any("google.com" in u for u in urls)
    assert any("example.com/path" in u for u in urls)
    assert not any("file.txt" in u for u in urls)  # .txt is not a public suffix
    assert not any("1.2.3" in u for u in urls)
    for e in got:
        assert text[e.start : e.end]  # spans index into text


def test_extract_urls_defanged():
    got = extract_urls("payload at hxxps://evil[.]test/x please")
    assert got and got[0].defanged and "evil.test" in got[0].url


def test_extract_urls_bounded():
    many = " ".join(f"site{i}.com" for i in range(1000))
    assert len(extract_urls(many, max_urls=50)) == 50


@given(st.text(max_size=300))
def test_parse_never_raises(s):
    parse_url(s)  # must not raise on arbitrary input


@given(st.text(max_size=300))
def test_normalize_reaches_fixpoint(s):
    # A handful of pathological chars (fullwidth '＠', ideographic '｡') are UTS-46
    # mapped onto URL delimiters, so one pass is not always a fixpoint — but the
    # normaliser must stabilise, and real URLs are idempotent in one step.
    b = normalize_url(normalize_url(s))
    assert normalize_url(b) == b


@given(st.from_regex(r"https?://[a-z]{1,8}\.(com|org|net)(/[a-z]{0,8}){0,3}", fullmatch=True))
def test_normalize_idempotent_for_real_urls(s):
    assert normalize_url(normalize_url(s)) == normalize_url(s)
