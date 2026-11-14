"""Lexical feature extraction on crafted (synthetic, inert) URLs."""

from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from uniphish.url.lexical import LexicalFeatures, features


def test_sizes_and_host_shape():
    f = features("https://a.b.c.example.test/p/q?x=1#frag")
    assert f.url_len == len("https://a.b.c.example.test/p/q?x=1#frag")
    assert f.host_len == len("a.b.c.example.test")
    assert (f.path_len, f.query_len) == (4, 3)
    assert f.num_dots == 4 and f.num_subdomains == 3 and not f.many_subdomains
    assert f.tld == "test"
    assert features("https://a.b.c.d.example.test/").many_subdomains


def test_digits_hyphens_entropy():
    f = features("https://my-bank-1234.example.test/")
    assert f.num_hyphens == 2 and f.num_digits_in_host == 4
    assert 0 < f.digit_ratio_host < 0.2 and f.raw_entropy > 2.5


def test_userinfo_and_at_redirect():
    f = features("https://paypal.com@evil.example/login")
    assert f.has_at and f.has_atsign_redirect
    g = features("ftp://anon:pw@files.example/")
    assert g.has_at and not g.has_atsign_redirect
    assert not features("https://example.test/a@b").has_at


def test_ports():
    assert features("https://a.test:8443/").non_std_port
    h = features("https://a.test:443/")
    assert h.has_port and not h.non_std_port
    assert not features("https://a.test/").has_port
    assert features("http://a.test:80/").non_std_port is False


def test_ip_hosts():
    f = features("http://203.0.113.5/x")
    assert f.is_ip and not f.ip_obfuscated and f.tld == "" and f.tld_risk is None
    g = features("http://0xCB007105/x")
    assert g.is_ip and g.ip_obfuscated
    assert features("http://[2001:db8::1]/").is_ip


def test_punycode_and_confusable_host():
    f = features("https://xn--pypal-4ve.com/")
    assert f.punycode and f.confusable_host and f.confusable_char_count == 1
    assert not features("https://example.com/").confusable_host


def test_mixed_script_host():
    f = features("https://pаypal.com/")  # Cyrillic a: whole label is mixed Latin+Cyrillic
    assert f.mixed_script_host
    assert not features("https://пример.example/").mixed_script_host


def test_tld_risk_and_lists():
    assert features("https://x.example.top/").tld_risk is not None
    assert features("https://x.example.com/").tld_risk is None
    assert features("https://bit.ly/abc").is_shortener
    assert features("https://evil.duckdns.org/").is_dyndns
    assert not features("https://example.com/").is_shortener


def test_lots_hosting():
    f = features("https://abc.pages.dev/login")
    assert f.lots is not None and f.lots.match == "pages.dev"
    assert features("https://example.com/").lots is None


def test_open_redirect_known_and_param():
    f = features("https://www.google.com/url?q=https%3A%2F%2Fevil.example%2Fx")
    assert f.open_redirect == "https://evil.example/x" and f.open_redirect_via.startswith("known:")
    g = features("https://site.test/go?next=https://other.example/a")
    assert g.open_redirect == "https://other.example/a" and g.open_redirect_via == "param:next"
    same = features("https://site.test/go?next=https://site.test/a")
    assert same.open_redirect is None
    assert features("https://site.test/go?next=/local").open_redirect is None


def test_lure_words_host_and_path():
    f = features("https://secure-login.example.test/account/verify")
    assert {"secure", "login"} <= set(f.sensitive_words_in_host)
    assert {"account", "verify"} <= set(f.sensitive_words_in_path)
    assert f.sensitive_weight_host > 0 and f.sensitive_weight_path > 0
    assert not features("https://example.test/syntax").sensitive_words_in_path


def test_brand_keywords_exclude_owner():
    f = features("https://paypal.com.evil.test/")
    assert f.brand_keyword_in_subdomain == ("paypal",)
    g = features("https://paypal-secure.test/")
    assert g.brand_keyword_in_sld == ("paypal",)
    h = features("https://example.test/microsoft/login")
    assert h.brand_keyword_in_path == ("microsoft",)
    own = features("https://www.paypal.com/paypal/help")
    assert own.brand_keyword_in_sld == () and own.brand_keyword_in_path == ()


def test_deep_path_and_encoding():
    f = features("https://a.test/1/2/3/4/5/6/7")
    assert f.deep_path and f.path_depth == 7
    assert not features("https://a.test/1/2").deep_path
    e = features("https://a.test/%6Cogin?x=%41%42")
    assert e.encoded_chars == 3 and not e.double_encoding
    assert features("https://a.test/%2541").double_encoding


def test_schemes():
    assert features("data:text/html,hello").data_or_js_scheme
    assert features("javascript:alert(1)").data_or_js_scheme
    assert not features("https://a.test/").data_or_js_scheme


def test_file_extensions():
    assert features("https://a.test/dl/setup.exe").suspicious_file_ext_in_path == ".exe"
    assert features("https://a.test/a.ZIP?x=1").suspicious_file_ext_in_path == ".zip"
    assert features("https://a.test/page.html").suspicious_file_ext_in_path is None
    d = features("https://a.test/invoice.pdf.exe")
    assert d.double_extension and d.suspicious_file_ext_in_path == ".exe"
    assert not features("https://a.test/setup.exe").double_extension


def test_random_label_heuristics():
    assert features("https://xkqzvbnmtrw.example/").vowelless_label
    assert features("https://a8f3k2x9q1.example/").random_looking_label
    assert features("https://3f9a1c7e5b2d4a60.example/").random_looking_label
    for ok in (
        "https://strengths.org/",
        "https://example.com/",
        "https://wikipedia.org/",
        "https://my-bank.example/",
    ):
        f = features(ok)
        assert not f.random_looking_label, ok
        assert not f.vowelless_label, ok


def test_benign_baseline_is_quiet():
    f = features("https://www.example.com/")
    assert not (
        f.has_at
        or f.is_ip
        or f.punycode
        or f.lots
        or f.is_shortener
        or f.deep_path
        or f.open_redirect
        or f.sensitive_words_in_host
        or f.random_looking_label
    )


def test_to_dict_is_json_serialisable():
    d = features("https://abc.pages.dev/login").to_dict()
    assert d["lots"]["match"] == "pages.dev"
    json.dumps(d)


def test_accepts_parsed_and_is_deterministic():
    from uniphish.url.parse import parse_url

    u = "https://a.b.example.top/x?y=1"
    assert features(parse_url(u)) == features(u)
    assert isinstance(features(u), LexicalFeatures)


@pytest.mark.parametrize("u", ["", "   ", "http://", "https://[::1", "http://a..b/", "%%%", "\x00"])
def test_degenerate_inputs_do_not_raise(u):
    features(u)


@given(st.text(max_size=200))
def test_never_raises(s):
    features(s)
    features("http://" + s)


def test_huge_input_bounded():
    f = features("https://" + "a." * 100 + "test/" + "login/" * 3000 + "?" + "a=%25" * 3000)
    assert f.deep_path and f.path_depth == 3000
