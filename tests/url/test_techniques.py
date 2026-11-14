"""Attack-technique classification and MITRE mapping."""

from __future__ import annotations

import pytest

from uniphish.core.mitre import CATALOG
from uniphish.url.techniques import MITRE_MAP, TAXONOMY, classify


def test_every_technique_maps_to_catalog_ids():
    assert set(MITRE_MAP) == set(TAXONOMY)
    for tech, ids in MITRE_MAP.items():
        assert ids, tech
        assert all(i in CATALOG for i in ids), (tech, ids)


@pytest.mark.parametrize(
    "url,primary",
    [
        ("https://pаypal.com/", "homoglyph"),
        ("https://paypa1.com/", "typosquat"),
        ("https://paypal-secure.test/", "combosquat"),
        ("https://paypal.com.evil.test/", "subdomain_stuffing"),
        ("http://203.0.113.5/x", "ip_host"),
        ("http://0xCB007105/x", "ip_obfuscation"),
        ("https://bit.ly/abc", "url_shortener"),
        ("https://evil.duckdns.org/x", "dynamic_dns"),
        ("https://paypal.com@evil.example/", "at_redirect"),
        ("data:text/html,hello", "data_uri"),
        ("https://a.b.c.d.evil.test/", "excessive_subdomains"),
        ("https://site.test/go?next=https://other.example/a", "open_redirect_abuse"),
        ("https://example.top/", "suspicious_tld"),
    ],
)
def test_primary_technique(url, primary):
    r = classify(url)
    assert r.primary == primary, r
    assert primary in r.techniques and r.descriptions[primary]


def test_idn_homograph_via_native_or_contains():
    r = classify("https://pаypal-secure.test/")
    assert "idn_homograph" in r.techniques and r.target_brand == "paypal"
    assert "punycode" in r.techniques  # the wire form of any IDN host is xn--


def test_punycode_input_adds_punycode_technique():
    r = classify("https://xn--pypal-4ve.com/")
    assert {"homoglyph", "punycode"} <= set(r.techniques)
    assert r.primary == "homoglyph"


def test_multiple_techniques_and_taxonomy_order():
    r = classify("https://paypal.com.login-verify.abc.pages.dev/account/verify")
    assert {"subdomain_stuffing", "lots_hosting", "credential_path"} <= set(r.techniques)
    assert r.techniques == [t for t in TAXONOMY if t in r.techniques]
    assert r.target_brand == "paypal" and r.primary == "subdomain_stuffing"
    assert r.mitre == sorted(set(r.mitre)) and "T1566.002" in r.mitre and "T1583.006" in r.mitre


def test_path_deception_needs_credible_confidence():
    assert "path_deception" in classify("https://example.test/paypal/signin").techniques
    assert "path_deception" not in classify("https://example.test/paypal/").techniques


def test_official_hosts_have_no_impersonation_techniques():
    for u in ("https://www.paypal.com/signin/verify", "https://login.microsoftonline.com/"):
        r = classify(u)
        assert r.techniques == [] and r.primary is None and r.mitre == []


def test_official_redirector_still_reported():
    r = classify("https://www.google.com/url?q=https%3A%2F%2Fevil.example%2Fx")
    assert r.techniques == ["open_redirect_abuse"]
    assert not r.target_brand


def test_benign_url_is_empty():
    r = classify("https://www.example.com/about")
    assert r.techniques == [] and r.primary is None and r.target_brand is None


def test_credential_path_requires_corroboration():
    assert "credential_path" not in classify("https://example.test/login").techniques
    assert "credential_path" in classify("https://example.test/login/verify").techniques


def test_accepts_parsed_and_lexical_reuse():
    from uniphish.url.lexical import features
    from uniphish.url.parse import parse_url

    u = "https://paypal-secure.test/"
    assert classify(parse_url(u), lexical=features(u)) == classify(u)


@pytest.mark.parametrize("u", ["", "http://", "%%%", "javascript:void(0)"])
def test_degenerate_inputs(u):
    classify(u)
