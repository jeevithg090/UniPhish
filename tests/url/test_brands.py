"""Brand impersonation: techniques, official-host safety and restraint."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from uniphish.url.brands import (
    brand_candidates,
    brand_impersonation,
    scan_brand_ids,
    split_host,
)
from uniphish.url.parse import parse_url


def tech(url: str) -> tuple[str, str] | None:
    m = brand_impersonation(url)
    return (m.brand, m.technique) if m else None


@pytest.mark.parametrize("url", [
    "https://www.paypal.com/signin",
    "https://paypal.com/",
    "https://login.microsoftonline.com/common/oauth2",
    "https://accounts.google.com/",
    "https://appleid.apple.com/",
    "https://www.amazon.co.uk/gp/css",
    "https://ssl.gstatic.com/x.js",
])
def test_official_hosts_are_official_not_impersonation(url):
    m = brand_impersonation(url)
    assert m is not None and m.official and m.technique == "official"
    assert m.confidence >= 0.95
    assert [c.official for c in brand_candidates(url)] == [True]


@pytest.mark.parametrize("url", [
    "https://evil.sharepoint.com/sites/x",
    "https://myapp.web.app/",
    "https://someone.github.io/page",
    "https://example.com/",
    "https://www.example.org/news",
])
def test_user_content_and_unrelated_hosts_not_flagged(url):
    assert brand_impersonation(url) is None


def test_lookalike_of_official_suffix_is_not_official():
    assert tech("https://notpaypal.com/") != ("paypal", "official")
    m = brand_impersonation("https://paypal.com.evil.test/")
    assert m is not None and not m.official


def test_homoglyph_cyrillic_a():
    m = brand_impersonation("https://pаypal.com/login")
    assert m is not None
    assert (m.brand, m.technique) == ("paypal", "homoglyph")
    assert m.confidence >= 0.95 and "paypal.com" in m.legit_domains


def test_punycode_host_detected_and_labelled():
    m = brand_impersonation("https://xn--pypal-4ve.com/")
    assert m is not None and m.brand == "paypal" and m.technique == "homoglyph"
    assert "punycode" in m.evidence


def test_idn_contains_brand_with_extra_word():
    m = brand_impersonation("https://pаypal-secure.test/")
    assert m is not None and m.brand == "paypal" and m.technique == "idn"


def test_leet_visual_typosquat():
    m = brand_impersonation("https://paypa1.com/")
    assert (m.brand, m.technique) == ("paypal", "typosquat") and m.confidence >= 0.9
    assert tech("https://rnicrosoft.com/") == ("microsoft", "typosquat")


def test_edit_distance_typosquat_and_confidence_ordering():
    d1 = brand_impersonation("https://paypall.com/")
    assert d1 is not None and (d1.brand, d1.technique) == ("paypal", "typosquat")
    assert d1.confidence < brand_impersonation("https://paypa1.com/").confidence


def test_hyphen_split_typosquat():
    m = brand_impersonation("https://pay-pal.com/")
    assert (m.brand, m.technique) == ("paypal", "typosquat")


def test_bitsquat():
    m = brand_impersonation("https://gnogle.com/")
    assert (m.brand, m.technique) == ("google", "bitsquat")


def test_tld_swap_is_low_confidence_and_abused_tld_raises_it():
    low = brand_impersonation("https://paypal.example/")
    high = brand_impersonation("https://paypal.xyz/")
    assert low is not None and high is not None
    assert low.technique == high.technique == "typosquat"
    assert low.confidence < 0.6 <= high.confidence + 0.01


@pytest.mark.parametrize("url", [
    "https://paypal-secure.test/", "https://paypalsecure.com/",
    "https://secure-appleid-verify.test/", "https://paypa1-login.top/",
])
def test_combosquat(url):
    m = brand_impersonation(url)
    assert m is not None and m.technique == "combosquat" and m.confidence >= 0.8


def test_combosquat_with_arbitrary_short_brand_text_is_ignored():
    # real words that merely contain a short brand keyword
    assert brand_impersonation("https://pineapple.com/") is None
    assert brand_impersonation("https://applebees.com/") is None


def test_subdomain_stuffing_variants():
    full = brand_impersonation("https://login.paypal.com.evil.test/x")
    assert (full.brand, full.technique) == ("paypal", "subdomain") and full.confidence >= 0.95
    part = brand_impersonation("https://login.paypal.evil.test/")
    assert part.technique == "subdomain" and 0.7 <= part.confidence < 0.95


def test_shared_platform_tenant_label_is_subdomain():
    m = brand_impersonation("https://paypal.pages.dev/")
    assert (m.brand, m.technique) == ("paypal", "subdomain")
    assert "shared hosting" in m.evidence


def test_other_brand_on_user_content_host_still_flagged_but_not_owner():
    m = brand_impersonation("https://paypal-login.web.app/")
    assert m is not None and m.brand == "paypal"
    assert all(c.brand != "google" for c in brand_candidates("https://paypal-login.web.app/"))


def test_path_deception():
    m = brand_impersonation("https://example.test/paypal/signin")
    assert (m.brand, m.technique) == ("paypal", "path")
    plain = brand_impersonation("https://example.test/paypal/")
    assert plain.confidence < m.confidence
    lots = brand_impersonation("https://storage.googleapis.com/b/paypal-login.html")
    assert lots.brand == "paypal" and lots.confidence > m.confidence - 0.01


def test_path_on_ip_host():
    m = brand_impersonation("http://203.0.113.9/paypal/login")
    assert m is not None and m.technique == "path"


def test_official_domain_in_path_boosts_confidence():
    a = brand_impersonation("https://example.test/www.paypal.com/signin")
    b = brand_impersonation("https://example.test/paypal/signin")
    assert a.confidence > b.confidence


def test_ambiguous_brand_needs_context():
    assert brand_impersonation("https://ups.test/") is None
    m = brand_impersonation("https://ups-tracking-delivery.test/")
    assert m is not None and m.brand == "ups" and m.confidence <= 0.6


def test_min_confidence_filter():
    assert brand_impersonation("https://example.test/paypal/", min_confidence=0.9) is None
    assert brand_impersonation("https://example.test/paypal/", min_confidence=0.3) is not None


def test_popular_site_exempt_from_fuzzy_techniques():
    # a top-ranked unrelated site that contains a brand keyword must not be flagged
    from uniphish.assets.lists import top_rank

    assert top_rank("wikipedia.org") is not None
    assert brand_impersonation("https://en.wikipedia.org/wiki/paypal") is None


def test_split_host_handles_reserved_tld():
    p = split_host(parse_url("https://a.b.paypal-login.test/"))
    assert p.sub == ("a", "b") and p.sld == "paypal-login" and p.suffix == "test"
    q = split_host(parse_url("https://x.example.co.uk/"))
    assert q.sld == "example" and q.suffix == "co.uk"
    assert split_host(parse_url("http://1.2.3.4/")).sld == ""


def test_scan_brand_ids_token_and_concat():
    assert scan_brand_ids("paypal-secure") == ("paypal",)
    assert scan_brand_ids("paypalsecure", concat=False) == ()
    assert scan_brand_ids("paypalsecure") == ("paypal",)
    assert scan_brand_ids("ups") == ()


def test_deterministic_and_pydantic_valid():
    a = brand_impersonation("https://paypa1.com/")
    b = brand_impersonation("https://paypa1.com/")
    assert a == b and 0.0 <= a.confidence <= 1.0


@given(st.text(max_size=120))
def test_never_raises_on_arbitrary_text(s):
    brand_impersonation(s)
    brand_impersonation("https://" + s)


def test_long_hostile_input_is_bounded():
    url = "https://" + "-".join(["paypal"] * 500) + ".test/" + "paypal/" * 2000
    assert brand_impersonation(url) is not None
