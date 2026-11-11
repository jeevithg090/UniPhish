"""Tests for the URL analyzer (``uniphish.analyzers.url``).

Covers the spec's required cases — homoglyph / typosquat / combosquat / subdomain /
IP-obfuscation / ``@``-trick / shortener / LOTS / official — asserting the right top
signal, brand match, techniques and (for official hosts) negative legitimacy evidence,
plus the invariants that make the analyzer safe: spans index into the submitted URL,
every emitted signal id is declared in the catalog, and nothing raises on hostile input.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from uniphish.analyzers.url import UrlAnalyzer
from uniphish.core.analyzer import REGISTRY, AnalysisContext, AnalysisOptions
from uniphish.core.engine import Engine
from uniphish.core.types import Artifact, ArtifactKind, IndicatorType, Level

ANALYZER = UrlAnalyzer()

# A Cyrillic 'а' (U+0430) in place of the ASCII 'a' — the canonical homoglyph.
PAYPAL_HOMOGLYPH = "https://pаypal.com/login"


def run(url: str):
    """Analyze one URL and return (url, AnalyzerResult)."""
    art = Artifact.from_url(url)
    ctx = AnalysisContext(options=AnalysisOptions())
    return url, ANALYZER.analyze_sync(art, ctx)


def ids(result) -> set[str]:
    return {s.id for s in result.signals}


def by_id(result, sid: str):
    return next((s for s in result.signals if s.id == sid), None)


def top_signal(result):
    """The signal with the largest magnitude pre-fusion contribution (weight x confidence)."""
    return max(result.signals, key=lambda s: abs(s.weight * s.confidence))


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #
def test_analyzer_registered():
    assert REGISTRY.get("url") is UrlAnalyzer
    assert ANALYZER.kinds == frozenset({ArtifactKind.URL})
    assert ANALYZER.stage == 0 and ANALYZER.blocking and not ANALYZER.requires_online


def test_loads_as_builtin():
    from uniphish.analyzers import load_builtin_analyzers

    assert "uniphish.analyzers.url" in load_builtin_analyzers()
    assert "url" in REGISTRY


# --------------------------------------------------------------------------- #
# Brand impersonation — the right top signal, brand and technique per case
# --------------------------------------------------------------------------- #
def test_homoglyph_cyrillic():
    url, r = run(PAYPAL_HOMOGLYPH)
    assert r.brand is not None and (r.brand.brand, r.brand.technique) == ("paypal", "homoglyph")
    assert not r.brand.official
    top = top_signal(r)
    assert top.id == "brand.homoglyph" and top.weight >= 4.0
    assert "homoglyph" in r.techniques
    # span points at the offending label and includes the non-ASCII character
    s, e = by_id(r, "brand.homoglyph").span
    assert url[s:e] == "pаypal"


def test_punycode_homoglyph():
    # xn--pypal-4ve.com decodes to a PayPal look-alike.
    url, r = run("https://xn--pypal-4ve.com/")
    assert r.brand is not None and r.brand.technique == "homoglyph"
    assert "unicode.punycode_lookalike" in ids(r)
    s, e = by_id(r, "brand.homoglyph").span
    assert url[s:e].startswith("xn--")


def test_typosquat():
    url, r = run("https://micros0ft.com/account")
    assert r.brand is not None and r.brand.brand == "microsoft"
    assert r.brand.technique in ("typosquat", "bitsquat")
    top = top_signal(r)
    assert top.id in ("brand.typosquat", "brand.bitsquat")
    assert "typosquat" in r.techniques
    s, e = by_id(r, top.id).span
    assert url[s:e] == "micros0ft"


def test_combosquat():
    url, r = run("https://paypal-login.com/verify")
    assert r.brand is not None and (r.brand.brand, r.brand.technique) == ("paypal", "combosquat")
    assert top_signal(r).id == "brand.combosquat"
    assert "combosquat" in r.techniques


def test_subdomain_stuffing():
    url, r = run("http://paypal.com.evil.test/login")
    assert r.brand is not None and (r.brand.brand, r.brand.technique) == ("paypal", "subdomain")
    assert "brand.subdomain" in ids(r)
    assert "subdomain_stuffing" in r.techniques
    # the brand signal is the strongest positive evidence
    assert top_signal(r).id == "brand.subdomain"


def test_path_impersonation():
    url, r = run("http://unrelated-host.test/paypal/login/verify-account")
    assert "brand.path" in ids(r)
    s, e = by_id(r, "brand.path").span
    assert "paypal" in url[s:e].lower()


# --------------------------------------------------------------------------- #
# Official / legitimacy
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("url", [
    "https://www.paypal.com/signin",
    "https://login.microsoftonline.com/common/oauth2",
    "https://accounts.google.com/",
])
def test_official_domain_negative_evidence(url):
    _, r = run(url)
    off = by_id(r, "brand.official")
    assert off is not None and off.weight < 0
    assert r.brand is not None and r.brand.official
    # no positive impersonation / structure noise on a brand's own host
    assert not any(s.weight > 0 and s.id != "url.open_redirect" for s in r.signals)
    assert r.techniques == [] or r.techniques == ["open_redirect_abuse"]


def test_official_host_is_benign_end_to_end():
    eng = Engine(analyzers=[UrlAnalyzer()])
    v = eng.analyze_sync(Artifact.from_url("https://www.paypal.com/signin"))
    assert v.level is Level.BENIGN and v.score < 20


def test_homoglyph_is_malicious_end_to_end():
    eng = Engine(analyzers=[UrlAnalyzer()])
    v = eng.analyze_sync(Artifact.from_url(PAYPAL_HOMOGLYPH))
    assert v.level is Level.MALICIOUS
    assert v.brand is not None and v.brand.name == "PayPal" and not v.brand.official


# --------------------------------------------------------------------------- #
# Structure / infrastructure
# --------------------------------------------------------------------------- #
def test_ip_host():
    url, r = run("http://203.0.113.9/login")
    assert "url.ip_host" in ids(r)
    assert "ip_host" in r.techniques
    s, e = by_id(r, "url.ip_host").span
    assert url[s:e] == "203.0.113.9"
    # an IPv4 indicator is emitted
    assert any(i.type is IndicatorType.IPV4 and i.value == "203.0.113.9" for i in r.indicators)


def test_ip_obfuscation():
    url, r = run("http://3232235777/login")
    assert "url.ip_obfuscation" in ids(r)
    assert "ip_obfuscation" in r.techniques
    top = top_signal(r)
    assert top.id == "url.ip_obfuscation" and top.weight >= 2.5
    s, e = by_id(r, "url.ip_obfuscation").span
    assert url[s:e] == "3232235777"


def test_at_sign_redirect_trick():
    url, r = run("https://www.paypal.com@evil.test/login")
    at = by_id(r, "url.at_redirect")
    assert at is not None and at.weight >= 2.5
    assert "at_redirect" in r.techniques
    # the real destination is not paypal
    assert r.brand is None or r.brand.brand != "paypal"
    s, e = by_id(r, "url.at_redirect").span
    assert "paypal.com" in url[s:e]


def test_url_shortener():
    _, r = run("https://bit.ly/3xYz")
    assert "url.shortener" in ids(r)
    assert "url_shortener" in r.techniques


def test_lots_hosting_gets_no_reputation_bonus():
    _, r = run("https://sites.google.com/view/free-login")
    assert "url.lots_hosting" in ids(r)
    assert "lots_hosting" in r.techniques
    # a living-off-trusted-sites host must NOT earn an official/legitimacy bonus
    assert by_id(r, "brand.official") is None
    assert all(s.weight >= 0 for s in r.signals)


def test_open_redirect_emits_child_and_indicator():
    _, r = run("https://example.com/redirect?url=https://evil.test/phish")
    assert "url.open_redirect" in ids(r)
    assert "open_redirect_abuse" in r.techniques
    # the decoded destination is returned as a child artifact for the engine to recurse
    assert any(c.origin == "redirect" and "evil.test" in (c.url or "") for c in r.children)
    assert any(i.role == "redirect" and i.type is IndicatorType.URL for i in r.indicators)


def test_data_scheme():
    _, r = run("data:text/html,<script>alert(1)</script>")
    assert "url.dangerous_scheme" in ids(r)
    assert "data_uri" in r.techniques


def test_suspicious_file_extension():
    _, r = run("http://downloads.test/invoice/statement.pdf.exe")
    assert "url.double_extension" in ids(r) or "url.suspicious_file_ext" in ids(r)


# --------------------------------------------------------------------------- #
# Unicode spoofing restraint — legitimate IDN is not flagged
# --------------------------------------------------------------------------- #
def test_legitimate_idn_not_flagged():
    # A genuine single-script German domain; no spoof reasons should fire.
    _, r = run("https://müller.de/kontakt")
    assert not any(s.id.startswith("unicode.") and s.weight > 1.0 for s in r.signals)
    assert r.brand is None


def test_benign_url_has_no_positive_signals():
    _, r = run("https://www.example.org/news/today")
    assert all(s.weight <= 0 for s in r.signals)
    assert r.brand is None


# --------------------------------------------------------------------------- #
# Indicators
# --------------------------------------------------------------------------- #
def test_url_and_domain_indicators():
    _, r = run("https://login.account-verify.com/paypal")
    types = {(i.type, i.value) for i in r.indicators}
    assert any(t is IndicatorType.URL for t, _ in types)
    # the registrable domain (not the full host) is emitted as the DOMAIN indicator
    assert (IndicatorType.DOMAIN, "account-verify.com") in types


# --------------------------------------------------------------------------- #
# Invariants: catalog completeness, span validity, total function on hostile input
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("url", [
    PAYPAL_HOMOGLYPH,
    "https://micros0ft.com/account",
    "http://paypal.com.evil.test/login",
    "http://3232235777/login",
    "https://www.paypal.com@evil.test/login",
    "https://sites.google.com/view/x",
    "https://example.com/redirect?url=https://evil.test/phish",
    "data:text/html,<b>x</b>",
])
def test_every_signal_is_declared_and_spans_are_valid(url):
    _, r = run(url)
    for s in r.signals:
        assert s.id in UrlAnalyzer.signals, f"undeclared signal {s.id}"
        assert s.category in {"brand", "unicode", "url"}
        if s.span is not None:
            a, b = s.span
            assert 0 <= a < b <= len(url)
            assert url[a:b] != ""


@settings(max_examples=100, deadline=None)
@given(st.text(min_size=0, max_size=120))
def test_never_raises_on_arbitrary_input(raw):
    # Artifact.from_url rejects empty / oversized URLs; everything else must analyze cleanly.
    try:
        art = Artifact.from_url(raw)
    except Exception:  # from_url's documented size / format guards
        return
    ctx = AnalysisContext(options=AnalysisOptions())
    result = ANALYZER.analyze_sync(art, ctx)
    for s in result.signals:
        if s.span is not None:
            a, b = s.span
            assert 0 <= a <= b <= len(art.url or "")
