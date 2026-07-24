"""Tests for brand-impersonation + reasons (no TensorFlow required)."""

from uniphish.brands import brand_impersonation, normalize
from uniphish.reasons import analyze


def test_normalize_folds_homoglyph_and_leet():
    assert normalize("pаypаl") == "paypal"   # Cyrillic а -> a
    assert normalize("paypa1") == "paypal"    # 1 -> l
    assert normalize("g00gle") == "google"    # 0 -> o


def test_homoglyph_impersonation():
    r = brand_impersonation("https://pаypаl.com/login")   # Cyrillic а
    assert r and r["brand"] == "paypal" and r["type"] == "homoglyph"


def test_typo_impersonation():
    r = brand_impersonation("https://paypa1.xyz/verify")
    assert r and r["brand"] == "paypal" and r["type"] == "typo"


def test_subdomain_stuffing():
    r = brand_impersonation("https://google.com.evil.top/")
    assert r and r["brand"] == "google" and r["type"] == "subdomain"


def test_legit_brand_is_not_flagged():
    assert brand_impersonation("https://www.paypal.com/signin") is None
    assert brand_impersonation("https://accounts.google.com/") is None


def test_reasons_cover_key_signals():
    codes = lambda u: {r["code"] for r in analyze(u)["reasons"]}
    assert "brand_impersonation" in codes("https://pаypаl.com/login")
    assert "homoglyph_char" in codes("https://pаypаl.com/login")
    assert "ip_host" in codes("https://192.168.0.1/login")
    assert "shortener" in codes("https://bit.ly/xY")
    assert "suspicious_tld" in codes("https://login-verify.xyz/")
