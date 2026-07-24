"""Tests for the enrichment engine (offline parts; no TensorFlow, no network)."""

from uniphish.enrich import _is_public_host, decode_idn, fused_risk


def test_decode_idn_reveals_lookalike():
    r = decode_idn("https://xn--80ak6aa92e.com/login")   # Cyrillic "аррӏе"
    assert r["punycode"] is True
    assert any(ord(c) > 127 for c in r["decoded_host"])


def test_decode_idn_plain_url():
    r = decode_idn("https://www.paypal.com/")
    assert r["punycode"] is False and r["decoded_host"] == "www.paypal.com"


def test_ssrf_guard_blocks_private_and_loopback():
    assert _is_public_host("127.0.0.1") is False
    assert _is_public_host("10.0.0.1") is False
    assert _is_public_host("192.168.1.1") is False
    assert _is_public_host("169.254.1.1") is False
    assert _is_public_host("8.8.8.8") is True     # public IP literal, no DNS needed


def test_fused_risk_catches_model_miss_via_rules():
    # Even if the model is WRONG (prob 0.0), a homoglyph paypal is caught by rules.
    r = fused_risk(0.0, "https://pаypаl.com/login")
    assert r["risk"] >= 75 and r["tier"] == "block"
    assert r["brand"]["brand"] == "paypal"
    assert r["signal_score"] > r["model_score"]


def test_fused_risk_leaves_legit_low():
    r = fused_risk(0.02, "https://www.google.com/")
    assert r["risk"] < 40 and r["tier"] == "safe"
