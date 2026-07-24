"""Tests for the attack-technique classifier (no TensorFlow required)."""

from uniphish.classify_attack import classify


def test_homoglyph_technique():
    r = classify("https://pаypаl.com/login")   # Cyrillic а
    assert r["primary"] == "homoglyph" and r["target_brand"] == "paypal"


def test_typosquat_technique():
    r = classify("https://paypa1.xyz/verify")
    assert "typosquat" in r["techniques"] and r["target_brand"] == "paypal"


def test_combosquat_technique():
    r = classify("https://paypal-secure-login.top/")
    assert "combosquat" in r["techniques"] and r["target_brand"] == "paypal"


def test_ip_and_shortener():
    assert classify("https://192.168.0.1/login")["primary"] == "ip_host"
    assert classify("https://bit.ly/xY")["primary"] == "url_shortener"


def test_path_deception():
    r = classify("https://cdn-media.xyz/paypal/login/secure")
    assert "path_deception" in r["techniques"] and r["target_brand"] == "paypal"


def test_benign_has_no_techniques():
    assert classify("https://www.google.com/")["techniques"] == []
