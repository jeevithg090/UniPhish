"""Tests for STIX 2.1 / MITRE ATT&CK generation (no TensorFlow, no network)."""

from uniphish.threatintel import _attack_ids, to_stix

_DET = {
    "url": "https://pаypаl.com/login", "risk": 95, "tier": "block",
    "brand": {"brand": "paypal"}, "reasons": [{"text": "Homoglyph 'а'", "severity": "high"}],
    "techniques": ["homoglyph"], "target_brand": "paypal",
}


def test_base_attack_always_present():
    assert ("T1566", "Phishing") in _attack_ids([])


def test_homoglyph_maps_to_domains_and_masquerading():
    ids = {t for t, _ in _attack_ids(["homoglyph"])}
    assert {"T1566", "T1583.001", "T1036"} <= ids


def test_stix_bundle_structure():
    b = to_stix(_DET)
    types = [o["type"] for o in b["objects"]]
    assert b["type"] == "bundle"
    assert "indicator" in types and "attack-pattern" in types and "relationship" in types


def test_indicator_pattern_and_confidence():
    b = to_stix(_DET)
    ind = next(o for o in b["objects"] if o["type"] == "indicator")
    assert "url:value = 'https://pаypаl.com/login'" in ind["pattern"]
    assert ind["confidence"] == 95
    assert ind["x_uniphish_techniques"] == ["homoglyph"]


def test_attack_external_ids_present():
    b = to_stix(_DET)
    ids = {ref["external_id"] for o in b["objects"] if o["type"] == "attack-pattern"
           for ref in o["external_references"]}
    assert "T1566" in ids and "T1583.001" in ids
