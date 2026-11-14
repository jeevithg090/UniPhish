"""STIX 2.1 exporter tests (synthetic verdicts, offline)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

import pytest

from uniphish.core import mitre
from uniphish.core.types import (
    Action,
    ArtifactKind,
    BrandMatch,
    Indicator,
    IndicatorType,
    Level,
    Signal,
    Verdict,
)
from uniphish.export import stix

T0 = datetime(2026, 1, 2, 3, 4, 5, 678000, tzinfo=timezone.utc)


def homoglyph_verdict(**kw) -> Verdict:
    return Verdict(
        created_at=T0,
        kind=ArtifactKind.URL,
        target="http://paypa1-login.example/verify",
        artifact_id="a" * 24,
        risk=0.97,
        score=97,
        logit=3.5,
        level=Level.MALICIOUS,
        action=Action.BLOCK,
        confidence=0.9,
        summary="Domain imitates PayPal.",
        brand=BrandMatch(brand="paypal", name="PayPal", technique="homoglyph", confidence=0.9),
        signals=[
            Signal(
                id="brand.homoglyph",
                title="Look-alike of PayPal",
                weight=4.0,
                category="brand",
                mitre=["T1566.002", "T1656"],
            )
        ],
        indicators=[
            Indicator(
                type=IndicatorType.URL, value="http://paypa1-login.example/verify", malicious=True
            ),
            Indicator(type=IndicatorType.DOMAIN, value="PayPa1-Login.example.", malicious=True),
            Indicator(type=IndicatorType.IPV4, value="192.0.2.7", malicious=True),
            Indicator(type=IndicatorType.SHA256, value="ab" * 32, malicious=True),
            Indicator(type=IndicatorType.DOMAIN, value="paypal.com", malicious=False),
            Indicator(type=IndicatorType.IPV4, value="not-an-ip", malicious=True),
        ],
        mitre=[mitre.resolve("T1566.002"), mitre.resolve("T1656")],
        **kw,
    )


def injection_verdict() -> Verdict:
    return Verdict(
        created_at=T0,
        kind=ArtifactKind.TEXT,
        target="page text",
        artifact_id="b" * 24,
        risk=0.9,
        score=90,
        logit=2.2,
        level=Level.MALICIOUS,
        action=Action.BLOCK,
        confidence=0.8,
        signals=[
            Signal(
                id="agent.injection",
                title="Hidden instructions",
                weight=5.0,
                category="agent",
                mitre=["AML.T0051.001"],
            )
        ],
        indicators=[Indicator(type=IndicatorType.URL, value="https://evil.test/x", malicious=True)],
        mitre=[mitre.resolve("AML.T0051.001")],
    )


def by_type(bundle, t):
    return [o for o in bundle["objects"] if o["type"] == t]


def test_homoglyph_bundle_structure():
    b = stix.to_stix_bundle(homoglyph_verdict())
    assert b["type"] == "bundle" and b["id"].startswith("bundle--")
    (ind,) = by_type(b, "indicator")
    assert ind["pattern_type"] == "stix" and ind["spec_version"] == "2.1"
    assert "[url:value = 'http://paypa1-login.example/verify']" in ind["pattern"]
    assert "[domain-name:value = 'paypa1-login.example']" in ind["pattern"]
    assert "[ipv4-addr:value = '192.0.2.7']" in ind["pattern"]
    assert "file:hashes.'SHA-256'" in ind["pattern"]
    assert "paypal.com" not in ind["pattern"] and "not-an-ip" not in ind["pattern"]
    assert ind["indicator_types"] == ["malicious-activity"]
    assert ind["valid_from"] == "2026-01-02T03:04:05.678Z"
    aps = by_type(b, "attack-pattern")
    assert {a["external_references"][0]["external_id"] for a in aps} == {"T1566.002", "T1656"}
    ap = next(a for a in aps if a["name"].startswith("Phishing"))
    assert ap["external_references"][0]["url"] == "https://attack.mitre.org/techniques/T1566/002"
    assert ap["external_references"][0]["source_name"] == "mitre-attack"
    rels = by_type(b, "relationship")
    indicates = {r["target_ref"] for r in rels if r["relationship_type"] == "indicates"}
    assert indicates == {a["id"] for a in aps}
    assert all(r["source_ref"] == ind["id"] for r in rels)
    assert len([r for r in rels if r["relationship_type"] == "based-on"]) == 4
    assert by_type(b, "identity") and by_type(b, "observed-data") and by_type(b, "note")
    od = by_type(b, "observed-data")[0]
    assert set(od["object_refs"]) == {
        o["id"] for o in b["objects"] if o["type"] in ("url", "domain-name", "ipv4-addr", "file")
    }


def test_atlas_technique_for_prompt_injection():
    b = stix.to_stix_bundle(injection_verdict())
    (ap,) = by_type(b, "attack-pattern")
    ref = ap["external_references"][0]
    assert ref["source_name"] == "mitre-atlas" and ref["external_id"] == "AML.T0051.001"
    assert ref["url"] == "https://atlas.mitre.org/techniques/AML.T0051.001"
    assert ap["kill_chain_phases"][0]["kill_chain_name"] == "mitre-atlas"


def test_deterministic_and_time_independent():
    a = stix.to_stix_bundle(homoglyph_verdict())
    b = stix.to_stix_bundle(homoglyph_verdict())  # different random Verdict.id
    assert a == b
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    c = stix.to_stix_bundle(homoglyph_verdict(), namespace="other-org")
    assert {o["id"] for o in by_type(c, "indicator")} != {o["id"] for o in by_type(a, "indicator")}
    # SCO ids use the STIX namespace and are not affected by the caller namespace
    assert {o["id"] for o in by_type(c, "url")} == {o["id"] for o in by_type(a, "url")}


def test_caller_supplied_created():
    b = stix.to_stix_bundle(homoglyph_verdict(), created=datetime(2025, 5, 5, tzinfo=timezone.utc))
    assert by_type(b, "indicator")[0]["created"] == "2025-05-05T00:00:00.000Z"


def test_json_serialisable_and_stix2_valid():
    for v in (homoglyph_verdict(), injection_verdict()):
        b = stix.to_stix_bundle(v, validate=True)
        json.dumps(b)
    pytest.importorskip("stix2")
    assert stix.validate_bundle(stix.to_stix_bundle(homoglyph_verdict())) == []
    assert stix.validate_bundle({"type": "bundle", "id": "bundle--x", "objects": []})


def test_benign_verdict_has_no_indicator():
    v = homoglyph_verdict()
    v = v.model_copy(update={"level": Level.BENIGN, "action": Action.ALLOW})
    b = stix.to_stix_bundle(v)
    assert not by_type(b, "indicator") and not by_type(b, "relationship")
    assert by_type(stix.to_stix_bundle(v, include_benign=True), "indicator")[0][
        "indicator_types"
    ] == ["benign"]


def test_stix_pattern_helper_and_escaping():
    assert (
        stix.stix_pattern(Indicator(type=IndicatorType.URL, value="http://x.test/a'b\\c"))
        == "[url:value = 'http://x.test/a\\'b\\\\c']"
    )
    assert (
        stix.stix_pattern(Indicator(type=IndicatorType.IPV6, value="2001:DB8::1"))
        == "[ipv6-addr:value = '2001:db8::1']"
    )
    assert (
        stix.stix_pattern(Indicator(type=IndicatorType.ASN, value="AS64500"))
        == "[autonomous-system:number = 64500]"
    )
    assert (
        stix.stix_pattern(Indicator(type=IndicatorType.MD5, value="0" * 32))
        == "[file:hashes.'MD5' = '" + "0" * 32 + "']"
    )
    assert stix.stix_pattern(Indicator(type=IndicatorType.IPV4, value="2001:db8::1")) is None
    assert stix.stix_pattern(Indicator(type=IndicatorType.SHA256, value="zz")) is None
    assert stix.stix_pattern(Indicator(type=IndicatorType.PHONE, value="+10000000000")) is None


def test_text_fields_are_defanged():
    b = stix.to_stix_bundle(homoglyph_verdict())
    ind = by_type(b, "indicator")[0]
    assert "http://" not in ind["name"] and "hxxp://" in ind["name"]
    assert not re.search(r"https?://", by_type(b, "note")[0]["content"])


def test_bundle_many_dedupes_shared_objects():
    b = stix.bundle_many(
        [homoglyph_verdict(), homoglyph_verdict(), injection_verdict()], validate=True
    )
    ids = [o["id"] for o in b["objects"]]
    assert len(ids) == len(set(ids))
    assert len(by_type(b, "identity")) == 1
    assert len(by_type(b, "indicator")) == 2
    env = stix.taxii_envelope(b)
    assert env["more"] is False and env["objects"] == b["objects"]


def test_per_observable_indicators_and_children():
    v = homoglyph_verdict()
    child = injection_verdict()
    v = v.model_copy(update={"children": [child]})
    b = stix.to_stix_bundle(v, per_observable=True, validate=True)
    assert len(by_type(b, "indicator")) == 5  # 4 parent observables + child url
    assert {a["external_references"][0]["external_id"] for a in by_type(b, "attack-pattern")} >= {
        "AML.T0051.001",
        "T1566.002",
    }


def test_signal_mitre_ids_resolved_without_verdict_mitre():
    v = homoglyph_verdict().model_copy(update={"mitre": []})
    ids = {
        a["external_references"][0]["external_id"]
        for a in by_type(stix.to_stix_bundle(v), "attack-pattern")
    }
    assert ids == {"T1566.002", "T1656"}


def test_observable_cap():
    inds = [
        Indicator(type=IndicatorType.DOMAIN, value=f"d{i}.example", malicious=True)
        for i in range(80)
    ]
    v = homoglyph_verdict().model_copy(update={"indicators": inds})
    assert len(stix.select_indicators(v)) == stix.MAX_OBSERVABLES
