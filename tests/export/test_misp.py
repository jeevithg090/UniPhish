"""MISP exporter tests (synthetic verdicts, offline)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

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
from uniphish.export import misp

T0 = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def verdict(**kw) -> Verdict:
    base = dict(
        created_at=T0,
        kind=ArtifactKind.EMAIL,
        target="Urgent: verify account",
        artifact_id="c" * 24,
        risk=0.95,
        score=95,
        logit=3.0,
        level=Level.MALICIOUS,
        action=Action.BLOCK,
        confidence=0.9,
        summary="Credential phishing impersonating PayPal.",
        brand=BrandMatch(brand="paypal", name="PayPal", technique="sender", confidence=0.9),
        signals=[Signal(id="x", title="t", weight=3.0, category="email")],
        indicators=[
            Indicator(
                type=IndicatorType.URL,
                value="https://login.paypa1.example/a?b=1",
                malicious=True,
                role="landing",
            ),
            Indicator(type=IndicatorType.DOMAIN, value="login.paypa1.example", malicious=True),
            Indicator(type=IndicatorType.IPV4, value="192.0.2.9", malicious=True),
            Indicator(type=IndicatorType.SHA256, value="cd" * 32, malicious=True),
            Indicator(type=IndicatorType.EMAIL, value="Support@Paypa1.example", malicious=True),
            Indicator(type=IndicatorType.DOMAIN, value="paypal.com", malicious=False),
        ],
        mitre=[mitre.resolve("T1566.002"), mitre.resolve("AML.T0051.001")],
    )
    base.update(kw)
    return Verdict(**base)


def attrs(ev):
    return {(a["type"], a["value"]): a for a in ev["Event"]["Attribute"]}


def test_attributes_typed_and_to_ids():
    ev = misp.to_misp_event(verdict())
    a = attrs(ev)
    assert a[("url", "https://login.paypa1.example/a?b=1")]["to_ids"] is True
    assert ("domain", "login.paypa1.example") in a
    assert ("ip-dst", "192.0.2.9") in a
    assert ("sha256", "cd" * 32) in a
    assert ("email-src", "support@paypa1.example") in a
    assert ("domain", "paypal.com") not in a
    comment = next(x for x in ev["Event"]["Attribute"] if x["type"] == "comment")
    assert comment["to_ids"] is False


def test_event_fields_and_secure_defaults():
    e = misp.to_misp_event(verdict())["Event"]
    assert e["threat_level_id"] == "1" and e["analysis"] == "2"
    assert e["distribution"] == "0" and e["published"] is False
    assert e["date"] == "2026-01-02" and e["timestamp"] == str(int(T0.timestamp()))
    assert e["info"].startswith("UniPhish malicious")
    tags = {t["name"] for t in e["Tag"]}
    assert "tlp:amber" in tags and 'uniphish:brand="paypal"' in tags
    assert 'misp-galaxy:mitre-attack-pattern="Spearphishing Link - T1566.002"' in tags
    assert any(
        t.startswith("misp-galaxy:mitre-atlas-attack-pattern=") and "AML.T0051.001" in t
        for t in tags
    )
    assert {g["namespace"] for g in e["Galaxy"]} == {"mitre-attack", "mitre-atlas"}


def test_objects_for_url_and_file():
    objs = {o["name"]: o for o in misp.to_misp_event(verdict())["Event"]["Object"]}
    url_rel = {a["object_relation"]: a["value"] for a in objs["url"]["Attribute"]}
    assert url_rel["domain"] == "login.paypa1.example" and url_rel["scheme"] == "https"
    assert url_rel["resource_path"] == "/a"
    file_rel = {a["object_relation"]: a["value"] for a in objs["file"]["Attribute"]}
    assert file_rel["sha256"] == "cd" * 32


def test_deterministic_and_serialisable():
    a = misp.to_misp_event(verdict())
    b = misp.to_misp_event(verdict())
    assert a == b
    json.dumps(a)
    assert len({x["uuid"] for x in a["Event"]["Attribute"]}) == len(a["Event"]["Attribute"])


def test_benign_and_suspicious_levels():
    ben = misp.to_misp_event(verdict(level=Level.BENIGN, action=Action.ALLOW))["Event"]
    assert ben["threat_level_id"] == "4"
    assert [x["type"] for x in ben["Attribute"]] == ["comment"]
    assert not any(t["name"].startswith("misp-galaxy") for t in ben["Tag"])
    sus = misp.to_misp_event(verdict(level=Level.SUSPICIOUS, action=Action.WARN))["Event"]
    assert sus["threat_level_id"] == "2"


def test_options():
    e = misp.to_misp_event(verdict(), tlp="red", distribution="1", extra_tags=["x:y"])["Event"]
    names = {t["name"] for t in e["Tag"]}
    assert "tlp:red" in names and "x:y" in names and e["distribution"] == "1"


def test_feed_manifest_hashes_and_files():
    other = verdict(artifact_id="d" * 24)
    feed = misp.to_misp_feed([verdict(), verdict(), other])
    assert len(feed["events"]) == 2 and set(feed["manifest"]) == set(feed["events"])
    uid = next(iter(feed["events"]))
    want = hashlib.md5(b"192.0.2.9", usedforsecurity=False).hexdigest()
    assert [want, uid] in feed["hashes"]
    files = misp.misp_feed_files([verdict(), other])
    assert "manifest.json" in files and "hashes.csv" in files
    assert len(files) == 4
    json.loads(files["manifest.json"])
    assert all(len(line.split(",")) == 2 for line in files["hashes.csv"].splitlines())
