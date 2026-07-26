"""Threat-intelligence output: STIX 2.1 + MITRE ATT&CK attribution.

Turns a UniPhish detection into machine-readable, standards-compliant CTI so any
SIEM / TIP / ISAC can ingest it: an OASIS STIX 2.1 bundle whose Indicator is linked
(via `indicates` relationships) to MITRE ATT&CK Attack-Pattern objects derived from
the detected construction technique. Pairs with the TAXII 2.1 feed in api/server.py
and the Certificate-Transparency hunter in scripts/ct_hunter.py.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List

import stix2

from uniphish.classify_attack import classify
from uniphish.enrich import fused_risk

# Our construction techniques -> MITRE ATT&CK (Enterprise) techniques.
ATTACK_MAP: Dict[str, List[tuple]] = {
    "homoglyph":          [("T1583.001", "Acquire Infrastructure: Domains"), ("T1036", "Masquerading")],
    "idn_punycode":       [("T1583.001", "Acquire Infrastructure: Domains"), ("T1036", "Masquerading")],
    "typosquat":          [("T1583.001", "Acquire Infrastructure: Domains")],
    "combosquat":         [("T1583.001", "Acquire Infrastructure: Domains")],
    "subdomain_stuffing": [("T1583.001", "Acquire Infrastructure: Domains"), ("T1036", "Masquerading")],
    "path_deception":     [("T1036", "Masquerading")],
    "ip_host":            [("T1566.002", "Phishing: Spearphishing Link")],
    "url_shortener":      [("T1566.002", "Phishing: Spearphishing Link")],
    "suspicious_tld":     [("T1583.001", "Acquire Infrastructure: Domains")],
}
# Every phishing URL is, at delivery, ATT&CK Phishing.
_BASE_ATTACK = ("T1566", "Phishing")


def detect(scorer, url: str) -> Dict:
    """Unified detection: model score + fused risk + technique taxonomy."""
    prob = scorer.scan(url)["prob"]
    fr = fused_risk(prob, url)
    atk = classify(url)
    return {"url": url, "model_prob": prob, "risk": fr["risk"], "tier": fr["tier"],
            "brand": fr["brand"], "reasons": fr["reasons"],
            "techniques": atk["techniques"], "target_brand": atk["target_brand"]}


def _attack_ids(techniques: List[str]) -> List[tuple]:
    ids = {_BASE_ATTACK}
    for t in techniques:
        for pair in ATTACK_MAP.get(t, []):
            ids.add(pair)
    return sorted(ids)


def to_stix(detection: Dict) -> Dict:
    """Build a STIX 2.1 bundle (as a dict) for a detection."""
    now = datetime.now(timezone.utc)
    brand = detection.get("target_brand")
    name = f"Phishing URL{f' impersonating {brand}' if brand else ''}"
    desc = "; ".join(r["text"] for r in detection.get("reasons", [])[:4]) or "Phishing indicators detected."

    indicator = stix2.Indicator(
        name=name,
        description=desc,
        pattern=f"[url:value = '{detection['url']}']",
        pattern_type="stix",
        valid_from=now,
        confidence=int(detection.get("risk", 50)),
        labels=["malicious-activity"],
        allow_custom=True,
        custom_properties={"x_uniphish_techniques": detection.get("techniques", []),
                            "x_uniphish_tier": detection.get("tier")},
    )

    objects = [indicator]
    for tid, tname in _attack_ids(detection.get("techniques", [])):
        base = tid.split(".")[0]
        ap = stix2.AttackPattern(
            name=tname,
            external_references=[stix2.ExternalReference(
                source_name="mitre-attack", external_id=tid,
                url=f"https://attack.mitre.org/techniques/{base}/"
                    + (f"{tid.split('.')[1]}/" if "." in tid else ""))],
        )
        objects.append(ap)
        objects.append(stix2.Relationship(indicator, "indicates", ap))

    bundle = stix2.Bundle(objects=objects, allow_custom=True)
    import json
    return json.loads(bundle.serialize())
