"""Elastic Common Schema (ECS 8.x) export of UniPhish verdicts.

Why: to land findings in Elastic / OpenSearch (or any ECS-aware SIEM) without a custom
mapping. :func:`to_ecs` renders one alert document per verdict with ``event.*``,
``threat.indicator.*``, ``threat.technique/tactic.*``, ``url.*``, ``related.*``, ``rule.*``
and a small ``uniphish.*`` namespace for engine-specific data. :func:`to_ndjson` produces
Bulk-API-friendly newline-delimited JSON.

Notes
-----
* ``event.kind`` is ``alert`` for suspicious/malicious verdicts and ``event`` for benign
  ones; benign verdicts carry no ``threat.indicator``.
* ``threat.indicator`` holds the *primary* indicator (URL, else domain, IP, hash); every
  selected observable is also listed under ``related.*`` for pivoting.
* ``risk.score`` mirrors the spec and ``event.risk_score``; ECS's own
  ``risk.calculated_score(_norm)`` are set too.
* Real (not defanged) URLs are stored in ``url.full`` - that is what SIEM pivots need;
  ``message`` uses the defanged form so it is safe to paste into tickets.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from uniphish.core.types import Level, Verdict
from uniphish.export.sigma import Iocs, brand_name, collect_iocs, mitre_techniques
from uniphish.url.parse import defang, parse_url

__all__ = ["ECS_VERSION", "to_ecs", "to_ndjson"]

ECS_VERSION = "8.11.0"
_TACTIC_IDS = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}
_CONFIDENCE = ((0.85, "High"), (0.5, "Medium"))


def _confidence(risk: float) -> str:
    for floor, label in _CONFIDENCE:
        if risk >= floor:
            return label
    return "Low"


def _url_fields(url: str) -> dict[str, Any]:
    p = parse_url(url)
    out: dict[str, Any] = {"full": p.url, "original": url, "scheme": p.scheme}
    if p.host_ascii:
        out["domain"] = p.host_ascii
    if p.registrable_domain and not p.is_ip:
        out["registered_domain"] = p.registrable_domain
        if p.suffix:
            out["top_level_domain"] = p.suffix
        if p.subdomain:
            out["subdomain"] = p.subdomain
    if p.port is not None:
        out["port"] = p.port
    if p.path:
        out["path"] = p.path
    if p.query:
        out["query"] = p.query
    if p.fragment:
        out["fragment"] = p.fragment
    return out


def _indicator(iocs: Iocs, verdict: Verdict) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (threat.indicator, top-level url) for the primary IOC ({} if none)."""
    base: dict[str, Any] = {
        "provider": "UniPhish",
        "confidence": _confidence(verdict.risk),
        "description": verdict.summary or "Phishing indicator",
        "first_seen": verdict.created_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    }
    if iocs.urls:
        url = _url_fields(iocs.urls[0].url)
        return {**base, "type": "url", "url": url}, url
    if iocs.domains or iocs.shared_hosts:
        host = (iocs.domains or iocs.shared_hosts)[0]
        return {**base, "type": "domain-name", "url": {"domain": host}}, {"domain": host}
    if iocs.ips:
        return {
            **base,
            "type": "ipv6-addr" if ":" in iocs.ips[0] else "ipv4-addr",
            "ip": iocs.ips[0],
        }, {}
    if iocs.sha256:
        return {**base, "type": "file", "file": {"hash": {"sha256": iocs.sha256[0]}}}, {}
    if iocs.emails:
        return {**base, "type": "email-addr", "email": {"address": iocs.emails[0]}}, {}
    return {}, {}


def to_ecs(verdict: Verdict, *, allow_benign: bool = False) -> dict[str, Any]:
    """Render ``verdict`` as one ECS alert document (JSON-serialisable ``dict``)."""
    iocs = collect_iocs(verdict, allow_benign=allow_benign)
    techs = mitre_techniques(verdict)
    attack = [t for t in techs if t.framework == "attack"]
    benign = verdict.level is Level.BENIGN
    ts = verdict.created_at.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    brand = brand_name(verdict)

    doc: dict[str, Any] = {
        "@timestamp": ts,
        "ecs": {"version": ECS_VERSION},
        "event": {
            "kind": "event" if benign else "alert",
            "category": ["threat"],
            "type": ["indicator"] if not benign else ["info"],
            "dataset": "uniphish.verdict",
            "module": "uniphish",
            "id": verdict.id,
            "action": verdict.action.value,
            "severity": verdict.score,
            "risk_score": float(verdict.score),
            "reason": verdict.summary,
        },
        "rule": {
            "name": "UniPhish phishing detection",
            "id": f"uniphish.{verdict.level.value}",
            "category": "phishing",
            "ruleset": "UniPhish",
            "description": verdict.summary or "UniPhish explainable phishing verdict",
        },
        "risk": {
            "score": verdict.score,
            "calculated_score": float(verdict.score),
            "calculated_score_norm": float(verdict.score),
        },
        "message": (
            f"UniPhish verdict {verdict.level.value} ({verdict.score}/100) for "
            f"{_safe_target(verdict)}" + (f": {verdict.summary}" if verdict.summary else "")
        ),
        "tags": ["uniphish", verdict.level.value, verdict.kind.value],
        "uniphish": {
            "verdict_id": verdict.id,
            "artifact_id": verdict.artifact_id,
            "kind": verdict.kind.value,
            "level": verdict.level.value,
            "risk": verdict.risk,
            "confidence": verdict.confidence,
            "engine_version": verdict.engine_version,
            "signals": [
                {"id": s.id, "weight": s.weight, "category": s.category}
                for s in verdict.top_signals(10)
            ],
        },
    }
    if brand:
        doc["uniphish"]["brand"] = brand
    if attack:
        tactics = sorted({t.tactic for t in attack if t.tactic})
        doc["threat"] = {
            "framework": "MITRE ATT&CK",
            "technique": {
                "id": [t.id for t in attack],
                "name": [t.name for t in attack],
                "reference": [t.url for t in attack],
            },
        }
        if tactics:
            doc["threat"]["tactic"] = {
                "id": [_TACTIC_IDS[t] for t in tactics if t in _TACTIC_IDS],
                "name": [t.replace("-", " ").title() for t in tactics],
                "reference": [
                    f"https://attack.mitre.org/tactics/{_TACTIC_IDS[t]}/"
                    for t in tactics
                    if t in _TACTIC_IDS
                ],
            }
    atlas = [t.id for t in techs if t.framework == "atlas"]
    if atlas:
        doc["uniphish"]["atlas_techniques"] = atlas

    indicator, url = _indicator(iocs, verdict)
    if indicator:
        doc.setdefault("threat", {"framework": "MITRE ATT&CK"})["indicator"] = indicator
    if url:
        doc["url"] = url
    related: dict[str, list[str]] = {}
    hosts = iocs.all_hosts()
    if hosts:
        related["hosts"] = hosts
    if iocs.ips:
        related["ip"] = list(iocs.ips)
    if iocs.sha256:
        related["hash"] = list(iocs.sha256)
    if iocs.emails:
        related["user"] = list(iocs.emails)
    if related:
        doc["related"] = related
    return doc


def _safe_target(verdict: Verdict) -> str:
    t = verdict.target
    return defang(t) if t.startswith(("http://", "https://")) else t[:200]


def to_ndjson(verdicts: Iterable[Verdict] | Verdict, *, allow_benign: bool = False) -> str:
    """ECS documents as newline-delimited JSON (one per verdict, trailing newline)."""
    items = [verdicts] if isinstance(verdicts, Verdict) else list(verdicts)
    return "".join(
        json.dumps(to_ecs(v, allow_benign=allow_benign), ensure_ascii=True, separators=(",", ":"))
        + "\n"
        for v in items
    )
