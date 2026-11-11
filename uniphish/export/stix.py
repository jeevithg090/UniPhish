"""STIX 2.1 export: turn a :class:`~uniphish.core.types.Verdict` into shareable CTI.

Why this exists: SOC teams, TIPs and ISACs ingest STIX/TAXII, not UniPhish JSON. This
module maps a verdict to a self-contained STIX 2.1 bundle:

* ``identity`` (UniPhish as producer, optional)
* STIX Cyber-observable Objects (url, domain-name, ipv4-addr, ipv6-addr, email-addr,
  file, autonomous-system, x509-certificate)
* ``indicator`` with a STIX pattern over the selected observables
* ``observed-data`` referencing the SCOs
* ``attack-pattern`` per MITRE ATT&CK / ATLAS technique with ``external_references``
* ``relationship`` objects (indicator *indicates* attack-pattern, indicator
  *based-on* SCO)
* ``note`` carrying the explainable summary (a lightweight malware-analysis record)

Everything is built by a dependency-free dict builder, so output is deterministic:
ids are UUIDv5 over the observable / technique / pattern, never random, and
timestamps default to the verdict's own ``created_at`` (or a caller-supplied value).
When the ``stix2`` library is installed the bundle can be validated against it
(``validate=True``). Text fields defang URLs so they never auto-link in a TIP UI.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from uniphish.core import mitre as _mitre
from uniphish.core.types import Indicator, IndicatorType, Level, MitreTechnique, Verdict

log = logging.getLogger("uniphish.export")

#: Default namespace for deterministic SDO/SRO ids. Pass your own to scope ids to an org.
UNIPHISH_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://uniphish.org/stix")
#: STIX-mandated namespace for deterministic SCO ids.
STIX_SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE = "application/stix+json;version=2.1"

_CATALOG_EPOCH = "2025-01-01T00:00:00.000Z"  # static timestamp for identity/attack-patterns
MAX_OBSERVABLES = 50
_MAX_VALUE_CHARS = 8192
_HEX = {"sha256": 64, "sha1": 40, "md5": 32}
_HASH_NAMES = {"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}
_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_ASN_RE = re.compile(r"(?:AS)?(\d{1,10})", re.IGNORECASE)
_SCHEME_RE = re.compile(r"\bhttp(s?)://", re.IGNORECASE)


class StixValidationError(ValueError):
    """Raised when ``validate=True`` and the bundle fails stix2 validation."""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _ns(namespace: uuid.UUID | str | None) -> uuid.UUID:
    if namespace is None:
        return UNIPHISH_NAMESPACE
    if isinstance(namespace, uuid.UUID):
        return namespace
    try:
        return uuid.UUID(str(namespace))
    except ValueError:
        return uuid.uuid5(UNIPHISH_NAMESPACE, str(namespace))


def _ts(value: datetime | str | None) -> str:
    """Format a datetime as a STIX timestamp (UTC, millisecond precision)."""
    if isinstance(value, str):
        return value
    if value is None:
        return _CATALOG_EPOCH
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _defang(text: str) -> str:
    return _SCHEME_RE.sub(lambda m: f"hxxp{m.group(1)}://", text)


def _q(value: str) -> str:
    """Quote a string literal for a STIX pattern."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _sco_id(sco_type: str, contributing: dict[str, Any]) -> str:
    canon = json.dumps(contributing, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{sco_type}--{uuid.uuid5(STIX_SCO_NAMESPACE, canon)}"


def _clean(ind: Indicator) -> tuple[str, str] | None:
    """Return ``(type, normalised value)`` or None if not representable/valid."""
    t, v = ind.type, (ind.value or "").strip()
    if not v or len(v) > _MAX_VALUE_CHARS:
        return None
    if t is IndicatorType.DOMAIN:
        return t.value, v.rstrip(".").lower()
    if t in (IndicatorType.IPV4, IndicatorType.IPV6):
        try:
            addr = ipaddress.ip_address(v)
        except ValueError:
            return None
        want = 4 if t is IndicatorType.IPV4 else 6
        return (t.value, str(addr)) if addr.version == want else None
    if t in (IndicatorType.SHA256, IndicatorType.SHA1, IndicatorType.MD5,
             IndicatorType.CERT_SHA256):
        key = "sha256" if t is IndicatorType.CERT_SHA256 else t.value
        if len(v) != _HEX[key] or not _HEX_RE.fullmatch(v):
            return None
        return t.value, v.lower()
    if t is IndicatorType.EMAIL:
        return (t.value, v.lower()) if "@" in v else None
    if t is IndicatorType.ASN:
        m = _ASN_RE.fullmatch(v)
        return (t.value, m.group(1)) if m else None
    if t in (IndicatorType.URL, IndicatorType.FILENAME):
        return t.value, v
    return None  # phone, crypto wallet, user agent: no STIX SCO/pattern mapping


def stix_pattern(indicator: Indicator) -> str | None:
    """STIX 2.1 pattern comparison for one indicator, e.g. ``[url:value = 'x']``.

    Returns None when the indicator type has no STIX mapping or its value is invalid.
    """
    cleaned = _clean(indicator)
    if cleaned is None:
        return None
    return f"[{_comparison(*cleaned)}]"


def _comparison(t: str, v: str) -> str:
    if t == "url":
        return f"url:value = {_q(v)}"
    if t == "domain":
        return f"domain-name:value = {_q(v)}"
    if t == "ipv4":
        return f"ipv4-addr:value = {_q(v)}"
    if t == "ipv6":
        return f"ipv6-addr:value = {_q(v)}"
    if t == "email":
        return f"email-addr:value = {_q(v)}"
    if t in _HASH_NAMES:
        return f"file:hashes.'{_HASH_NAMES[t]}' = {_q(v)}"
    if t == "cert_sha256":
        return f"x509-certificate:hashes.'SHA-256' = {_q(v)}"
    if t == "filename":
        return f"file:name = {_q(v)}"
    if t == "asn":
        return f"autonomous-system:number = {int(v)}"
    raise ValueError(t)  # pragma: no cover - guarded by _clean


def _sco(t: str, v: str) -> dict[str, Any]:
    base: dict[str, Any]
    if t in ("url", "domain", "ipv4", "ipv6", "email"):
        stix_t = {"url": "url", "domain": "domain-name", "ipv4": "ipv4-addr",
                  "ipv6": "ipv6-addr", "email": "email-addr"}[t]
        base = {"type": stix_t, "value": v}
        contrib: dict[str, Any] = {"value": v}
    elif t in _HASH_NAMES:
        base = {"type": "file", "hashes": {_HASH_NAMES[t]: v}}
        contrib = {"hashes": base["hashes"]}
    elif t == "cert_sha256":
        base = {"type": "x509-certificate", "hashes": {"SHA-256": v}}
        contrib = {"hashes": base["hashes"]}
    elif t == "filename":
        base = {"type": "file", "name": v}
        contrib = {"name": v}
    else:  # asn
        base = {"type": "autonomous-system", "number": int(v)}
        contrib = {"number": int(v)}
    return {"type": base["type"], "spec_version": "2.1",
            "id": _sco_id(base["type"], contrib), **{k: x for k, x in base.items() if k != "type"}}


def select_indicators(verdict: Verdict, *, limit: int = MAX_OBSERVABLES) -> list[Indicator]:
    """Choose the observables worth publishing for a verdict.

    Indicators explicitly judged benign (``malicious is False``) are never published. If
    any indicator is flagged malicious only those are used; otherwise every remaining
    indicator of the (non-benign) verdict is. Duplicates are removed, order is stable and
    the list is capped at ``limit``.
    """
    seen: dict[tuple[str, str], Indicator] = {}
    for ind in verdict.all_indicators():
        if ind.malicious is False:
            continue
        cleaned = _clean(ind)
        if cleaned is None:
            continue
        seen.setdefault(cleaned, ind)
    inds = list(seen.values())
    flagged = [i for i in inds if i.malicious is True]
    return (flagged or inds)[:limit]


def build_pattern(indicators: Iterable[Indicator]) -> str | None:
    """OR-combine indicator patterns into one STIX pattern (None if nothing mappable)."""
    parts = [p for p in (stix_pattern(i) for i in indicators) if p]
    return " OR ".join(dict.fromkeys(parts)) if parts else None


def _techniques(verdict: Verdict) -> list[MitreTechnique]:
    found: dict[str, MitreTechnique] = {}
    for v in verdict.walk():
        for t in v.mitre:
            found.setdefault(t.id, t)
        for s in v.signals:
            for tid in s.mitre:
                if tid not in found:
                    found[tid] = _mitre.resolve(tid)
    return [found[k] for k in sorted(found)]


def _attack_pattern(t: MitreTechnique, ns: uuid.UUID) -> dict[str, Any]:
    atlas = t.framework == "atlas"
    src = "mitre-atlas" if atlas else "mitre-attack"
    obj: dict[str, Any] = {
        "type": "attack-pattern", "spec_version": "2.1",
        "id": f"attack-pattern--{uuid.uuid5(ns, 'attack-pattern:' + t.id)}",
        "created": _CATALOG_EPOCH, "modified": _CATALOG_EPOCH,
        "name": t.name,
        "external_references": [{"source_name": src, "external_id": t.id,
                                 **({"url": t.url} if t.url else {})}],
    }
    if t.tactic:
        obj["kill_chain_phases"] = [{"kill_chain_name": src, "phase_name": t.tactic}]
    return obj


def _identity(ns: uuid.UUID) -> dict[str, Any]:
    return {"type": "identity", "spec_version": "2.1",
            "id": f"identity--{uuid.uuid5(ns, 'identity:uniphish')}",
            "created": _CATALOG_EPOCH, "modified": _CATALOG_EPOCH,
            "name": "UniPhish", "identity_class": "system",
            "description": "UniPhish open-source anti-phishing detection engine."}


def _note_text(verdict: Verdict, skipped: int) -> str:
    lines = [f"UniPhish verdict: {verdict.level.value.upper()} (score {verdict.score}/100, "
             f"action {verdict.action.value}) for {_defang(verdict.target)}"]
    if verdict.summary:
        lines.append(_defang(verdict.summary))
    if verdict.brand is not None:
        lines.append(f"Brand: {verdict.brand.name} ({verdict.brand.technique})")
    for s in verdict.top_signals(8):
        lines.append(f"- [{s.id}] {_defang(s.title)} (weight {s.weight:+.1f})")
    if skipped:
        lines.append(f"{skipped} observable(s) have no STIX mapping and were omitted.")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def to_stix_objects(verdict: Verdict, *, namespace: uuid.UUID | str | None = None,
                    created: datetime | str | None = None, include_identity: bool = True,
                    include_note: bool = True, include_benign: bool = False,
                    per_observable: bool = False) -> list[dict[str, Any]]:
    """Build the STIX objects (list of dicts) for one verdict, without a bundle wrapper.

    Args:
        namespace: UUID (or string) namespace for SDO/SRO ids; default is UniPhish's.
        created: timestamp for created/modified/valid_from; defaults to
            ``verdict.created_at`` so re-exporting the same verdict is byte-stable.
        include_benign: also emit an Indicator for BENIGN verdicts (default: no).
        per_observable: one Indicator per observable instead of one combined OR pattern.
    """
    ns = _ns(namespace)
    now = _ts(created if created is not None else verdict.created_at)
    objects: list[dict[str, Any]] = []
    identity = _identity(ns) if include_identity else None
    if identity:
        objects.append(identity)
    creator = {"created_by_ref": identity["id"]} if identity else {}

    inds = select_indicators(verdict)
    publish = verdict.level is not Level.BENIGN or include_benign
    n_all = len([i for i in verdict.all_indicators() if i.malicious is not False])
    skipped = max(0, n_all - len(inds)) if publish else 0

    scos: list[dict[str, Any]] = []
    sco_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for ind in inds:
        key = _clean(ind)
        if key is None:
            continue
        sco = _sco(*key)
        if key not in sco_by_key:
            sco_by_key[key] = sco
            scos.append(sco)
    objects.extend(scos)

    patterns: list[tuple[str, list[tuple[str, str]]]] = []
    if publish and inds:
        if per_observable:
            for ind in inds:
                key = _clean(ind)
                if key is not None:
                    patterns.append((f"[{_comparison(*key)}]", [key]))
        else:
            keys = [k for k in (_clean(i) for i in inds) if k]
            joined = " OR ".join(f"[{_comparison(*k)}]" for k in keys)
            patterns.append((joined, keys))

    techniques = _techniques(verdict)
    aps = [_attack_pattern(t, ns) for t in techniques] if patterns else []
    objects.extend(aps)

    level = verdict.level
    itype = {Level.MALICIOUS: "malicious-activity", Level.SUSPICIOUS: "anomalous-activity",
             Level.BENIGN: "benign"}[level]
    indicators: list[dict[str, Any]] = []
    rels: list[dict[str, Any]] = []
    for pattern, keys in patterns:
        ind_obj: dict[str, Any] = {
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid5(ns, 'indicator:' + pattern)}",
            "created": now, "modified": now,
            "name": f"UniPhish {level.value}: {_defang(verdict.target)[:80]}",
            "description": _defang(verdict.summary) or f"UniPhish {level.value} verdict.",
            "indicator_types": [itype],
            "pattern": pattern, "pattern_type": "stix", "pattern_version": "2.1",
            "valid_from": now,
            "confidence": int(round(verdict.confidence * 100)),
            "labels": ["phishing", level.value],
            "x_uniphish_score": verdict.score,
            "x_uniphish_risk": round(verdict.risk, 4),
            "x_uniphish_signals": [s.id for s in verdict.top_signals(10)],
            **creator,
        }
        if verdict.brand is not None:
            ind_obj["x_uniphish_brand"] = verdict.brand.brand
        indicators.append(ind_obj)
        for key in keys:
            rels.append(_rel(ns, ind_obj["id"], "based-on", sco_by_key[key]["id"], now, creator))
        for ap in aps:
            rels.append(_rel(ns, ind_obj["id"], "indicates", ap["id"], now, creator))
    objects.extend(indicators)
    objects.extend(rels)

    if indicators and scos:
        refs = sorted(s["id"] for s in scos)
        seed = verdict.artifact_id + "|" + "|".join(refs)
        objects.append({
            "type": "observed-data", "spec_version": "2.1",
            "id": f"observed-data--{uuid.uuid5(ns, 'observed-data:' + seed)}",
            "created": now, "modified": now, "first_observed": now, "last_observed": now,
            "number_observed": 1, "object_refs": refs, **creator})
    if include_note and indicators:
        objects.append({
            "type": "note", "spec_version": "2.1",
            "id": f"note--{uuid.uuid5(ns, 'note:' + verdict.artifact_id)}",
            "created": now, "modified": now, "abstract": "UniPhish analysis summary",
            "content": _note_text(verdict, skipped),
            "object_refs": [i["id"] for i in indicators], **creator})
    return objects


def _rel(ns: uuid.UUID, src: str, rtype: str, dst: str, now: str,
         creator: dict[str, str]) -> dict[str, Any]:
    return {"type": "relationship", "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid5(ns, f'{src}|{rtype}|{dst}')}",
            "created": now, "modified": now, "relationship_type": rtype,
            "source_ref": src, "target_ref": dst, **creator}


def _dedupe(objects: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for o in objects:
        out.setdefault(o["id"], o)
    return list(out.values())


def _bundle(objects: list[dict[str, Any]]) -> dict[str, Any]:
    digest = hashlib.sha256("|".join(sorted(o["id"] for o in objects)).encode()).hexdigest()
    bid = uuid.uuid5(UNIPHISH_NAMESPACE, "bundle:" + digest)
    return {"type": "bundle", "id": f"bundle--{bid}", "objects": objects}


def validate_bundle(bundle: dict[str, Any]) -> list[str] | None:
    """Validate with the ``stix2`` library. Returns error strings ([] = valid) or None
    when the library is not installed."""
    try:
        import stix2
    except ImportError:
        return None
    errors: list[str] = []
    try:
        stix2.parse(bundle, allow_custom=True)
    except Exception as exc:  # stix2 raises many exception types
        errors.append(f"{type(exc).__name__}: {exc}")
    return errors


def to_stix_bundle(verdict: Verdict, *, validate: bool = False, **kwargs: Any) -> dict[str, Any]:
    """Convert a verdict to a STIX 2.1 bundle (JSON-serialisable dict).

    Keyword options are those of :func:`to_stix_objects`. With ``validate=True`` the
    bundle is checked by ``stix2`` (when installed) and :class:`StixValidationError` is
    raised on failure.
    """
    bundle = _bundle(_dedupe(to_stix_objects(verdict, **kwargs)))
    if validate:
        errors = validate_bundle(bundle)
        if errors:
            raise StixValidationError("; ".join(errors))
    return bundle


def bundle_many(verdicts: Iterable[Verdict], *, validate: bool = False,
                **kwargs: Any) -> dict[str, Any]:
    """One bundle for many verdicts; shared objects (identity, attack-patterns, SCOs,
    identical indicators) are de-duplicated by id."""
    objs: list[dict[str, Any]] = []
    for v in verdicts:
        objs.extend(to_stix_objects(v, **kwargs))
    bundle = _bundle(_dedupe(objs))
    if validate:
        errors = validate_bundle(bundle)
        if errors:
            raise StixValidationError("; ".join(errors))
    return bundle


def taxii_envelope(bundle: dict[str, Any]) -> dict[str, Any]:
    """Wrap a bundle's objects as a TAXII 2.1 envelope, the body of an add-objects POST
    (send with ``Content-Type: application/taxii+json;version=2.1``)."""
    return {"more": False, "objects": list(bundle.get("objects", []))}
