"""MISP export: turn a :class:`~uniphish.core.types.Verdict` into a MISP event.

Why this exists: MISP is the de-facto sharing platform for phishing IOCs. This module
emits MISP event JSON (the ``{"Event": {...}}`` format accepted by the REST API and
file import) with typed attributes, MITRE ATT&CK / ATLAS galaxy tags, ``url`` and
``file`` objects, and a MISP *feed* (manifest + hashes + events) for pull-based sharing.

Secure by default: distribution is "your organisation only", the event is unpublished,
and ``to_ids`` is set only for observables UniPhish selected for publication (same
selection as the STIX exporter). Ids and timestamps are deterministic (UUIDv5 over the
artifact id / values; time from the verdict or the caller), so re-exports are stable.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from uniphish.core.types import Indicator, Level, MitreTechnique, Verdict
from uniphish.export.stix import _clean, _techniques, select_indicators

log = logging.getLogger("uniphish.export")

MISP_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://uniphish.org/misp")

# indicator type -> (misp attribute type, category)
_ATTR_MAP: dict[str, tuple[str, str]] = {
    "url": ("url", "Network activity"),
    "domain": ("domain", "Network activity"),
    "ipv4": ("ip-dst", "Network activity"),
    "ipv6": ("ip-dst", "Network activity"),
    "email": ("email-src", "Payload delivery"),
    "sha256": ("sha256", "Payload delivery"),
    "sha1": ("sha1", "Payload delivery"),
    "md5": ("md5", "Payload delivery"),
    "filename": ("filename", "Payload delivery"),
    "cert_sha256": ("x509-fingerprint-sha256", "Network activity"),
    "asn": ("AS", "Network activity"),
}
_THREAT_LEVEL = {Level.MALICIOUS: "1", Level.SUSPICIOUS: "2", Level.BENIGN: "4"}
# Object template ids from the misp-objects repository (verify against your MISP instance).
_URL_TEMPLATE = "60efb77b-40b5-4c46-871b-ed1ed999fce5"
_FILE_TEMPLATE = "688c46fb-5edb-40a3-8273-1af7923e2215"


def _dt(value: datetime | None, fallback: datetime) -> datetime:
    v = value or fallback
    return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v.astimezone(timezone.utc)


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(MISP_NAMESPACE, "|".join(parts)))


def _attr(
    ev: str,
    t: str,
    cat: str,
    value: str,
    *,
    ids: bool,
    comment: str = "",
    ts: str = "0",
    disable_correlation: bool = False,
) -> dict[str, Any]:
    return {
        "uuid": _uuid(ev, t, value),
        "type": t,
        "category": cat,
        "value": value,
        "to_ids": ids,
        "distribution": "5",
        "comment": comment,
        "timestamp": ts,
        "disable_correlation": disable_correlation,
    }


def galaxy_tag(t: MitreTechnique) -> str:
    """MISP galaxy tag for a technique, e.g.
    ``misp-galaxy:mitre-attack-pattern="Spearphishing Link - T1566.002"``."""
    name = t.name.split(": ", 1)[-1].replace('"', "'")
    galaxy = "mitre-atlas-attack-pattern" if t.framework == "atlas" else "mitre-attack-pattern"
    return f'misp-galaxy:{galaxy}="{name} - {t.id}"'


def _objects(
    ev: str, selected: list[tuple[Indicator, tuple[str, str]]], ts: str
) -> list[dict[str, Any]]:
    objs: list[dict[str, Any]] = []
    hashes: dict[str, str] = {}
    for _ind, (t, v) in selected:
        if t == "url":
            parts = urlsplit(v)
            attrs = [
                _attr(ev, "url", "Network activity", v, ids=False, ts=ts, disable_correlation=True)
            ]
            if parts.scheme:
                attrs.append(
                    _attr(
                        ev,
                        "text",
                        "Other",
                        parts.scheme,
                        ids=False,
                        ts=ts,
                        disable_correlation=True,
                    )
                    | {"object_relation": "scheme"}
                )
            if parts.hostname:
                attrs.append(
                    _attr(
                        ev,
                        "domain",
                        "Network activity",
                        parts.hostname,
                        ids=False,
                        ts=ts,
                        disable_correlation=True,
                    )
                    | {"object_relation": "domain"}
                )
            if parts.path and parts.path != "/":
                attrs.append(
                    _attr(
                        ev, "text", "Other", parts.path, ids=False, ts=ts, disable_correlation=True
                    )
                    | {"object_relation": "resource_path"}
                )
            attrs[0]["object_relation"] = "url"
            objs.append(
                {
                    "uuid": _uuid(ev, "object-url", v),
                    "name": "url",
                    "meta-category": "network",
                    "template_uuid": _URL_TEMPLATE,
                    "distribution": "5",
                    "timestamp": ts,
                    "Attribute": attrs,
                }
            )
        elif t in ("sha256", "sha1", "md5"):
            hashes[t] = v
    if hashes:
        attrs = []
        for t, v in sorted(hashes.items()):
            attrs.append(
                _attr(ev, t, "Payload delivery", v, ids=False, ts=ts, disable_correlation=True)
                | {"object_relation": t}
            )
        objs.append(
            {
                "uuid": _uuid(ev, "object-file", *sorted(hashes.values())),
                "name": "file",
                "meta-category": "file",
                "template_uuid": _FILE_TEMPLATE,
                "distribution": "5",
                "timestamp": ts,
                "Attribute": attrs,
            }
        )
    return objs


def to_misp_event(
    verdict: Verdict,
    *,
    created: datetime | None = None,
    tlp: str = "amber",
    distribution: str = "0",
    org_name: str = "UniPhish",
    include_benign: bool = False,
    extra_tags: Iterable[str] = (),
) -> dict[str, Any]:
    """Convert a verdict to a MISP event (``{"Event": {...}}``, JSON-serialisable).

    Args:
        created: event timestamp; defaults to ``verdict.created_at``.
        tlp: TLP tag colour (white/green/amber/red); default amber.
        distribution: MISP distribution level; default ``"0"`` (this organisation only).
        include_benign: emit observables for BENIGN verdicts too (default: no).
    """
    when = _dt(created, verdict.created_at)
    ts = str(int(when.timestamp()))
    ev = _uuid("event", verdict.artifact_id)
    publish = verdict.level is not Level.BENIGN or include_benign

    selected: list[tuple[Indicator, tuple[str, str]]] = []
    if publish:
        for ind in select_indicators(verdict):
            key = _clean(ind)
            if key is not None:
                selected.append((ind, key))

    attributes: list[dict[str, Any]] = []
    for ind, (t, v) in selected:
        mtype, cat = _ATTR_MAP[t]
        value = f"AS{v}" if t == "asn" else v
        attributes.append(
            _attr(ev, mtype, cat, value, ids=True, ts=ts, comment=ind.role or ind.context or "")
        )
    summary = verdict.summary or f"UniPhish {verdict.level.value} verdict"
    attributes.append(
        _attr(ev, "comment", "Other", summary[:2000], ids=False, ts=ts, disable_correlation=True)
    )

    techniques = _techniques(verdict) if publish else []
    tags = [f"tlp:{tlp}", "phishing", f'uniphish:level="{verdict.level.value}"']
    if verdict.brand is not None:
        tags.append(f'uniphish:brand="{verdict.brand.brand}"')
    tags += [galaxy_tag(t) for t in techniques]
    tags += list(extra_tags)
    tags = list(dict.fromkeys(tags))

    galaxies = []
    for fw, gname, ns_, gtype in (
        ("attack", "Attack Pattern", "mitre-attack", "mitre-attack-pattern"),
        ("atlas", "Attack Pattern", "mitre-atlas", "mitre-atlas-attack-pattern"),
    ):
        clusters = [
            {
                "value": galaxy_tag(t).split('="', 1)[1][:-1],
                "tag_name": galaxy_tag(t),
                "meta": {"external_id": [t.id], **({"refs": [t.url]} if t.url else {})},
            }
            for t in techniques
            if t.framework == fw
        ]
        if clusters:
            galaxies.append(
                {"name": gname, "namespace": ns_, "type": gtype, "GalaxyCluster": clusters}
            )

    event: dict[str, Any] = {
        "uuid": ev,
        "info": f"UniPhish {verdict.level.value}: {verdict.target[:120]}".replace("http", "hxxp"),
        "date": when.strftime("%Y-%m-%d"),
        "timestamp": ts,
        "threat_level_id": _THREAT_LEVEL[verdict.level],
        "analysis": "2",
        "distribution": distribution,
        "published": False,
        "Orgc": {"name": org_name, "uuid": _uuid("org", org_name)},
        "Tag": [{"name": n} for n in tags],
        "Attribute": attributes,
        "Object": _objects(ev, selected, ts),
        "Galaxy": galaxies,
    }
    return {"Event": event}


# --------------------------------------------------------------------------- #
# Feed
# --------------------------------------------------------------------------- #
def to_misp_feed(verdicts: Iterable[Verdict], **kwargs: Any) -> dict[str, Any]:
    """Build a MISP feed as dicts: ``{"manifest": {...}, "hashes": [[md5, uuid], ...],
    "events": {uuid: {"Event": ...}}}``. Events are de-duplicated by uuid."""
    events: dict[str, dict[str, Any]] = {}
    for v in verdicts:
        e = to_misp_event(v, **kwargs)
        events.setdefault(e["Event"]["uuid"], e)
    manifest: dict[str, Any] = {}
    hashes: list[list[str]] = []
    for uid, e in events.items():
        ev = e["Event"]
        manifest[uid] = {
            "info": ev["info"],
            "Orgc": ev["Orgc"],
            "date": ev["date"],
            "analysis": ev["analysis"],
            "threat_level_id": ev["threat_level_id"],
            "timestamp": ev["timestamp"],
            "Tag": ev["Tag"],
        }
        for a in ev["Attribute"]:
            if a["type"] != "comment":
                digest = hashlib.md5(a["value"].encode(), usedforsecurity=False).hexdigest()
                hashes.append([digest, uid])
    return {"manifest": manifest, "hashes": hashes, "events": events}


def misp_feed_files(verdicts: Iterable[Verdict], **kwargs: Any) -> dict[str, str]:
    """Render a feed as ``{filename: text}``: ``manifest.json``, ``hashes.csv`` and one
    ``<uuid>.json`` per event, ready to be served over HTTP or written to a directory."""
    feed = to_misp_feed(verdicts, **kwargs)
    files = {
        "manifest.json": json.dumps(feed["manifest"], sort_keys=True, indent=1),
        "hashes.csv": "".join(f"{h},{u}\n" for h, u in feed["hashes"]),
    }
    for uid, e in feed["events"].items():
        files[f"{uid}.json"] = json.dumps(e, sort_keys=True, indent=1)
    return files
