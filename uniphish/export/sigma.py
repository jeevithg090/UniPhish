"""Sigma detection-as-code export, plus the IOC selection shared by every DaC exporter.

Why this module exists
----------------------
A verdict is only useful to a SOC if the defender can *deploy* it in their own stack.
This module turns a :class:`~uniphish.core.types.Verdict` into vendor-neutral Sigma
rules (web-proxy, Zeek DNS and e-mail gateway variants). It also hosts
:func:`collect_iocs` and :func:`mitre_techniques`, the single, conservative IOC selection
used by the Suricata, YARA and ECS exporters too (``uniphish/export/suricata.py`` etc.
import them from here), so all four exports agree on *what is worth blocking*.

Safety rules baked into IOC selection (a bad rule that blocks ``paypal.com`` is worse
than no rule):

* verdicts judged ``benign`` (and official-brand artifacts) contribute nothing unless the
  caller passes ``allow_benign=True``;
* an indicator is used only if it is explicitly ``malicious`` or is un-judged but carries
  an actionable role (landing / redirect / exfil / payload / sender);
* any host at or under a brand's legitimate domain is dropped;
* hosts on shared "living-off-trusted-sites" platforms (``pages.dev``, ``sites.google.com``
  ...) never yield *domain-level* rules - only URL-level ones - so a rule cannot block a
  whole platform;
* private / loopback / link-local addresses are dropped; counts are capped.

All generators are pure: they never run the engine and never touch the network.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any
from urllib.parse import quote

import yaml

from uniphish.assets import load_yaml
from uniphish.core.mitre import resolve
from uniphish.core.types import (
    ArtifactKind,
    IndicatorType,
    Level,
    MitreTechnique,
    Verdict,
)
from uniphish.url.parse import host_is_under, parse_url, refang

__all__ = [
    "Iocs",
    "NoIndicatorsError",
    "UrlIoc",
    "collect_iocs",
    "mitre_techniques",
    "to_sigma",
    "to_sigma_rules",
    "to_sigma_yaml",
    "validate_sigma",
]

#: Hard cap per IOC class so a hostile / huge verdict cannot yield an unbounded rule.
MAX_IOCS = 200
#: Cap on per-URL selections (each becomes its own Sigma selection / Suricata rule).
MAX_URL_IOCS = 50
#: Fixed namespace so rule ids (uuid5) are stable across runs and machines.
RULE_NAMESPACE = uuid.UUID("6f1c7a52-2b8e-5c4d-9a37-0d5e1b9f4a10")

_ACTIONABLE_ROLES = frozenset({"landing", "redirect", "exfil-endpoint", "exfil", "payload",
                               "sender", "c2", "kit"})
_KIT_EVIDENCE_KEYS = ("fingerprints", "fingerprint", "strings", "matched_strings", "matches",
                      "patterns", "markers")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'\-]{1,64}@[A-Za-z0-9.\-]{1,253}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "::/128"))

_TACTIC_TAG = {
    "initial-access": "initial_access", "execution": "execution", "persistence": "persistence",
    "privilege-escalation": "privilege_escalation", "defense-evasion": "defense_evasion",
    "credential-access": "credential_access", "discovery": "discovery",
    "lateral-movement": "lateral_movement", "collection": "collection",
    "command-and-control": "command_and_control", "exfiltration": "exfiltration",
    "impact": "impact", "reconnaissance": "reconnaissance",
    "resource-development": "resource_development",
}


class NoIndicatorsError(ValueError):
    """Raised when a verdict yields no deployable indicators (e.g. a benign verdict)."""


# --------------------------------------------------------------------------- #
# IOC selection
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class UrlIoc:
    """A selected URL IOC split into the parts rule languages need."""

    url: str          # normalised, ASCII host
    scheme: str
    host: str         # A-label host (lower-case)
    path_query: str   # '/path?query' (always starts with '/')
    shared_host: bool  # host is on a shared hosting platform (no domain-level rule)


@dataclass
class Iocs:
    """Deployable observables selected from a verdict tree (ordered, de-duplicated)."""

    urls: list[UrlIoc] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)   # safe for domain-level rules
    shared_hosts: list[str] = field(default_factory=list)  # LOTS hosts, URL-level only
    ips: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    sha256: list[str] = field(default_factory=list)
    kit_strings: list[str] = field(default_factory=list)

    @property
    def web(self) -> bool:
        """True if any URL / domain / IP IOC is present."""
        return bool(self.urls or self.domains or self.ips)

    def empty(self) -> bool:
        return not (self.urls or self.domains or self.ips or self.emails or self.sha256
                    or self.kit_strings)

    def fingerprint(self) -> str:
        """Stable digest of the IOC content (drives deterministic rule ids / sids)."""
        h = hashlib.sha256()
        for name in ("urls", "domains", "shared_hosts", "ips", "emails", "sha256",
                     "kit_strings"):
            h.update(name.encode())
            for item in getattr(self, name):
                h.update((item.url if isinstance(item, UrlIoc) else item).encode())
                h.update(b"\x00")
        return h.hexdigest()

    def all_hosts(self) -> list[str]:
        """Every host seen (domains + shared hosts), ordered, unique."""
        return _uniq([*self.domains, *self.shared_hosts])


def _uniq(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


@lru_cache(maxsize=1)
def _lots_suffixes() -> tuple[str, ...]:
    try:
        data = load_yaml("lots.yaml") or {}
        return tuple(str(e["match"]).lower() for e in data.get("entries", []) if e.get("match"))
    except Exception:  # pragma: no cover - asset problems must not break exports
        return ()


def _is_shared_host(host: str) -> bool:
    return any(host_is_under(host, s) for s in _lots_suffixes())


def _is_internal_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(ip in net for net in _INTERNAL_NETS if net.version == ip.version)


def _add_ip(out: Iocs, value: str) -> None:
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return
    if _is_internal_ip(ip):
        return
    out.ips.append(str(ip))


def _add_host(out: Iocs, host: str, legit: list[str]) -> None:
    if not host:
        return
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        _add_ip(out, host)
        return
    if "." not in host or any(host_is_under(host, d) for d in legit):
        return
    (out.shared_hosts if _is_shared_host(host) else out.domains).append(host)


def _add_url(out: Iocs, raw: str, legit: list[str]) -> None:
    p = parse_url(refang(raw.strip()))
    if not p.valid or p.scheme not in ("http", "https") or not p.host_ascii:
        return
    host = p.host_ascii.lower().strip("[]")
    if any(host_is_under(host, d) for d in legit):
        return
    pq = p.path_and_query or "/"
    if not pq.startswith("/"):
        pq = "/" + pq
    pq = quote(pq, safe="/%:@!$&'()*+,;=-._~?")
    shared = _is_shared_host(host) and not p.is_ip
    norm = f"{p.scheme}://{host}{pq}"
    out.urls.append(UrlIoc(norm, p.scheme, host, pq, shared))
    _add_host(out, host, legit)


def _kit_strings(verdict: Verdict) -> list[str]:
    found: list[str] = []
    for sig in verdict.signals:
        if sig.category != "kit" and not sig.id.startswith("kit."):
            continue
        for key in _KIT_EVIDENCE_KEYS:
            val = sig.evidence.get(key)
            vals = [val] if isinstance(val, str) else val if isinstance(val, (list, tuple)) else []
            for v in vals:
                if isinstance(v, str) and 4 <= len(v) <= 200 and v.isprintable():
                    found.append(v)
    return found


def collect_iocs(verdict: Verdict, *, allow_benign: bool = False) -> Iocs:
    """Select the deployable IOCs of ``verdict`` and its children (see module docstring)."""
    out = Iocs()
    nodes = list(verdict.walk())
    legit = [d.lower().rstrip(".") for v in nodes if v.brand for d in v.brand.legit_domains]
    for v in nodes:
        if not allow_benign and (v.level is Level.BENIGN or (v.brand and v.brand.official)):
            continue
        target = refang(v.target.strip())
        if v.kind in (ArtifactKind.URL, ArtifactKind.PAGE) and target.lower().startswith(
                ("http://", "https://")):
            _add_url(out, target, legit)
        for ind in v.indicators:
            if ind.malicious is False:
                continue
            if ind.malicious is None and (ind.role or "") not in _ACTIONABLE_ROLES:
                continue
            val = ind.value.strip()
            if not val or len(val) > 2048:
                continue
            t = ind.type
            if t is IndicatorType.URL:
                _add_url(out, val, legit)
            elif t is IndicatorType.DOMAIN:
                _add_host(out, parse_url("http://" + refang(val).strip("./")).host_ascii, legit)
            elif t in (IndicatorType.IPV4, IndicatorType.IPV6):
                _add_ip(out, refang(val))
            elif t is IndicatorType.EMAIL:
                addr = refang(val).lower()
                if _EMAIL_RE.match(addr):
                    out.emails.append(addr)
            elif t is IndicatorType.SHA256 and _SHA256_RE.match(val):
                out.sha256.append(val.lower())
        out.kit_strings.extend(_kit_strings(v))
    # de-duplicate (order preserving) and cap
    seen: set[str] = set()
    urls: list[UrlIoc] = []
    for u in out.urls:
        if u.url not in seen:
            seen.add(u.url)
            urls.append(u)
    out.urls = urls[:MAX_URL_IOCS]
    for name in ("domains", "shared_hosts", "ips", "emails", "sha256", "kit_strings"):
        setattr(out, name, _uniq(getattr(out, name))[:MAX_IOCS])
    return out


def mitre_techniques(verdict: Verdict) -> list[MitreTechnique]:
    """Union of ATT&CK/ATLAS techniques on the verdict tree (resolved, sorted by id)."""
    ids: dict[str, MitreTechnique] = {}
    for v in verdict.walk():
        for t in v.mitre:
            ids.setdefault(t.id, t)
        for s in v.signals:
            for tid in s.mitre:
                if tid not in ids:
                    ids[tid] = resolve(tid)
    return [ids[k] for k in sorted(ids)]


def brand_name(verdict: Verdict) -> str:
    """Display name of the impersonated brand anywhere in the tree ('' if none)."""
    for v in verdict.walk():
        if v.brand and not v.brand.official:
            return v.brand.name
    return ""


# --------------------------------------------------------------------------- #
# Sigma
# --------------------------------------------------------------------------- #
def _sigma_level(verdict: Verdict) -> str:
    if verdict.level is Level.MALICIOUS:
        return "critical" if verdict.score >= 95 else "high"
    return "medium" if verdict.level is Level.SUSPICIOUS else "low"


def _sigma_tags(techs: list[MitreTechnique]) -> list[str]:
    tags: list[str] = []
    for t in techs:
        if t.framework != "attack":
            continue
        tactic = _TACTIC_TAG.get(t.tactic)
        if tactic:
            tags.append(f"attack.{tactic}")
        tags.append(f"attack.{t.id.lower()}")
    if not tags:
        tags = ["attack.initial_access", "attack.t1566"]
    return _uniq(tags)


def _refs(techs: list[MitreTechnique]) -> list[str]:
    return _uniq([t.url for t in techs if t.url]) or ["https://attack.mitre.org/techniques/T1566/"]


def _base(verdict: Verdict, techs: list[MitreTechnique], kind: str, iocs: Iocs,
          title: str, description: str) -> dict[str, Any]:
    rid = uuid.uuid5(RULE_NAMESPACE, f"sigma|{kind}|{iocs.fingerprint()}")
    score = f"{verdict.score}/100"
    return {
        "title": title[:256],
        "id": str(rid),
        "status": "experimental",
        "description": f"{description} UniPhish verdict: {verdict.level.value} ({score}). "
                       f"{verdict.summary}".strip()[:1000],
        "references": _refs(techs),
        "author": "UniPhish",
        "date": verdict.created_at.strftime("%Y/%m/%d"),
        "tags": _sigma_tags(techs),
    }


def _lead(verdict: Verdict) -> str:
    b = brand_name(verdict)
    return f"phishing impersonating {b}" if b else "phishing infrastructure"


def _proxy_rule(verdict: Verdict, techs: list[MitreTechnique], iocs: Iocs) -> dict[str, Any]:
    det: dict[str, Any] = {}
    if iocs.domains:
        det["selection_host_exact"] = {"cs-host": list(iocs.domains)}
        det["selection_host_subdomain"] = {"cs-host|endswith": [f".{d}" for d in iocs.domains]}
    shared_urls = [u for u in iocs.urls if u.shared_host]
    for i, u in enumerate(shared_urls, 1):
        path = u.path_query.split("?", 1)[0]
        sel: dict[str, Any] = {"cs-host": u.host}
        if path != "/":
            sel["c-uri|startswith"] = path
        det[f"selection_url_{i}"] = sel
    if iocs.ips:
        det["selection_ip"] = {"dst_ip": list(iocs.ips)}
    det["condition"] = "1 of selection_*"
    rule = _base(verdict, techs, "proxy", iocs,
                 f"UniPhish: web access to {_lead(verdict)}",
                 "Detects web-proxy requests to hosts, URLs or addresses that UniPhish "
                 f"identified as {_lead(verdict)}.")
    rule.update({
        "logsource": {"category": "proxy"},
        "detection": det,
        "fields": ["c-ip", "cs-host", "c-uri"],
        "falsepositives": ["Security-awareness exercises or red-team engagements that "
                           "deliberately use these hosts",
                           "Analysts or sandboxes visiting the indicator to investigate it"],
        "level": _sigma_level(verdict),
    })
    return rule


def _dns_rule(verdict: Verdict, techs: list[MitreTechnique], iocs: Iocs) -> dict[str, Any]:
    rule = _base(verdict, techs, "zeek-dns", iocs,
                 f"UniPhish: DNS lookup of {_lead(verdict)} domain",
                 f"Detects Zeek DNS queries for domains UniPhish identified as {_lead(verdict)}.")
    rule.update({
        "logsource": {"product": "zeek", "service": "dns"},
        "detection": {
            "selection_exact": {"query": list(iocs.domains)},
            "selection_subdomain": {"query|endswith": [f".{d}" for d in iocs.domains]},
            "condition": "1 of selection_*",
        },
        "fields": ["id.orig_h", "query", "answers"],
        "falsepositives": ["Threat-hunting or take-down tooling resolving the domain"],
        "level": _sigma_level(verdict),
    })
    return rule


def _email_rule(verdict: Verdict, techs: list[MitreTechnique], iocs: Iocs) -> dict[str, Any]:
    rule = _base(verdict, techs, "email", iocs,
                 f"UniPhish: e-mail from {_lead(verdict)} sender",
                 f"Detects inbound mail from sender addresses tied to {_lead(verdict)}.")
    rule.update({
        "logsource": {"category": "email"},
        "detection": {"selection": {"sender_address": list(iocs.emails)},
                      "condition": "selection"},
        "fields": ["sender_address", "recipient_address", "subject"],
        "falsepositives": ["Sender address later recovered by its legitimate owner",
                           "Spoofed envelope senders that impersonate an innocent party"],
        "level": _sigma_level(verdict),
    })
    return rule


def to_sigma_rules(verdict: Verdict, *, allow_benign: bool = False) -> list[dict[str, Any]]:
    """All Sigma rules for ``verdict``: proxy, Zeek-DNS and e-mail (whichever apply).

    Raises:
        NoIndicatorsError: nothing deployable (e.g. a benign verdict).
    """
    iocs = collect_iocs(verdict, allow_benign=allow_benign)
    techs = mitre_techniques(verdict)
    rules: list[dict[str, Any]] = []
    if iocs.web:
        rules.append(_proxy_rule(verdict, techs, iocs))
    if iocs.domains:
        rules.append(_dns_rule(verdict, techs, iocs))
    if iocs.emails:
        rules.append(_email_rule(verdict, techs, iocs))
    if not rules:
        raise NoIndicatorsError("verdict yields no URL, domain, IP or sender indicators")
    return rules


def to_sigma(verdict: Verdict, *, allow_benign: bool = False) -> dict[str, Any]:
    """Primary Sigma rule (web-proxy when web IOCs exist, otherwise the e-mail rule)."""
    return to_sigma_rules(verdict, allow_benign=allow_benign)[0]


def to_sigma_yaml(verdict: Verdict, *, allow_benign: bool = False) -> str:
    """All Sigma rules as one multi-document YAML string (``---`` separated)."""
    return yaml.safe_dump_all(to_sigma_rules(verdict, allow_benign=allow_benign),
                              sort_keys=False, allow_unicode=False, width=100)


_SIGMA_REQUIRED = ("title", "id", "status", "description", "logsource", "detection", "level")
_SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}
_SIGMA_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}


def validate_sigma(rule: dict[str, Any]) -> list[str]:
    """Structural validation of a Sigma rule dict; returns a list of problems (empty = ok)."""
    problems = [f"missing key: {k}" for k in _SIGMA_REQUIRED if k not in rule]
    if problems:
        return problems
    try:
        uuid.UUID(str(rule["id"]))
    except ValueError:
        problems.append("id is not a UUID")
    if rule["level"] not in _SIGMA_LEVELS:
        problems.append(f"bad level {rule['level']!r}")
    if rule["status"] not in _SIGMA_STATUS:
        problems.append(f"bad status {rule['status']!r}")
    if not isinstance(rule["logsource"], dict) or not rule["logsource"]:
        problems.append("logsource must be a non-empty mapping")
    det = rule["detection"]
    if not isinstance(det, dict) or "condition" not in det:
        return [*problems, "detection needs a condition"]
    names = [k for k in det if k != "condition"]
    if not names:
        problems.append("detection has no selections")
    cond = str(det["condition"])
    for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_*]*", cond):
        if tok in {"and", "or", "not", "of", "all", "them", "1"}:
            continue
        if tok.endswith("*"):
            if not any(n.startswith(tok[:-1]) for n in names):
                problems.append(f"condition pattern {tok!r} matches nothing")
        elif tok not in names:
            problems.append(f"condition references unknown selection {tok!r}")
    for n in names:
        sel = det[n]
        if not isinstance(sel, (dict, list)) or not sel:
            problems.append(f"selection {n!r} empty or malformed")
    return problems
