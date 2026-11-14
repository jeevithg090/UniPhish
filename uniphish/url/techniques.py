"""Attack-construction technique classification for URLs.

Where :mod:`uniphish.url.lexical` measures and :mod:`uniphish.url.brands` names the
impersonated brand, this module answers *how the URL is built to deceive*, using a fixed
taxonomy (:data:`TAXONOMY`) so verdicts, dashboards and detection-as-code exports speak one
vocabulary.  Every technique maps to MITRE ATT&CK ids that exist in
:data:`uniphish.core.mitre.CATALOG`.  Official brand hosts yield no techniques.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from uniphish.core.mitre import CATALOG
from uniphish.url.brands import brand_candidates
from uniphish.url.lexical import LexicalFeatures, features
from uniphish.url.parse import ParsedURL, parse_url

__all__ = ["MITRE_MAP", "TAXONOMY", "TechniqueResult", "classify"]

TAXONOMY: tuple[str, ...] = (
    "homoglyph",
    "idn_homograph",
    "typosquat",
    "combosquat",
    "subdomain_stuffing",
    "path_deception",
    "ip_host",
    "ip_obfuscation",
    "url_shortener",
    "open_redirect_abuse",
    "lots_hosting",
    "dynamic_dns",
    "at_redirect",
    "punycode",
    "suspicious_tld",
    "excessive_subdomains",
    "data_uri",
    "credential_path",
)

#: Which technique is reported as ``primary`` when several apply (most deceptive first).
_PRIORITY: tuple[str, ...] = (
    "homoglyph",
    "idn_homograph",
    "typosquat",
    "combosquat",
    "subdomain_stuffing",
    "at_redirect",
    "data_uri",
    "path_deception",
    "open_redirect_abuse",
    "ip_obfuscation",
    "ip_host",
    "lots_hosting",
    "url_shortener",
    "dynamic_dns",
    "punycode",
    "credential_path",
    "suspicious_tld",
    "excessive_subdomains",
)

_BRAND_TECHNIQUE = {
    "homoglyph": "homoglyph",
    "idn": "idn_homograph",
    "typosquat": "typosquat",
    "bitsquat": "typosquat",
    "combosquat": "combosquat",
    "subdomain": "subdomain_stuffing",
    "path": "path_deception",
}

#: technique -> MITRE ATT&CK technique ids (all present in ``core.mitre.CATALOG``).
MITRE_MAP: dict[str, tuple[str, ...]] = {
    "homoglyph": ("T1583.001", "T1656", "T1566.002"),
    "idn_homograph": ("T1583.001", "T1656", "T1566.002"),
    "typosquat": ("T1583.001", "T1656", "T1566.002"),
    "combosquat": ("T1583.001", "T1656", "T1566.002"),
    "subdomain_stuffing": ("T1656", "T1566.002"),
    "path_deception": ("T1656", "T1566.002"),
    "ip_host": ("T1566.002", "T1608.005"),
    "ip_obfuscation": ("T1027", "T1566.002"),
    "url_shortener": ("T1566.002", "T1204.001"),
    "open_redirect_abuse": ("T1566.002", "T1204.001"),
    "lots_hosting": ("T1583.006", "T1566.002"),
    "dynamic_dns": ("T1583.001", "T1566.002"),
    "at_redirect": ("T1566.002", "T1204.001"),
    "punycode": ("T1583.001", "T1656"),
    "suspicious_tld": ("T1583.001",),
    "excessive_subdomains": ("T1566.002",),
    "data_uri": ("T1027.006", "T1204.001"),
    "credential_path": ("T1598.003",),
}

_SUSPICIOUS_TLD_RISK = 0.8
_BRAND_MIN_CONFIDENCE = 0.5


@dataclass
class TechniqueResult:
    """Outcome of :func:`classify`."""

    techniques: list[str] = field(default_factory=list)
    primary: str | None = None
    target_brand: str | None = None
    descriptions: dict[str, str] = field(default_factory=dict)
    mitre: list[str] = field(default_factory=list)
    brand_confidence: float = 0.0

    def has(self, technique: str) -> bool:
        return technique in self.techniques


def classify(url: str | ParsedURL, *, lexical: LexicalFeatures | None = None) -> TechniqueResult:
    """Classify how ``url`` is constructed to deceive.

    ``lexical`` may be passed to avoid recomputing features. Never raises on bad input.
    """
    p = url if isinstance(url, ParsedURL) else parse_url(url)
    cands = brand_candidates(p)
    f = lexical if lexical is not None else features(p)
    found: dict[str, str] = {}
    official = bool(cands and cands[0].official)

    target = None
    brand_c = [c for c in cands if c.confidence >= _BRAND_MIN_CONFIDENCE and not c.official]
    if brand_c:
        target = brand_c[0]
        for c in brand_c:
            if c.brand != target.brand:
                continue
            tech = _BRAND_TECHNIQUE.get(c.technique)
            if tech and tech not in found:
                found[tech] = f"{c.name}: {c.evidence}."

    if official:
        # A brand's own host is never impersonation, but its redirectors are abused.
        if f.open_redirect or (f.open_redirect_via or "").startswith("known:"):
            found["open_redirect_abuse"] = (
                f"{p.host_ascii} hosts a redirect endpoint "
                f"({f.open_redirect_via}) that can forward victims "
                f"to {f.open_redirect or 'another site'}."
            )
        return _result(found, None)
    if p.is_ip:
        found["ip_host"] = f"The link points at a raw IP address ({p.host}) instead of a domain."
    if f.ip_obfuscated:
        found["ip_obfuscation"] = (
            f"The IP address is written in an obfuscated numeric form and resolves to {p.host}."
        )
    if f.is_shortener:
        found["url_shortener"] = f"{p.host_ascii} is a link shortener, hiding the real destination."
    if f.open_redirect or (f.open_redirect_via or "").startswith("known:"):
        dest = f" to {f.open_redirect}" if f.open_redirect else ""
        found["open_redirect_abuse"] = (
            f"A redirect endpoint on {p.host_ascii} ({f.open_redirect_via}) forwards "
            f"visitors{dest}, borrowing that site's reputation."
        )
    if f.lots is not None:
        found["lots_hosting"] = (
            f"Hosted on {f.lots.name}, a legitimate {f.lots.kind} platform anyone can publish on."
        )
    if f.is_dyndns:
        found["dynamic_dns"] = f"{p.host_ascii} sits on a dynamic-DNS zone anyone can register in."
    if f.has_atsign_redirect:
        found["at_redirect"] = (
            f"Text before '@' ({p.userinfo!r}) looks like the destination, "
            f"but the browser connects to {p.host_ascii}."
        )
    if f.punycode:
        found["punycode"] = f"The host uses punycode (xn--) labels: {p.host_ascii}."
    if f.tld_risk is not None and f.tld_risk >= _SUSPICIOUS_TLD_RISK:
        found["suspicious_tld"] = f".{f.tld} is a TLD with a high phishing abuse rate."
    if f.many_subdomains:
        found["excessive_subdomains"] = (
            f"{f.num_subdomains} sub-domain labels push the real domain out of view."
        )
    if f.data_or_js_scheme:
        found["data_uri"] = f"The URL uses the {p.scheme}: scheme, which carries content inline."
    if p.host_ascii or p.is_ip:
        cred = [w for w in f.sensitive_words_in_path]
        if len(cred) >= 2 or (cred and len(found) > 0):
            found["credential_path"] = (
                "The path contains sign-in / verification vocabulary: " + ", ".join(cred[:4]) + "."
            )

    return _result(found, target)


def _result(found: dict[str, str], target) -> TechniqueResult:
    techniques = [t for t in TAXONOMY if t in found]
    primary = next((t for t in _PRIORITY if t in found), None)
    ids: set[str] = set()
    for t in techniques:
        ids.update(i for i in MITRE_MAP[t] if i in CATALOG)
    return TechniqueResult(
        techniques=techniques,
        primary=primary,
        target_brand=target.brand if target else None,
        descriptions={t: found[t] for t in techniques},
        mitre=sorted(ids),
        brand_confidence=target.confidence if target else 0.0,
    )
