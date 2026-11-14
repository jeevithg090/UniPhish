"""URL analyzer: turns the lexical / Unicode / brand machinery into engine signals.

This is the stage-0, CPU-bound analyzer for :class:`~uniphish.core.types.ArtifactKind.URL`
artifacts. It does no I/O: everything is derived from the URL string itself, reusing the
pure building blocks already shipped by the ``uniphish.url`` package —

* :func:`uniphish.url.parse.parse_url` — browser-faithful, hostile-input-safe parsing;
* :func:`uniphish.url.lexical.features` — the explainable lexical / structural feature set;
* :func:`uniphish.url.brands.brand_candidates` — which brand the URL imitates, and how;
* :func:`uniphish.url.idn_policy.assess_host` — Chromium-style IDN spoof assessment;
* :func:`uniphish.url.techniques.classify` — the attack-construction technique taxonomy.

Each measurement becomes a signed-log-odds :class:`~uniphish.core.types.Signal` with a
title, a specifics-carrying detail, a MITRE mapping and — wherever the offending text can
be located — a character ``span`` into the submitted URL (which the dashboard highlights).
A brand's own official / login / CDN host yields a single *negative* signal so legitimate
brand URLs are confidently benign; "living-off-trusted-sites" hosts never earn that bonus.

The analyzer never raises on hostile input: parsing, feature extraction and brand matching
are all total functions, and every optional phase is wrapped so one failure degrades the
verdict instead of breaking it.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from urllib.parse import unquote

from uniphish.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult, register
from uniphish.core.types import Artifact, ArtifactKind, BrandMatch, Indicator, IndicatorType, Signal
from uniphish.url.brandkb import get_kb
from uniphish.url.brands import HostParts, brand_candidates, split_host
from uniphish.url.confusables import brand_skeleton, confusable_chars_in
from uniphish.url.idn_policy import assess_host
from uniphish.url.lexical import LexicalFeatures, features
from uniphish.url.parse import ParsedURL, parse_url
from uniphish.url.techniques import classify

log = logging.getLogger("uniphish.url")

# --------------------------------------------------------------------------- #
# Signal catalog (id -> generic title). The analyzer declares this verbatim as
# ``UrlAnalyzer.signals`` and every emitted signal draws its title from it, so the
# documented catalog and the runtime output can never drift apart.
# --------------------------------------------------------------------------- #
_CATALOG: dict[str, str] = {
    # brand impersonation
    "brand.homoglyph": "Domain imitates a brand using look-alike characters",
    "brand.idn": "Internationalised domain imitates a brand",
    "brand.typosquat": "Domain is a typo-variant of a brand",
    "brand.bitsquat": "Domain differs from a brand by one flipped bit",
    "brand.combosquat": "Brand name combined with extra words in the domain",
    "brand.subdomain": "Brand name placed in a sub-domain of an unrelated site",
    "brand.path": "Brand name appears in the URL path of an unrelated site",
    "brand.content": "Page content impersonates a brand",
    "brand.sender": "Sender impersonates a brand",
    "brand.official": "URL belongs to the brand's official domain (legitimacy evidence)",
    # unicode / IDN
    "unicode.skeleton_matches_top_domain": "Host is a look-alike of a popular domain",
    "unicode.whole_script_confusable": "A whole host label in another script reads as Latin",
    "unicode.mixed_script_host": "Host mixes characters from multiple writing systems",
    "unicode.confusable_host": "Host contains characters that imitate ASCII letters",
    "unicode.invisible_char": "Host contains invisible characters",
    "unicode.bidi_control": "Host contains bidirectional control characters",
    "unicode.dangerous_char": "Host contains characters that imitate URL delimiters",
    "unicode.combining_mark": "Host stacks combining marks on Latin letters",
    "unicode.digit_lookalike": "Host contains characters that imitate digits",
    "unicode.disallowed_char": "Host contains disallowed identifier characters",
    "unicode.punycode_lookalike": "Punycode host decodes to a look-alike domain",
    "unicode.punycode": "Host uses punycode (xn--) encoding",
    # structure / infrastructure
    "url.ip_host": "Link uses a raw IP address as the host",
    "url.ip_obfuscation": "IP address written in an obfuscated numeric form",
    "url.at_redirect": "Deceptive text before '@' in the URL",
    "url.shortener": "URL uses a link-shortening service",
    "url.dynamic_dns": "Host is on a dynamic-DNS service",
    "url.lots_hosting": "Hosted on a legitimate platform anyone can publish on",
    "url.open_redirect": "URL abuses an open-redirect endpoint",
    "url.suspicious_tld": "Top-level domain is frequently abused for phishing",
    "url.many_subdomains": "Excessive sub-domain labels hide the real domain",
    "url.credential_lure_host": "Host contains sign-in / security lure words",
    "url.credential_lure_path": "Path contains sign-in / security lure words",
    "url.suspicious_file_ext": "Path points at a dangerous downloadable file",
    "url.double_extension": "File in the path uses a deceptive double extension",
    "url.dangerous_scheme": "URL uses a data:/javascript: scheme carrying inline content",
    "url.double_encoding": "URL uses double percent-encoding to hide content",
    "url.random_label": "Host label looks randomly generated",
    "url.non_standard_port": "Connection uses a non-standard port",
    "url.long_url": "Unusually long URL",
    "url.many_hyphens": "Unusually many hyphens in the host",
}

# --------------------------------------------------------------------------- #
# Weight tables (signed log-odds; calibrated against the contract's weight scale)
# --------------------------------------------------------------------------- #
# Brand impersonation — scaled in fusion by the match confidence.
_BRAND_WEIGHT: dict[str, float] = {
    "homoglyph": 4.5,
    "idn": 4.0,
    "bitsquat": 3.5,
    "typosquat": 3.0,
    "combosquat": 2.5,
    "subdomain": 2.5,
    "path": 1.5,
    "content": 2.0,
    "sender": 2.0,
}
_OFFICIAL_WEIGHT = -3.0

_SQUAT_MITRE = ["T1036", "T1566.002", "T1583.001"]
_BRAND_MITRE: dict[str, list[str]] = {
    "homoglyph": _SQUAT_MITRE,
    "idn": _SQUAT_MITRE,
    "bitsquat": _SQUAT_MITRE,
    "typosquat": _SQUAT_MITRE,
    "combosquat": _SQUAT_MITRE,
    "subdomain": ["T1036", "T1566.002", "T1656"],
    "path": ["T1566.002", "T1656"],
    "content": ["T1036", "T1656"],
    "sender": ["T1036", "T1656"],
}

# Minimum confidence for a brand candidate to become a signal, and the per-URL cap.
_BRAND_SIGNAL_MIN = 0.35
_MAX_BRAND_SIGNALS = 6

# Unicode / IDN spoof reasons -> (signal id, weight, mitre). Gated on assess_host, which is
# browser-faithful, so a legitimately non-ASCII domain (e.g. 'müller.de') is not flagged.
_HOMO_MITRE = ["T1036", "T1583.001"]
_OBF_MITRE = ["T1027", "T1036"]
_REASON_SIGNAL: dict[str, tuple[str, float, list[str]]] = {
    "skeleton_matches_top_domain": ("unicode.skeleton_matches_top_domain", 3.5, _HOMO_MITRE),
    "whole_script_confusable": ("unicode.whole_script_confusable", 3.5, _HOMO_MITRE),
    "mixed_script": ("unicode.mixed_script_host", 2.0, _HOMO_MITRE),
    "invisible_char": ("unicode.invisible_char", 3.0, _OBF_MITRE),
    "bidi_control": ("unicode.bidi_control", 3.0, _OBF_MITRE),
    "dangerous_char": ("unicode.dangerous_char", 3.0, _OBF_MITRE),
    "combining_mark_on_latin": ("unicode.combining_mark", 2.0, _HOMO_MITRE),
    "digit_lookalike": ("unicode.digit_lookalike", 2.0, _HOMO_MITRE),
    "disallowed_identifier_char": ("unicode.disallowed_char", 1.5, _OBF_MITRE),
}
_REASON_DETAIL: dict[str, str] = {
    "skeleton_matches_top_domain": "its skeleton matches a popular domain",
    "whole_script_confusable": "a whole label in another script reads as Latin",
    "mixed_script": "it mixes characters from multiple writing systems",
    "invisible_char": "it hides invisible (zero-width) characters",
    "bidi_control": "it embeds bidirectional-override control characters",
    "dangerous_char": "it uses characters that imitate URL delimiters",
    "combining_mark_on_latin": "it stacks combining marks on Latin letters",
    "digit_lookalike": "it uses letters that imitate digits",
    "disallowed_identifier_char": "it uses characters disallowed in identifiers",
}

_MIN_TOP_SKELETON_LEN = 5  # ignore very short brand labels for the look-alike check
_LURE_CAP = 2.0  # cap the summed credential-lure weight per location
_SUSPICIOUS_TLD_MIN = 0.5  # emit the TLD signal only above this log-odds risk
_LONG_URL = 100  # characters
_MANY_HYPHENS = 4

__all__ = ["UrlAnalyzer"]


# --------------------------------------------------------------------------- #
# Span helpers (best-effort location of offending text in the submitted URL)
# --------------------------------------------------------------------------- #
def _find_span(haystack: str, needle: str) -> tuple[int, int] | None:
    """First occurrence of ``needle`` in ``haystack`` (case-insensitive fallback)."""
    if not needle:
        return None
    idx = haystack.find(needle)
    if idx < 0:
        idx = haystack.lower().find(needle.lower())
    return (idx, idx + len(needle)) if idx >= 0 else None


def _raw_authority_host_span(url: str) -> tuple[int, int] | None:
    """Span of the host within the *raw* authority (handles forms the parser normalises,
    e.g. an obfuscated numeric IP) without trusting any attacker-chosen delimiter text."""
    sep = url.find("//")
    start = sep + 2 if sep >= 0 else 0
    end = len(url)
    for ch in "/?#":
        idx = url.find(ch, start)
        if idx != -1:
            end = min(end, idx)
    authority = url[start:end]
    at = authority.rfind("@")
    if at != -1:
        start += at + 1
        authority = url[start:end]
    if authority.startswith("["):  # IPv6 literal [::1]:port
        close = authority.find("]")
        if close != -1:
            return (start, start + close + 1)
    colon = authority.rfind(":")
    if colon > 0 and authority[colon + 1 :].isdigit():
        end = start + colon
    return (start, end) if end > start else None


def _host_region(url: str, p: ParsedURL) -> tuple[int, int] | None:
    for cand in (p.host_unicode, p.host_ascii, p.host):
        span = _find_span(url, cand)
        if span:
            return span
    return _raw_authority_host_span(url)


def _brand_span(
    url: str, p: ParsedURL, parts: HostParts, cand: BrandMatch
) -> tuple[int, int] | None:
    tech = cand.technique
    if tech in ("homoglyph", "idn"):
        label = next((lbl for lbl in (*parts.sub, parts.sld) if lbl and not lbl.isascii()), "")
        span = _find_span(url, label) if label else None
        if span:
            return span
        for alabel in p.host_ascii.split("."):
            if alabel.startswith("xn--"):
                span = _find_span(url, alabel)
                if span:
                    return span
        return _host_region(url, p)
    if tech in ("typosquat", "combosquat", "bitsquat"):
        return _find_span(url, parts.sld) or _host_region(url, p)
    if tech == "subdomain":
        return (_find_span(url, p.subdomain) if p.subdomain else None) or _host_region(url, p)
    if tech == "path":
        brand = get_kb().get(cand.brand)
        if brand is not None:
            low = url.lower()
            for kw in sorted(brand.keywords, key=len, reverse=True):
                idx = low.find(kw.lower())
                if idx >= 0:
                    return (idx, idx + len(kw))
    return _host_region(url, p)


@lru_cache(maxsize=1)
def _top_skeletons() -> frozenset[str]:
    """Brand skeletons of the KB's official-domain labels (for the look-alike check)."""
    out: set[str] = set()
    for brand in get_kb().all():
        for domain in brand.official_domains:
            sld = parse_url("http://" + domain).sld
            if sld and len(sld) >= _MIN_TOP_SKELETON_LEN:
                out.add(brand_skeleton(sld))
    return frozenset(out)


# --------------------------------------------------------------------------- #
# Signal builders
# --------------------------------------------------------------------------- #
def _sig(
    sid: str,
    detail: str,
    weight: float,
    category: str,
    *,
    title: str | None = None,
    confidence: float = 1.0,
    mitre: list[str] | None = None,
    span: tuple[int, int] | None = None,
    evidence: dict | None = None,
) -> Signal:
    return Signal(
        id=sid,
        title=(title or _CATALOG[sid])[:70],
        detail=detail,
        weight=weight,
        confidence=confidence,
        category=category,
        mitre=mitre or [],
        span=span,
        evidence=evidence or {},
    )


def _brand_signals(
    url: str, p: ParsedURL, parts: HostParts, cands: list[BrandMatch]
) -> tuple[list[Signal], BrandMatch | None]:
    """Brand impersonation signals plus the best :class:`BrandMatch` for the verdict."""
    if not cands:
        return [], None
    best = cands[0]
    if best.official:
        sig = _sig(
            "brand.official",
            best.evidence or f"{p.host_ascii} is an official asset of {best.name}.",
            _OFFICIAL_WEIGHT,
            "brand",
            title=f"URL belongs to {best.name}'s official domain",
            confidence=best.confidence,
            span=_host_region(url, p),
            evidence={"brand": best.brand, "host": p.host_ascii},
        )
        return [sig], best

    signals: list[Signal] = []
    for cand in cands:
        if cand.official or cand.confidence < _BRAND_SIGNAL_MIN:
            continue
        sid = f"brand.{cand.technique}"
        if sid not in _CATALOG:
            continue
        signals.append(
            _sig(
                sid,
                f"{cand.name}: {cand.evidence}.",
                _BRAND_WEIGHT.get(cand.technique, 2.0),
                "brand",
                title=f"{_CATALOG[sid]} ({cand.name})",
                confidence=cand.confidence,
                mitre=_BRAND_MITRE.get(cand.technique, _SQUAT_MITRE),
                span=_brand_span(url, p, parts, cand),
                evidence={
                    "brand": cand.brand,
                    "technique": cand.technique,
                    "confidence": cand.confidence,
                    "legit_domains": cand.legit_domains[:5],
                },
            )
        )
        if len(signals) >= _MAX_BRAND_SIGNALS:
            break
    best_match = best if best.confidence >= 0.3 else None
    return signals, best_match


def _unicode_signals(url: str, p: ParsedURL, f: LexicalFeatures) -> list[Signal]:
    """IDN / homoglyph signals, gated on the browser-faithful IDN spoof assessment."""
    if p.is_ip or not p.host_unicode or not p.has_nonascii_host:
        return []
    try:
        tld = p.host_unicode.rsplit(".", 1)[-1]
        assessment = assess_host(p.host_unicode, tld=tld, top_domain_skeletons=_top_skeletons())
    except Exception:  # pragma: no cover - assess_host is total, defensive only
        log.debug("assess_host failed for %s", p.host_ascii, exc_info=True)
        return []

    reasons = set(assessment.reasons)
    confusables = confusable_chars_in(p.host_unicode)
    region = _find_span(url, p.host_unicode)
    char_span: tuple[int, int] | None = None
    if region and confusables:
        base = region[0]
        char_span = (base + confusables[0][0], base + confusables[-1][0] + 1)
    host_span = char_span or region or _host_region(url, p)

    signals: list[Signal] = []
    for reason in sorted(reasons):
        mapped = _REASON_SIGNAL.get(reason)
        if mapped is None:
            continue
        sid, weight, mitre = mapped
        signals.append(
            _sig(
                sid,
                f"The host {p.host_unicode!r} is a spoofing risk because "
                f"{_REASON_DETAIL.get(reason, reason)}.",
                weight,
                "unicode",
                span=host_span,
                mitre=mitre,
                evidence={
                    "host": p.host_unicode,
                    "reason": reason,
                    "scripts": list(assessment.scripts),
                },
            )
        )

    # A confusable host that is spoofy but whose only tells are weaker: name it explicitly.
    strong = {"skeleton_matches_top_domain", "whole_script_confusable", "mixed_script"}
    if confusables and assessment.is_spoof and not (reasons & strong):
        looks = ", ".join(f"{ch!r}->{asc!r}" for _, ch, asc in confusables[:6])
        signals.append(
            _sig(
                "unicode.confusable_host",
                f"The host {p.host_unicode!r} uses look-alike characters ({looks}).",
                3.0,
                "unicode",
                span=char_span or host_span,
                mitre=_HOMO_MITRE,
                evidence={
                    "host": p.host_unicode,
                    "confusables": [[i, ch, asc] for i, ch, asc in confusables[:12]],
                },
            )
        )

    if f.punycode:
        if assessment.is_spoof:
            signals.append(
                _sig(
                    "unicode.punycode_lookalike",
                    f"The punycode host {p.host_ascii} decodes to {p.host_unicode!r}, "
                    "a spoofing risk.",
                    3.0,
                    "unicode",
                    span=_host_region(url, p),
                    mitre=_HOMO_MITRE,
                    evidence={"host_ascii": p.host_ascii, "host_unicode": p.host_unicode},
                )
            )
        else:
            signals.append(
                _sig(
                    "unicode.punycode",
                    f"The host {p.host_ascii} is punycode-encoded ({p.host_unicode!r}).",
                    0.5,
                    "unicode",
                    span=_host_region(url, p),
                    evidence={"host_ascii": p.host_ascii, "host_unicode": p.host_unicode},
                )
            )
    return signals


def _structure_signals(url: str, p: ParsedURL, f: LexicalFeatures, official: bool) -> list[Signal]:
    """Structural / infrastructure URL signals (IP tricks, redirects, TLD, lures ...)."""
    out: list[Signal] = []

    def add(
        sid: str,
        detail: str,
        weight: float,
        *,
        mitre: list[str] | None = None,
        span: tuple[int, int] | None = None,
        evidence: dict | None = None,
    ) -> None:
        out.append(_sig(sid, detail, weight, "url", mitre=mitre, span=span, evidence=evidence))

    # --- authority tricks ------------------------------------------------- #
    if f.ip_obfuscated:
        add(
            "url.ip_obfuscation",
            f"The host is an obfuscated numeric form of the IP address {p.host}.",
            3.0,
            mitre=["T1027", "T1566.002"],
            span=_host_region(url, p),
            evidence={"ip": p.host},
        )
    elif p.is_ip:
        add(
            "url.ip_host",
            f"The link points at the raw IP address {p.host} instead of a domain name.",
            1.5,
            mitre=["T1566.002", "T1608.005"],
            span=_host_region(url, p),
            evidence={"ip": p.host},
        )
    if f.has_atsign_redirect:
        add(
            "url.at_redirect",
            f"Text before '@' ({p.userinfo!r}) looks like the destination, but the browser "
            f"connects to {p.host_ascii}.",
            3.0,
            mitre=["T1036", "T1566.002"],
            span=_find_span(url, p.userinfo),
            evidence={"userinfo": p.userinfo, "real_host": p.host_ascii},
        )

    # --- hosting infrastructure ------------------------------------------- #
    if f.is_shortener:
        add(
            "url.shortener",
            f"{p.host_ascii} is a link shortener, which hides the real destination.",
            1.0,
            mitre=["T1204.001", "T1566.002"],
            span=_host_region(url, p),
        )
    if f.is_dyndns:
        add(
            "url.dynamic_dns",
            f"{p.host_ascii} sits on a dynamic-DNS zone anyone can register a name in.",
            1.5,
            mitre=["T1566.002", "T1583.001"],
            span=_host_region(url, p),
        )
    if f.lots is not None:
        # "Living off trusted sites" is a real hosting technique, but these platforms
        # carry overwhelmingly legitimate content, so on its own the host is only weak
        # context: it denies the reputation bonus (handled in the reputation analyzer)
        # and lightly corroborates other phishing signals rather than deciding alone.
        add(
            "url.lots_hosting",
            f"Hosted on {f.lots.name}, a legitimate {f.lots.kind} platform anyone can publish on "
            f"(no reputation credit is given for the host).",
            0.6,
            mitre=["T1566.002", "T1583.006"],
            span=_host_region(url, p),
            evidence={"platform": f.lots.name, "kind": f.lots.kind},
        )
    if f.open_redirect or (f.open_redirect_via or "").startswith("known:"):
        dest = f" to {f.open_redirect}" if f.open_redirect else ""
        add(
            "url.open_redirect",
            f"A redirect endpoint on {p.host_ascii} ({f.open_redirect_via}) forwards "
            f"visitors{dest}, borrowing that site's reputation.",
            2.0,
            mitre=["T1204.001", "T1566.002"],
            evidence={"via": f.open_redirect_via, "destination": f.open_redirect},
        )

    # --- TLD / shape ------------------------------------------------------ #
    if f.tld_risk is not None and f.tld_risk >= _SUSPICIOUS_TLD_MIN:
        add(
            "url.suspicious_tld",
            f".{f.tld} is a top-level domain with a high phishing-abuse rate.",
            round(min(f.tld_risk, 2.0), 2),
            mitre=["T1583.001"],
            evidence={"tld": f.tld, "tld_risk": f.tld_risk},
        )
    if f.many_subdomains:
        add(
            "url.many_subdomains",
            f"{f.num_subdomains} sub-domain labels push the real domain out of view.",
            1.0,
            mitre=["T1566.002"],
            span=_host_region(url, p),
            evidence={"num_subdomains": f.num_subdomains},
        )

    # --- credential-lure vocabulary --------------------------------------- #
    if f.sensitive_words_in_host and f.sensitive_weight_host > 0:
        add(
            "url.credential_lure_host",
            "The host uses sign-in / verification vocabulary: "
            + ", ".join(f.sensitive_words_in_host[:5])
            + ".",
            round(min(f.sensitive_weight_host, _LURE_CAP), 2),
            mitre=["T1566.002", "T1598.003"],
            span=_host_region(url, p),
            evidence={"words": list(f.sensitive_words_in_host[:8])},
        )
    if f.sensitive_words_in_path and f.sensitive_weight_path > 0:
        add(
            "url.credential_lure_path",
            "The path uses sign-in / verification vocabulary: "
            + ", ".join(f.sensitive_words_in_path[:5])
            + ".",
            round(min(f.sensitive_weight_path, _LURE_CAP), 2),
            mitre=["T1566.002", "T1598.003"],
            span=_find_span(url, p.path),
            evidence={"words": list(f.sensitive_words_in_path[:8])},
        )

    # --- path / encoding -------------------------------------------------- #
    if f.suspicious_file_ext_in_path:
        fname = unquote(p.path).rsplit("/", 1)[-1]
        if f.double_extension:
            add(
                "url.double_extension",
                f"The path downloads a file whose real type is {f.suspicious_file_ext_in_path} "
                f"behind a harmless-looking extension.",
                2.5,
                mitre=["T1036.007", "T1204.002"],
                span=_find_span(url, fname),
                evidence={"ext": f.suspicious_file_ext_in_path},
            )
        else:
            add(
                "url.suspicious_file_ext",
                f"The path points at a {f.suspicious_file_ext_in_path} file, an executable / "
                f"script type commonly used to deliver malware.",
                2.0,
                mitre=["T1204.002"],
                span=_find_span(url, fname),
                evidence={"ext": f.suspicious_file_ext_in_path},
            )
    if f.data_or_js_scheme:
        add(
            "url.dangerous_scheme",
            f"The URL uses the {p.scheme}: scheme, which carries executable / markup content "
            f"inline rather than pointing at a host.",
            3.0,
            mitre=["T1027.006", "T1059.007", "T1204.001"],
            evidence={"scheme": p.scheme},
        )
    if f.double_encoding:
        add(
            "url.double_encoding",
            "The URL is doubly percent-encoded, a common way to hide its real content from "
            "filters.",
            1.0,
            mitre=["T1027"],
        )

    # --- weak / contextual cues ------------------------------------------- #
    if f.random_looking_label:
        add(
            "url.random_label",
            "A host label looks algorithmically generated (high entropy / no vowels).",
            0.5,
            span=_host_region(url, p),
            evidence={"random_label_score": f.random_label_score},
        )
    if f.non_std_port:
        add(
            "url.non_standard_port",
            f"The URL forces a non-standard port ({p.port}).",
            0.5,
            evidence={"port": p.port},
        )
    if f.url_len > _LONG_URL:
        add(
            "url.long_url",
            f"The URL is {f.url_len} characters long, which can hide its true target.",
            0.3,
            evidence={"url_len": f.url_len},
        )
    if f.num_hyphens >= _MANY_HYPHENS:
        add(
            "url.many_hyphens",
            f"The host contains {f.num_hyphens} hyphens, a common squatting pattern.",
            0.3,
            span=_host_region(url, p),
            evidence={"num_hyphens": f.num_hyphens},
        )

    if official:
        # A brand's own host is legitimate; keep only the genuinely abusable open-redirect.
        return [s for s in out if s.id == "url.open_redirect"]
    return out


def _indicators(p: ParsedURL, f: LexicalFeatures) -> list[Indicator]:
    """Extract observables (IOCs) from the URL."""
    out: list[Indicator] = []
    if p.valid and (p.host_ascii or p.is_ip):
        out.append(Indicator(type=IndicatorType.URL, value=p.url, role="landing"))
    if p.is_ip and p.ip is not None:
        itype = IndicatorType.IPV6 if p.ip.version == 6 else IndicatorType.IPV4
        out.append(Indicator(type=itype, value=str(p.ip), role="landing"))
    elif p.registrable_domain:
        out.append(Indicator(type=IndicatorType.DOMAIN, value=p.registrable_domain, role="host"))
    if f.open_redirect:
        dest = parse_url(f.open_redirect)
        if dest.valid and dest.scheme in ("http", "https"):
            out.append(Indicator(type=IndicatorType.URL, value=dest.url, role="redirect"))
            if dest.registrable_domain:
                out.append(
                    Indicator(
                        type=IndicatorType.DOMAIN, value=dest.registrable_domain, role="redirect"
                    )
                )
    return out


def _children(f: LexicalFeatures, parent: Artifact) -> list[Artifact]:
    """String-only child artifacts (open-redirect destinations).

    Shortener destinations require a network round-trip, so no child is produced for them
    here — the fetch analyzer resolves those downstream.
    """
    children: list[Artifact] = []
    if f.open_redirect:
        dest = parse_url(f.open_redirect)
        if dest.valid and dest.scheme in ("http", "https") and dest.host_ascii:
            try:
                children.append(
                    Artifact.from_url(f.open_redirect, origin="redirect", parent_id=parent.id)
                )
            except Exception:  # defensive: Artifact.from_url guards size / format
                log.debug("could not build redirect child for %r", f.open_redirect)
    return children


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #
@register
class UrlAnalyzer(Analyzer):
    """Stage-0 URL analyzer: lexical structure, Unicode spoofing and brand impersonation."""

    name = "url"
    kinds = frozenset({ArtifactKind.URL})
    stage = 0
    requires_online = False
    blocking = True
    description = (
        "URL structure, IDN/homoglyph spoofing and brand impersonation: emits "
        "explainable signals, IOCs, the impersonated brand, techniques and "
        "redirect-target child artifacts."
    )
    signals = _CATALOG

    def applies(self, artifact: Artifact, ctx: AnalysisContext) -> bool:
        return artifact.kind is ArtifactKind.URL and bool(artifact.url)

    def analyze_sync(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        url = artifact.url or ""
        p = parse_url(url)
        f = features(p)
        parts = split_host(p)

        try:
            cands = brand_candidates(p)
        except Exception:  # pragma: no cover - brand_candidates is total, defensive only
            log.exception("brand_candidates failed for %s", artifact.id)
            cands = []
        official = bool(cands and cands[0].official)

        signals: list[Signal] = []
        brand: BrandMatch | None = None
        try:
            brand_sigs, brand = _brand_signals(url, p, parts, cands)
            signals.extend(brand_sigs)
        except Exception:  # pragma: no cover - defensive
            log.exception("brand signal build failed for %s", artifact.id)

        try:
            signals.extend(_unicode_signals(url, p, f))
        except Exception:  # pragma: no cover - defensive
            log.exception("unicode signal build failed for %s", artifact.id)

        try:
            signals.extend(_structure_signals(url, p, f, official))
        except Exception:  # pragma: no cover - defensive
            log.exception("structure signal build failed for %s", artifact.id)

        indicators = _indicators(p, f)
        children = _children(f, artifact)

        try:
            tech = classify(p, lexical=f)
            techniques, primary = tech.techniques, tech.primary
        except Exception:  # pragma: no cover - classify is total, defensive only
            log.exception("technique classification failed for %s", artifact.id)
            techniques, primary = [], None

        meta = {
            "url": {
                "scheme": p.scheme,
                "host": p.host_unicode,
                "host_ascii": p.host_ascii,
                "registrable_domain": p.registrable_domain,
                "tld": f.tld,
                "is_ip": p.is_ip,
                "valid": p.valid,
                "primary_technique": primary,
            }
        }

        return AnalyzerResult(
            signals=signals,
            indicators=indicators,
            children=children,
            brand=brand,
            techniques=techniques,
            meta=meta,
        )
