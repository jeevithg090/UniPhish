"""Human-readable reasons for a phishing verdict.

Converts URL structure + brand analysis into plain-language explanations a user or
analyst can act on. Pure string analysis (no TensorFlow); pairs with the model score
and the byte-saliency map to answer "*why* is this flagged?".
"""

from __future__ import annotations

import re
from typing import Dict, List

from uniphish.brands import _REVERSE, _host, brand_impersonation

_SUSPICIOUS_TLDS = {"top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "link",
                    "live", "online", "site", "click", "rest", "zip", "mov", "work"}
_SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
               "cutt.ly", "rebrand.ly", "t.me", "shorturl.at"}
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _tld(host: str) -> str:
    return host.rsplit(".", 1)[-1].lower() if "." in host else ""


def analyze(url: str) -> Dict:
    """Return {reasons: [{code, text, severity}], brand: {...}|None}."""
    host = _host(url)
    reasons: List[Dict] = []

    def add(code, text, severity="medium"):
        reasons.append({"code": code, "text": text, "severity": severity})

    # brand impersonation (most important)
    brand = brand_impersonation(url)
    if brand:
        verb = {"homoglyph": "disguises itself as",
                "typo": "is a lookalike misspelling of",
                "subdomain": "hides the real domain behind"}[brand["type"]]
        add("brand_impersonation",
            f"Domain {verb} “{brand['brand']}” ({brand['evidence']}).", "high")

    # homoglyph characters in the host
    for ch in host:
        if ord(ch) > 127 and ch in _REVERSE:
            add("homoglyph_char",
                f"Uses the character “{ch}”, which looks like “{_REVERSE[ch]}” "
                f"but is a different Unicode letter.", "high")
            break

    # raw IP host
    if _IP_RE.match(host):
        add("ip_host", "Uses a raw IP address instead of a domain name.", "high")

    # punycode / IDN
    if "xn--" in host:
        add("punycode", "Internationalized (punycode) domain — often used to build "
                        "visually identical lookalikes.", "high")

    # '@' trick (everything before '@' is ignored by the browser)
    if "@" in url.split("://", 1)[-1].split("/", 1)[0] or "@" in url.split("?", 1)[0]:
        add("at_symbol", "Contains “@”, which can hide the true destination.", "high")

    # suspicious TLD
    if _tld(host) in _SUSPICIOUS_TLDS:
        add("suspicious_tld", f"Uses the “.{_tld(host)}” top-level domain, "
                             f"which is disproportionately used for phishing.", "medium")

    # URL shortener
    if host in _SHORTENERS:
        add("shortener", "Shortened link — the real destination is hidden until you click.",
            "medium")

    # deep subdomain nesting
    depth = max(host.count(".") - 1, 0)
    if depth >= 3:
        add("deep_subdomain", f"Unusually deep subdomain structure ({depth} levels).", "medium")

    # excessive hyphens
    if host.count("-") >= 3:
        add("many_hyphens", "Many hyphens in the domain — common in fake login pages.", "low")

    # very long URL
    if len(url) > 90:
        add("long_url", "Unusually long URL.", "low")

    return {"reasons": reasons, "brand": brand}
