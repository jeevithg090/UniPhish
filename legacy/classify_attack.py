"""Attack-technique classification — actionable threat intelligence.

A verdict of "phishing" is far more useful as "phishing via **homoglyph
impersonation of paypal**". This maps a URL to the specific construction technique(s)
(the taxonomy from the paper's Section II-A), so the output is triage-ready for an
analyst and educational for a user. Pure string analysis; no model needed.
"""

from __future__ import annotations

import re
from typing import Dict, List

from uniphish.brands import BRANDS, _host, brand_impersonation, normalize
from uniphish.reasons import _SHORTENERS, _SUSPICIOUS_TLDS

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

_DESCR = {
    "homoglyph": "Homoglyph attack — Unicode look-alike characters imitate a brand",
    "idn_punycode": "IDN homograph — punycode domain disguising Unicode look-alikes",
    "typosquat": "Typosquatting — a misspelling of a known brand",
    "combosquat": "Combosquatting — brand name combined with extra words",
    "subdomain_stuffing": "Subdomain stuffing — brand placed in a subdomain",
    "path_deception": "Path deception — brand/keywords in the path of another domain",
    "ip_host": "Raw IP host — no domain name",
    "url_shortener": "URL shortener — real destination hidden",
    "suspicious_tld": "Abused TLD commonly used for phishing",
}


def classify(url: str) -> Dict:
    """Return {techniques: [codes], primary, target_brand, descriptions}."""
    host = _host(url)
    labels = host.split(".")
    sld = labels[-2] if len(labels) >= 2 else host
    path = url.split(host, 1)[-1] if host in url else ""
    techniques: List[str] = []

    brand = brand_impersonation(url)
    target = brand["brand"] if brand else None

    if _IP_RE.match(host):
        techniques.append("ip_host")
    if host in _SHORTENERS:
        techniques.append("url_shortener")
    if "xn--" in host:
        techniques.append("idn_punycode")
    if brand:
        techniques.append({"homoglyph": "homoglyph", "typo": "typosquat",
                           "subdomain": "subdomain_stuffing"}[brand["type"]])
    # combosquat: a brand appears *inside* the SLD with extra chars (paypal-secure)
    if not brand:
        for b in BRANDS:
            nb = normalize(b)
            if len(nb) >= 4 and nb in normalize(sld) and normalize(sld) != nb:
                techniques.append("combosquat"); target = b
                break
    # path deception: brand in path but not the registrable domain
    if not target and path:
        for b in BRANDS:
            if normalize(b) in normalize(path) and normalize(b) != normalize(sld):
                techniques.append("path_deception"); target = b
                break
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in _SUSPICIOUS_TLDS:
        techniques.append("suspicious_tld")

    techniques = list(dict.fromkeys(techniques))   # dedup, keep order
    return {
        "techniques": techniques,
        "primary": techniques[0] if techniques else None,
        "target_brand": target,
        "descriptions": [_DESCR[t] for t in techniques if t in _DESCR],
    }
