"""Hybrid enrichment: signals the URL string alone can't show + a fused risk score.

Real phishing detectors are ensembles, not one model. This module adds:
  - IDN / punycode decoding (expose the Unicode a lookalike is hiding)
  - redirect-chain resolution behind shorteners (with SSRF guards)
  - domain age via RDAP (freshly registered domains are a top phishing signal)
  - a transparent *fused* risk score that combines the ML probability with the
    structural reasons — so a homoglyph the model misses is still caught by rules
    (defense in depth), and an overconfident model is tempered by evidence.

Network calls (redirects, RDAP) are best-effort and degrade gracefully offline.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Dict, List, Optional

from uniphish.brands import _host
from uniphish.reasons import analyze

# How much each reason code contributes to the rule-based signal (0-100 space).
# Brand impersonation + homoglyphs are near-decisive on their own.
_WEIGHTS = {
    "brand_impersonation": 60, "homoglyph_char": 40, "at_symbol": 45,
    "ip_host": 40, "punycode": 35, "suspicious_tld": 20, "shortener": 15,
    "deep_subdomain": 15, "many_hyphens": 10, "long_url": 5,
}


# --------------------------------------------------------------------------- #
# IDN / punycode
# --------------------------------------------------------------------------- #
def decode_idn(url: str) -> Dict:
    """Decode punycode labels to Unicode so the hidden lookalike is visible."""
    host = _host(url)
    if "xn--" not in host:
        return {"punycode": False, "decoded_host": host}
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                out.append(label.encode("ascii").decode("idna"))
            except Exception:
                out.append(label)
        else:
            out.append(label)
    return {"punycode": True, "decoded_host": ".".join(out)}


# --------------------------------------------------------------------------- #
# SSRF-safe redirect resolution
# --------------------------------------------------------------------------- #
def _is_public_host(host: str) -> bool:
    """False for private/loopback/link-local/reserved targets — SSRF protection."""
    try:
        try:
            addrs = [ipaddress.ip_address(host)]           # IP literal
        except ValueError:
            addrs = [ipaddress.ip_address(ai[4][0]) for ai in socket.getaddrinfo(host, None)]
    except Exception:
        return False
    return all(not (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast or ip.is_unspecified)
               for ip in addrs)


def resolve_redirects(url: str, max_hops: int = 5, timeout: int = 5) -> Dict:
    """Follow shortener/redirect chains to the final destination, safely.

    Every hop's host is SSRF-checked before the request. Returns the chain and the
    final URL (or the last safe URL). Best-effort; never raises.
    """
    chain: List[str] = [url]
    current = url
    try:
        import requests
        for _ in range(max_hops):
            host = _host(current)
            if not host or not _is_public_host(host):
                break
            r = requests.head(current, allow_redirects=False, timeout=timeout,
                              headers={"User-Agent": "UniPhish/0.1"})
            loc = r.headers.get("Location")
            if not loc or r.status_code not in (301, 302, 303, 307, 308):
                break
            current = requests.compat.urljoin(current, loc)
            chain.append(current)
    except Exception:
        pass
    return {"final_url": chain[-1], "chain": chain, "hops": len(chain) - 1}


# --------------------------------------------------------------------------- #
# Domain age (RDAP)
# --------------------------------------------------------------------------- #
def domain_age_days(host: str, timeout: int = 6) -> Optional[int]:
    """Days since domain registration via free RDAP, or None if unavailable."""
    try:
        import datetime as dt
        import requests
        reg = _host("https://" + host).split(".")
        domain = ".".join(reg[-2:]) if len(reg) >= 2 else host
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=timeout)
        r.raise_for_status()
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                d = dt.datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return (dt.datetime.now(dt.timezone.utc) - d).days
    except Exception:
        return None
    return None


# --------------------------------------------------------------------------- #
# Fused risk score
# --------------------------------------------------------------------------- #
def fused_risk(model_prob: float, url: str, young_domain_days: Optional[int] = None) -> Dict:
    """Combine ML probability with structural signals into a 0-100 risk.

    Fusion is an OR of evidence: high if the model is confident *or* the rules find
    strong signals. Transparent — returns both components and the contributing reasons.
    """
    a = analyze(url)
    signal = min(100, sum(_WEIGHTS.get(r["code"], 5) for r in a["reasons"]))
    if young_domain_days is not None and young_domain_days <= 30:
        signal = min(100, signal + 25)
    model = round(100 * float(model_prob))
    risk = round(min(100, max(model, signal)))
    tier = "block" if risk >= 75 else "warn" if risk >= 40 else "safe"
    return {"risk": risk, "tier": tier, "model_score": model, "signal_score": signal,
            "brand": a["brand"], "reasons": a["reasons"],
            "domain_age_days": young_domain_days}
