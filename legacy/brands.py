"""Brand-impersonation identification (Unicode TR39 "skeleton" + typo distance).

Given a suspect URL, name the legitimate brand it is most likely mimicking and how
(homoglyph, leetspeak/typo, or subdomain stuffing). This is the single most
*actionable* signal a phishing tool can produce: not just "dangerous", but
"this pretends to be **paypal**".

No TensorFlow required — pure string analysis, reusing the confusables map.
"""

from __future__ import annotations

from typing import Optional

from uniphish.homoglyphs import HomoglyphMap

# Reverse the confusables map: confusable char -> the ASCII letter it imitates.
_REVERSE = {}
for _ascii, _confs in HomoglyphMap.builtin().mapping.items():
    for _c in _confs:
        _REVERSE.setdefault(_c, _ascii)

# Leetspeak / digit-for-letter substitutions common in domain squatting.
_LEET = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"}

# Commonly impersonated brands (lowercase, ASCII skeletons).
BRANDS = [
    "paypal", "apple", "icloud", "google", "gmail", "youtube", "amazon", "aws",
    "microsoft", "outlook", "office365", "windows", "facebook", "instagram",
    "whatsapp", "messenger", "netflix", "spotify", "linkedin", "twitter", "ebay",
    "coinbase", "binance", "metamask", "kraken", "wellsfargo", "chase",
    "bankofamerica", "citibank", "hsbc", "barclays", "santander", "revolut",
    "sbi", "hdfc", "icici", "axisbank", "paytm", "phonepe", "upi", "alibaba",
    "aliexpress", "taobao", "wechat", "alipay", "unionpay", "kakao", "kakaopay",
    "naver", "dhl", "fedex", "ups", "usps", "steam", "roblox", "discord",
    "telegram", "yahoo", "dropbox", "adobe", "docusign",
]
_TWO_LEVEL = {"com.tr", "com.br", "co.in", "com.cn", "co.kr", "com.bd", "co.tz",
              "com.qa", "co.uk", "com.au", "co.jp"}


def normalize(s: str) -> str:
    """Confusable + leetspeak skeleton: fold homoglyphs and digit-letters to ASCII."""
    out = []
    for ch in s.lower():
        ch = _REVERSE.get(ch, ch)      # Cyrillic 'а' -> 'a', Greek 'ο' -> 'o', ...
        ch = _LEET.get(ch, ch)         # '1' -> 'l', '0' -> 'o', ...
        out.append(ch)
    return "".join(out)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _host(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].split(":", 1)[0]


def _registrable(host: str):
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL:
        return labels[-3], labels        # (sld, all-labels)
    return (labels[-2] if len(labels) >= 2 else host), labels


def brand_impersonation(url: str) -> Optional[dict]:
    """Return {brand, type, confidence, evidence} or None.

    type ∈ {"homoglyph", "typo", "subdomain"}.
    """
    host = _host(url)
    if not host:
        return None
    sld, labels = _registrable(host)
    nsld = normalize(sld)
    has_nonascii = any(ord(c) > 127 for c in sld)

    for brand in BRANDS:
        nb = normalize(brand)
        if nsld == nb:
            if sld == brand:
                return None  # it *is* the real brand's registrable domain — legit
            return {"brand": brand,
                    "type": "homoglyph" if has_nonascii else "typo",
                    "confidence": 0.9,
                    "evidence": f"'{sld}' folds to '{brand}'"}
    # near-miss typo (edit distance 1 on the skeleton)
    for brand in BRANDS:
        nb = normalize(brand)
        if len(nb) >= 5 and sld != brand and _levenshtein(nsld, nb) == 1:
            return {"brand": brand, "type": "typo", "confidence": 0.7,
                    "evidence": f"'{sld}' is one edit from '{brand}'"}
    # subdomain stuffing: a brand appears as a non-registrable label
    for lbl in labels[:-2]:
        nl = normalize(lbl)
        for brand in BRANDS:
            if nl == normalize(brand) and normalize(sld) != normalize(brand):
                return {"brand": brand, "type": "subdomain", "confidence": 0.85,
                        "evidence": f"'{brand}' is in a subdomain; real domain is '{sld}'"}
    return None
