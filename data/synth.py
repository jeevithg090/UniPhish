"""Multilingual phishing/benign URL synthesizer.

The real MultiPhishDB sources (Saudi NCA, CNCERT, CERT-In, KrCERT ...) are gated
and non-public. To keep the project fully reproducible, this module *synthesizes*
realistic URLs across the paper's six script families, implementing the exact
phishing construction strategies described in Section II-A:

  - SLD squatting (paypal -> paypa1)
  - subdomain stuffing (paypal.com.login-verify.xyz)
  - path-based deception (cdn-media.xyz/paypal/login/secure)
  - IDN homograph (Unicode confusables -> punycode xn--...)
  - percent-encoded non-ASCII path content

Synthetic data is clearly labeled (`source="synthetic"`) so it never masquerades
as real threat-intel. It is meant to (a) let the whole train/eval/compress/deploy
pipeline run end-to-end today, and (b) be blended with real public feeds
(see data/sources.py) when those are available.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Dict, List
from urllib.parse import quote

from uniphish.homoglyphs import HomoglyphMap

# --- Script-family content banks (real Unicode) -------------------------------
# Each family: (brands used for impersonation, content words for paths, TLDs).
FAMILIES: Dict[str, Dict[str, List[str]]] = {
    "latin_nonenglish": {  # Turkish / French / Spanish / Portuguese
        "brands": ["garanti", "bbva", "santander", "caixa", "ziraat", "isbank",
                    "laposte", "orange", "mercadolibre", "correios"],
        "words": ["giris", "guvenlik", "hesap", "connexion", "compte", "seguridad",
                   "acesso", "verificacao", "entrar", "cuenta", "sifre"],
        "tlds": [".com.tr", ".fr", ".es", ".pt", ".com.br", ".de"],
    },
    "arabic": {
        "brands": ["alrajhi", "alahli", "riyadbank", "stcpay", "emiratesnbd"],
        "words": ["دخول", "حساب", "تحقق", "مصرف", "أمان", "تسجيل", "بطاقة"],
        "tlds": [".sa", ".ae", ".com", ".qa"],
    },
    "cjk": {  # Chinese simplified
        "brands": ["alipay", "wechatpay", "icbc", "unionpay", "taobao"],
        "words": ["登录", "账户", "验证", "银行", "安全", "支付", "密码"],
        "tlds": [".cn", ".com.cn", ".com"],
    },
    "devanagari": {  # Hindi
        "brands": ["sbi", "hdfcbank", "icici", "paytm", "phonepe", "upi"],
        "words": ["लॉगिन", "खाता", "सत्यापन", "बैंक", "सुरक्षा", "भुगतान"],
        "tlds": [".in", ".co.in", ".com"],
    },
    "hangul": {  # Korean
        "brands": ["kbstar", "shinhan", "wooribank", "naverpay", "kakaopay"],
        "words": ["로그인", "계정", "인증", "은행", "보안", "결제", "비밀번호"],
        "tlds": [".kr", ".co.kr", ".com"],
    },
    "other": {  # Swahili / Indonesian / Tagalog / Bengali
        "brands": ["mpesa", "bri", "bca", "gcash", "bkash", "dana"],
        "words": ["akaunti", "masuk", "verifikasi", "keamanan", "pembayaran",
                   "লগইন", "অ্যাকাউন্ট", "sandi"],
        "tlds": [".co.tz", ".id", ".ph", ".com.bd", ".com"],
    },
}

_SUFFIX_TLDS = [".xyz", ".top", ".online", ".click", ".info", ".live", ".site"]
_SUB_STUFF = ["login", "secure", "verify", "account", "update", "signin", "auth"]
_ASCII_SUB = str.maketrans({"a": "4", "o": "0", "l": "1", "e": "3", "i": "1", "s": "5"})

# Large generic word bank so synthesized *benign* domains are highly unique and do
# not collapse under dedup + per-domain capping (which previously skewed the set
# heavily toward phishing). ~60 words -> thousands of unique second-level domains.
_BENIGN_WORDS = [
    "media", "cloud", "data", "group", "tech", "systems", "digital", "global",
    "network", "solutions", "services", "market", "shop", "store", "news", "daily",
    "central", "prime", "smart", "next", "vision", "logic", "core", "spark", "nova",
    "atlas", "delta", "orbit", "pixel", "vertex", "quantum", "fusion", "matrix",
    "beacon", "harbor", "summit", "ridge", "valley", "river", "forest", "garden",
    "studio", "labs", "works", "hub", "point", "zone", "space", "world", "life",
    "health", "learn", "edu", "connect", "flow", "wave", "bright", "clear", "true",
]


@dataclass
class SynthConfig:
    per_family: int = 2000          # total URLs per family (~half phishing)
    phish_ratio: float = 0.5
    seed: int = 42


def _rand_token(rng: random.Random, n: int = 6) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def _benign_url(rng: random.Random, fam: str) -> str:
    b = FAMILIES[fam]
    tld = rng.choice(b["tlds"])
    # 70% synthesized unique domain (two words from the bank), 30% a known brand.
    if rng.random() < 0.7:
        sld = rng.choice(_BENIGN_WORDS)
        if rng.random() < 0.6:
            sld += rng.choice(_BENIGN_WORDS)
        if rng.random() < 0.2:
            sld += str(rng.randint(1, 999))
        host = sld + tld
    else:
        host = rng.choice(b["brands"]) + tld
    if rng.random() < 0.5:
        host = "www." + host
    scheme = "https://" if rng.random() < 0.85 else "http://"
    # path: sometimes native-script content, sometimes an ascii word, sometimes none
    if rng.random() < 0.55:
        seg = rng.choice(b["words"])
        seg = quote(seg) if rng.random() < 0.5 else rng.choice(_BENIGN_WORDS)
        return f"{scheme}{host}/{seg}"
    return f"{scheme}{host}/"


def _sld_squat(rng: random.Random, brand: str, tld: str) -> str:
    squat = brand.translate(_ASCII_SUB)
    if squat == brand:  # ensure it changed
        squat = brand + rng.choice(["-secure", "-login", str(rng.randint(1, 99))])
    return f"https://{squat}{rng.choice(_SUFFIX_TLDS)}/{rng.choice(_SUB_STUFF)}"


def _subdomain_stuffing(rng: random.Random, brand: str, tld: str) -> str:
    evil = _rand_token(rng, rng.randint(6, 10))
    return f"https://{brand}{tld}.{rng.choice(_SUB_STUFF)}-{evil}{rng.choice(_SUFFIX_TLDS)}/"


def _path_deception(rng: random.Random, brand: str, word: str) -> str:
    cdn = f"{_rand_token(rng)}-{rng.choice(['cdn','media','app','static'])}"
    return f"https://{cdn}{rng.choice(_SUFFIX_TLDS)}/{brand}/{rng.choice(_SUB_STUFF)}/{quote(word)}"


def _homoglyph_domain(rng: random.Random, homo: HomoglyphMap, brand: str, tld: str) -> str:
    spoofed = homo.substitute(brand, rate=0.4, rng=rng)
    if spoofed == brand:
        spoofed = brand[:-1] + homo.substitute(brand[-1], rate=1.0, rng=rng)
    return f"https://{spoofed}{tld if tld.count('.')==1 else '.com'}/{rng.choice(_SUB_STUFF)}"


def _idn_punycode(rng: random.Random, homo: HomoglyphMap, brand: str) -> str:
    spoofed = homo.substitute(brand, rate=0.5, rng=rng)
    try:
        import idna
        label = idna.encode(spoofed, uts46=True).decode("ascii")
    except Exception:
        try:
            label = spoofed.encode("idna").decode("ascii")
        except Exception:
            label = "xn--" + _rand_token(rng)
    return f"https://{label}.com/{rng.choice(_SUB_STUFF)}"


def _phish_url(rng: random.Random, homo: HomoglyphMap, fam: str) -> tuple[str, str]:
    b = FAMILIES[fam]
    brand = rng.choice(b["brands"])
    tld = rng.choice(b["tlds"])
    word = rng.choice(b["words"])
    technique = rng.choice(
        ["sld_squat", "subdomain_stuffing", "path_deception", "homoglyph", "idn_punycode"]
    )
    if technique == "sld_squat":
        return _sld_squat(rng, brand, tld), technique
    if technique == "subdomain_stuffing":
        return _subdomain_stuffing(rng, brand, tld), technique
    if technique == "path_deception":
        return _path_deception(rng, brand, word), technique
    if technique == "homoglyph":
        return _homoglyph_domain(rng, homo, brand, tld), technique
    return _idn_punycode(rng, homo, brand), technique


def synthesize(cfg: SynthConfig | None = None):
    """Return a list of dict rows: url, label, script_family, technique, source."""
    cfg = cfg or SynthConfig()
    rng = random.Random(cfg.seed)
    homo = HomoglyphMap.builtin()
    rows: List[dict] = []
    for fam in FAMILIES:
        n_phish = int(cfg.per_family * cfg.phish_ratio)
        n_benign = cfg.per_family - n_phish
        for _ in range(n_phish):
            url, tech = _phish_url(rng, homo, fam)
            rows.append({"url": url, "label": 1, "script_family": fam,
                          "technique": tech, "source": "synthetic"})
        for _ in range(n_benign):
            rows.append({"url": _benign_url(rng, fam), "label": 0, "script_family": fam,
                          "technique": "benign", "source": "synthetic"})
    rng.shuffle(rows)
    return rows


if __name__ == "__main__":
    sample = synthesize(SynthConfig(per_family=6))
    for r in sample[:12]:
        print(f"[{r['label']}] {r['script_family']:16s} {r['technique']:18s} {r['url']}")
