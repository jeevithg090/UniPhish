"""Explainable lexical / structural URL features.

The classic phishing-URL feature set (length, dots, hyphens, ``@``, IP hosts, TLD risk ...)
extended with 2025-era tells: punycode and confusable hosts, living-off-trusted-sites
hosting, open-redirect wrappers, double encoding, ``data:``/``javascript:`` URLs and
random-looking labels.  Each feature is a plain measurement a human can verify; the URL
analyzer turns them into weighted, attributable signals.  Nothing here decides "phishing".

:func:`features` is pure, deterministic, offline and never raises on hostile input: every
text scanned is length-bounded and no unbounded regex is applied to attacker data.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qsl, unquote

from uniphish.assets.lists import (
    LotsEntry,
    find_lures,
    is_dyndns,
    is_shortener,
    lots_match,
    open_redirect_match,
    tld_risk,
)
from uniphish.url import scripts
from uniphish.url.brandkb import normalize_host
from uniphish.url.brands import _kb, scan_brand_ids, split_host
from uniphish.url.confusables import confusable_chars_in
from uniphish.url.idn_policy import assess_host
from uniphish.url.parse import SPECIAL_SCHEMES, ParsedURL, parse_url

__all__ = ["LexicalFeatures", "features"]

MANY_SUBDOMAINS = 4  # sub-domain labels at or above which ``many_subdomains`` is set
DEEP_PATH = 6  # path segments at or above which ``deep_path`` is set
_MAX_SCAN = 4096
_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_PCT2_RE = re.compile(r"%25[0-9A-Fa-f]{2}")
_VOWELS = frozenset("aeiouy")
_DIGITS = frozenset("0123456789")
_HEX = frozenset("0123456789abcdef")
_DANGEROUS_EXT = frozenset(
    {
        ".exe",
        ".scr",
        ".zip",
        ".apk",
        ".hta",
        ".js",
        ".msi",
        ".bat",
        ".cmd",
        ".vbs",
        ".jar",
        ".iso",
        ".img",
        ".lnk",
        ".ps1",
        ".dll",
        ".rar",
        ".7z",
        ".dmg",
        ".pkg",
        ".docm",
        ".xlsm",
        ".wsf",
        ".cab",
        ".com",
        ".pif",
    }
)
_DOC_EXT = frozenset(
    {
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".jpg",
        ".jpeg",
        ".png",
        ".txt",
        ".ppt",
        ".pptx",
        ".html",
        ".htm",
    }
)
_REDIRECT_PARAMS = frozenset(
    {
        "url",
        "redirect",
        "redirect_url",
        "redirect_uri",
        "redir",
        "next",
        "goto",
        "return",
        "returnurl",
        "return_to",
        "dest",
        "destination",
        "continue",
        "target",
        "link",
        "u",
        "r",
        "forward",
        "out",
        "to",
    }
)
_NO_HOST_SCHEMES = frozenset({"data", "javascript", "vbscript", "blob"})


@dataclass(frozen=True, slots=True)
class LexicalFeatures:
    """Structural measures of one URL. Tuples hold ids/terms (empty = none found)."""

    # sizes
    url_len: int = 0
    host_len: int = 0
    path_len: int = 0
    query_len: int = 0
    # host shape
    num_dots: int = 0
    num_hyphens: int = 0
    num_subdomains: int = 0  # labels left of the registrable domain
    num_digits_in_host: int = 0
    digit_ratio_host: float = 0.0  # digits / non-dot host characters
    many_subdomains: bool = False
    raw_entropy: float = 0.0  # Shannon entropy (bits/char) of the ASCII host
    # authority tricks
    has_at: bool = False  # user-info present (``user@host``)
    has_atsign_redirect: bool = False  # user-info itself looks like a domain/URL
    has_port: bool = False
    non_std_port: bool = False
    is_ip: bool = False
    ip_obfuscated: bool = False
    # IDN / Unicode
    punycode: bool = False
    mixed_script_host: bool = False
    confusable_host: bool = False
    confusable_char_count: int = 0
    idn_spoof_reasons: tuple[str, ...] = ()
    # TLD / hosting infrastructure
    tld: str = ""
    tld_risk: float | None = None
    is_shortener: bool = False
    is_dyndns: bool = False
    lots: LotsEntry | None = None
    open_redirect: str | None = None  # recovered destination URL
    open_redirect_via: str | None = None  # "known:<name>" | "param:<name>"
    # lure vocabulary and brand keywords (brand ids other than the host's owner)
    sensitive_words_in_host: tuple[str, ...] = ()
    sensitive_words_in_path: tuple[str, ...] = ()
    sensitive_weight_host: float = 0.0
    sensitive_weight_path: float = 0.0
    brand_keyword_in_subdomain: tuple[str, ...] = ()
    brand_keyword_in_sld: tuple[str, ...] = ()
    brand_keyword_in_path: tuple[str, ...] = ()
    # path / encoding
    deep_path: bool = False
    path_depth: int = 0
    encoded_chars: int = 0
    double_encoding: bool = False
    data_or_js_scheme: bool = False
    suspicious_file_ext_in_path: str | None = None
    double_extension: bool = False
    # label randomness
    vowelless_label: bool = False
    random_looking_label: bool = False
    random_label_score: float = 0.0
    notes: tuple[str, ...] = field(default=())

    def to_dict(self) -> dict:
        """JSON-friendly dict (``lots`` becomes a plain mapping)."""
        d = asdict(self)
        d["lots"] = (
            None
            if self.lots is None
            else {"match": self.lots.match, "kind": self.lots.kind, "name": self.lots.name}
        )
        return d


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _longest_run(label: str, pred: frozenset[str], *, invert: bool) -> int:
    best = run = 0
    for ch in label:
        if ch.isalpha() and ((ch in pred) != invert):
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def _label_randomness(label: str) -> tuple[bool, float]:
    """``(vowelless, score 0-1)`` for one ASCII label; weak, dictionary-free heuristics."""
    lab = label.lower()
    letters = [c for c in lab if c.isalpha()]
    if not lab.isascii() or len(lab) < 6 or lab.startswith("xn--"):
        return False, 0.0
    vowels = sum(1 for c in letters if c in _VOWELS)
    vowelless = len(letters) >= 7 and vowels / len(letters) <= 0.1
    score = 0.0
    if vowelless:
        score = max(score, 0.7)
    cons_run = _longest_run(lab, _VOWELS, invert=True)
    if cons_run >= 6:
        score = max(score, 0.6 + 0.05 * min(cons_run - 6, 4))
    flips = sum(
        1
        for a, b in zip(lab, lab[1:], strict=False)
        if (a in _DIGITS) != (b in _DIGITS) and a != "-" and b != "-"
    )
    if flips >= 4 and len(lab) >= 8:
        score = max(score, 0.65 + 0.05 * min(flips - 4, 4))
    if len(lab) >= 12 and all(c in _HEX for c in lab) and any(c in _DIGITS for c in lab):
        score = max(score, 0.75)
    if len(lab) >= 12 and _entropy(lab) >= 3.6:
        score = max(score, 0.6)
    return vowelless, round(min(score, 1.0), 2)


def _lure_terms(text: str) -> tuple[tuple[str, ...], float]:
    hits = find_lures(text[:_MAX_SCAN], max_chars=_MAX_SCAN, max_hits=64)
    seen: dict[str, float] = {}
    for h in hits:
        seen.setdefault(h.term, h.weight)
    return tuple(seen), round(sum(seen.values()), 2)


def _redirect(p: ParsedURL) -> tuple[str | None, str | None]:
    known = open_redirect_match(p.host_ascii, p.path, p.query)
    if known is not None:
        if known.destination:
            return known.destination, f"known:{known.name}"
        return None, f"known:{known.name}"
    if not p.query:
        return None, None
    try:
        pairs = parse_qsl(p.query[:_MAX_SCAN], max_num_fields=64)
    except ValueError:
        return None, None
    for key, value in pairs:
        if key.lower() not in _REDIRECT_PARAMS or not value[:8].lower().startswith(
            ("http://", "https://", "//")
        ):
            continue
        dest = parse_url(value if "://" in value else "https:" + value)
        if dest.valid and dest.host_ascii and dest.registrable_domain != p.registrable_domain:
            return value[:2048], f"param:{key.lower()}"
    return None, None


def _file_ext(path: str) -> tuple[str | None, bool]:
    seg = unquote(path[:_MAX_SCAN]).rstrip("/").rsplit("/", 1)[-1].lower().strip()
    if "." not in seg:
        return None, False
    parts = seg.split(".")
    ext = "." + parts[-1]
    double = len(parts) >= 3 and ("." + parts[-2]) in _DOC_EXT and ext in _DANGEROUS_EXT
    return (ext if ext in _DANGEROUS_EXT else None), double


def features(parsed: ParsedURL | str) -> LexicalFeatures:
    """Compute :class:`LexicalFeatures` for a URL (string or already-parsed)."""
    p = parsed if isinstance(parsed, ParsedURL) else parse_url(parsed)
    host = p.host_ascii
    parts = split_host(p)
    no_host = not host
    path = p.path[:_MAX_SCAN] if p.scheme not in _NO_HOST_SCHEMES else ""
    notes: list[str] = []

    # ---- sizes / shape
    host_chars = host.replace(".", "")
    digits = sum(1 for c in host_chars if c.isdigit())
    n_sub = len(parts.sub)
    tail = f"{p.path}?{p.query}#{p.fragment}"[:_MAX_SCAN]

    # ---- authority
    user = p.userinfo
    at_redirect = p.has_userinfo and (
        "." in user or "://" in user or "/" in user or user.lower().startswith(("http", "www"))
    )
    std_ports = {80, 443, SPECIAL_SCHEMES.get(p.scheme, 0)}
    non_std = p.port is not None and p.port not in std_ports

    # ---- unicode
    conf: list[tuple[int, str, str]] = []
    mixed = False
    reasons: tuple[str, ...] = ()
    if not no_host and not p.is_ip and not p.host_unicode.isascii():
        conf = confusable_chars_in(p.host_unicode)
        mixed = any(
            not lab.isascii() and scripts.is_mixed_script(lab) for lab in p.host_unicode.split(".")
        )
        try:
            reasons = assess_host(p.host_unicode, tld=p.host_unicode.rsplit(".", 1)[-1]).reasons
        except Exception:
            notes.append("idn_policy_failed")

    # ---- infrastructure lists
    tld = "" if (p.is_ip or no_host) else host.rsplit(".", 1)[-1]
    lots = None if (no_host or p.is_ip) else lots_match(host, p.path)
    shortener = (not p.is_ip) and is_shortener(host)
    dyndns = (not p.is_ip) and is_dyndns(host)
    dest, via = (None, None) if no_host or p.is_ip else _redirect(p)

    # ---- lures
    host_text = ".".join([*parts.sub, parts.sld]) if parts.sld else ""
    w_host, wt_host = _lure_terms(host_text) if host_text else ((), 0.0)
    w_path, wt_path = _lure_terms(unquote(path)) if path else ((), 0.0)

    # ---- brand keywords, excluding whichever brand officially owns the host
    owner = None
    if not no_host and not p.is_ip:
        kb = _kb()
        b = kb.official_brand_for_host(normalize_host(host) or host)
        owner = b.id if b is not None else None
    excl = {owner} if owner else set()
    b_sub = scan_brand_ids(" ".join(parts.sub), exclude=excl) if parts.sub else ()
    b_sld = scan_brand_ids(parts.sld, exclude=excl) if parts.sld else ()
    b_path = scan_brand_ids(unquote(path[:2048]), concat=False, exclude=excl) if path else ()

    # ---- path / encoding
    segs = [s for s in p.path.split("/") if s]
    ext, double_ext = _file_ext(p.path) if p.scheme not in _NO_HOST_SCHEMES else (None, False)

    # ---- label randomness over every non-suffix label
    vowelless, rscore = False, 0.0
    for lab in [*parts.sub, parts.sld]:
        v, s = _label_randomness(lab)
        vowelless = vowelless or v
        rscore = max(rscore, s)

    return LexicalFeatures(
        url_len=len(p.raw.strip()),
        host_len=len(host),
        path_len=len(p.path),
        query_len=len(p.query),
        num_dots=host.count("."),
        num_hyphens=host.count("-"),
        num_subdomains=n_sub,
        num_digits_in_host=digits,
        digit_ratio_host=round(digits / len(host_chars), 3) if host_chars else 0.0,
        many_subdomains=n_sub >= MANY_SUBDOMAINS,
        raw_entropy=round(_entropy(host if host.isascii() else ""), 3),
        has_at=p.has_userinfo,
        has_atsign_redirect=at_redirect,
        has_port=p.port is not None,
        non_std_port=non_std,
        is_ip=p.is_ip,
        ip_obfuscated=p.ip_obfuscated,
        punycode=any(lab.startswith("xn--") for lab in host.split(".")),
        mixed_script_host=mixed,
        confusable_host=bool(conf),
        confusable_char_count=len(conf),
        idn_spoof_reasons=reasons,
        tld=tld,
        tld_risk=tld_risk(tld) if tld else None,
        is_shortener=shortener,
        is_dyndns=dyndns,
        lots=lots,
        open_redirect=dest,
        open_redirect_via=via,
        sensitive_words_in_host=w_host,
        sensitive_words_in_path=w_path,
        sensitive_weight_host=wt_host,
        sensitive_weight_path=wt_path,
        brand_keyword_in_subdomain=b_sub,
        brand_keyword_in_sld=b_sld,
        brand_keyword_in_path=b_path,
        deep_path=len(segs) >= DEEP_PATH,
        path_depth=len(segs),
        encoded_chars=len(_PCT_RE.findall(tail)),
        double_encoding=bool(_PCT2_RE.search(tail)),
        data_or_js_scheme=p.scheme in _NO_HOST_SCHEMES,
        suspicious_file_ext_in_path=ext,
        double_extension=double_ext,
        vowelless_label=vowelless,
        random_looking_label=rscore >= 0.6,
        random_label_score=rscore,
        notes=tuple(notes),
    )
