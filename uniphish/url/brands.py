"""Brand impersonation detection for URLs.

Answers the most actionable question a phishing detector can answer: *which brand does
this URL pretend to be, and by what trick?*  The brand knowledge base
(:mod:`uniphish.url.brandkb`) supplies the ground truth (official / login / CDN /
user-content hosts, keywords, native-script names); the UTS #39 skeletons in
:mod:`uniphish.url.confusables` supply the look-alike folding.

Techniques (``BrandMatch.technique``)
-------------------------------------
``homoglyph``  non-ASCII label whose confusable skeleton equals a brand name.
``idn``        non-ASCII label that *contains* / nearly equals a brand (or uses its native
               script name) on an unrelated domain.
``bitsquat``   one bit flipped in an official domain's label, same suffix.
``typosquat``  edit distance 1-2 (length aware), leet/visual fold (``paypa1``), hyphen
               split (``pay-pal``) or the bare brand name on an unrelated suffix.
``combosquat`` brand plus extra tokens in the registrable label (``paypal-secure``).
``subdomain``  brand as a non-registrable label (``paypal.com.evil.test``) or as a tenant
               label on a shared platform (``paypal.pages.dev``).
``path``       brand keyword in the path of an unrelated domain.
``official``   the URL *is* an official / login / CDN host (never impersonation).

Confidence
----------
Confidences are hand-set priors per evidence type (documented in the code), **not** a
fitted probability: exact skeleton equality 0.97, visual/leet fold 0.90, subdomain
with the brand's real domain spelled out 0.95, edit distance 1 0.80, distance 2 0.65,
combosquat 0.55-0.88 depending on the extra tokens, bare-name TLD swap 0.45, path 0.35-0.75.
Ambiguous brands (``ups``, ``line`` ...) and very short keywords (<=4 chars) need a
credential/security context word and are capped lower.  Analyzers should scale signal
weight by ``confidence``.

Guards against false positives: official/login/CDN hosts and a brand's own user-content
hosts are never flagged for that brand; popular sites (Tranco top 20k) that are not
shared hosting are exempt from the fuzzy techniques (``applebees.com``).
"""

from __future__ import annotations

import logging
import re
import unicodedata
from collections.abc import Collection
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import unquote

from uniphish.assets import load_yaml
from uniphish.assets.lists import find_lures, lots_match, tld_risk, top_rank
from uniphish.core.types import BrandMatch
from uniphish.url import brandkb as _brandkb
from uniphish.url.brandkb import Brand, BrandKB, BrandKBError
from uniphish.url.confusables import brand_skeleton
from uniphish.url.parse import ParsedURL, parse_url

log = logging.getLogger("uniphish.url")

__all__ = [
    "HostParts",
    "brand_candidates",
    "brand_impersonation",
    "scan_brand_ids",
    "split_host",
]

_POPULAR_RANK = 20_000
_MAX_TOKENS = 64
_MAX_LABEL = 63
_MAX_PATH = 2048
_TOK_RE = re.compile(r"[a-z0-9]+")
_NONALNUM_RE = re.compile(r"[^a-z0-9]")
_CONTEXT_WORDS: frozenset[str] = frozenset(getattr(_brandkb, "_CONTEXT_WORDS", ())) | frozenset(
    {"login", "logon", "signin", "secure", "verify", "account", "support", "update", "wallet"}
)
_TECH_PRIORITY = {
    "homoglyph": 0,
    "idn": 1,
    "bitsquat": 2,
    "typosquat": 3,
    "subdomain": 4,
    "combosquat": 5,
    "path": 6,
}


# --------------------------------------------------------------------------- #
# Knowledge base (fail soft if the data file is inconsistent)
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def _kb() -> BrandKB:
    """The brand KB; if ``brands.yaml`` fails validation, build one from the sane subset.

    A data-file inconsistency (a domain claimed official by two brands) must degrade
    detection slightly, not disable it, so the offending duplicates are dropped here
    (and logged) rather than raising into the analyzer pipeline.
    """
    try:
        return _brandkb.get_kb()
    except BrandKBError as exc:
        log.warning("brands.yaml failed validation (%s); using de-duplicated subset", exc)
    try:
        data = load_yaml("brands.yaml")
        raw = data.get("brands") if isinstance(data, dict) else data
        seen: set[str] = set()
        cleaned: list[dict] = []
        for item in raw or []:
            if not isinstance(item, dict):
                continue
            item = dict(item)
            official = []
            for d in item.get("official_domains") or []:
                if d not in seen:
                    seen.add(d)
                    official.append(d)
            item["official_domains"] = official
            item["login_hosts"] = [
                h
                for h in item.get("login_hosts") or []
                if any(h == d or h.endswith("." + d) for d in official)
            ]
            ucs = item.get("user_content_domains") or []
            item["user_content_domains"] = [d for d in ucs if d not in official]
            cleaned.append(item)
        return BrandKB(cleaned)
    except Exception as exc:
        log.error("brand KB unavailable (%s); brand detection disabled", exc)
        return BrandKB([])


# --------------------------------------------------------------------------- #
# Term index
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class _Term:
    brand: Brand
    text: str  # lowercase ASCII alnum, e.g. "paypal"
    skel: str  # brand_skeleton(text)
    kw: bool  # from a keyword/alias (else only from an official domain)
    suffixes: frozenset[str]  # public suffixes of official domains with this label


@dataclass(frozen=True)
class _Index:
    exact: dict[str, tuple[_Term, ...]]
    exact_skel: dict[str, tuple[_Term, ...]]
    affix: tuple[_Term, ...]
    by_skel: dict[str, tuple[_Term, ...]]
    by_len: dict[int, tuple[_Term, ...]]
    all_texts: frozenset[str]


def _fold_text(s: str) -> str:
    return _NONALNUM_RE.sub("", s.lower())


@lru_cache(maxsize=1)
def _index() -> _Index:
    kb = _kb()
    acc: dict[tuple[str, str], list] = {}

    def add(b: Brand, text: str, kw: bool, suffix: str | None = None) -> None:
        if not text or not text.isascii() or len(text) > 40 or len(text) < (4 if kw else 5):
            return
        slot = acc.setdefault((b.id, text), [b, False, set()])
        slot[1] = slot[1] or kw
        if suffix:
            slot[2].add(suffix)

    for b in kb.all():
        for kw in (*b.keywords, *(a for a in b.aliases if a.isascii())):
            add(b, _fold_text(kw), True)
        for d in b.official_domains:
            p = parse_url("http://" + d)
            if p.sld and p.suffix and not p.subdomain:
                add(b, _fold_text(p.sld), False, p.suffix)

    terms = [
        _Term(b, t, brand_skeleton(t), kw, frozenset(sfx)) for (_, t), (b, kw, sfx) in acc.items()
    ]
    exact: dict[str, list[_Term]] = {}
    exact_skel: dict[str, list[_Term]] = {}
    by_skel: dict[str, list[_Term]] = {}
    by_len: dict[int, list[_Term]] = {}
    for t in terms:
        by_skel.setdefault(t.skel, []).append(t)
        if t.kw:
            exact.setdefault(t.text, []).append(t)
            exact_skel.setdefault(t.skel, []).append(t)
        if len(t.text) >= 5 and (t.kw or len(t.text) >= 6):
            by_len.setdefault(len(t.skel), []).append(t)
    return _Index(
        exact={k: tuple(v) for k, v in exact.items()},
        exact_skel={k: tuple(v) for k, v in exact_skel.items()},
        affix=tuple(t for t in terms if t.kw and len(t.text) >= 5),
        by_skel={k: tuple(v) for k, v in by_skel.items()},
        by_len={k: tuple(v) for k, v in by_len.items()},
        all_texts=frozenset(t.text for t in terms),
    )


# --------------------------------------------------------------------------- #
# Host splitting (handles reserved TLDs the PSL does not know, e.g. ``.test``)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class HostParts:
    """Host split into non-registrable labels, registrable label and public suffix."""

    sub: tuple[str, ...] = ()
    sld: str = ""
    suffix: str = ""

    @property
    def registrable(self) -> str:
        return f"{self.sld}.{self.suffix}" if self.sld and self.suffix else self.sld


def split_host(p: ParsedURL) -> HostParts:
    """Split ``p``'s host; falls back to "last label is the TLD" for unknown suffixes.

    ``tldextract`` treats an unlisted TLD (``paypal-secure.test``) as the registrable
    label, which would hide the real label from every brand check.
    """
    if p.is_ip or not p.host_unicode:
        return HostParts()
    if p.suffix and p.sld:
        sub = tuple(x for x in p.subdomain.split(".") if x) if p.subdomain else ()
        return HostParts(sub, p.sld, p.suffix)
    labels = [x for x in p.host_unicode.split(".") if x]
    if len(labels) >= 2:
        return HostParts(tuple(labels[:-2]), labels[-2], labels[-1])
    return HostParts((), labels[0] if labels else "", "")


# --------------------------------------------------------------------------- #
# Token scanning
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class _Hit:
    term: _Term
    mode: str  # "token" | "affix"
    extra: int  # token mode: tokens beyond the brand; affix mode: remainder length
    remainder: str  # affix mode: leftover characters


def _has_context(text: str) -> bool:
    low = text.lower()[:2000]
    if any(t in _CONTEXT_WORDS for t in _TOK_RE.findall(low)[: _MAX_TOKENS * 4]):
        return True
    return bool(find_lures(low, max_chars=2000, max_hits=1))


def _scan(text: str, *, concat: bool, fold: bool = False) -> list[_Hit]:
    """Find brand terms in ``text``; with ``fold`` match on look-alike skeletons (leet)."""
    toks = _TOK_RE.findall((brand_skeleton(text[:2000]) if fold else text).lower())
    toks = toks[:_MAX_TOKENS]
    idx = _index()
    table = idx.exact_skel if fold else idx.exact
    best: dict[str, _Hit] = {}

    def rec(h: _Hit) -> None:
        cur = best.get(h.term.brand.id)
        if (
            cur is None
            or (h.mode == "token" and cur.mode != "token")
            or (len(h.term.text) > len(cur.term.text) and h.mode == cur.mode)
        ):
            best[h.term.brand.id] = h

    n = len(toks)
    for i in range(n):
        acc = ""
        for j in range(i, min(i + 3, n)):
            acc += toks[j]
            for t in table.get(acc, ()):
                rec(_Hit(t, "token", n - (j - i + 1), ""))
    if concat:
        for tok in toks:
            if not 5 <= len(tok) <= _MAX_LABEL:
                continue
            for t in idx.affix:
                key = t.skel if fold else t.text
                pos = tok.find(key)
                if pos < 0 or tok == key:
                    continue
                at_edge = pos == 0 or pos + len(key) == len(tok)
                if not at_edge and len(key) < 6:
                    continue
                rem = tok[:pos] + tok[pos + len(key) :]
                rec(_Hit(t, "affix", len(rem), rem))
    return list(best.values())


def scan_brand_ids(
    text: str, *, concat: bool = True, context: bool | None = None, exclude: Collection[str] = ()
) -> tuple[str, ...]:
    """Brand ids whose keyword appears in ``text`` (a host part or path), in brand-id order.

    Token-aware; with ``concat`` also glued forms (``paypalsecure``).  Ambiguous brands and
    keywords of <=4 characters need a context word in ``text`` (or ``context=True``).
    """
    ctx = _has_context(text) if context is None else context
    ids = {
        h.term.brand.id
        for h in _scan(text, concat=concat)
        if h.term.brand.id not in exclude
        and (ctx or not (h.term.brand.ambiguous or len(h.term.text) <= 4))
    }
    return tuple(sorted(ids))


# --------------------------------------------------------------------------- #
# Edit distance
# --------------------------------------------------------------------------- #
def _osa(a: str, b: str, k: int) -> int:
    """Optimal-string-alignment distance, or ``k + 1`` if it exceeds ``k``."""
    if abs(len(a) - len(b)) > k:
        return k + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if (
                prev2 is not None
                and i > 1
                and j > 1
                and a[i - 1] == b[j - 2]
                and a[i - 2] == b[j - 1]
            ):
                v = min(v, prev2[j - 2] + 1)
            cur[j] = v
        if min(cur) > k:
            return k + 1
        prev2, prev = prev, cur
    return prev[-1]


def _is_bitflip(a: str, b: str) -> bool:
    """True if ``a`` and ``b`` have equal length and differ by exactly one flipped bit."""
    if len(a) != len(b):
        return False
    diffs = [(x, y) for x, y in zip(a, b, strict=True) if x != y]
    if len(diffs) != 1:
        return False
    x = ord(diffs[0][0]) ^ ord(diffs[0][1])
    return x & (x - 1) == 0


# --------------------------------------------------------------------------- #
# Candidate construction
# --------------------------------------------------------------------------- #
def _official(b: Brand, host: str, cdn: bool) -> BrandMatch:
    what = "asset CDN host" if cdn else "official host"
    return BrandMatch(
        brand=b.id,
        name=b.name,
        technique="official",
        confidence=0.99,
        legit_domains=list(b.official_domains[:8]),
        evidence=f"{host} is an {what} of {b.name}",
        official=True,
    )


def _mk(b: Brand, technique: str, conf: float, evidence: str) -> BrandMatch:
    return BrandMatch(
        brand=b.id,
        name=b.name,
        technique=technique,
        confidence=round(max(0.0, min(0.99, conf)), 2),
        legit_domains=list(b.official_domains[:8]),
        evidence=evidence,
    )


def _strip_marks(s: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFD", s) if unicodedata.category(c) != "Mn")


def _adjust(conf: float, t: _Term, bonus: float = 0.0) -> float:
    if len(t.text) <= 4:
        conf -= 0.1
    if t.brand.ambiguous:
        conf = min(conf, 0.6)
    return conf + bonus


def _idn_candidates(p: ParsedURL, parts: HostParts, excl: set[str]) -> list[BrandMatch]:
    out: list[BrandMatch] = []
    idx = _index()
    punycode = "xn--" in p.raw.lower()
    how = "punycode host decoding to" if punycode else "non-ASCII host"
    labels = [*parts.sub, parts.sld]
    for label in labels:
        if label.isascii() or not label:
            continue
        sk = _strip_marks(brand_skeleton(label))
        variants = {sk, sk.replace("-", "")}
        done: set[str] = set()
        for v in variants:
            for t in idx.by_skel.get(v, ()):
                if t.brand.id in excl or t.brand.id in done or v != t.skel:
                    continue
                done.add(t.brand.id)
                conf = min(0.97, 0.8) if t.brand.ambiguous else 0.97
                out.append(
                    _mk(
                        t.brand,
                        "homoglyph",
                        conf,
                        f"{how} {label!r}, which renders as '{t.text}' (confusable skeleton '{v}')",
                    )
                )
        if done:
            continue
        for h in _scan(sk, concat=True):
            t = h.term
            if t.brand.id in excl or t.brand.id in done:
                continue
            if (t.brand.ambiguous or len(t.text) <= 4) and not _has_context(sk):
                continue
            done.add(t.brand.id)
            conf = _adjust(0.85 if h.mode == "token" else 0.78, t)
            out.append(
                _mk(
                    t.brand,
                    "idn",
                    conf,
                    f"{how} {label!r}, which contains '{t.text}' after folding "
                    f"look-alike characters",
                )
            )
        if done:
            continue
        flat = sk.replace("-", "")
        for ln in range(len(flat) - 1, len(flat) + 2):
            for t in idx.by_len.get(ln, ()):
                if t.brand.id in excl or t.brand.ambiguous or t.brand.id in done:
                    continue
                if _osa(flat, t.skel, 1) <= 1:
                    done.add(t.brand.id)
                    out.append(
                        _mk(t.brand, "idn", 0.75, f"{how} {label!r}, one edit away from '{t.text}'")
                    )
    folded = unicodedata.normalize("NFKC", p.host_unicode).casefold()
    for native, b in _kb().native_name_index():
        if b.id not in excl and native in folded and not any(m.brand == b.id for m in out):
            out.append(
                _mk(
                    b,
                    "idn",
                    0.7,
                    f"host contains {b.name}'s native-script name "
                    f"'{native}' on an unrelated domain",
                )
            )
    return out


def _typo_candidates(
    label: str, suffix: str, excl: set[str], *, sld: bool, tld_bonus: float
) -> list[BrandMatch]:
    idx = _index()
    out: list[BrandMatch] = []
    variants = [(label, "")]
    if "-" in label:
        variants.insert(0, (label.replace("-", ""), "hyphen"))
    seen: set[str] = set()
    for v, tag in variants:
        if not v.isascii() or not 4 <= len(v) <= 40:
            continue
        if v in idx.all_texts and not tag:
            # The label *is* a brand name: the brand on an unrelated suffix (TLD swap).
            if not sld:
                continue
            for t in idx.exact.get(v, ()):
                b = t.brand
                if b.id in excl or b.id in seen or b.ambiguous or len(v) < 5:
                    continue
                seen.add(b.id)
                bonus = 0.2 if tld_bonus else 0.0
                out.append(
                    _mk(
                        b,
                        "typosquat",
                        0.45 + bonus,
                        f"'{v}' is {b.name}'s name on an unrelated domain "
                        f"(.{suffix or '?'} instead of its official domains)",
                    )
                )
            continue
        sk = brand_skeleton(v)
        if len(sk) < 5:
            continue
        for t in idx.by_skel.get(sk, ()):
            b = t.brand
            if b.id in excl or b.id in seen or b.ambiguous or len(t.text) < 5:
                continue
            if v == t.text and not tag:
                continue
            seen.add(b.id)
            if tag:
                out.append(
                    _mk(
                        b,
                        "typosquat",
                        0.8 + tld_bonus,
                        f"'{label}' is '{t.text}' split by a hyphen",
                    )
                )
            else:
                out.append(
                    _mk(
                        b,
                        "typosquat",
                        0.9 + tld_bonus,
                        f"'{v}' reads as '{t.text}' once look-alike letters/digits are folded",
                    )
                )
        if v in idx.all_texts:
            continue
        for ln in range(len(sk) - 2, len(sk) + 3):
            for t in idx.by_len.get(ln, ()):
                b = t.brand
                if b.id in excl or b.id in seen or b.ambiguous:
                    continue
                k = 2 if len(t.skel) >= 9 else 1
                d = _osa(sk, t.skel, k)
                if d > k:
                    continue
                seen.add(b.id)
                if d == 1 and suffix in t.suffixes and _is_bitflip(v, t.text):
                    out.append(
                        _mk(
                            b,
                            "bitsquat",
                            0.85 + tld_bonus,
                            f"'{v}.{suffix}' differs from {t.text}.{suffix} by a "
                            f"single flipped bit",
                        )
                    )
                else:
                    conf = (0.8 if d == 1 else 0.65) + tld_bonus
                    out.append(
                        _mk(
                            b,
                            "typosquat",
                            conf,
                            f"'{v}' is {d} edit{'s' if d > 1 else ''} away from '{t.text}'",
                        )
                    )
    return out


def _dedupe(cands: list[BrandMatch]) -> list[BrandMatch]:
    best: dict[tuple[str, str], BrandMatch] = {}
    for c in cands:
        key = (c.brand, c.technique)
        if key not in best or c.confidence > best[key].confidence:
            best[key] = c
    return sorted(
        best.values(), key=lambda c: (-c.confidence, _TECH_PRIORITY.get(c.technique, 9), c.brand)
    )


def brand_candidates(url_or_parsed: str | ParsedURL) -> list[BrandMatch]:
    """All brand-impersonation hypotheses for a URL, strongest first.

    Returns ``[official match]`` when the URL is an official/login/CDN host, otherwise
    zero or more impersonation candidates (one per brand+technique).
    """
    p = url_or_parsed if isinstance(url_or_parsed, ParsedURL) else parse_url(url_or_parsed)
    host = p.host_ascii
    if not host and not p.is_ip:
        return []
    kb = _kb()
    if host and not p.is_ip:
        b = kb.official_brand_for_host(host)
        if b is not None:
            return [_official(b, host, False)]
        b = kb.cdn_brand_for_host(host)
        if b is not None:
            return [_official(b, host, True)]

    parts = split_host(p)
    owner = kb.is_user_content_host(host) if host and not p.is_ip else None
    lots = lots_match(host, p.path) if host and not p.is_ip else None
    platform = owner is not None or lots is not None
    excl: set[str] = {owner.id} if owner is not None else set()
    rank = top_rank(p.registrable_ascii) if p.registrable_ascii else None
    popular = (not platform) and rank is not None and rank <= _POPULAR_RANK
    risk = tld_risk(parts.suffix or host) if host and not p.is_ip else None
    bonus = 0.04 if (risk or 0.0) >= 0.8 else 0.0

    path_text = unquote(p.path[:_MAX_PATH]).lower()
    host_text = ".".join([*parts.sub, parts.sld]) if parts.sld else ""
    ctx = _has_context(f"{host_text} {path_text}")
    cands: list[BrandMatch] = []

    if parts.sld:
        if p.has_nonascii_host:
            cands += _idn_candidates(p, parts, excl)
        ascii_sub = " ".join(x for x in parts.sub if x.isascii())
        # --- brand tokens in sub-domain labels (or tenant labels on shared platforms)
        scans: list[tuple[str, str]] = [("sub", ascii_sub)]
        scans.append(("sub" if platform else "sld", parts.sld if parts.sld.isascii() else ""))
        dotted = "." + ".".join(parts.sub) + "."
        for where, text in scans:
            if not text:
                continue
            hits = _scan(text, concat=True)
            known = {h.term.brand.id for h in hits}
            hits += [h for h in _scan(text, concat=True, fold=True) if h.term.brand.id not in known]
            for h in hits:
                t, b = h.term, h.term.brand
                if b.id in excl:
                    continue
                if (b.ambiguous or len(t.text) <= 4) and not ctx:
                    continue
                if where == "sub":
                    if h.mode == "token":
                        real = any(f".{d}." in dotted for d in b.official_domains)
                        conf = 0.95 if real else (0.85 if ctx else 0.8)
                        ev = (
                            f"{b.name}'s real domain is spelled out inside the sub-domain "
                            f"of {parts.registrable or host}"
                            if real
                            else f"'{t.text}' appears as a sub-domain label of "
                            f"{parts.registrable or host}, which is not a {b.name} domain"
                        )
                    else:
                        conf = 0.75 if _has_context(h.remainder) else 0.7
                        ev = (
                            f"sub-domain contains '{t.text}' glued to '{h.remainder}' on "
                            f"{parts.registrable or host}"
                        )
                    if platform and not real_sub(b, dotted):
                        ev += " (shared hosting platform: anyone can create this)"
                    cands.append(_mk(b, "subdomain", _adjust(conf, t, bonus), ev))
                    continue
                if popular:
                    continue
                if h.mode == "token" and h.extra == 0:
                    if b.ambiguous or len(t.text) < 5:
                        continue
                    cands.append(
                        _mk(
                            b,
                            "typosquat",
                            0.45 + (0.2 if bonus else 0.0),
                            f"'{t.text}' is {b.name}'s name on an unrelated domain "
                            f"(.{parts.suffix or '?'})",
                        )
                    )
                elif h.mode == "token":
                    conf = 0.88 if ctx else 0.8
                    cands.append(
                        _mk(
                            b,
                            "combosquat",
                            _adjust(conf, t, bonus),
                            f"'{parts.sld}' combines '{t.text}' with extra words "
                            f"on an unrelated domain",
                        )
                    )
                else:
                    if _has_context(h.remainder):
                        conf = 0.82
                    elif h.remainder.isdigit():
                        conf = 0.7
                    elif len(t.text) >= 7:
                        conf = 0.55
                    else:
                        continue  # short brand + arbitrary text: too many real words
                    cands.append(
                        _mk(
                            b,
                            "combosquat",
                            _adjust(conf, t, bonus),
                            f"'{parts.sld}' embeds '{t.text}' plus '{h.remainder}'",
                        )
                    )
        # --- typosquats / bitsquats on the registrable (or tenant) label
        if not popular:
            targets = [parts.sld] if not platform else [*parts.sub, parts.sld]
            for lab in targets:
                cands += _typo_candidates(
                    lab, parts.suffix, excl, sld=lab == parts.sld, tld_bonus=bonus
                )

    # --- brand keyword in the path of an unrelated domain
    if path_text and not popular:
        for h in _scan(path_text, concat=False):
            t, b = h.term, h.term.brand
            if b.id in excl or ((b.ambiguous or len(t.text) <= 4) and not ctx):
                continue
            conf = 0.55 if ctx else 0.35
            if platform:
                conf += 0.15
            if any(d in path_text for d in b.official_domains):
                conf += 0.15
            conf = min(conf, 0.75)
            cands.append(
                _mk(
                    b,
                    "path",
                    _adjust(conf, t),
                    f"'{t.text}' appears in the path of {host or 'an IP address'}, "
                    f"which is not a {b.name} domain",
                )
            )
    return _dedupe(cands)


def real_sub(b: Brand, dotted: str) -> bool:
    """True if ``b``'s official domain is spelled out in the dotted sub-domain string."""
    return any(f".{d}." in dotted for d in b.official_domains)


def brand_impersonation(
    url_or_parsed: str | ParsedURL, *, min_confidence: float = 0.3
) -> BrandMatch | None:
    """The single best brand finding for a URL, or ``None``.

    Returns ``BrandMatch(official=True)`` for a brand's own official/login/CDN hosts,
    the highest-confidence impersonation candidate otherwise, or ``None`` when nothing
    reaches ``min_confidence``.  Never raises on malformed input.
    """
    try:
        cands = brand_candidates(url_or_parsed)
    except Exception:
        log.exception("brand_candidates failed")
        return None
    if not cands:
        return None
    best = cands[0]
    return best if best.official or best.confidence >= min_confidence else None
