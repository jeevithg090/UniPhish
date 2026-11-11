"""Multilingual social-engineering *language* model (lexicon + rules, no ML dependency).

Phishing, BEC and smishing share a small set of manipulation tactics (urgency, fear,
authority, greed, secrecy, ...) whatever the delivery vector or language. This module
scores the language of a message body for that pressure so the text analyzer can raise
a signal even when the message carries no URL, no brand and no attachment ("Your
account is locked, reply with the code we just sent you").

Design goals
------------
* **Deterministic and explainable** - every point of score traces back to a lexicon hit
  with a character span, a tactic and a language (``TacticHit``).
* **Many languages, one matcher** - phrases for 22 language tags live in
  ``uniphish/assets/se_lexicons.yaml``. All of them are compiled into a single
  Aho-Corasick automaton, so matching is linear in the text length regardless of
  lexicon size (no regex alternation, no backtracking). Latin / Cyrillic / Greek phrases
  are token-aware (word boundaries); every other script is matched as a substring.
* **Evasion-aware normalisation** - case folding, Latin accent stripping, Arabic
  diacritic stripping, NFKC (full-width, ligatures), digit unification, zero-width and
  bidi control removal, whitespace collapsing. A map back to original offsets keeps the
  hit spans valid for UI highlighting.
* **Hostile input** - input is truncated to ``MAX_TEXT_CHARS`` and nothing is evaluated.
  The only regexes applied to attacker text are linear (``[^\\W\\d_]+``) or bounded
  (phone numbers: fixed digit counts, disjoint separator classes).

Scoring
-------
Hit weights are log-odds-style (see the build contract scale). Within one tactic the
distinct phrases are summed with geometric decay and capped; the per-tactic totals are
then combined across tactics with diminishing returns, plus bonuses for combinations
that are far likelier in an attack than apart (urgency + credential ask, secrecy +
payment ask = BEC, tech-support lure + callback number = TOAD, ...). Long texts are
damped because a lure is dense. ``SEResult.score`` is ``1 - exp(-log_odds / scale)``.

Limitations (see also tests): this is lexical. It does not understand negation beyond
the OTP phrases, paraphrase outside the lexicon, or confusable-script obfuscation of
individual letters. It is one weak-to-moderate evidence family and must be fused with
URL / sender / structural evidence by the engine.
"""

from __future__ import annotations

import logging
import math
import re
import unicodedata
from collections import Counter, deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from uniphish.assets import load_yaml

log = logging.getLogger("uniphish.nlp")

__all__ = [
    "MAX_TEXT_CHARS",
    "TACTICS",
    "SEResult",
    "TacticHit",
    "analyze_text",
    "detect_otp_request",
    "detect_phone_number",
    "lexicon_stats",
]

#: Text longer than this is truncated before analysis (hostile-input bound).
MAX_TEXT_CHARS = 100_000
#: Hard cap on raw automaton matches processed (pathological repetition guard).
_MAX_RAW_MATCHES = 20_000
#: Hits returned in ``SEResult.tactics`` (scoring always uses all of them).
_MAX_HITS_RETURNED = 500
_MAX_PHONES = 20
_LANG_SAMPLE_CHARS = 20_000
_LANG_SAMPLE_TOKENS = 3_000

#: Tactic identifiers, in lexicon order. ``cta`` (call to action) is a weak tactic that
#: never becomes the dominant tactic.
TACTICS: tuple[str, ...] = (
    "urgency", "threat", "authority", "reward", "scarcity", "secrecy", "payment",
    "credential", "delivery", "tax", "techsupport", "crypto", "otp", "cta",
)  # fmt: skip


# ------------------------------------------------------------------ public types
@dataclass(frozen=True, slots=True)
class TacticHit:
    """One lexicon match. ``start``/``end`` are character offsets in the *input* text."""

    tactic: str
    lang: str
    weight: float
    term: str
    start: int
    end: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "tactic": self.tactic, "lang": self.lang, "weight": self.weight,
            "term": self.term, "start": self.start, "end": self.end,
        }  # fmt: skip


@dataclass(frozen=True, slots=True)
class SEResult:
    """Outcome of :func:`analyze_text`.

    ``score`` is the 0..1 pressure; ``log_odds`` is the same evidence on the signal
    weight scale of the build contract (what an analyzer should use as a ``weight``,
    usually clipped). ``tactic_scores`` holds the capped log-odds contribution per
    tactic that fired.
    """

    score: float = 0.0
    log_odds: float = 0.0
    tactics: list[TacticHit] = field(default_factory=list)
    tactic_scores: dict[str, float] = field(default_factory=dict)
    languages: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    dominant_tactic: str | None = None
    has_call_to_action: bool = False
    has_credential_ask: bool = False
    has_payment_ask: bool = False
    has_otp_ask: bool = False
    urgency_score: float = 0.0
    authority_score: float = 0.0
    phone_numbers: list[str] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4), "log_odds": round(self.log_odds, 3),
            "tactics": [h.to_dict() for h in self.tactics],
            "tactic_scores": {k: round(v, 3) for k, v in self.tactic_scores.items()},
            "languages": list(self.languages), "scripts": list(self.scripts),
            "dominant_tactic": self.dominant_tactic,
            "has_call_to_action": self.has_call_to_action,
            "has_credential_ask": self.has_credential_ask,
            "has_payment_ask": self.has_payment_ask, "has_otp_ask": self.has_otp_ask,
            "urgency_score": round(self.urgency_score, 4),
            "authority_score": round(self.authority_score, 4),
            "phone_numbers": list(self.phone_numbers), "truncated": self.truncated,
        }  # fmt: skip


# ------------------------------------------------------------------ normalisation
_APOSTROPHES = "’‘ʼ`´′"
_TRANSLATE = str.maketrans({
    "ё": "е", "ı": "i", "ł": "l", "đ": "d", "ø": "o",
    "أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا", "ى": "ي", "ی": "ي", "ک": "ك", "ة": "ه",
    **{c: "'" for c in _APOSTROPHES},
})  # fmt: skip
_ASCII_WS = " \t\n\r\x0b\x0c"
_PUNCT_RE = re.compile(r"[.,;:!?()\[\]{}\"'\-_/\\|]")


def _is_arabic_script(ch: str) -> bool:
    o = ord(ch)
    return 0x600 <= o <= 0x6FF or 0x750 <= o <= 0x77F or 0xFB50 <= o <= 0xFEFF


@lru_cache(maxsize=8192)
def _map_char(ch: str) -> str:
    """Context-free normalisation of one non-ASCII character ('' = drop)."""
    cat = unicodedata.category(ch)
    o = ord(ch)
    if cat == "Cf" or o == 0xAD:  # zero-width, bidi marks, soft hyphen, BOM
        return ""
    if ch.isspace() or cat in ("Zs", "Zl", "Zp"):
        return " "
    if cat == "Cc":
        return ""
    if cat == "Mn" and (0x300 <= o <= 0x36F or 0x64B <= o <= 0x65F or o in (0x670, 0x640)):
        return ""  # combining diacritics, Arabic harakat / superscript alef
    if o == 0x640:  # tatweel (category Lm)
        return ""
    if cat == "Nd":
        d = unicodedata.decimal(ch, None)
        if d is not None:
            return str(d)
    nk = unicodedata.normalize("NFKD", ch)
    if nk != ch and "A" <= nk[0] <= "z" and nk[0].isascii():
        nk = "".join(c for c in nk if unicodedata.category(c) != "Mn")  # strip Latin accents
    else:
        nk = unicodedata.normalize("NFKC", ch)
    return nk.casefold().translate(_TRANSLATE)


def _normalize(text: str) -> tuple[str, list[int]]:
    """Normalise ``text``; return ``(normalised, idx)`` where ``idx[i]`` is the original
    offset of normalised character ``i`` (so hit spans can be mapped back)."""
    out: list[str] = []
    idx: list[int] = []
    last = " "
    for i, ch in enumerate(text):
        if ch < "\x80":
            if ch in _ASCII_WS:
                rep = " "
            elif ch < " " or ch == "\x7f":
                continue
            else:
                rep = ch.lower()
        elif ch == "‌":  # ZWNJ is a word separator in Persian, invisible elsewhere
            if not _is_arabic_script(last):
                continue
            rep = " "
        else:
            rep = _map_char(ch)
            if not rep:
                continue
        for c in rep:
            if c == " " and (last == " " or not out):
                continue
            out.append(c)
            idx.append(i)
            last = c
    while out and out[-1] == " ":
        out.pop()
        idx.pop()
    return "".join(out), idx


def _is_spaced_char(ch: str) -> bool:
    """True for letters/digits of scripts that separate words with spaces (token-aware)."""
    o = ord(ch)
    if o < 0x80:
        return ch.isalnum()
    return (0xC0 <= o <= 0x24F or 0x370 <= o <= 0x52F or 0x1E00 <= o <= 0x1EFF) and ch.isalnum()


def _is_unspaced_char(ch: str) -> bool:
    o = ord(ch)
    return (0xE00 <= o <= 0xE7F or 0x1100 <= o <= 0x11FF or 0x3040 <= o <= 0x9FFF
            or 0xAC00 <= o <= 0xD7AF or 0xF900 <= o <= 0xFAFF)  # fmt: skip


# --------------------------------------------------------------- Aho-Corasick
class _Automaton:
    """Aho-Corasick multi-pattern matcher: O(len(text) + matches), no backtracking."""

    __slots__ = ("_fail", "_goto", "_out")

    def __init__(self, patterns: Iterable[tuple[str, int]]) -> None:
        goto: list[dict[str, int]] = [{}]
        out: list[list[int]] = [[]]
        for pat, ident in patterns:
            node = 0
            for ch in pat:
                nxt = goto[node].get(ch)
                if nxt is None:
                    goto.append({})
                    out.append([])
                    nxt = len(goto) - 1
                    goto[node][ch] = nxt
                node = nxt
            out[node].append(ident)
        fail = [0] * len(goto)
        queue: deque[int] = deque(goto[0].values())
        while queue:
            node = queue.popleft()
            for ch, child in goto[node].items():
                f = fail[node]
                while f and ch not in goto[f]:
                    f = fail[f]
                fail[child] = goto[f].get(ch, 0)
                out[child] = out[child] + out[fail[child]]
                queue.append(child)
        self._goto, self._fail = goto, fail
        self._out = [tuple(o) for o in out]

    def finditer(self, text: str) -> Iterator[tuple[int, tuple[int, ...]]]:
        """Yield ``(end_exclusive, pattern_ids)`` for every match end."""
        goto, fail, out = self._goto, self._fail, self._out
        state = 0
        for i, ch in enumerate(text):
            while state and ch not in goto[state]:
                state = fail[state]
            state = goto[state].get(ch, 0)
            o = out[state]
            if o:
                yield i + 1, o


# ------------------------------------------------------------------- lexicon
@dataclass(frozen=True, slots=True)
class _Entry:
    tactic: str
    lang: str
    weight: float
    term: str  # as written in the lexicon (reported in hits)
    norm_len: int
    left_check: bool
    right_check: bool


@dataclass(slots=True)
class _Lexicon:
    entries: list[_Entry]
    automaton: _Automaton
    scoring: dict[str, Any]
    stopwords: dict[str, frozenset[str]]
    diacritics: dict[str, frozenset[str]]
    hans_only: frozenset[str]
    hant_only: frozenset[str]
    neg_before: tuple[tuple[str, bool], ...]
    neg_after: tuple[tuple[str, bool], ...]
    neg_before_n: int
    neg_after_n: int


_WEIGHT_RE = re.compile(r"\s@(\d+(?:\.\d+)?)$")


def _parse_term(raw: str, default: float) -> tuple[str, float, bool]:
    s = raw.strip()
    weight = default
    m = _WEIGHT_RE.search(s)
    if m:
        weight = float(m.group(1))
        s = s[: m.start()].strip()
    open_right = s.endswith("*")
    if open_right:
        s = s[:-1].rstrip()
    if not s:
        raise ValueError(f"empty lexicon term: {raw!r}")
    if not 0.05 <= weight <= 5.0:
        raise ValueError(f"lexicon weight out of range for {raw!r}: {weight}")
    return s, weight, open_right


def _negator_list(items: Iterable[str]) -> tuple[tuple[str, bool], ...]:
    out: list[tuple[str, bool]] = []
    for raw in items:
        n = " ".join(_PUNCT_RE.sub(" ", _normalize(raw)[0]).split())
        if n:
            out.append((n, not any(_is_unspaced_char(c) for c in n)))
    return tuple(out)


@lru_cache(maxsize=1)
def _lexicon() -> _Lexicon:
    """Load + compile the YAML lexicon once (validated; raises ``ValueError`` if broken)."""
    data = load_yaml("se_lexicons.yaml")
    entries: list[_Entry] = []
    patterns: list[tuple[str, int]] = []
    seen: set[tuple[str, str]] = set()
    for tactic, spec in data["tactics"].items():
        if tactic not in TACTICS:
            raise ValueError(f"unknown tactic in lexicon: {tactic}")
        default = float(spec["weight"])
        for lang, terms in spec["terms"].items():
            for raw in terms:
                term, weight, open_right = _parse_term(str(raw), default)
                norm = _normalize(term)[0]
                if not norm or (tactic, norm) in seen:
                    continue
                seen.add((tactic, norm))
                entries.append(_Entry(
                    tactic, lang, weight, term, len(norm),
                    _is_spaced_char(norm[0]),
                    _is_spaced_char(norm[-1]) and not open_right,
                ))  # fmt: skip
                patterns.append((norm, len(entries) - 1))
    han = data["han_variants"]
    hans, hant = frozenset(han["hans"]), frozenset(han["hant"])
    neg = data["negators"]
    lex = _Lexicon(
        entries=entries,
        automaton=_Automaton(patterns),
        scoring=data["scoring"],
        stopwords={k: frozenset(_normalize(w)[0] for w in v) for k, v in data["stopwords"].items()},
        diacritics={k: frozenset(v) for k, v in data["diacritics"].items()},
        hans_only=hans - hant,
        hant_only=hant - hans,
        neg_before=_negator_list(neg["before"]),
        neg_after=_negator_list(neg["after"]),
        neg_before_n=int(neg["window_before"]),
        neg_after_n=int(neg["window_after"]),
    )
    log.debug("social-engineering lexicon: %d entries, %d patterns", len(entries), len(patterns))
    return lex


def lexicon_stats() -> dict[str, Any]:
    """Counts of compiled entries: ``total``, ``by_tactic``, ``by_lang``, ``by_lang_tactic``."""
    lex = _lexicon()
    by_tactic = Counter(e.tactic for e in lex.entries)
    by_lang = Counter(e.lang for e in lex.entries)
    by_lt: dict[str, dict[str, int]] = {}
    for e in lex.entries:
        by_lt.setdefault(e.lang, {}).setdefault(e.tactic, 0)
        by_lt[e.lang][e.tactic] += 1
    return {"total": len(lex.entries), "by_tactic": dict(by_tactic),
            "by_lang": dict(by_lang), "by_lang_tactic": by_lt}  # fmt: skip


# ----------------------------------------------------------------- matching
def _boundary_ok(ntext: str, s: int, e: int, entry: _Entry) -> bool:
    if entry.left_check and s > 0 and _is_spaced_char(ntext[s - 1]):
        return False
    return not (entry.right_check and e < len(ntext) and _is_spaced_char(ntext[e]))


def _contains_negator(window: str, negators: tuple[tuple[str, bool], ...]) -> bool:
    if not window:
        return False
    clean = " ".join(_PUNCT_RE.sub(" ", window).split())
    padded = f" {clean} "
    return any((f" {n} " in padded) if spaced else (n in clean) for n, spaced in negators)


@dataclass(slots=True)
class _Hit:
    s: int  # normalised offsets
    e: int
    entry: _Entry


def _scan(ntext: str, lex: _Lexicon) -> tuple[list[_Hit], bool]:
    """All boundary-valid matches, resolved to leftmost-longest non-overlapping per tactic."""
    per_tactic: dict[str, list[_Hit]] = {}
    count = 0
    capped = False
    entries = lex.entries
    for end, ids in lex.automaton.finditer(ntext):
        for ident in ids:
            entry = entries[ident]
            start = end - entry.norm_len
            if _boundary_ok(ntext, start, end, entry):
                per_tactic.setdefault(entry.tactic, []).append(_Hit(start, end, entry))
                count += 1
        if count >= _MAX_RAW_MATCHES:
            capped = True
            break
    kept: list[_Hit] = []
    for hits in per_tactic.values():
        hits.sort(key=lambda h: (h.s, -(h.e - h.s), -h.entry.weight))
        last_end = -1
        for h in hits:
            if h.s >= last_end:
                kept.append(h)
                last_end = h.e
    # drop negated OTP asks ("never share the code with anyone")
    kept = [
        h for h in kept
        if h.entry.tactic != "otp" or not (
            _contains_negator(ntext[max(0, h.s - lex.neg_before_n): h.s], lex.neg_before)
            or _contains_negator(ntext[h.e: h.e + lex.neg_after_n], lex.neg_after)
        )
    ]  # fmt: skip
    kept.sort(key=lambda h: (h.s, h.e))
    return kept, capped


# ------------------------------------------------------------------ phone numbers
_SEP = r"[\s.\-()]{0,2}"
_PHONE_INTL = re.compile(rf"(?<!\w)(?:\+|00)\d{{1,3}}(?:{_SEP}\d){{6,12}}(?!\d)")
_PHONE_NANP = re.compile(
    r"(?<![\w+\-.])(?:\+?1[\s.\-]?)?(?:\(\d{3}\)[\s.\-]?|\d{3}[\s.\-])\d{3}[\s.\-]\d{4}(?!\d)"
)
_CALL_WORDS = (
    "call", "dial", "tel", "phone", "hotline", "helpline", "contact us at", "llame", "llama",
    "ligue", "appelez", "rufen sie", "chiama", "zadzwoń", "zadzwon", "звоните", "позвоните",
    "拨打", "致电", "撥打", "電話", "전화", "bel ", "hubungi", "gọi", "โทร", "ara",
)  # fmt: skip
_PHONE_KEYWORD = re.compile(
    r"(?:" + "|".join(re.escape(w) for w in _CALL_WORDS) + r")[^\d+\n]{0,12}"
    rf"(\d(?:{_SEP}\d){{6,13}})(?!\d)",
    re.IGNORECASE,
)


def detect_phone_number(text: str) -> list[str]:
    """Phone numbers in ``text`` for callback (TOAD) style lures, in order of appearance.

    Recognised: ``+``/``00`` international numbers (returned as E.164-ish ``+<digits>``,
    8-15 digits), North-American formats (``(555) 123-4567``, ``1-800-555-0100``; returned as
    ``+1XXXXXXXXXX``, NANP area/exchange rules enforced) and national numbers immediately
    after a calling word such as "call" / "llame" / "звоните" (returned as bare digits).
    Dates, IPs and bare digit strings are not matched. Input is truncated to
    ``MAX_TEXT_CHARS``; at most 20 numbers are returned.
    """
    text = text[:MAX_TEXT_CHARS]
    found: list[tuple[int, str]] = []
    for m in _PHONE_INTL.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if raw.startswith("00"):
            if raw.isdigit():
                continue  # bare 00-prefixed digit run: more likely an id than a phone
            digits = digits[2:]
        if 8 <= len(digits) <= 15:
            found.append((m.start(), "+" + digits))
    for m in _PHONE_NANP.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if len(digits) == 11 and digits[0] == "1":
            digits = digits[1:]
        if len(digits) == 10 and digits[0] in "23456789" and digits[3] in "23456789":
            found.append((m.start(), "+1" + digits))
    known = [n.lstrip("+") for _, n in found]
    for m in _PHONE_KEYWORD.finditer(text):
        digits = re.sub(r"\D", "", m.group(1))
        core = digits[2:] if digits.startswith("00") else digits
        if 7 <= len(digits) <= 15 and not any(core in k for k in known):
            found.append((m.start(1), digits))
    out: list[str] = []
    for _, num in sorted(found):
        if num not in out:
            out.append(num)
        if len(out) >= _MAX_PHONES:
            break
    return out


# ---------------------------------------------------------------- language guess
@lru_cache(maxsize=8192)
def _script_of(ch: str) -> str | None:
    o = ord(ch)
    if o < 0x80:
        return "latin" if ch.isalpha() else None
    for lo, hi, name in _SCRIPT_RANGES:
        if lo <= o <= hi:
            return name
    return None


_SCRIPT_RANGES: tuple[tuple[int, int, str], ...] = (
    (0xC0, 0x24F, "latin"), (0x1E00, 0x1EFF, "latin"), (0x370, 0x3FF, "greek"),
    (0x400, 0x52F, "cyrillic"), (0x590, 0x5FF, "hebrew"), (0x600, 0x6FF, "arabic"),
    (0x750, 0x77F, "arabic"), (0xFB50, 0xFDFF, "arabic"), (0xFE70, 0xFEFF, "arabic"),
    (0x900, 0x97F, "devanagari"), (0xE00, 0xE7F, "thai"), (0x1100, 0x11FF, "hangul"),
    (0x3130, 0x318F, "hangul"), (0xAC00, 0xD7AF, "hangul"), (0x3040, 0x309F, "kana"),
    (0x30A0, 0x30FF, "kana"), (0xFF66, 0xFF9F, "kana"), (0x3400, 0x4DBF, "han"),
    (0x4E00, 0x9FFF, "han"), (0xF900, 0xFAFF, "han"),
)  # fmt: skip
_TOKEN_RE = re.compile(r"[^\W\d_]+")
_LANG_ALIASES = {
    "zh-cn": "zh-Hans", "zh-sg": "zh-Hans", "zh-hans": "zh-Hans", "zh-tw": "zh-Hant",
    "zh-hk": "zh-Hant", "zh-mo": "zh-Hant", "zh-hant": "zh-Hant", "hi-latn": "hi-Latn",
    "iw": "he", "in": "id",
}  # fmt: skip
_LANG_TAG_RE = re.compile(r"^[a-z]{2,3}(?:-[a-z0-9]{2,8})*$")


def _canon_lang(tag: str | None) -> str | None:
    if not tag:
        return None
    t = tag.strip().lower().replace("_", "-")
    if not _LANG_TAG_RE.match(t) or len(t) > 16:
        return None
    return _LANG_ALIASES.get(t) or t.split("-")[0]


def _base_lang(lang: str) -> str:
    return lang if lang == "hi-Latn" else lang.split("-")[0]


def _guess_languages(text: str, ntext: str, lex: _Lexicon) -> tuple[list[str], list[str]]:
    """Return ``(languages, scripts)`` guessed from scripts, distinctive characters and
    stop words (best first). Cheap and approximate by design."""
    sample = text[:_LANG_SAMPLE_CHARS]
    counts: Counter[str] = Counter(s for s in map(_script_of, sample) if s)
    total = sum(counts.values())
    if not total:
        return [], []
    scripts = [s for s, n in counts.most_common() if n / total >= 0.05]
    low = sample.lower()
    langs: list[tuple[str, float]] = []
    for script in scripts:
        n = float(counts[script])
        if script == "cyrillic":
            langs.append(("uk" if any(c in low for c in "іїєґ") else "ru", n))
        elif script == "arabic":
            fa = sum(low.count(c) for c in "پچژگکی")
            ar = sum(low.count(c) for c in "كيةأإ")
            langs.append(("fa" if fa > ar else "ar", n))
        elif script == "han":
            if counts["kana"] or counts["hangul"]:
                continue
            hs = sum(1 for c in sample if c in lex.hans_only)
            ht = sum(1 for c in sample if c in lex.hant_only)
            langs.append(("zh-Hans" if hs > ht else "zh-Hant" if ht > hs else "zh", n))
        elif script == "kana":
            langs.append(("ja", n))
        elif script == "hangul":
            langs.append(("ko", n))
        elif script == "devanagari":
            langs.append(("hi", n))
        elif script == "thai":
            langs.append(("th", n))
        elif script == "greek":
            langs.append(("el", n))
        elif script == "hebrew":
            langs.append(("he", n))
        elif script == "latin":
            tokens = _TOKEN_RE.findall(ntext[:_LANG_SAMPLE_CHARS])[:_LANG_SAMPLE_TOKENS]
            pts: dict[str, int] = {}
            for lang, words in lex.stopwords.items():
                p = sum(1 for t in tokens if t in words)
                chars = lex.diacritics.get(lang)
                if chars:
                    p += sum(1 for c in low if c in chars)
                pts[lang] = p
            best = max(pts.values(), default=0)
            if best >= 2:
                cut = max(2.0, 0.6 * best)
                for lang, p in sorted(pts.items(), key=lambda kv: -kv[1])[:3]:
                    if p >= cut:
                        langs.append((lang, n * p / best))
    langs.sort(key=lambda kv: -kv[1])
    names = ["kana" if s in ("kana",) else s for s in scripts]
    return [lang for lang, _ in langs], names


# ----------------------------------------------------------------------- scoring
def _score(
    hits: list[_Hit], phones: list[str], n_chars: int, lex: _Lexicon
) -> tuple[float, dict[str, float]]:
    cfg = lex.scoring
    decay, cap = float(cfg["within_decay"]), float(cfg["tactic_cap"])
    best_per_term: dict[str, dict[str, float]] = {}
    for h in hits:
        d = best_per_term.setdefault(h.entry.tactic, {})
        d[h.entry.term] = max(d.get(h.entry.term, 0.0), h.entry.weight)
    tactic_scores: dict[str, float] = {}
    for tactic, terms in best_per_term.items():
        ws = sorted(terms.values(), reverse=True)
        tactic_scores[tactic] = min(cap, sum(w * decay**i for i, w in enumerate(ws)))
    ranked = sorted(tactic_scores.values(), reverse=True)
    cross = cfg["cross_decay"]
    total = sum(v * cross[min(i, len(cross) - 1)] for i, v in enumerate(ranked))
    present = set(tactic_scores) | ({"phone"} if phones else set())
    combo = 0.0
    for rule in cfg["combos"]:
        if all((r in present) if isinstance(r, str) else any(x in present for x in r)
               for r in rule["requires"]):  # fmt: skip
            combo += float(rule["bonus"])
    total += min(combo, float(cfg["combo_cap"]))
    ref = float(cfg["density_ref_chars"])
    if n_chars > ref:
        total /= 1.0 + float(cfg["density_slope"]) * math.log10(n_chars / ref)
    return min(total, float(cfg["logit_cap"])), tactic_scores


def analyze_text(text: str, *, lang_hint: str | None = None) -> SEResult:
    """Score ``text`` for social-engineering pressure.

    Args:
        text: message / email body / chat line (any language; truncated to
            ``MAX_TEXT_CHARS``).
        lang_hint: optional BCP-47 tag (``"de"``, ``"zh-TW"``, ``"pt_BR"``); it is listed
            first in ``SEResult.languages``. Matching always covers every language, because
            attackers mix them.

    Returns:
        :class:`SEResult` with score, per-hit explanations (original-text spans) and the
        ask flags (credential / payment / OTP / call to action). Pure and deterministic.
    """
    truncated = len(text) > MAX_TEXT_CHARS
    text = text[:MAX_TEXT_CHARS]
    hint = _canon_lang(lang_hint)
    if not text.strip():
        return SEResult(languages=[hint] if hint else [], truncated=truncated)
    lex = _lexicon()
    ntext, idx = _normalize(text)
    hits, capped = _scan(ntext, lex) if ntext else ([], False)
    phones = detect_phone_number(text)
    log_odds, tactic_scores = _score(hits, phones, len(ntext), lex)
    detected, scripts = _guess_languages(text, ntext, lex)
    languages: list[str] = []
    for lang in [hint, *detected]:
        if lang and lang not in languages:
            languages.append(lang)
    hit_langs = Counter[str]()
    for h in hits:
        hit_langs[h.entry.lang] += 1
    for lang, _ in hit_langs.most_common():
        if _base_lang(lang) not in {_base_lang(x) for x in languages}:
            languages.append(lang)
    cfg = lex.scoring
    present = set(tactic_scores)
    non_cta = {t: v for t, v in tactic_scores.items() if t != "cta"}
    dominant = max(non_cta, key=lambda t: non_cta[t]) if non_cta else None
    cred_min = cfg["credential_ask_min_weight"]
    pay_min = cfg["payment_ask_min_weight"]
    has_cred = any(h.entry.tactic == "credential" and h.entry.weight >= cred_min for h in hits)
    has_pay = any(h.entry.tactic == "payment" and h.entry.weight >= pay_min for h in hits)
    has_otp = "otp" in present
    out_hits = [
        TacticHit(h.entry.tactic, h.entry.lang, h.entry.weight, h.entry.term,
                  idx[h.s], idx[h.e - 1] + 1)
        for h in hits[:_MAX_HITS_RETURNED]
    ]  # fmt: skip
    return SEResult(
        score=1.0 - math.exp(-log_odds / float(cfg["score_scale"])),
        log_odds=log_odds,
        tactics=out_hits,
        tactic_scores=tactic_scores,
        languages=languages,
        scripts=scripts,
        dominant_tactic=dominant,
        has_call_to_action="cta" in present or has_cred or has_pay or has_otp,
        has_credential_ask=has_cred,
        has_payment_ask=has_pay,
        has_otp_ask=has_otp,
        urgency_score=1.0 - math.exp(-tactic_scores.get("urgency", 0.0) / 2.0),
        authority_score=1.0 - math.exp(-tactic_scores.get("authority", 0.0) / 2.0),
        phone_numbers=phones,
        truncated=truncated or capped,
    )


def detect_otp_request(text: str) -> bool:
    """True if ``text`` asks the reader to hand over / read back / reply with a one-time
    code or 2FA code (a strong smishing and vishing signal), in any covered language.

    A message that merely *delivers* a code ("Your code is 123456") or warns against
    sharing it ("never share this code") is not a request and returns ``False``.
    """
    text = text[:MAX_TEXT_CHARS]
    if not text.strip():
        return False
    lex = _lexicon()
    ntext, _ = _normalize(text)
    hits, _ = _scan(ntext, lex)
    return any(h.entry.tactic == "otp" for h in hits)
