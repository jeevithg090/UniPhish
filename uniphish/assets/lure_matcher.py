"""Linear-time multilingual lure-term matcher backing ``uniphish.assets.lists.find_lures``.

Why a dedicated matcher: phishing URLs and SMS reuse the *victim's* language
("verifica tu cuenta", "您的账户已冻结"), and the lexicon has ~1,500 terms across 30 language
tags. A single big regex alternation would be both slow (every position tries every
branch) and a ReDoS surface, so matching is done with hash lookups instead:

* the text is tokenised once with one character-class regex (no nested quantifiers);
* terms in space-delimited scripts (Latin, Cyrillic, Greek, Arabic, Indic ...) match by
  token (so ``tax`` never fires inside ``syntax``), multi-word terms by token sequence;
* terms in spaceless scripts (Han, kana, Hangul, Thai ...) match as substrings, found via
  a first-character index so the scan is C-speed ``finditer`` plus a few ``startswith``;
* a discounted "partial" pass catches English terms glued into one token
  (``securelogin``) and stem matches for suffixing languages (``stem_languages`` in
  ``lures.yaml``: Turkish/Indonesian/Malay ``hesabiniz``, ``akunnya``).

Overlaps are resolved greedily in favour of the longest then heaviest hit.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache

from uniphish.assets import load_yaml

__all__ = ["LureHit", "find_lures", "lure_languages", "lure_term_count"]

_DEFAULT_MAX_CHARS = 262_144
_PARTIAL_DISCOUNT = 0.7
_COMPOUND_LANGS = frozenset({"und", "en"})  # glued-token lures are an English-kit habit
_NO_COMPOUND = frozenset({"relogin", "locked", "expire", "crypto", "reward", "prize"})
_STEM_MIN = 5

# Separator characters between words: whitespace, ASCII punctuation (incl. "_"), Latin-1
# punctuation, general punctuation, arrows/symbols, CJK + fullwidth punctuation, and
# Arabic/Devanagari punctuation. Non-ASCII letters (and combining marks) are NOT
# separators, so Devanagari/Arabic words stay in one token.
_SEP_CLASS = (
    "\\s!-/:-@\\[-`{-~"
    "\\u00a0-\\u00a9\\u00ab-\\u00b4\\u00b6-\\u00b9\\u00bb-\\u00bf\\u00d7\\u00f7"
    "\\u2000-\\u206f\\u2190-\\u2bff\\u3000-\\u3004\\u3008-\\u3020\\u3030"
    "\\uff00-\\uff0f\\uff1a-\\uff20\\uff3b-\\uff40\\uff5b-\\uff65"
    "\\u060c\\u061b\\u061f\\u06d4\\u0964\\u0965"
)
_TOKEN_RE = re.compile("[^" + _SEP_CLASS + "]+")
_SPACELESS = ("CJK", "HIRAGANA", "KATAKANA", "HANGUL", "THAI", "LAO", "KHMER", "MYANMAR",
              "TIBETAN", "BOPOMOFO", "IDEOGRAPHIC", "HALFWIDTH KATAKANA")


@dataclass(frozen=True)
class LureHit:
    """One lure term found in text; ``start``/``end`` index the *original* string."""

    term: str
    lang: str
    category: str
    weight: float
    start: int
    end: int
    partial: bool = False   # glued into / stemmed from a longer token; weight discounted


@dataclass(frozen=True)
class _Term:
    term: str
    lang: str
    category: str
    weight: float


@dataclass(frozen=True)
class _Index:
    tokens: dict[str, tuple[tuple[tuple[str, ...], _Term], ...]]
    by_first_char: dict[str, tuple[tuple[str, _Term], ...]]
    first_char_re: re.Pattern[str] | None
    compound_re: re.Pattern[str] | None
    compound_terms: dict[str, _Term]
    stems: dict[str, _Term]
    stem_lengths: tuple[int, ...]
    languages: frozenset[str]
    count: int


def _fold(text: str) -> str:
    """Lower-case without changing length, so hit offsets stay valid in the original."""
    low = text.lower()
    if len(low) == len(text):
        return low
    return "".join(c.lower() if len(c.lower()) == 1 else c for c in text)


def _strip_accents(s: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFD", s) if not unicodedata.combining(c))


def _is_latin(s: str) -> bool:
    letters = [c for c in s if c.isalpha()]
    return bool(letters) and all(unicodedata.name(c, "").startswith("LATIN") for c in letters)


def _is_spaceless(s: str) -> bool:
    return any(unicodedata.name(c, "").startswith(_SPACELESS) for c in s)


def _best(table: dict, key, term: _Term) -> None:
    old = table.get(key)
    if old is None or term.weight > old.weight:
        table[key] = term


@lru_cache(maxsize=1)
def _index() -> _Index:
    data = load_yaml("lures.yaml")
    if not isinstance(data, dict):
        raise ValueError("lures.yaml: top level must be a mapping")
    cat_w, langs = data.get("category_weights"), data.get("languages")
    if not isinstance(cat_w, dict) or not isinstance(langs, dict) or not langs:
        raise ValueError("lures.yaml: need 'category_weights' and 'languages' mappings")
    for cat, w in cat_w.items():
        if isinstance(w, bool) or not isinstance(w, (int, float)) or not 0 < w <= 2:
            raise ValueError(f"lures.yaml: bad category weight {cat!r}: {w!r}")
    stem_langs = data.get("stem_languages", [])
    if not isinstance(stem_langs, list) or not set(stem_langs) <= set(langs):
        raise ValueError("lures.yaml: 'stem_languages' must list known language tags")

    token_idx: dict[str, dict[tuple[str, ...], _Term]] = {}
    substr: dict[str, dict[str, _Term]] = {}
    compounds: dict[str, _Term] = {}
    stems: dict[str, _Term] = {}
    count = 0
    for lang, cats in langs.items():
        if not isinstance(cats, dict):
            raise ValueError(f"lures.yaml: language {lang!r} must map categories to lists")
        for cat, items in cats.items():
            if cat not in cat_w or not isinstance(items, list):
                raise ValueError(f"lures.yaml: bad category {cat!r} under {lang!r}")
            for item in items:
                text, weight = (item.get("t"), item.get("w", cat_w[cat])) \
                    if isinstance(item, dict) else (item, cat_w[cat])
                if (not isinstance(text, str) or not text.strip() or text != text.strip().lower()
                        or isinstance(weight, bool) or not isinstance(weight, (int, float))
                        or not 0 < weight <= 2):
                    raise ValueError(f"lures.yaml: bad term {item!r} under {lang}/{cat}")
                term = _Term(text, lang, cat, float(weight))
                count += 1
                if _is_spaceless(text):
                    _best(substr.setdefault(text[0], {}), text, term)
                    continue
                forms = {text} | ({_strip_accents(text)} if _is_latin(text) else set())
                for form in forms:
                    toks = tuple(_TOKEN_RE.findall(form))
                    if not toks:
                        raise ValueError(f"lures.yaml: term {text!r} has no word characters")
                    _best(token_idx.setdefault(toks[0], {}), toks, term)
                    if len(toks) != 1:
                        continue
                    if (lang in _COMPOUND_LANGS and form.isascii() and form.isalnum()
                            and len(form) >= 5 and weight >= 0.5 and form not in _NO_COMPOUND):
                        _best(compounds, form, term)
                    if lang in stem_langs and len(form) >= _STEM_MIN:
                        _best(stems, form, term)

    tokens = {first: tuple(sorted(p.items(), key=lambda kv: -len(kv[0])))
              for first, p in token_idx.items()}
    by_first = {c: tuple(sorted(d.items(), key=lambda kv: -len(kv[0]))) for c, d in substr.items()}
    first_re = (re.compile("[" + "".join(re.escape(c) for c in sorted(by_first)) + "]")
                if by_first else None)
    comp_re = (re.compile("|".join(re.escape(t) for t in sorted(compounds, key=lambda s: -len(s))))
               if compounds else None)
    return _Index(tokens, by_first, first_re, comp_re, compounds, stems,
                  tuple(sorted({len(s) for s in stems})), frozenset(langs), count)


def lure_languages() -> frozenset[str]:
    """Language tags covered by the lexicon (includes ``und`` for language-neutral terms)."""
    return _index().languages


def lure_term_count() -> int:
    """Number of lexicon entries (before accent-variant expansion)."""
    return _index().count


def find_lures(text: str | None, *, max_chars: int = _DEFAULT_MAX_CHARS,
               max_hits: int = 512) -> list[LureHit]:
    """Find credential/urgency lure terms in a host, path, URL or short text.

    Linear time in ``len(text)``. Input beyond ``max_chars`` is ignored (attacker-
    controlled size). Hits are non-overlapping, sorted by ``start``, capped at
    ``max_hits``; ``start``/``end`` index the original ``text``.
    """
    if not text:
        return []
    text = text[:max(0, max_chars)]
    idx = _index()
    low = _fold(text)
    cand: list[tuple[int, int, _Term, bool]] = []

    toks = [(m.group(), m.start(), m.end()) for m in _TOKEN_RE.finditer(low)]
    n = len(toks)
    token_map, stems, compound_re = idx.tokens, idx.stems, idx.compound_re
    for i in range(n):
        tok, t_start, _ = toks[i]
        phrases = token_map.get(tok)
        if phrases is not None:
            for seq, term in phrases:
                m_len = len(seq)
                if i + m_len <= n and all(toks[i + k][0] == seq[k] for k in range(1, m_len)):
                    cand.append((t_start, toks[i + m_len - 1][2], term, False))
            continue
        if stems and len(tok) >= _STEM_MIN:
            for length in idx.stem_lengths:
                if length < len(tok):
                    term = stems.get(tok[:length])
                    if term is not None:
                        cand.append((t_start, t_start + length, term, True))
        if compound_re is not None and 5 <= len(tok) <= 64 and tok.isascii():
            for m in compound_re.finditer(tok):
                cand.append((t_start + m.start(), t_start + m.end(),
                             idx.compound_terms[m.group()], True))

    if idx.first_char_re is not None:
        for m in idx.first_char_re.finditer(low):
            i = m.start()
            for form, term in idx.by_first_char[low[i]]:
                if low.startswith(form, i):
                    cand.append((i, i + len(form), term, False))

    cand.sort(key=lambda c: (-(c[1] - c[0]), c[3], -c[2].weight, c[2].lang != "und", c[0]))
    taken = bytearray(len(low))
    hits: list[LureHit] = []
    for start, end, term, partial in cand:
        if taken.find(1, start, end) != -1:
            continue
        taken[start:end] = b"\x01" * (end - start)
        weight = term.weight * (_PARTIAL_DISCOUNT if partial else 1.0)
        hits.append(LureHit(term.term, term.lang, term.category, round(weight, 4),
                            start, end, partial))
    hits.sort(key=lambda h: h.start)
    return hits[:max_hits]
