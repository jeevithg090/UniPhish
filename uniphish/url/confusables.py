"""Unicode confusable *skeletons* and domain-squatting folds (UTS #39 §4).

Phishing's oldest multilingual trick is the *homoglyph*: a domain that is a different
byte sequence from the brand it imitates but renders identically — ``pаypal.com`` with a
Cyrillic ``а`` (U+0430), ``xn--80ak6aa92e.com`` which displays as ``аррӏе.com``. The
Unicode Consortium publishes, in `UTS #39 <https://www.unicode.org/reports/tr39/>`_, a
*confusables* table that maps every known look-alike code point to a canonical
*prototype*. Collapsing a string through that table yields its **skeleton**; two strings
are *confusable* exactly when their skeletons are equal.

This module implements the UTS #39 skeleton algorithm on top of the generated
``uniphish/assets/unicode/confusables.json.gz`` table (see ``scripts/gen_unicode_data.py``)
and adds the extra folds that catch ASCII *squatting* rather than pure homoglyphs — leet
substitutions (``g00gle``, ``paypa1``) and multi-glyph look-alikes (``rn`` → ``m`` so
``micrornicrosoft`` ... ``vv`` → ``w``). :func:`brand_skeleton` is the canonical form the
brand matcher compares against: everything that *looks* like ``paypal`` folds onto
``paypal``.

Everything here is pure, deterministic and offline; the data table is loaded once and
cached.
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

from uniphish.assets import load_json

_ASSET = ("unicode", "confusables.json.gz")


# --------------------------------------------------------------------------- #
# Table loading (lazy, cached)
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def _table() -> dict[int, str]:
    """``{source code point -> prototype string}`` from the packaged asset."""
    data = load_json(*_ASSET)
    out: dict[int, str] = {}
    for src_hex, proto_hex in data["map"].items():
        out[int(src_hex, 16)] = "".join(chr(int(cp, 16)) for cp in proto_hex.split())
    return out


@lru_cache(maxsize=1)
def _reverse_single() -> dict[str, tuple[str, ...]]:
    """``{single-ASCII prototype -> (confusable source chars...)}`` for lookalikes_of."""
    rev: dict[str, list[str]] = {}
    for src_cp, proto in _table().items():
        if len(proto) == 1 and proto.isascii() and proto.isprintable():
            rev.setdefault(proto, []).append(chr(src_cp))
    return {k: tuple(v) for k, v in rev.items()}


def unicode_version() -> str:
    """The Unicode version the confusables table was generated from."""
    return str(load_json(*_ASSET).get("version", "0.0.0"))


# --------------------------------------------------------------------------- #
# Skeleton (UTS #39 §4)
# --------------------------------------------------------------------------- #
def skeleton(s: str) -> str:
    """The UTS #39 confusable skeleton of ``s``.

    Algorithm: NFD-decompose, replace every code point by its confusable prototype,
    then NFD-decompose again. Two strings render confusably iff their skeletons match.
    The upstream table is transitively closed, so a single mapping pass is exact.
    """
    if not s:
        return ""
    table = _table()
    decomposed = unicodedata.normalize("NFD", s)
    mapped = "".join(table.get(ord(ch), ch) for ch in decomposed)
    return unicodedata.normalize("NFD", mapped)


def are_confusable(a: str, b: str) -> bool:
    """True if ``a`` and ``b`` have the same confusable skeleton."""
    return skeleton(a) == skeleton(b)


# --------------------------------------------------------------------------- #
# Squatting folds (leet + multi-glyph) on top of the skeleton
# --------------------------------------------------------------------------- #
# Single-character leet / symbol substitutions, applied after the skeleton so that
# look-alike digits and '@' collapse onto the letters they imitate.
_LEET = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a",
})
# Multi-glyph look-alikes. Applied case-insensitively (brand matching lower-cases
# afterwards); each pattern is a fixed literal, so matching is linear and ReDoS-free.
_MULTI = [
    (re.compile("rn", re.IGNORECASE), "m"),
    (re.compile("vv", re.IGNORECASE), "w"),
    (re.compile("cl", re.IGNORECASE), "d"),
]


def ascii_fold(s: str) -> str:
    """:func:`skeleton` plus extra squatting folds (leet digits, ``rn``→``m`` …).

    Use this (via :func:`brand_skeleton`) for brand look-alike matching, where an
    attacker may mix homoglyphs with ASCII tricks (``раyра1`` → ``paypal``). Not a
    security-identity function — it deliberately over-folds to catch impersonation.
    """
    out = skeleton(s)
    for rx, repl in _MULTI:
        out = rx.sub(repl, out)
    return out.translate(_LEET)


def brand_skeleton(s: str) -> str:
    """Canonical lower-case fold used for brand impersonation matching."""
    return ascii_fold(s).lower()


# --------------------------------------------------------------------------- #
# Inspection helpers
# --------------------------------------------------------------------------- #
def lookalikes_of(ascii_char: str) -> list[str]:
    """Unicode characters whose skeleton is the single ASCII character ``ascii_char``.

    For defensive permutation / fixture generation (building look-alike test domains),
    never for producing attack payloads. Returns an empty list for inputs with no
    known single-character confusables.
    """
    if len(ascii_char) != 1:
        raise ValueError("lookalikes_of expects a single character")
    return list(_reverse_single().get(ascii_char, ()))


def confusable_chars_in(s: str) -> list[tuple[int, str, str]]:
    """Every non-ASCII character in ``s`` that imitates printable ASCII.

    Returns ``(index, char, looks_like_ascii)`` tuples, where ``looks_like_ascii`` is
    the character's ASCII skeleton (e.g. the Cyrillic ``а`` in ``pаypal`` yields
    ``(1, 'а', 'a')``). Indices point into the original string.
    """
    out: list[tuple[int, str, str]] = []
    table = _table()
    for i, ch in enumerate(s):
        if ord(ch) < 0x80:
            continue
        proto = table.get(ord(ch))
        if proto is None:
            # Fall back to the full skeleton to catch decomposable look-alikes.
            proto = skeleton(ch)
        if proto and proto.isascii() and proto.isprintable() and proto.strip():
            out.append((i, ch, proto))
    return out
