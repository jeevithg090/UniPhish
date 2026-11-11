"""Unicode script resolution, restriction levels and invisible/bidi/tag detectors.

Where :mod:`uniphish.url.confusables` answers "does this *look* like that?", this module
answers "is this label *plausibly* a single human language, or is it a Frankenstein of
scripts stitched together to spoof?". It implements:

* the UAX #24 **Script** and **Script_Extensions** properties,
* the UTS #39 **augmented script sets** (so a legitimate Japanese ``漢字かな`` or Korean
  ``한국어`` mixture resolves to a single logical script instead of looking "mixed"),
* UTS #39 **restriction levels** (ASCII-only → single-script → Latin+CJK → … →
  unrestricted) and the **Identifier_Status** (Allowed / Restricted) property,
* detectors for the invisible and formatting characters that hide spoofing from the eye:
  zero-width joiners, variation selectors, soft hyphens, Hangul fillers
  (:func:`find_invisible`); the RTL/LTR override "Trojan Source" controls
  (:func:`find_bidi_controls`); and the U+E00xx **Tags** block used for "ASCII smuggling"
  of hidden instructions into text an AI agent reads (:func:`decode_tag_chars`).

All lookups are backed by the generated, range-compressed assets under
``uniphish/assets/unicode/`` and are pure and offline.
"""

from __future__ import annotations

import bisect
import unicodedata
from enum import Enum
from functools import lru_cache

from uniphish.assets import load_json
from uniphish.url import confusables

_SCRIPTS_ASSET = ("unicode", "scripts.json.gz")
_IDENT_ASSET = ("unicode", "identifier_status.json.gz")

# Script short codes with special meaning.
COMMON = "Zyyy"
INHERITED = "Zinh"
UNKNOWN = "Zzzz"
_NON_CONSTRAINING = frozenset({COMMON, INHERITED})


class RestrictionLevel(str, Enum):
    """UTS #39 §5.2 restriction levels, most to least restrictive."""

    ASCII_ONLY = "ASCII_ONLY"
    SINGLE_SCRIPT = "SINGLE_SCRIPT"
    HIGHLY_RESTRICTIVE = "HIGHLY_RESTRICTIVE"
    MODERATELY_RESTRICTIVE = "MODERATELY_RESTRICTIVE"
    MINIMALLY_RESTRICTIVE = "MINIMALLY_RESTRICTIVE"
    UNRESTRICTED = "UNRESTRICTED"


# --------------------------------------------------------------------------- #
# Range-table loading (lazy, cached) + bisection lookup
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def _script_ranges() -> tuple[list[int], list[list[object]]]:
    data = load_json(*_SCRIPTS_ASSET)
    ranges = data["scripts"]
    return [r[0] for r in ranges], ranges


@lru_cache(maxsize=1)
def _ext_ranges() -> tuple[list[int], list[list[object]]]:
    data = load_json(*_SCRIPTS_ASSET)
    ranges = data["extensions"]
    return [r[0] for r in ranges], ranges


@lru_cache(maxsize=1)
def _allowed_ranges() -> tuple[list[int], list[list[int]]]:
    data = load_json(*_IDENT_ASSET)
    ranges = data["allowed"]
    return [r[0] for r in ranges], ranges


@lru_cache(maxsize=1)
def _script_names() -> dict[str, str]:
    """Short ISO-15924 code -> long Unicode script name (e.g. ``Cyrl`` -> ``Cyrillic``)."""
    return dict(load_json(*_SCRIPTS_ASSET).get("names", {}))


def _range_value(cp: int, starts: list[int], ranges: list) -> object | None:
    i = bisect.bisect_right(starts, cp) - 1
    if i >= 0 and ranges[i][0] <= cp <= ranges[i][1]:
        return ranges[i][2] if len(ranges[i]) > 2 else True
    return None


def unicode_version() -> str:
    """The Unicode version the script tables were generated from."""
    return str(load_json(*_SCRIPTS_ASSET).get("version", "0.0.0"))


# --------------------------------------------------------------------------- #
# Script / Script_Extensions / Identifier_Status
# --------------------------------------------------------------------------- #
def script_of(ch: str) -> str:
    """ISO-15924 short code of ``ch``'s primary Script property (``Zzzz`` if unassigned)."""
    val = _range_value(ord(ch[0]), *_script_ranges())
    return str(val) if val is not None else UNKNOWN


def script_name(short: str) -> str:
    """Human-readable script name for a short code (``Cyrl`` -> ``Cyrillic``)."""
    return _script_names().get(short, short)


def script_extensions(ch: str) -> list[str]:
    """Script_Extensions of ``ch`` as short codes, falling back to its primary script."""
    val = _range_value(ord(ch[0]), *_ext_ranges())
    if val is not None:
        return list(val)  # type: ignore[arg-type]
    return [script_of(ch)]


def identifier_status(ch: str) -> str:
    """UTS #39 Identifier_Status: ``"allowed"`` or ``"restricted"``."""
    if _range_value(ord(ch[0]), *_allowed_ranges()) is not None:
        return "allowed"
    return "restricted"


# --------------------------------------------------------------------------- #
# Augmented script sets + resolved script set (UTS #39 §5.1)
# --------------------------------------------------------------------------- #
def _augment(scripts: set[str]) -> set[str]:
    """Add the UTS #39 composite scripts (Jpan/Kore/Hanb) implied by a script set."""
    s = set(scripts)
    if "Hani" in s:
        s |= {"Hanb", "Jpan", "Kore"}
    if "Hira" in s or "Kana" in s:
        s.add("Jpan")
    if "Hang" in s:
        s.add("Kore")
    if "Bopo" in s:
        s.add("Hanb")
    return s


def _augmented_for_char(ch: str) -> set[str] | None:
    """Augmented script set of a single character; ``None`` means "all scripts".

    Characters whose only script is Common or Inherited do not constrain the script of
    the string they sit in, so they are represented by the universal set (``None``).
    """
    exts = script_extensions(ch)
    if all(e in _NON_CONSTRAINING for e in exts):
        return None
    return _augment({e for e in exts if e not in _NON_CONSTRAINING})


def _resolved(s: str) -> set[str] | None:
    """Resolved script set (intersection of augmented sets); ``None`` = universal.

    An empty *set* means the string is genuinely mixed-script. ``None`` means every
    character was script-neutral (Common/Inherited, e.g. digits and punctuation).
    """
    result: set[str] | None = None
    for ch in s:
        aug = _augmented_for_char(ch)
        if aug is None:
            continue
        result = set(aug) if result is None else (result & aug)
    return result


def resolved_script_set(s: str) -> frozenset[str]:
    """The UTS #39 resolved script set of ``s`` (empty for mixed or script-neutral)."""
    r = _resolved(s)
    return frozenset(r) if r else frozenset()


def is_mixed_script(s: str) -> bool:
    """True if ``s`` combines scripts that no single (augmented) script covers."""
    r = _resolved(s)
    return r is not None and len(r) == 0


def _primary_scripts(s: str) -> set[str]:
    """Concrete primary scripts present (ASCII letters counted as Latin)."""
    present: set[str] = set()
    for ch in s:
        if ch.isascii():
            if ch.isalpha():
                present.add("Latn")
            continue
        sc = script_of(ch)
        if sc not in _NON_CONSTRAINING and sc != UNKNOWN:
            present.add(sc)
    return present


# Latin + one CJK family — the only cross-script mixtures UTS #39 calls Highly Restrictive.
_HIGHLY_RESTRICTIVE_COMBOS = (
    {"Latn", "Hani", "Hira", "Kana"},
    {"Latn", "Hani", "Hira"},
    {"Latn", "Hani", "Kana"},
    {"Latn", "Hani", "Bopo"},
    {"Latn", "Hani", "Hang"},
)
_CONFUSABLE_WITH_LATIN = frozenset({"Cyrl", "Grek"})


def restriction_level(s: str) -> RestrictionLevel:
    """Classify ``s`` by UTS #39 restriction level (used to judge mixed-script risk)."""
    if s == "":
        return RestrictionLevel.ASCII_ONLY
    if all(ord(c) < 0x80 for c in s):
        return RestrictionLevel.ASCII_ONLY
    # Any Restricted identifier character drops the whole string to Unrestricted.
    if any(ord(c) >= 0x80 and identifier_status(c) == "restricted" for c in s):
        return RestrictionLevel.UNRESTRICTED

    r = _resolved(s)
    if r is None or len(r) >= 1:
        # Covered by at least one script (or entirely script-neutral) -> single script.
        return RestrictionLevel.SINGLE_SCRIPT

    present = _primary_scripts(s)
    if any(present <= combo for combo in _HIGHLY_RESTRICTIVE_COMBOS):
        return RestrictionLevel.HIGHLY_RESTRICTIVE
    others = present - {"Latn"}
    if "Latn" in present and len(others) == 1 and others.isdisjoint(_CONFUSABLE_WITH_LATIN):
        return RestrictionLevel.MODERATELY_RESTRICTIVE
    return RestrictionLevel.MINIMALLY_RESTRICTIVE


def whole_script_confusable(label: str) -> bool:
    """True if ``label`` is a single non-Latin script that renders as plain Latin.

    The classic whole-script homograph: an all-Cyrillic label whose confusable skeleton
    is pure ASCII Latin (``раураӏ`` → ``paypal``). A Greek or Cyrillic word containing a
    character with no Latin look-alike is *not* whole-script-confusable.
    """
    if not label or label.isascii():
        return False
    r = _resolved(label)
    if r is None or len(r) != 1:
        return False
    if next(iter(r)) == "Latn":
        return False
    sk = confusables.skeleton(label)
    return bool(sk) and sk.isascii() and sk.isprintable() and any(c.isalpha() for c in sk)


# --------------------------------------------------------------------------- #
# Invisible / formatting / bidi / tag-smuggling detectors
# --------------------------------------------------------------------------- #
# Zero-width, formatting and filler characters that can hide or alter apparent text.
_INVISIBLE: dict[int, str] = {
    0x00AD: "SOFT HYPHEN",
    0x034F: "COMBINING GRAPHEME JOINER",
    0x061C: "ARABIC LETTER MARK",
    0x115F: "HANGUL CHOSEONG FILLER",
    0x1160: "HANGUL JUNGSEONG FILLER",
    0x17B4: "KHMER VOWEL INHERENT AQ",
    0x17B5: "KHMER VOWEL INHERENT AA",
    0x180B: "MONGOLIAN FREE VARIATION SELECTOR ONE",
    0x180C: "MONGOLIAN FREE VARIATION SELECTOR TWO",
    0x180D: "MONGOLIAN FREE VARIATION SELECTOR THREE",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0x206A: "INHIBIT SYMMETRIC SWAPPING",
    0x206B: "ACTIVATE SYMMETRIC SWAPPING",
    0x206C: "INHIBIT ARABIC FORM SHAPING",
    0x206D: "ACTIVATE ARABIC FORM SHAPING",
    0x206E: "NATIONAL DIGIT SHAPES",
    0x206F: "NOMINAL DIGIT SHAPES",
    0x2800: "BRAILLE PATTERN BLANK",
    0x3164: "HANGUL FILLER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
    0xFFA0: "HALFWIDTH HANGUL FILLER",
}


def _is_variation_selector(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def find_invisible(s: str) -> list[tuple[int, int, str]]:
    """Invisible / zero-width / filler characters in ``s``.

    Returns ``(index, codepoint, name)`` for each. Any hit on a hostname or a piece of
    text an agent will act on is suspicious: these characters are invisible to a human
    but split tokens, defeat string comparisons and smuggle structure.
    """
    out: list[tuple[int, int, str]] = []
    for i, ch in enumerate(s):
        cp = ord(ch)
        if cp in _INVISIBLE:
            out.append((i, cp, _INVISIBLE[cp]))
        elif _is_variation_selector(cp):
            out.append((i, cp, _char_name(cp, "VARIATION SELECTOR")))
    return out


# Bidirectional formatting controls — the "Trojan Source" / RTLO reordering set.
_BIDI_CONTROLS: dict[int, str] = {
    0x061C: "ARABIC LETTER MARK",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
}


def find_bidi_controls(s: str) -> list[tuple[int, int, str]]:
    """Bidirectional override/isolate controls in ``s`` ('Trojan Source' / RTLO spoofing)."""
    return [(i, ord(ch), _BIDI_CONTROLS[ord(ch)])
            for i, ch in enumerate(s) if ord(ch) in _BIDI_CONTROLS]


_TAG_BASE = 0xE0000
_TAG_SPACE = 0xE0020
_TAG_END = 0xE007E
_TAG_CANCEL = 0xE007F
_TAG_LANG = 0xE0001


def decode_tag_chars(s: str) -> str | None:
    """Decode hidden ASCII carried in the Unicode Tags block (U+E0000..E007F).

    The Tags block maps one-to-one onto ASCII and is invisible when rendered, so it is
    used for "ASCII smuggling": hiding instructions (e.g. a prompt injection aimed at an
    AI agent) inside otherwise innocent-looking text. Returns the decoded ASCII string,
    or ``None`` if ``s`` contains no tag characters.
    """
    decoded: list[str] = []
    found = False
    for ch in s:
        cp = ord(ch)
        if _TAG_SPACE <= cp <= _TAG_END:
            decoded.append(chr(cp - _TAG_BASE))
            found = True
        elif cp in (_TAG_CANCEL, _TAG_LANG) or _TAG_BASE <= cp <= _TAG_CANCEL:
            found = True  # tag control char (language tag / cancel / reserved)
    return "".join(decoded) if found else None


def has_combining_on_latin(s: str) -> bool:
    """True if a combining mark is applied to a Latin base (disallowed IDN pattern)."""
    prev_latin = False
    for ch in s:
        if unicodedata.combining(ch):
            if prev_latin:
                return True
            continue
        prev_latin = ch.isascii() and ch.isalpha() or script_of(ch) == "Latn"
    return False


def _char_name(cp: int, fallback: str) -> str:
    try:
        return unicodedata.name(chr(cp))
    except ValueError:
        return f"{fallback} U+{cp:04X}"
