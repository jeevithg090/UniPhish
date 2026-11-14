"""Look-alike domain permutation engine (a dnstwist-class generator).

This is a **defensive** tool: given a domain *you own or protect* (``paypal.com`` for the
PayPal brand team, ``acme.example`` for a company's own security team) it enumerates the
registrable look-alikes an attacker is most likely to register, so that they can be
watched, blocked pre-emptively or taken down.  It never touches the network; liveness
checks live in :mod:`uniphish.hunt.brandwatch`.

Permutation kinds (``Permutation.kind``)
----------------------------------------
``homoglyph``      one or two characters swapped for a visually confusable one (Cyrillic
                   ``а``, Greek ``ο``, ASCII ``1``/``0``, multi-glyph ``rn`` for ``m`` ...).
                   Non-ASCII results are returned in their IDNA A-label (``xn--``) form.
``idn_homograph``  as many characters as possible replaced from *one* foreign script
                   (the classic whole-script Cyrillic / Greek / Armenian spoof).
``bitsquat``       a single flipped bit in one ASCII character of the label.
``typo``           keyboard-adjacent insertion, replacement and adjacent transposition.
``omission``       one character dropped.
``addition``       one character (or ``www``) added at the end / start.
``double_char``    one character repeated.
``vowel_swap``     one vowel replaced by another vowel.
``hyphenation``    a hyphen inserted between two characters.
``subdomain``      a dot inserted inside the label (``pay.pal.com``).
``combosquat``     brand plus a credential / support keyword (``paypal-secure.com``).
``tld_swap``       the same label under another (abused or common) TLD.

Guarantees: output is de-duplicated, never contains the input domain, is bounded by
``max`` (kinds are sampled round-robin so rare kinds are never starved by large ones),
is deterministic, and every entry is a syntactically valid hostname (LDH labels or valid
IDNA A-labels, total length <= 253).  Keyword and TLD data come from
``assets/lures.yaml`` and ``assets/tlds.yaml``, not from this file.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from functools import lru_cache

import idna

from uniphish.assets import load_yaml
from uniphish.url.brands import split_host
from uniphish.url.confusables import lookalikes_of
from uniphish.url.parse import parse_url
from uniphish.url.scripts import script_of

log = logging.getLogger("uniphish.hunt")

__all__ = [
    "DEFAULT_MAX",
    "KINDS",
    "Permutation",
    "generate_permutations",
    "normalize_kinds",
    "split_domain",
]

#: Kinds in priority order: when two kinds yield the same domain the earlier one wins.
KINDS: tuple[str, ...] = (
    "homoglyph",
    "idn_homograph",
    "bitsquat",
    "typo",
    "omission",
    "addition",
    "double_char",
    "vowel_swap",
    "hyphenation",
    "subdomain",
    "combosquat",
    "tld_swap",
)
DEFAULT_MAX = 2000
_MAX_INPUT_LEN = 253
_MAX_LABEL = 63
_MAX_SLD_LEN = 40  # permuting very long labels explodes output for no benefit
_KIND_CAPS: dict[str, int] = {
    "homoglyph": 400,
    "idn_homograph": 12,
    "bitsquat": 200,
    "typo": 800,
    "omission": 80,
    "addition": 120,
    "double_char": 80,
    "vowel_swap": 60,
    "hyphenation": 60,
    "subdomain": 60,
    "combosquat": 240,
    "tld_swap": 200,
}
_ALLOWED_SCRIPTS = ("Cyrl", "Grek", "Latn", "Armn")  # preference order for look-alikes
_PER_CHAR_LOOKALIKES = 8
_WHOLE_SCRIPTS = ("Cyrl", "Grek", "Armn")
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_VOWELS = "aeiou"

# ASCII-only visual / leet confusions (source substring -> replacements).
_ASCII_CONFUSIONS: dict[str, tuple[str, ...]] = {
    "o": ("0",),
    "l": ("1", "i"),
    "i": ("1", "l"),
    "e": ("3",),
    "a": ("4",),
    "s": ("5",),
    "t": ("7",),
    "b": ("8",),
    "g": ("9", "q"),
    "q": ("g",),
    "m": ("rn",),
    "w": ("vv",),
    "d": ("cl",),
    "u": ("v",),
    "v": ("u",),
    "n": ("m",),
    "1": ("l", "i"),
    "0": ("o",),
}
_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")
_CORE_KEYWORDS: tuple[str, ...] = (
    "login",
    "secure",
    "support",
    "verify",
    "account",
    "online",
    "service",
    "update",
    "billing",
    "wallet",
    "help",
    "official",
    "app",
    "pay",
    "mail",
    "portal",
    "signin",
    "security",
    "id",
    "my",
)
_LURE_CATEGORIES = ("credential", "account", "security", "financial", "delivery", "identity")
_COMMON_TLDS: tuple[str, ...] = (
    "com",
    "net",
    "org",
    "co",
    "io",
    "info",
    "biz",
    "us",
    "uk",
    "co.uk",
    "de",
    "fr",
    "ru",
    "cn",
    "in",
    "br",
    "app",
    "online",
    "site",
    "shop",
    "store",
    "live",
    "cc",
    "me",
    "tv",
)


@dataclass(frozen=True, slots=True)
class Permutation:
    """One generated look-alike domain.

    ``domain`` is always the ASCII (IDNA A-label) form so it is valid in DNS and safe to
    log or store; :attr:`display` is the Unicode form an end user would see.
    """

    domain: str
    kind: str
    note: str = ""

    @property
    def display(self) -> str:
        """Unicode (U-label) form of :attr:`domain`; falls back to ``domain``."""
        try:
            return idna.decode(self.domain)
        except (idna.IDNAError, UnicodeError):
            return self.domain

    def to_dict(self) -> dict[str, str]:
        return {
            "domain": self.domain,
            "display": self.display,
            "kind": self.kind,
            "note": self.note,
        }


# --------------------------------------------------------------------------- #
# Input handling
# --------------------------------------------------------------------------- #
def normalize_kinds(kinds: Iterable[str] | str | None) -> tuple[str, ...]:
    """Validate ``kinds`` (``None`` = all) and return them in canonical priority order.

    Accepts hyphenated spellings (``tld-swap``) and the alias ``"all"``.
    """
    if kinds is None:
        return KINDS
    items = [kinds] if isinstance(kinds, str) else list(kinds)
    wanted: set[str] = set()
    for k in items:
        name = str(k).strip().lower().replace("-", "_")
        if name == "all":
            return KINDS
        if name not in KINDS:
            raise ValueError(f"unknown permutation kind {k!r}; valid: {', '.join(KINDS)}")
        wanted.add(name)
    return tuple(k for k in KINDS if k in wanted)


def split_domain(domain: str) -> tuple[str, str]:
    """Return ``(sld, suffix)`` of ``domain`` in Unicode form.

    Accepts a bare host, a host with sub-domains or a URL; sub-domains are dropped
    (look-alikes are registered at the registrable level).  Raises ``ValueError`` for
    empty / IP / single-label / over-long input.
    """
    raw = (domain or "").strip()
    if not raw or len(raw) > _MAX_INPUT_LEN * 2:
        raise ValueError("domain must be a non-empty hostname")
    p = parse_url(raw if "://" in raw else "http://" + raw)
    if not p.valid or p.is_ip:
        raise ValueError(f"not a permutable domain name: {domain!r}")
    parts = split_host(p)
    if not parts.sld or not parts.suffix:
        raise ValueError(f"domain needs a label and a TLD: {domain!r}")
    return parts.sld, parts.suffix


# --------------------------------------------------------------------------- #
# Validation / encoding
# --------------------------------------------------------------------------- #
def _alabel(label: str) -> str | None:
    """ASCII form of one label, or ``None`` if it is not a valid DNS / IDNA label."""
    if not label or len(label) > _MAX_LABEL * 4:
        return None
    if label.isascii():
        return label if _LABEL_RE.match(label) else None
    try:
        out = idna.alabel(label).decode("ascii")
    except (idna.IDNAError, UnicodeError, ValueError):
        return None
    return out if len(out) <= _MAX_LABEL and _LABEL_RE.match(out) else None


def _assemble(sld: str, suffix: str) -> str | None:
    """Join a (possibly dotted / Unicode) sld with ``suffix`` into a valid ASCII domain."""
    labels: list[str] = []
    for lab in sld.split("."):
        a = _alabel(lab)
        if a is None:
            return None
        labels.append(a)
    suf: list[str] = []
    for lab in suffix.split("."):
        a = _alabel(lab)
        if a is None:
            return None
        suf.append(a)
    if not _TLD_RE.match(suf[-1]):
        return None
    out = ".".join(labels + suf)
    return out if len(out) <= _MAX_INPUT_LEN else None


# --------------------------------------------------------------------------- #
# Data (assets)
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def _keywords() -> tuple[str, ...]:
    """Combosquat keywords: a small core set, then lure-lexicon terms by weight."""
    out: list[str] = list(_CORE_KEYWORDS)
    try:
        data = load_yaml("lures.yaml")
        weights = data.get("category_weights", {}) or {}
        langs = data.get("languages", {}) or {}
        scored: list[tuple[float, str]] = []
        for lang in ("und", "en"):
            for cat in _LURE_CATEGORIES:
                for item in (langs.get(lang, {}) or {}).get(cat, []) or []:
                    term, w = (
                        (item, weights.get(cat, 0.5))
                        if isinstance(item, str)
                        else (item.get("t", ""), item.get("w", weights.get(cat, 0.5)))
                    )
                    term = str(term).lower().replace("-", "")
                    if 3 <= len(term) <= 14 and term.isascii() and term.isalnum():
                        scored.append((-float(w), term))
        for _w, term in sorted(scored):
            if term not in out:
                out.append(term)
    except Exception as exc:  # data problem must not disable the generator
        log.warning("lures.yaml unusable for combosquat keywords: %s", exc)
    return tuple(out[:40])


@lru_cache(maxsize=1)
def _swap_tlds() -> tuple[str, ...]:
    """Abused TLDs from ``tlds.yaml`` (riskiest first) followed by common TLDs."""
    risky: list[tuple[float, str]] = []
    try:
        table = (load_yaml("tlds.yaml") or {}).get("tlds", {}) or {}
        for tld, spec in table.items():
            risk = float(spec.get("risk", 0.0)) if isinstance(spec, dict) else 0.0
            risky.append((-risk, str(tld)))
    except Exception as exc:
        log.warning("tlds.yaml unusable for tld-swap: %s", exc)
    out = [t for _r, t in sorted(risky)]
    out.extend(t for t in _COMMON_TLDS if t not in out)
    return tuple(out)


@lru_cache(maxsize=256)
def _safe_lookalikes(ch: str) -> tuple[str, ...]:
    """Non-ASCII look-alikes of ``ch`` that are IDNA-valid, preferred scripts first."""
    try:
        cands = lookalikes_of(ch)
    except ValueError:
        return ()
    ranked: list[tuple[int, str]] = []
    for c in cands:
        if c.isascii():
            continue
        sc = script_of(c)
        if sc not in _ALLOWED_SCRIPTS or _alabel("x" + c + "x") is None:
            continue
        ranked.append((_ALLOWED_SCRIPTS.index(sc), c))
    ranked.sort()
    return tuple(c for _i, c in ranked[:_PER_CHAR_LOOKALIKES])


@lru_cache(maxsize=1)
def _neighbors() -> dict[str, str]:
    """QWERTY adjacency (same row +-1, adjacent rows) as ``{char: neighbours}``."""
    out: dict[str, str] = {}
    for r, row in enumerate(_ROWS):
        for i, ch in enumerate(row):
            near = set(row[max(0, i - 1) : i] + row[i + 1 : i + 2])
            if r > 0:  # row above: keys at i and i+1
                near.update(_ROWS[r - 1][i : i + 2])
            if r + 1 < len(_ROWS):  # row below: keys at i-1 and i
                near.update(_ROWS[r + 1][max(0, i - 1) : i + 1])
            out[ch] = "".join(sorted(near))
    return out


# --------------------------------------------------------------------------- #
# Generators (each yields (sld_text, note); suffix handled by the caller)
# --------------------------------------------------------------------------- #
def _gen_homoglyph(sld: str, suffix: str) -> Iterator[tuple[str, str, str]]:
    # single substitutions: Unicode look-alikes first (the most dangerous), then ASCII
    for i, ch in enumerate(sld):
        for repl in _safe_lookalikes(ch):
            yield sld[:i] + repl + sld[i + 1 :], suffix, f"{ch!r}->U+{ord(repl):04X} at {i}"
    for i, ch in enumerate(sld):
        for repl in _ASCII_CONFUSIONS.get(ch, ()):
            yield sld[:i] + repl + sld[i + 1 :], suffix, f"{ch!r}->{repl!r} (ASCII look-alike)"
    # confusable multi-glyph sequences in the other direction (rn -> m, vv -> w, cl -> d)
    for seq, repl in (("rn", "m"), ("vv", "w"), ("cl", "d")):
        start = sld.find(seq)
        while start != -1:
            yield sld[:start] + repl + sld[start + len(seq) :], suffix, f"{seq!r}->{repl!r}"
            start = sld.find(seq, start + 1)
    # double substitutions with the preferred (first) look-alike per character
    firsts = [(i, _safe_lookalikes(ch)[:1]) for i, ch in enumerate(sld)]
    firsts = [(i, f[0]) for i, f in firsts if f]
    for a in range(len(firsts)):
        for b in range(a + 1, len(firsts)):
            (i, ri), (j, rj) = firsts[a], firsts[b]
            chars = list(sld)
            chars[i], chars[j] = ri, rj
            yield "".join(chars), suffix, f"two look-alikes at {i} and {j}"


def _gen_idn_homograph(sld: str, suffix: str) -> Iterator[tuple[str, str, str]]:
    for script in _WHOLE_SCRIPTS:
        chars: list[str] = []
        replaced = 0
        letters = 0
        for ch in sld:
            if ch.isalpha():
                letters += 1
            alt = next((c for c in _safe_lookalikes(ch) if script_of(c) == script), None)
            if alt is not None:
                chars.append(alt)
                replaced += 1
            else:
                chars.append(ch)
        if replaced >= 2:
            scope = "whole-script" if replaced >= letters else f"{replaced}/{letters} letters"
            yield "".join(chars), suffix, f"{script} homograph ({scope})"


def _gen_bitsquat(sld: str, suffix: str) -> Iterator[tuple[str, str, str]]:
    for i, ch in enumerate(sld):
        if not ch.isascii():
            continue
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit)).lower()
            if flipped != ch and flipped in _ALPHABET + "-":
                yield sld[:i] + flipped + sld[i + 1 :], suffix, f"bit {bit} of {ch!r} at {i}"


def _gen_typo(sld: str, suffix: str) -> Iterator[tuple[str, str, str]]:
    near = _neighbors()
    for i, ch in enumerate(sld):  # replacement
        for n in near.get(ch, ""):
            yield sld[:i] + n + sld[i + 1 :], suffix, f"{ch!r} replaced by adjacent key {n!r}"
    for i in range(len(sld) - 1):  # transposition
        if sld[i] != sld[i + 1]:
            yield (
                sld[:i] + sld[i + 1] + sld[i] + sld[i + 2 :],
                suffix,
                f"transposed {sld[i : i + 2]!r}",
            )
    for i, ch in enumerate(sld):  # insertion next to a key
        for n in near.get(ch, ""):
            yield sld[:i] + n + sld[i:], suffix, f"inserted adjacent key {n!r} before {i}"
            yield sld[: i + 1] + n + sld[i + 1 :], suffix, f"inserted adjacent key {n!r} after {i}"


def _gen_omission(sld: str, suffix: str) -> Iterator[tuple[str, str, str]]:
    for i, ch in enumerate(sld):
        yield sld[:i] + sld[i + 1 :], suffix, f"omitted {ch!r} at {i}"


def _gen_addition(sld: str, suffix: str) -> Iterator[tuple[str, str, str]]:
    for c in _ALPHABET:
        yield sld + c, suffix, f"appended {c!r}"
    for pre in ("www", "ww", "w", "my", "e"):
        yield pre + sld, suffix, f"prefixed {pre!r}"
    yield sld + "s", suffix, "plural"


def _gen_double_char(sld: str, suffix: str) -> Iterator[tuple[str, str, str]]:
    for i, ch in enumerate(sld):
        yield sld[: i + 1] + ch + sld[i + 1 :], suffix, f"repeated {ch!r} at {i}"


def _gen_vowel_swap(sld: str, suffix: str) -> Iterator[tuple[str, str, str]]:
    for i, ch in enumerate(sld):
        if ch in _VOWELS:
            for v in _VOWELS:
                if v != ch:
                    yield sld[:i] + v + sld[i + 1 :], suffix, f"vowel {ch!r}->{v!r} at {i}"


def _gen_hyphenation(sld: str, suffix: str) -> Iterator[tuple[str, str, str]]:
    for i in range(1, len(sld)):
        if sld[i - 1] != "-" and sld[i] != "-":
            yield sld[:i] + "-" + sld[i:], suffix, f"hyphen at {i}"


def _gen_subdomain(sld: str, suffix: str) -> Iterator[tuple[str, str, str]]:
    for i in range(1, len(sld)):
        if sld[i - 1] != "-" and sld[i] != "-":
            yield sld[:i] + "." + sld[i:], suffix, f"dot at {i}"


def _gen_combosquat(sld: str, suffix: str) -> Iterator[tuple[str, str, str]]:
    for kw in _keywords():
        if kw in sld:
            continue
        yield f"{sld}-{kw}", suffix, f"brand-{kw}"
        yield f"{sld}{kw}", suffix, f"brand{kw}"
        yield f"{kw}-{sld}", suffix, f"{kw}-brand"
        yield f"{kw}{sld}", suffix, f"{kw}brand"


def _gen_tld_swap(sld: str, suffix: str) -> Iterator[tuple[str, str, str]]:
    for tld in _swap_tlds():
        if tld != suffix:
            yield sld, tld, f"TLD .{suffix} -> .{tld}"


_GENERATORS = {
    "homoglyph": _gen_homoglyph,
    "idn_homograph": _gen_idn_homograph,
    "bitsquat": _gen_bitsquat,
    "typo": _gen_typo,
    "omission": _gen_omission,
    "addition": _gen_addition,
    "double_char": _gen_double_char,
    "vowel_swap": _gen_vowel_swap,
    "hyphenation": _gen_hyphenation,
    "subdomain": _gen_subdomain,
    "combosquat": _gen_combosquat,
    "tld_swap": _gen_tld_swap,
}


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def generate_permutations(
    domain: str, *, kinds: Iterable[str] | str | None = None, max: int = DEFAULT_MAX
) -> list[Permutation]:
    """Generate look-alike domains of ``domain`` for defensive monitoring.

    ``kinds`` restricts the techniques (default: all, see :data:`KINDS`); ``max`` bounds
    the result (``<= 0`` gives ``[]``).  The exact input domain is never returned and
    every domain appears once, tagged with the highest-priority requested kind that
    produced it.
    When more than ``max`` candidates exist, kinds are sampled round-robin so every
    requested kind is represented.  Raises ``ValueError`` for an invalid ``domain`` or
    an unknown kind.
    """
    chosen = normalize_kinds(kinds)
    sld, suffix = split_domain(domain)
    limit = int(max)
    if limit <= 0:
        return []
    if len(sld) > _MAX_SLD_LEN:
        sld_work = sld[:_MAX_SLD_LEN]
        log.debug("label %r truncated to %d chars for permutation", sld, _MAX_SLD_LEN)
    else:
        sld_work = sld
    original = _assemble(sld, suffix)
    if original is None:
        raise ValueError(f"domain is not a valid hostname: {domain!r}")

    seen: set[str] = {original}
    per_kind: dict[str, list[Permutation]] = {k: [] for k in chosen}
    # dedupe in priority order so a domain is credited to the strongest *requested* kind
    for kind in KINDS:
        if kind not in per_kind:
            continue
        cap = _KIND_CAPS[kind]
        bucket = per_kind[kind]
        for cand_sld, cand_suffix, note in _GENERATORS[kind](sld_work, suffix):
            if len(bucket) >= cap:
                break
            full = _assemble(cand_sld, cand_suffix)
            if full is None or full in seen:
                continue
            seen.add(full)
            bucket.append(Permutation(full, kind, note))

    total = sum(len(v) for v in per_kind.values())
    if total <= limit:
        return [p for k in chosen for p in per_kind[k]]
    picked: dict[str, int] = dict.fromkeys(chosen, 0)
    remaining = limit
    while remaining > 0:
        progressed = False
        for k in chosen:
            if remaining and picked[k] < len(per_kind[k]):
                picked[k] += 1
                remaining -= 1
                progressed = True
        if not progressed:
            break
    return [p for k in chosen for p in per_kind[k][: picked[k]]]
