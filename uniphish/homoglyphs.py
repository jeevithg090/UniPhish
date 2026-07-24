"""Unicode homoglyph substitution (Section IV-D of the paper).

Builds a map  H: ascii_char -> [visually-confusable Unicode chars]  and uses it
to generate adversarial URL variants: a phishing URL that looks identical to a
human but is a different byte sequence (the primary multilingual evasion trick).

Two map sources:
  1. A curated built-in map (always available, offline) covering the highest-value
     Latin<->Cyrillic/Greek confusables — including every pair in the paper's
     Table II.
  2. Optionally, the full Unicode Consortium `confusables.txt` if present on disk
     (download via `fetch_confusables()`), which expands coverage to tens of
     thousands of pairs.
"""

from __future__ import annotations

import os
import random
import unicodedata
from typing import Dict, List, Optional

# --- Curated built-in confusables (superset includes the paper's Table II) ----
# Keyed by the ASCII character an attacker wants to *impersonate*.
_BUILTIN: Dict[str, List[str]] = {
    "a": ["а", "α", "ɑ", "ӑ"],   # Cyrillic а, Greek α, ɑ, ӑ
    "c": ["с", "ϲ", "ⅽ"],              # Cyrillic с, Greek ϲ, ⅽ
    "e": ["е", "ҽ", "℮"],              # Cyrillic е, ҽ, ℮
    "i": ["і", "ї", "ⅰ", "ӏ"],    # Cyrillic і, ї, ⅰ, ӏ
    "j": ["ј"],                                   # Cyrillic ј
    "l": ["ӏ", "ⅼ", "ḷ", "ɩ"],    # Cyrillic ӏ, ⅼ, ḷ, ɩ
    "o": ["о", "ο", "օ", "ⲟ"],    # Cyrillic о, Greek ο, Armenian օ
    "p": ["р", "ρ", "ⲣ"],              # Cyrillic р, Greek ρ
    "s": ["ѕ", "ƽ"],                         # Cyrillic ѕ
    "x": ["х", "χ", "ⅹ"],              # Cyrillic х, Greek χ, ⅹ
    "y": ["у", "ү", "ỳ"],              # Cyrillic у, ү, ỳ
    "b": ["в", "Ь", "Ƅ"],              # Cyrillic в, ь
    "h": ["һ", "հ"],                         # Cyrillic һ, Armenian հ
    "k": ["к", "ӄ"],                         # Cyrillic к
    "m": ["м", "ɱ"],                         # Cyrillic м
    "n": ["ո", "ɳ"],                         # Armenian ն
    "t": ["т", "τ"],                         # Cyrillic т, Greek τ
    "u": ["ս", "ц"],                         # Armenian ս
    "d": ["ԁ", "ⅾ"],                         # Cyrillic ԁ, ⅾ
    "g": ["ɡ", "ԍ"],                         # ɡ
    "w": ["ѡ", "ԝ"],                         # Cyrillic ѡ
    "0": ["О", "о", "Օ"],              # letter-O homoglyphs for digit 0
    "1": ["І", "Ӏ", "ⅼ"],              # letter-I / l homoglyphs for digit 1
}


class HomoglyphMap:
    """Character -> list of confusable substitutes, with adversarial generation."""

    def __init__(self, mapping: Dict[str, List[str]]):
        self.mapping = mapping

    # ---- construction ----------------------------------------------------
    @classmethod
    def builtin(cls) -> "HomoglyphMap":
        return cls({k: list(v) for k, v in _BUILTIN.items()})

    @classmethod
    def from_confusables_file(cls, path: str, merge_builtin: bool = True) -> "HomoglyphMap":
        """Parse Unicode `confusables.txt` into an ascii-target -> sources map.

        Each data line looks like:  `0430 ;   0061 ;  MA  # ... ( а → a )`
        i.e. <source> ; <prototype> ; <type>. We invert it: for every prototype
        that is a single printable ASCII char, collect the confusable sources.
        """
        mapping: Dict[str, List[str]] = {k: list(v) for k, v in _BUILTIN.items()} if merge_builtin else {}
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line or ";" not in line:
                    continue
                parts = [p.strip() for p in line.split(";")]
                if len(parts) < 2:
                    continue
                try:
                    src = "".join(chr(int(cp, 16)) for cp in parts[0].split())
                    proto = "".join(chr(int(cp, 16)) for cp in parts[1].split())
                except ValueError:
                    continue
                # keep only single-char ASCII prototypes with a non-ASCII source
                if len(proto) == 1 and proto.isascii() and proto.isprintable() and not src.isascii():
                    mapping.setdefault(proto.lower(), [])
                    if src not in mapping[proto.lower()]:
                        mapping[proto.lower()].append(src)
        return cls(mapping)

    @classmethod
    def load(cls, confusables_path: Optional[str] = None) -> "HomoglyphMap":
        """Load full map if confusables.txt is available, else the builtin map."""
        if confusables_path and os.path.exists(confusables_path):
            return cls.from_confusables_file(confusables_path)
        return cls.builtin()

    # ---- adversarial generation -----------------------------------------
    def substitutable_positions(self, url: str) -> List[int]:
        return [i for i, ch in enumerate(url) if ch.lower() in self.mapping]

    def substitute(self, url: str, rate: float = 0.15,
                   rng: Optional[random.Random] = None) -> str:
        """Return an adversarial variant of `url` with a fraction `rate` of its
        substitutable characters replaced by random confusables.

        Only the netloc + path region is targeted lightly here (whole-string is
        fine for training); the label is unchanged (evasion, not relabeling).
        """
        rng = rng or random
        positions = self.substitutable_positions(url)
        if not positions:
            return url
        n_sub = max(1, int(rate * len(url)))
        n_sub = min(n_sub, len(positions))
        chosen = set(rng.sample(positions, n_sub))
        chars = list(url)
        for i in chosen:
            key = chars[i].lower()
            repl = rng.choice(self.mapping[key])
            chars[i] = repl
        return "".join(chars)

    def __len__(self) -> int:
        return sum(len(v) for v in self.mapping.values())


def fetch_confusables(dest: str = "data/raw/confusables.txt") -> str:
    """Download the Unicode 15.x confusables database (optional, ~1.7 MB).

    Returns the local path. Network access required; wrap in try/except upstream.
    """
    import requests

    url = "https://www.unicode.org/Public/security/latest/confusables.txt"
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write(resp.text)
    return dest


def normalize_confusable_free(text: str) -> str:
    """NFKC-normalize (a light defensive baseline, for comparison in experiments)."""
    return unicodedata.normalize("NFKC", text)
