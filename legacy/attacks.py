"""Evasion attacks for red-teaming the detector (Track E).

Each attack transforms a phishing URL to try to slip past the model while staying
plausible to a human. Used by scripts/redteam.py to measure evasion rates and to
show that the enrichment/rules layer recovers what the raw model misses.
"""

from __future__ import annotations

import random
from typing import Callable, Dict

from uniphish.brands import _host
from uniphish.homoglyphs import HomoglyphMap

_ZW = "​"  # zero-width space
_homo = HomoglyphMap.builtin()


def _swap_host(url: str, new_host: str) -> str:
    h = _host(url)
    return url.replace(h, new_host, 1) if h else url


def homoglyph_swap(url: str, rng=None, rate: float = 0.3) -> str:
    return _homo.substitute(url, rate=rate, rng=rng or random)


def zero_width_inject(url: str, rng=None, n: int = 3) -> str:
    rng = rng or random
    h = _host(url)
    if len(h) < 2:
        return url
    chars = list(h)
    for _ in range(min(n, len(chars) - 1)):
        chars.insert(rng.randint(1, len(chars) - 1), _ZW)
    return _swap_host(url, "".join(chars))


def tld_swap(url: str, rng=None, tld: str = "com") -> str:
    h = _host(url)
    if "." not in h:
        return url
    return _swap_host(url, h.rsplit(".", 1)[0] + "." + tld)


def subdomain_pad(url: str, rng=None) -> str:
    rng = rng or random
    pad = rng.choice(["secure", "login", "account", "www", "verify"])
    return _swap_host(url, f"{pad}.{_host(url)}")


def case_randomize(url: str, rng=None) -> str:
    rng = rng or random
    h = _host(url)
    return _swap_host(url, "".join(c.upper() if rng.random() < 0.5 else c for c in h))


def char_duplicate(url: str, rng=None) -> str:
    rng = rng or random
    h = _host(url)
    idxs = [i for i, c in enumerate(h) if c.isalpha()]
    if not idxs:
        return url
    i = rng.choice(idxs)
    return _swap_host(url, h[:i] + h[i] + h[i:])


ATTACKS: Dict[str, Callable] = {
    "homoglyph_swap": homoglyph_swap,
    "zero_width_inject": zero_width_inject,
    "tld_swap": tld_swap,
    "subdomain_pad": subdomain_pad,
    "case_randomize": case_randomize,
    "char_duplicate": char_duplicate,
}
