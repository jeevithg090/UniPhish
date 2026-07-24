"""Tests for the homoglyph substitution engine — no TensorFlow required."""

import random

from uniphish.encoding import encode_url
from uniphish.homoglyphs import HomoglyphMap


def test_builtin_map_loads():
    h = HomoglyphMap.builtin()
    assert "a" in h.mapping and "o" in h.mapping
    assert len(h) > 20


def test_substitution_changes_bytes_but_looks_similar():
    h = HomoglyphMap.builtin()
    rng = random.Random(0)
    url = "http://paypal.com/login"
    adv = h.substitute(url, rate=0.5, rng=rng)
    # visually similar length, but a different byte sequence
    assert adv != url
    assert len(adv) == len(url)  # 1-to-1 character substitution
    assert not (encode_url(adv) == encode_url(url)).all()


def test_no_substitutable_chars_is_noop():
    h = HomoglyphMap.builtin()
    # digits/punctuation only, none in map keys except maybe 0/1 -> use pure symbols
    url = "://.../???==="
    assert h.substitute(url, rate=0.5, rng=random.Random(1)) == url


def test_substitution_is_seed_deterministic():
    h = HomoglyphMap.builtin()
    a = h.substitute("http://amazon.com", rate=0.3, rng=random.Random(7))
    b = h.substitute("http://amazon.com", rate=0.3, rng=random.Random(7))
    assert a == b
