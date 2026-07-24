"""Tests for the red-team attacks (no TensorFlow required)."""

import random

from uniphish.attacks import (ATTACKS, char_duplicate, homoglyph_swap, tld_swap,
                              zero_width_inject)
from uniphish.encoding import encode_url


def test_all_attacks_return_strings():
    rng = random.Random(0)
    for name, fn in ATTACKS.items():
        out = fn("https://paypal-login.top/verify", rng=rng)
        assert isinstance(out, str) and out


def test_homoglyph_swap_changes_bytes():
    a = homoglyph_swap("https://paypal.com/login", rng=random.Random(1), rate=0.6)
    assert not (encode_url(a) == encode_url("https://paypal.com/login")).all()


def test_zero_width_injected():
    a = zero_width_inject("https://paypal.com/x", rng=random.Random(2), n=2)
    assert "​" in a


def test_tld_swap_to_com():
    a = tld_swap("https://paypal-login.top/verify")
    assert ".com/" in a and ".top" not in a


def test_char_duplicate_lengthens_host():
    a = char_duplicate("https://paypal.com/x", rng=random.Random(3))
    assert len(a) >= len("https://paypal.com/x")
