"""Tests for uniphish.page.favicon."""

from __future__ import annotations

import base64

import mmh3
import pytest

from uniphish.page.favicon import MAX_FAVICON_BYTES, favicon_mmh3, known_favicon_brand

DATA = bytes(range(256)) * 3  # synthetic, inert bytes (> 76 base64 columns)


def test_hash_is_stable_and_signed_32bit() -> None:
    h = favicon_mmh3(DATA)
    assert h == favicon_mmh3(DATA)
    assert -(2**31) <= h < 2**31
    assert h == mmh3.hash(base64.encodebytes(DATA))


def test_newlines_matter() -> None:
    # Shodan style hashes the newline-wrapped encoding, not the plain one.
    assert favicon_mmh3(DATA) != mmh3.hash(base64.b64encode(DATA))


def test_different_data_different_hash() -> None:
    assert favicon_mmh3(DATA) != favicon_mmh3(DATA + b"\x00")


def test_empty_input() -> None:
    assert isinstance(favicon_mmh3(b""), int)


def test_too_large_rejected() -> None:
    with pytest.raises(ValueError):
        favicon_mmh3(b"\x00" * (MAX_FAVICON_BYTES + 1))


def test_known_favicon_brand_lookup() -> None:
    h = favicon_mmh3(DATA)
    assert known_favicon_brand(h, {h: "ExampleBrand"}) == "ExampleBrand"
    assert known_favicon_brand(h, {str(h): "StrKey"}) == "StrKey"
    assert known_favicon_brand(h, {h + 1: "Other"}) is None
    assert known_favicon_brand(h, {}) is None
