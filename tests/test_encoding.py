"""Tests for the UTF-8 byte encoder — no TensorFlow required."""

import numpy as np

from uniphish.encoding import (MAX_LEN, PAD_BYTE, VOCAB_SIZE, byte_length,
                               decode_bytes, encode_batch, encode_url)


def test_ascii_roundtrip():
    arr = encode_url("http://a.com", max_len=32)
    assert arr.shape == (32,)
    assert arr.dtype == np.int32
    assert arr[0] == ord("h")
    assert decode_bytes(arr) == "http://a.com"


def test_padding_and_truncation():
    short = encode_url("ab", max_len=10)
    assert list(short[:2]) == [ord("a"), ord("b")]
    assert (short[2:] == PAD_BYTE).all()
    long = encode_url("a" * 100, max_len=10)
    assert long.shape == (10,)


def test_all_indices_in_vocab():
    # Multilingual URL must map entirely into [0, 255] with no [UNK].
    url = "https://банк.рф/登录?q=नमस्ते&x=안녕"
    arr = encode_url(url)
    assert arr.min() >= 0 and arr.max() < VOCAB_SIZE


def test_non_ascii_uses_multiple_bytes():
    # Cyrillic 'а' (U+0430) is 2 UTF-8 bytes, Latin 'a' is 1.
    assert byte_length("а") == 2
    assert byte_length("a") == 1


def test_batch_shape():
    m = encode_batch(["a.com", "http://пример.рф", "登录.cn"], max_len=MAX_LEN)
    assert m.shape == (3, MAX_LEN)
