"""Tests for baseline encoders / features — no TensorFlow required."""

import numpy as np

from uniphish.baselines import (ASCII_UNK, ascii_encode_batch, lexical_encode_batch,
                                lexical_features)


def test_ascii_encoder_maps_nonascii_to_unk():
    # Cyrillic 'а' is non-ASCII -> its bytes become UNK; ASCII 'a' stays itself.
    x = ascii_encode_batch(["aа"], max_len=8)[0]
    assert x[0] == ord("a")
    assert ASCII_UNK in x                     # the Cyrillic char's bytes -> UNK
    assert x.max() <= ASCII_UNK               # never exceeds the ASCII+UNK vocab


def test_ascii_encoder_shape():
    m = ascii_encode_batch(["http://a.com", "http://пример.рф"], max_len=32)
    assert m.shape == (2, 32) and m.dtype == np.int32


def test_lexical_feature_vector_is_fixed_width():
    f1 = lexical_features("https://paypa1.xyz/login")
    f2 = lexical_features("https://банк.рф/вход")
    assert len(f1) == len(f2) > 10
    # non-ASCII ratio (index 11) must be >0 for the Cyrillic URL, 0 for ascii one
    assert f2[11] > 0 and f1[11] == 0


def test_lexical_batch_shape():
    X = lexical_encode_batch(["https://a.com", "https://xn--e1afmkfd.xn--p1ai/"])
    assert X.shape[0] == 2 and X.shape[1] > 10
