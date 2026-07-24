"""Baseline models for the head-to-head comparison (paper Section VI).

The point of these is the *contrast*: an ASCII-vocabulary CNN — the prior
state of the art — should collapse on non-Latin scripts and under Unicode
homoglyph attack, while byte-level UniPhish holds. That single comparison is
the paper's central claim and the project's headline chart.

Each baseline exposes a uniform interface via `get_baseline(name)`:
    spec.encode(urls)     -> np.ndarray features/ids
    spec.build()          -> a fit-able estimator (Keras model or sklearn)
    spec.kind             -> "keras" | "sklearn"
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Callable

import numpy as np

from uniphish.encoding import MAX_LEN, encode_batch
from uniphish.model import build_model  # byte-level UniPhish

# --------------------------------------------------------------------------- #
# B1 — ASCII CNN: identical architecture, but a 128-token ASCII vocabulary.
# Every non-ASCII byte maps to a single [UNK] token -> multilingual info is lost.
# --------------------------------------------------------------------------- #
ASCII_VOCAB = 129  # 0..127 ASCII + 128 = [UNK]
ASCII_UNK = 128


def ascii_encode_batch(urls, max_len: int = MAX_LEN) -> np.ndarray:
    out = np.zeros((len(urls), max_len), dtype=np.int32)
    for i, u in enumerate(urls):
        ids = [c if c < 128 else ASCII_UNK for c in u.encode("utf-8", "ignore")[:max_len]]
        out[i, : len(ids)] = ids
    return out


def build_ascii_cnn(max_len: int = MAX_LEN):
    return build_model(max_len=max_len, vocab_size=ASCII_VOCAB, name="ascii_cnn")


# --------------------------------------------------------------------------- #
# B2 — byte-level BiLSTM: same input as UniPhish, recurrent instead of conv.
# --------------------------------------------------------------------------- #
def build_byte_bilstm(max_len: int = MAX_LEN, embed_dim: int = 64, units: int = 128):
    from tensorflow import keras
    from tensorflow.keras import layers

    inp = keras.Input(shape=(max_len,), dtype="int32", name="byte_ids")
    x = layers.Embedding(256, embed_dim, name="byte_embedding")(inp)
    x = layers.Bidirectional(layers.LSTM(units, return_sequences=True))(x)
    x = layers.Bidirectional(layers.LSTM(units))(x)
    x = layers.Dropout(0.3)(x)
    x = layers.Dense(128, activation="relu")(x)
    out = layers.Dense(1, activation="sigmoid")(x)
    return keras.Model(inp, out, name="byte_bilstm")


# --------------------------------------------------------------------------- #
# B4 — Random Forest on hand-engineered lexical features (classical ML).
# CPU-only and fast; a useful, Unicode-aware-ish non-deep baseline.
# --------------------------------------------------------------------------- #
_IP_RE = re.compile(r"^https?://\d{1,3}(?:\.\d{1,3}){3}")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def lexical_features(url: str) -> list:
    host = url.split("://", 1)[-1].split("/", 1)[0]
    path = url[len(url.split("/", 3)[0]) :] if url.count("/") >= 3 else ""
    digits = sum(c.isdigit() for c in url)
    non_ascii = sum(ord(c) > 127 for c in url)
    return [
        len(url), len(host), len(path),
        url.count("."), url.count("-"), url.count("/"), url.count("%"),
        url.count("=") + url.count("&"),
        digits, digits / max(len(url), 1),
        non_ascii, non_ascii / max(len(url), 1),
        int("https://" in url), int("@" in url),
        int(bool(_IP_RE.match(url))), int("xn--" in url),
        max(host.count(".") - 1, 0),               # subdomain depth
        _entropy(host), _entropy(url),
    ]


def lexical_encode_batch(urls, max_len: int = MAX_LEN) -> np.ndarray:
    return np.array([lexical_features(u) for u in urls], dtype=np.float32)


def build_random_forest():
    from sklearn.ensemble import RandomForestClassifier
    return RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=42,
                                  class_weight="balanced")


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
@dataclass
class BaselineSpec:
    name: str
    kind: str                       # "keras" | "sklearn"
    encode: Callable
    build: Callable


def get_baseline(name: str) -> BaselineSpec:
    reg = {
        "uniphish":     BaselineSpec("uniphish", "keras", encode_batch, build_model),
        "ascii_cnn":    BaselineSpec("ascii_cnn", "keras", ascii_encode_batch, build_ascii_cnn),
        "byte_bilstm":  BaselineSpec("byte_bilstm", "keras", encode_batch, build_byte_bilstm),
        "random_forest": BaselineSpec("random_forest", "sklearn", lexical_encode_batch, build_random_forest),
    }
    if name not in reg:
        raise KeyError(f"unknown baseline {name!r}; choose from {list(reg)}")
    return reg[name]


ALL_MODELS = ["uniphish", "ascii_cnn", "byte_bilstm", "random_forest"]
