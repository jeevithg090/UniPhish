"""Load processed CSV splits and turn URLs into byte-encoded tensors."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Optional, Tuple

import numpy as np
import pandas as pd

from uniphish.encoding import MAX_LEN, encode_batch
from uniphish.homoglyphs import HomoglyphMap


@dataclass
class Split:
    urls: np.ndarray          # (N,) object
    y: np.ndarray             # (N,) float32
    families: np.ndarray      # (N,) object
    X: np.ndarray             # (N, max_len) int32

    def __len__(self) -> int:
        return len(self.y)


def load_split(path: str, max_len: int = MAX_LEN) -> Split:
    df = pd.read_csv(path)
    urls = df["url"].astype(str).to_numpy()
    y = df["label"].astype("float32").to_numpy()
    fam = df["script_family"].astype(str).to_numpy() if "script_family" in df else np.array(["?"] * len(df))
    X = encode_batch(urls, max_len)
    return Split(urls=urls, y=y, families=fam, X=X)


def make_adversarial_X(urls, sub_rate: float, max_len: int = MAX_LEN,
                        seed: int = 0, homo: Optional[HomoglyphMap] = None) -> np.ndarray:
    """Encode homoglyph-substituted variants of `urls` (for min-max training)."""
    homo = homo or HomoglyphMap.builtin()
    rng = random.Random(seed)
    adv = [homo.substitute(u, rate=sub_rate, rng=rng) for u in urls]
    return encode_batch(adv, max_len)
