"""UTF-8 byte-level encoding layer (Section IV-B of the paper).

A URL string is converted to its UTF-8 byte sequence, then truncated or
zero-padded to a fixed length. Because every byte value is in {0, ..., 255},
a 256-entry vocabulary gives *complete* Unicode coverage with no [UNK] token:
this is the central idea of UniPhish.

    "paypal.com"      -> [112, 97, 121, 112, 97, 108, 46, 99, 111, 109, 0, 0, ...]
    "банк.рф" (Cyril) -> [208, 177, 208, 176, 208, 189, 208, 186, ...]   (2 bytes/char)

The pad value 0 doubles as NUL; genuine NUL bytes essentially never occur in
URLs, so collapsing pad and NUL onto embedding index 0 is harmless and matches
the paper (pad byte = value 0).
"""

from __future__ import annotations

from typing import Iterable, List

import numpy as np

MAX_LEN: int = 600      # covers 99.97% of URLs in MultiPhishDB (99th pct = 487 bytes)
VOCAB_SIZE: int = 256   # one token per byte value
PAD_BYTE: int = 0


def encode_url(url: str, max_len: int = MAX_LEN) -> np.ndarray:
    """Encode a single URL to a fixed-length int32 byte-index vector.

    Args:
        url: raw URL string (may contain any Unicode script).
        max_len: sequence length to pad/truncate to.

    Returns:
        np.ndarray of shape (max_len,), dtype int32, values in [0, 255].
    """
    raw = url.encode("utf-8", errors="ignore")[:max_len]
    arr = np.frombuffer(raw, dtype=np.uint8).astype(np.int32)
    if arr.shape[0] < max_len:
        arr = np.pad(arr, (0, max_len - arr.shape[0]), mode="constant", constant_values=PAD_BYTE)
    return arr


def encode_batch(urls: Iterable[str], max_len: int = MAX_LEN) -> np.ndarray:
    """Encode many URLs into a 2-D matrix of shape (N, max_len)."""
    urls = list(urls)
    out = np.empty((len(urls), max_len), dtype=np.int32)
    for i, u in enumerate(urls):
        out[i] = encode_url(u, max_len)
    return out


def byte_length(url: str) -> int:
    """Number of UTF-8 bytes in a URL (before truncation) — useful for dataset stats."""
    return len(url.encode("utf-8", errors="ignore"))


def decode_bytes(arr: Iterable[int]) -> str:
    """Best-effort inverse of encode_url (strips padding). For debugging only."""
    bs = bytes(int(b) for b in arr if int(b) != PAD_BYTE)
    return bs.decode("utf-8", errors="replace")
