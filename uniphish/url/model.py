"""TensorFlow-free runtime for the UniPhish byte-level CNN.

The original UniPhish classifier (IEEE paper, Section IV) is a tiny byte-level 1D-CNN:
a URL is encoded as its UTF-8 byte sequence (256-token vocabulary, no ``[UNK]``),
truncated/zero-padded to 600 bytes, embedded (256x64), passed through five parallel
``Conv1D`` branches (kernels 2..6, 128 filters each) with ReLU + global-max-pool, then
a dense head ``640 -> 256 -> 128 -> 1`` with a sigmoid output.

This module runs that exact forward pass in **pure NumPy**, reproducing
``extension/model.js`` byte-for-byte, so the whole platform scores URLs with no
TensorFlow, no TFLite and no network. Weights live in :mod:`uniphish.assets` as a
float32 blob (``model/weights.bin``) described by ``model/manifest.json`` — the same
artifacts the on-device browser extension uses.

Why a separate runtime (vs. importing Keras)? TensorFlow is a ~500 MB dependency that
is not installed in the platform's offline-first runtime, and a ``.keras`` file saved on
a newer Keras will not reload on an older one (see ``docs/paper_vs_reality.md`` section
6). A deterministic NumPy forward pass over a version-independent weight blob sidesteps
both problems and is trivially auditable.

Numerical fidelity: ``extension/model.js`` reads float32 weights but accumulates every
dot product in JavaScript ``number`` (float64) and stores each layer's output back to
float32. This module mirrors that exactly — accumulate in float64, round each layer
output to float32 — so NumPy and the JS reference agree to well within 1e-4 (verified by
``tests/url/test_model_parity.py`` against ``tests/url/parity_runner.js``).

The raw model is one weighted signal, not a verdict. It can over-score long legitimate
URLs and over-rely on suspicious TLDs; the fused UniPhish engine compensates. See
``info()`` / ``model_info.json`` for the honest metrics and caveats.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

from uniphish.assets import asset_path

__all__ = [
    "UrlModel",
    "ModelUnavailable",
    "get_model",
    "MAX_LEN",
    "VOCAB_SIZE",
    "PARAM_COUNT",
]

# Architecture constants (fixed by the trained weights; also encoded in the manifest).
MAX_LEN: int = 600
VOCAB_SIZE: int = 256
EMBED_DIM: int = 64
KERNELS: tuple[int, ...] = (2, 3, 4, 5, 6)
FILTERS: int = 128
PAD_BYTE: int = 0
PARAM_COUNT: int = 377_985

# Internal batch size: bound peak memory regardless of how many URLs are scored at once
# (a float64 conv activation for a chunk is ~chunk * 595 * 128 * 8 bytes). Chunking makes
# ``predict`` safe on arbitrarily large inputs and on long-URL saliency batches.
_CHUNK = 128


class ModelUnavailable(RuntimeError):
    """Raised when the model assets are missing, unreadable or inconsistent.

    Callers (e.g. the ML analyzer) should treat this as "no ML signal available" and
    degrade gracefully rather than failing the whole scan.
    """


@dataclass(frozen=True)
class _ConvBranch:
    """One im2col-ready conv branch."""

    k: int                                # kernel size
    w: np.ndarray                         # (k*64, 128) float32, rows ordered (offset, channel)
    b: np.ndarray                         # (128,) float32


@dataclass(frozen=True)
class _Weights:
    """Immutable, compute-ready view of the weight blob.

    Conv/embedding weights are float32 (the bulk of the compute; float32 BLAS is ~2x
    faster and the parity error stays ~1e-7). The small dense head runs in float64 to
    track ``model.js`` exactly through the sigmoid.
    """

    emb: np.ndarray                       # (256, 64) float32
    conv: tuple[_ConvBranch, ...]
    fc1_w: np.ndarray                     # (640, 256) float64
    fc1_b: np.ndarray                     # (256,) float64
    fc2_w: np.ndarray                     # (256, 128) float64
    fc2_b: np.ndarray                     # (128,) float64
    out_w: np.ndarray                     # (128, 1) float64
    out_b: np.ndarray                     # (1,) float64


def _encode(urls: Sequence[str]) -> np.ndarray:
    """Encode URLs to a ``(N, MAX_LEN)`` uint8 byte-index matrix.

    UTF-8 bytes, truncated to MAX_LEN and zero-padded — identical to the JS
    ``new TextEncoder().encode(url)`` then ``Uint8Array(L).set(raw.subarray(0, L))``.
    Malformed Unicode is dropped (``errors="ignore"``), matching :mod:`uniphish.encoding`;
    well-formed URLs are unaffected.
    """
    out = np.zeros((len(urls), MAX_LEN), dtype=np.uint8)
    for i, u in enumerate(urls):
        raw = u.encode("utf-8", "ignore")[:MAX_LEN]
        if raw:
            out[i, : len(raw)] = np.frombuffer(raw, dtype=np.uint8)
    return out


def _dense(x: np.ndarray, w: np.ndarray, b: np.ndarray, *, relu: bool) -> np.ndarray:
    """One dense layer: float64 accumulation, float32-rounded output (mirrors model.js)."""
    out = x.astype(np.float64, copy=False) @ w + b
    if relu:
        np.maximum(out, 0.0, out=out)
    return out.astype(np.float32)


class UrlModel:
    """Pure-NumPy byte-level CNN URL phishing classifier.

    Args:
        manifest_path: path to ``manifest.json``; defaults to the packaged asset.
        weights_path: path to ``weights.bin``; defaults to the packaged asset.
        temperature: logit temperature ``T`` for calibrated probabilities
            (``p = sigmoid(logit / T)``). Default 1.0 (no calibration). The raw model
            is overconfident, so a ``T > 1`` softens probabilities for non-default
            thresholds; it never changes the ranking or the logits.

    Raises:
        ModelUnavailable: if the assets are missing, truncated or inconsistent with the
            manifest.
    """

    def __init__(self, manifest_path: str | Path | None = None,
                 weights_path: str | Path | None = None, *, temperature: float = 1.0) -> None:
        if temperature <= 0:
            raise ValueError("temperature must be > 0")
        self.temperature = float(temperature)
        self._manifest_path = Path(manifest_path) if manifest_path else _default_manifest_path()
        self._weights_path = Path(weights_path) if weights_path else _default_weights_path()
        self.manifest = _load_manifest(self._manifest_path)
        self._raw_f32 = _load_weights(self._weights_path, self.manifest)
        self._w = _build_weights(self._raw_f32, self.manifest)
        self._info = _load_info()

    # ---- public API ------------------------------------------------------- #
    @property
    def param_count(self) -> int:
        """Number of trainable parameters (sum of tensor sizes in the manifest)."""
        return int(sum(t["size"] for t in self.manifest["tensors"]))

    def logits(self, urls: Sequence[str]) -> np.ndarray:
        """Raw pre-sigmoid logits (float32, shape ``(N,)``). Temperature is **not** applied."""
        return self._run(urls)[0]

    def predict(self, urls: Sequence[str]) -> np.ndarray:
        """Phishing probabilities (float32, shape ``(N,)``) in [0, 1].

        Accepts any sequence of URL strings (internally chunked). Passing a bare ``str``
        is treated as a single-URL batch of length ``len(str)`` characters would be — so
        don't: use :meth:`predict_one` for a single URL.
        """
        return self._run(urls)[1]

    def predict_one(self, url: str) -> float:
        """Phishing probability for a single URL."""
        return float(self._run([url])[1][0])

    def predict_seq(self, seq: np.ndarray) -> np.ndarray:
        """Probabilities for a pre-encoded ``(N, MAX_LEN)`` byte matrix (for saliency)."""
        return self._forward(seq)[1]

    def logits_seq(self, seq: np.ndarray) -> np.ndarray:
        """Raw logits for a pre-encoded ``(N, MAX_LEN)`` byte matrix (for saliency).

        Logit-space occlusion stays informative even when the probability is saturated
        near 0/1 (the model is overconfident by design — see :meth:`info`).
        """
        return self._forward(seq)[0]

    def encode(self, urls: Sequence[str]) -> np.ndarray:
        """Encode URLs to the ``(N, MAX_LEN)`` uint8 byte matrix the model consumes."""
        return _encode(list(urls))

    def info(self) -> dict[str, Any]:
        """Provenance, architecture, honest metrics and caveats (JSON-serialisable)."""
        runtime = {
            "param_count": self.param_count,
            "max_len": MAX_LEN,
            "vocab_size": VOCAB_SIZE,
            "embed_dim": EMBED_DIM,
            "kernels": list(KERNELS),
            "filters": FILTERS,
            "fc": [self._w.fc1_w.shape[1], self._w.fc2_w.shape[1]],
            "temperature": self.temperature,
            "manifest_path": str(self._manifest_path),
            "weights_path": str(self._weights_path),
            "runtime": "numpy",
        }
        merged = dict(self._info)
        merged["runtime"] = runtime
        return merged

    # ---- internals -------------------------------------------------------- #
    def _run(self, urls: Sequence[str]) -> tuple[np.ndarray, np.ndarray]:
        urls = list(urls)
        if not urls:
            return (np.zeros(0, np.float32), np.zeros(0, np.float32))
        logit_parts: list[np.ndarray] = []
        prob_parts: list[np.ndarray] = []
        for start in range(0, len(urls), _CHUNK):
            seq = _encode(urls[start : start + _CHUNK])
            lg, pr = self._forward(seq)
            logit_parts.append(lg)
            prob_parts.append(pr)
        return np.concatenate(logit_parts), np.concatenate(prob_parts)

    def _forward(self, seq: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Full forward pass on a ``(N, MAX_LEN)`` uint8 matrix -> (logits, probs) float32."""
        if seq.ndim != 2 or seq.shape[1] != MAX_LEN:
            raise ValueError(f"seq must be (N, {MAX_LEN}); got {seq.shape}")
        w = self._w
        n = seq.shape[0]
        x = w.emb[seq]                                  # (N, MAX_LEN, 64) float32
        pooled: list[np.ndarray] = []
        for br in w.conv:
            positions = MAX_LEN - br.k + 1
            # conv1d 'valid' via im2col: one (N*P, k*64) @ (k*64, 128) matmul per branch.
            # sliding_window_view -> (N, P, 64, k); transpose to (N, P, k, 64) so the
            # flattened window axis is ordered (offset, channel), matching the weight rows.
            win = sliding_window_view(x, br.k, axis=1).transpose(0, 1, 3, 2)
            win = np.ascontiguousarray(win).reshape(n * positions, br.k * EMBED_DIM)
            conv = (win @ br.w + br.b).reshape(n, positions, FILTERS)
            np.maximum(conv, 0.0, out=conv)             # ReLU (padding positions included)
            pooled.append(conv.max(axis=1))             # global max pool -> (N, 128) float32
        z = np.concatenate(pooled, axis=1)              # (N, 640) float32
        h1 = _dense(z, w.fc1_w, w.fc1_b, relu=True)
        h2 = _dense(h1, w.fc2_w, w.fc2_b, relu=True)
        logit = _dense(h2, w.out_w, w.out_b, relu=False)[:, 0]   # (N,) float32
        prob = _sigmoid(logit.astype(np.float64) / self.temperature).astype(np.float32)
        return logit, prob


def _sigmoid(x: np.ndarray) -> np.ndarray:
    # Numerically stable logistic sigmoid.
    out = np.empty_like(x, dtype=np.float64)
    pos = x >= 0
    out[pos] = 1.0 / (1.0 + np.exp(-x[pos]))
    ex = np.exp(x[~pos])
    out[~pos] = ex / (1.0 + ex)
    return out


# --------------------------------------------------------------------------- #
# Asset loading + validation
# --------------------------------------------------------------------------- #
def _default_manifest_path() -> Path:
    try:
        return asset_path("model", "manifest.json")
    except ValueError as e:  # pragma: no cover - defensive
        raise ModelUnavailable(str(e)) from e


def _default_weights_path() -> Path:
    try:
        return asset_path("model", "weights.bin")
    except ValueError as e:  # pragma: no cover - defensive
        raise ModelUnavailable(str(e)) from e


def _load_manifest(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ModelUnavailable(f"model manifest not found: {path}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ModelUnavailable(f"model manifest unreadable: {e}") from e
    if not isinstance(manifest, dict) or "tensors" not in manifest:
        raise ModelUnavailable("model manifest missing 'tensors'")
    names = {t["name"] for t in manifest["tensors"]}
    required = {"emb", "fc1_w", "fc1_b", "fc2_w", "fc2_b", "phish_prob_w", "phish_prob_b"}
    required |= {f"conv{k}_w" for k in KERNELS} | {f"conv{k}_b" for k in KERNELS}
    missing = required - names
    if missing:
        raise ModelUnavailable(f"model manifest missing tensors: {sorted(missing)}")
    return manifest


def _load_weights(path: Path, manifest: dict[str, Any]) -> np.ndarray:
    if not path.is_file():
        raise ModelUnavailable(f"model weights not found: {path}")
    try:
        data = np.fromfile(path, dtype="<f4")
    except OSError as e:  # pragma: no cover - defensive
        raise ModelUnavailable(f"model weights unreadable: {e}") from e
    expected = max(int(t["offset"]) + int(t["size"]) for t in manifest["tensors"])
    if data.size != expected:
        raise ModelUnavailable(
            f"weights size mismatch: file has {data.size} float32 values, "
            f"manifest describes {expected} ({path})")
    if not np.isfinite(data).all():
        raise ModelUnavailable("weights contain non-finite values (NaN/Inf)")
    return data


def _tensor(raw: np.ndarray, manifest: dict[str, Any], name: str, dtype: Any) -> np.ndarray:
    t = next(t for t in manifest["tensors"] if t["name"] == name)
    flat = raw[int(t["offset"]) : int(t["offset"]) + int(t["size"])]
    return flat.reshape(tuple(int(d) for d in t["shape"])).astype(dtype)


def _build_weights(raw: np.ndarray, manifest: dict[str, Any]) -> _Weights:
    emb = _tensor(raw, manifest, "emb", np.float32)
    if emb.shape != (VOCAB_SIZE, EMBED_DIM):
        raise ModelUnavailable(f"unexpected embedding shape {emb.shape}")
    branches = []
    for k in KERNELS:
        wk = _tensor(raw, manifest, f"conv{k}_w", np.float32)   # (k, 64, 128)
        bk = _tensor(raw, manifest, f"conv{k}_b", np.float32)   # (128,)
        if wk.shape != (k, EMBED_DIM, FILTERS) or bk.shape != (FILTERS,):
            raise ModelUnavailable(f"unexpected conv{k} shapes {wk.shape}, {bk.shape}")
        # C-order reshape (k, 64, 128) -> (k*64, 128): row index = offset*64 + channel.
        branches.append(_ConvBranch(k=k, w=wk.reshape(k * EMBED_DIM, FILTERS), b=bk))
    return _Weights(
        emb=emb,
        conv=tuple(branches),
        fc1_w=_tensor(raw, manifest, "fc1_w", np.float64),
        fc1_b=_tensor(raw, manifest, "fc1_b", np.float64),
        fc2_w=_tensor(raw, manifest, "fc2_w", np.float64),
        fc2_b=_tensor(raw, manifest, "fc2_b", np.float64),
        out_w=_tensor(raw, manifest, "phish_prob_w", np.float64),
        out_b=_tensor(raw, manifest, "phish_prob_b", np.float64),
    )


def _load_info() -> dict[str, Any]:
    try:
        return json.loads(asset_path("model", "model_info.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):  # provenance is optional metadata
        return {}


# --------------------------------------------------------------------------- #
# Lazy thread-safe singleton
# --------------------------------------------------------------------------- #
_singleton: UrlModel | None = None
_lock = threading.Lock()


def get_model() -> UrlModel:
    """Return the shared :class:`UrlModel`, constructing it once (thread-safe).

    Raises :class:`ModelUnavailable` if the packaged assets are missing/invalid.
    """
    global _singleton
    if _singleton is None:
        with _lock:
            if _singleton is None:
                _singleton = UrlModel()
    return _singleton
