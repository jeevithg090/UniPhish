"""Occlusion saliency for the byte-level CNN: *which characters move the score?*

For a human analyst or the SOC console the single most useful explanation of an ML URL
verdict is "these characters are why". This module computes that with **occlusion**:
replace one character's UTF-8 bytes with the pad byte (the model's neutral baseline),
re-score, and measure the probability change. A large positive change means that
character was pushing the URL toward *phishing*.

Why occlusion (vs. gradients)? It is model-agnostic (needs only batched prediction),
deterministic, and robust — no autodiff plumbing, no dependence on the training
framework. It is also honest about multi-byte scripts: occlusion is done per **character**
(all of its UTF-8 bytes at once), so a Cyrillic or CJK homoglyph is attributed as one
unit, not split across its bytes.

All variants are scored in a **single** batched call, so explaining a URL costs one
forward pass over ``len(url)+1`` rows, not ``len(url)`` separate calls.

Probability vs. logit space: by default :func:`occlusion_saliency` measures the change in
**phishing probability** (the spec contract). But the model is overconfident — on a URL
it is 99.99% sure about, removing any single character leaves the probability pinned at
~1.0, so every per-character probability delta is ~0 and highlighting would show nothing.
Pass ``on="logit"`` (and :func:`top_spans` does so by default) to measure the change in
the pre-sigmoid **logit**, which stays informative under saturation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import numpy as np

from uniphish.url.model import MAX_LEN, PAD_BYTE, UrlModel, get_model

Space = Literal["prob", "logit"]

__all__ = ["CharSaliency", "SalientSpan", "occlusion_saliency", "top_spans"]

# Cap how many characters we explain: saliency is O(len) forward rows, and the model only
# sees the first 600 bytes anyway. 600 chars comfortably covers that window for any script.
_MAX_CHARS = 600


@dataclass(frozen=True)
class CharSaliency:
    """Per-character occlusion result.

    Attributes:
        index: character position in the URL string.
        char: the character itself.
        start_byte: inclusive UTF-8 byte offset of this char in the (untruncated) URL.
        end_byte: exclusive UTF-8 byte offset.
        delta: ``base_score - occluded_score`` — how much the score *drops* when this
            character is removed, in the chosen space (probability by default, or logit).
            Positive = incriminating (drove the score up); negative = exculpatory (was
            holding the score down); ~0 = no effect (including characters whose bytes fall
            entirely beyond the 600-byte model window).
        space: ``"prob"`` or ``"logit"`` — the space ``delta`` is measured in.
    """

    index: int
    char: str
    start_byte: int
    end_byte: int
    delta: float
    space: Space = "prob"


@dataclass(frozen=True)
class SalientSpan:
    """A merged run of adjacent incriminating characters (for UI highlighting)."""

    start: int  # inclusive char index
    end: int  # exclusive char index
    text: str  # url[start:end]
    delta: float  # peak per-character delta within the span
    space: Space = "logit"


def _char_byte_spans(url: str) -> list[tuple[int, int]]:
    """UTF-8 (start, end) byte offsets for each character of ``url``."""
    spans: list[tuple[int, int]] = []
    pos = 0
    for ch in url:
        blen = len(ch.encode("utf-8", "ignore"))
        spans.append((pos, pos + blen))
        pos += blen
    return spans


def occlusion_saliency(
    url: str, model: UrlModel | None = None, *, max_chars: int = _MAX_CHARS, on: Space = "prob"
) -> list[CharSaliency]:
    """Per-character occlusion saliency for ``url``.

    Args:
        url: the URL to explain.
        model: a :class:`UrlModel`; defaults to the shared singleton (:func:`get_model`).
        max_chars: explain at most this many leading characters.
        on: score space to measure the change in — ``"prob"`` (phishing probability, the
            default and the spec contract) or ``"logit"`` (pre-sigmoid, robust to the
            model's near-0/1 saturation).

    Returns:
        One :class:`CharSaliency` per explained character, in order. Empty for an empty
        URL. All variants are scored in a single batched forward pass.
    """
    if on not in ("prob", "logit"):
        raise ValueError(f"on must be 'prob' or 'logit', got {on!r}")
    model = model or get_model()
    url = url[:max_chars]
    if not url:
        return []

    base_seq = model.encode([url])[0]  # (MAX_LEN,) uint8
    byte_spans = _char_byte_spans(url)

    # Row 0 is the unmodified URL; rows 1..n each zero out one character's bytes in-place
    # (no position shift — occlusion, not deletion). Bytes beyond MAX_LEN are already
    # truncated away, so occluding them is a no-op (delta ~ 0), which is the honest answer.
    variants = np.repeat(base_seq[None, :], len(url) + 1, axis=0)
    for i, (s, e) in enumerate(byte_spans):
        end = min(e, MAX_LEN)
        if s < end:
            variants[i + 1, s:end] = PAD_BYTE

    scorer = model.predict_seq if on == "prob" else model.logits_seq
    scores = scorer(variants)
    base = float(scores[0])
    deltas = base - scores[1:]

    return [
        CharSaliency(
            index=i,
            char=ch,
            start_byte=byte_spans[i][0],
            end_byte=byte_spans[i][1],
            delta=float(deltas[i]),
            space=on,
        )
        for i, ch in enumerate(url)
    ]


# Threshold floors below which a delta is treated as noise, per space. Logit deltas are
# unbounded and routinely O(1); probability deltas are tiny once the model saturates.
_FLOOR = {"logit": 0.1, "prob": 0.02}


def top_spans(
    url: str,
    k: int = 5,
    model: UrlModel | None = None,
    *,
    on: Space = "logit",
    min_frac: float = 0.25,
    min_delta: float | None = None,
) -> list[SalientSpan]:
    """Merge adjacent incriminating characters into the top ``k`` spans for highlighting.

    Defaults to ``on="logit"`` because the model's probabilities saturate near 0/1: on a
    confidently-flagged URL every per-character *probability* delta is ~0, so probability
    space would highlight nothing. Logit space stays discriminative.

    A character counts as incriminating when its occlusion ``delta`` clears a threshold
    that scales with the strongest character in this URL
    (``max(min_delta, min_frac * max_delta)``), so a URL with only weak signal yields no
    spans rather than noise. Runs of consecutive incriminating characters are merged into
    one span; spans are returned strongest-first, truncated to ``k``.

    Returns an empty list when nothing meaningfully drives the score up.
    """
    sals = occlusion_saliency(url, model, on=on)
    if not sals:
        return []
    max_delta = max((s.delta for s in sals), default=0.0)
    if max_delta <= 0:
        return []
    floor = _FLOOR[on] if min_delta is None else min_delta
    threshold = max(floor, min_frac * max_delta)

    spans: list[SalientSpan] = []
    i, n = 0, len(sals)
    while i < n:
        if sals[i].delta >= threshold:
            j = i
            while j < n and sals[j].delta >= threshold:
                j += 1
            peak = max(s.delta for s in sals[i:j])
            spans.append(SalientSpan(start=i, end=j, text=url[i:j], delta=float(peak), space=on))
            i = j
        else:
            i += 1

    spans.sort(key=lambda sp: sp.delta, reverse=True)
    return spans[:k]
