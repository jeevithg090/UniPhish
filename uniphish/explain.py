"""Character-level saliency — *which characters* drove the phishing verdict.

Occlusion method: remove one character at a time and measure how much the phishing
probability drops. A large drop means that character was pushing the URL toward
"phishing". Model-agnostic (only needs batched prediction), so it works identically
for the full Keras model and the quantized TFLite model, and is robust across Keras
versions (unlike gradient plumbing).
"""

from __future__ import annotations

from typing import Dict, List


def saliency(scorer, url: str, max_chars: int = 200) -> Dict:
    """Return {baseline, chars:[{char, weight}], top_spans:[{text, start, end}]}.

    `scorer` is a uniphish.infer.UniPhishScorer (Keras or TFLite).
    weight > 0  => removing the char lowers the phishing score (it was incriminating).
    """
    url = url[:max_chars]
    baseline = float(scorer.scan(url)["prob"])
    if len(url) <= 1:
        return {"baseline": baseline, "chars": [], "top_spans": []}

    variants = [url[:i] + url[i + 1:] for i in range(len(url))]
    probs = [r["prob"] for r in scorer.scan_batch(variants)]
    weights = [round(baseline - p, 4) for p in probs]      # importance of char i
    chars = [{"char": c, "weight": w} for c, w in zip(url, weights)]

    # merge adjacent incriminating characters into readable spans
    spans, i = [], 0
    thresh = max(0.05, 0.4 * max(weights + [0]))
    while i < len(url):
        if weights[i] >= thresh:
            j = i
            while j < len(url) and weights[j] >= thresh:
                j += 1
            spans.append({"text": url[i:j], "start": i, "end": j,
                          "weight": round(max(weights[i:j]), 4)})
            i = j
        else:
            i += 1
    spans.sort(key=lambda s: -s["weight"])
    return {"baseline": round(baseline, 4), "chars": chars, "top_spans": spans[:5]}


def explain_text(url: str, saliency_result: Dict) -> str:
    """One-line textual summary of the most incriminating span (for CLI / logs)."""
    spans = saliency_result.get("top_spans") or []
    if not spans:
        return "no single character dominated the score"
    top = spans[0]
    return f"most incriminating: “{top['text']}” (Δp={top['weight']})"
