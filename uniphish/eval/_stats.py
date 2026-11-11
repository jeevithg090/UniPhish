"""Small, dependency-free statistics used by the evaluation harness.

Why this module exists: the benchmark reports are only credible if the arithmetic is
simple, auditable and honest about uncertainty. Everything here is pure Python (no
numpy) so it can be unit-tested against hand-computed values:

* confusion counts and the usual rates (precision, recall, F1, FPR, FNR, MCC);
* Wilson score intervals, and the "rule of three" upper bound for zero-error cases
  (``0 false positives in n`` still allows a true rate up to ~``3/n``);
* percentile latency, rank-based ROC AUC;
* reliability (calibration) bins, expected calibration error and Brier score;
* the precision a detector would have at a *deployment* base rate, which is what
  actually decides whether users see false alarms.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from typing import Any


def safe_div(a: float, b: float) -> float | None:
    """``a / b`` or None when ``b`` is zero (an undefined rate, not zero)."""
    return a / b if b else None


def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    """Wilson score interval for ``k`` successes in ``n`` trials (95% by default)."""
    if n <= 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def rule_of_three(n: int) -> float | None:
    """95% upper bound on a rate after observing zero events in ``n`` trials (~3/n)."""
    return min(1.0, 3.0 / n) if n > 0 else None


def confusion(labels: Sequence[int], flagged: Sequence[bool]) -> dict[str, int]:
    """Confusion counts (tp, fp, tn, fn) for binary labels and boolean predictions."""
    tp = sum(1 for y, f in zip(labels, flagged, strict=True) if y and f)
    fp = sum(1 for y, f in zip(labels, flagged, strict=True) if not y and f)
    tn = sum(1 for y, f in zip(labels, flagged, strict=True) if not y and not f)
    fn = sum(1 for y, f in zip(labels, flagged, strict=True) if y and not f)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _r(x: float | None, nd: int = 4) -> float | None:
    return None if x is None else round(x, nd)


def rates(c: dict[str, int]) -> dict[str, Any]:
    """Derived rates from confusion counts. Undefined rates are None (never fake zeros)."""
    tp, fp, tn, fn = c["tp"], c["fp"], c["tn"], c["fn"]
    n = tp + fp + tn + fn
    pos, neg = tp + fn, fp + tn
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, pos)
    f1 = safe_div(2 * tp, 2 * tp + fp + fn)
    mcc_den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = safe_div(tp * tn - fp * fn, mcc_den)
    out: dict[str, Any] = {
        "n": n,
        "positives": pos,
        "negatives": neg,
        **c,
        "precision": _r(precision),
        "recall": _r(recall),
        "f1": _r(f1),
        "accuracy": _r(safe_div(tp + tn, n)),
        "fpr": _r(safe_div(fp, neg)),
        "fnr": _r(safe_div(fn, pos)),
        "specificity": _r(safe_div(tn, neg)),
        "mcc": _r(mcc),
    }
    ci_r = wilson_interval(tp, pos)
    ci_f = wilson_interval(fp, neg)
    out["recall_ci95"] = [round(x, 4) for x in ci_r] if ci_r else None
    out["fpr_ci95"] = [round(x, 4) for x in ci_f] if ci_f else None
    out["fpr_upper95_rule_of_three"] = _r(rule_of_three(neg)) if neg and fp == 0 else None
    return out


def percentile(values: Sequence[float], q: float) -> float | None:
    """Linear-interpolated percentile (``q`` in [0, 100]); None for an empty input."""
    if not values:
        return None
    xs = sorted(values)
    if len(xs) == 1:
        return xs[0]
    pos = (len(xs) - 1) * q / 100.0
    lo, hi = math.floor(pos), math.ceil(pos)
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def latency_summary(values: Sequence[float]) -> dict[str, float | int | None]:
    """mean / p50 / p95 / max (milliseconds) of a latency sample."""
    if not values:
        return {"n": 0, "mean": None, "p50": None, "p95": None, "max": None}
    return {
        "n": len(values),
        "mean": round(sum(values) / len(values), 3),
        "p50": round(percentile(values, 50) or 0.0, 3),
        "p95": round(percentile(values, 95) or 0.0, 3),
        "max": round(max(values), 3),
    }


def roc_auc(labels: Sequence[int], scores: Sequence[float]) -> float | None:
    """ROC AUC via the Mann-Whitney rank statistic (ties count one half). None if one class."""
    pos = [s for y, s in zip(labels, scores, strict=True) if y]
    neg = [s for y, s in zip(labels, scores, strict=True) if not y]
    if not pos or not neg:
        return None
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    rank_sum = sum(r for r, y in zip(ranks, labels, strict=True) if y)
    u = rank_sum - len(pos) * (len(pos) + 1) / 2
    return round(u / (len(pos) * len(neg)), 4)


def calibration(labels: Sequence[int], probs: Sequence[float], bins: int = 10) -> dict[str, Any]:
    """Reliability bins, expected calibration error and Brier score for ``probs``."""
    n = len(labels)
    if n == 0:
        return {"n": 0, "bins": [], "ece": None, "brier": None}
    buckets: list[list[tuple[int, float]]] = [[] for _ in range(bins)]
    for y, p in zip(labels, probs, strict=True):
        buckets[min(bins - 1, max(0, int(p * bins)))].append((y, p))
    out, ece = [], 0.0
    for b, members in enumerate(buckets):
        lo, hi = b / bins, (b + 1) / bins
        if not members:
            out.append({"lo": lo, "hi": hi, "n": 0, "mean_predicted": None, "observed_rate": None})
            continue
        mp = sum(p for _, p in members) / len(members)
        obs = sum(y for y, _ in members) / len(members)
        ece += len(members) / n * abs(obs - mp)
        out.append(
            {
                "lo": lo,
                "hi": hi,
                "n": len(members),
                "mean_predicted": round(mp, 4),
                "observed_rate": round(obs, 4),
            }
        )
    brier = sum((p - y) ** 2 for y, p in zip(labels, probs, strict=True)) / n
    return {"n": n, "bins": out, "ece": round(ece, 4), "brier": round(brier, 4)}


def precision_at_base_rate(
    recall: float | None, fpr: float | None, base_rate: float
) -> float | None:
    """Precision when only ``base_rate`` of the scanned traffic is malicious.

    ``precision = TPR*b / (TPR*b + FPR*(1-b))``. This is the number that decides how
    often a user sees a false alarm in production, and it is usually far below the
    precision measured on a balanced benchmark.
    """
    if recall is None or fpr is None:
        return None
    den = recall * base_rate + fpr * (1.0 - base_rate)
    return round(recall * base_rate / den, 4) if den > 0 else None


_URL_RE = re.compile(r"(?i)\b(https?|ftp)://[^\s)>\]\"']+")


def defang(text: str) -> str:
    """Defang URLs in ``text`` for safe display (hxxp, [.]); other text is unchanged."""

    def _sub(m: re.Match[str]) -> str:
        u = m.group(0)
        scheme, rest = u.split("://", 1)
        return scheme.replace("t", "x").replace("T", "X") + "://" + rest.replace(".", "[.]")

    return _URL_RE.sub(_sub, text)
