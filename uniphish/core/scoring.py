"""Evidence fusion: signals -> one calibrated, fully decomposable risk.

Model
-----
``logit = PRIOR + Σ contribution(signal)`` and ``risk = sigmoid(logit)``.

Each signal's contribution is ``weight × confidence × damping``. Damping handles
correlated evidence: within one ``category`` the strongest malicious signal counts
fully, the next one by ``DECAY``, the next by ``DECAY²`` … (same for benign
evidence). Six weak lexical cues therefore can't masquerade as one strong proof,
while independent evidence families (brand + page + infrastructure) add up — which
is exactly how a human analyst reasons.

Because fusion is additive, every verdict decomposes exactly into per-signal
contributions (``Signal.contribution``), which the dashboard renders as a waterfall.
"""

from __future__ import annotations

import math
from collections import defaultdict

from uniphish.core.config import Settings, get_settings
from uniphish.core.types import Action, Level, Signal, Verdict

PRIOR_LOGIT = -2.0  # ≈ 12 % — base rate for an arbitrary submitted artifact
DECAY = 0.55  # within-category damping factor for correlated evidence
LOGIT_CLAMP = 12.0


def sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    e = math.exp(x)
    return e / (1.0 + e)


def logit(p: float, eps: float = 1e-6) -> float:
    p = min(max(p, eps), 1.0 - eps)
    return math.log(p / (1.0 - p))


def apply_contributions(signals: list[Signal]) -> float:
    """Set ``Signal.contribution`` on every signal and return their sum."""
    groups: dict[tuple[str, bool], list[Signal]] = defaultdict(list)
    for s in signals:
        groups[(s.category, s.weight >= 0)].append(s)
    total = 0.0
    for members in groups.values():
        members.sort(key=lambda s: abs(s.weight * s.confidence), reverse=True)
        for rank, s in enumerate(members):
            c = s.weight * s.confidence * (DECAY**rank)
            s.contribution = round(c, 4)
            total += c
    return total


def decide(risk: float, settings: Settings | None = None) -> tuple[Level, Action]:
    st = settings or get_settings()
    if risk >= st.malicious_threshold:
        return Level.MALICIOUS, Action.BLOCK
    if risk >= st.suspicious_threshold:
        return Level.SUSPICIOUS, Action.WARN
    return Level.BENIGN, Action.ALLOW


def confidence(total_logit: float, settings: Settings | None = None) -> float:
    """Decision confidence from the log-odds margin to the nearest threshold."""
    st = settings or get_settings()
    bounds = (logit(st.suspicious_threshold), logit(st.malicious_threshold))
    margin = min(abs(total_logit - b) for b in bounds)
    return round(1.0 - math.exp(-margin), 3)


def fuse(signals: list[Signal], settings: Settings | None = None) -> dict:
    """Fuse signals. Returns {logit, risk, score, level, action, confidence}."""
    st = settings or get_settings()
    total = PRIOR_LOGIT + apply_contributions(signals)
    total = max(-LOGIT_CLAMP, min(LOGIT_CLAMP, total))
    risk = sigmoid(total)
    level, action = decide(risk, st)
    return {
        "logit": round(total, 4),
        "risk": round(risk, 4),
        "score": int(round(risk * 100)),
        "level": level,
        "action": action,
        "confidence": confidence(total, st),
    }


def child_weight(child: Verdict) -> float:
    """Log-odds a parent inherits from a child verdict (e.g. an email's link).

    Only suspicious/malicious children propagate, at 90 % of their excess over the
    prior — an email that *contains* a malicious link is itself malicious, but the
    child's benign evidence never whitewashes the parent.
    """
    excess = child.logit - PRIOR_LOGIT
    if child.level is Level.BENIGN or excess <= 0:
        return 0.0
    return round(0.9 * excess, 4)


_LEVEL_WORD = {
    Level.MALICIOUS: "Malicious",
    Level.SUSPICIOUS: "Suspicious",
    Level.BENIGN: "No significant threat",
}


def summarize(verdict: Verdict, max_reasons: int = 3) -> str:
    """Deterministic one-paragraph summary from the strongest signals."""
    head = f"{_LEVEL_WORD[verdict.level]} ({verdict.score}/100)"
    top = verdict.top_signals(max_reasons)
    if verdict.brand and not verdict.brand.official and verdict.level is not Level.BENIGN:
        head += f" — impersonates {verdict.brand.name}"
    if not top:
        return head + "."
    return head + ": " + "; ".join(s.title.rstrip(".") for s in top) + "."
