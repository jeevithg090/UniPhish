"""ML analyzer: the byte-level CNN as one calibrated, explainable evidence signal.

Why this module exists: the original UniPhish classifier is a tiny Unicode-native
byte-level CNN (see :mod:`uniphish.url.model`). The fused engine needs it expressed in
the common currency, signed log-odds, so it can be added to (and damped against) the
lexical, brand and reputation evidence rather than acting as a verdict on its own.

Probability -> weight mapping
-----------------------------
``weight = clamp(SHRINK * logit(p), MIN_WEIGHT, MAX_WEIGHT)`` with ``SHRINK = 0.6``,
``MIN_WEIGHT = -2.5`` and ``MAX_WEIGHT = +2.5``; ``p`` is clipped to ``[1e-6, 1-1e-6]``
before the logit.

* The model is trained on a balanced set and is overconfident (probabilities pin near 0
  or 1), so the raw logit is shrunk toward zero: ``p = 0.9`` gives about +1.3,
  ``p = 0.98`` about +2.3 and ``p >= 0.985`` hits the +2.5 ceiling, while
  ``p = 0.1`` gives about -1.3.
* The positive ceiling is deliberately kept below what, added to the ``-2.0`` prior,
  would reach the "malicious" threshold (risk ``0.85`` ≈ logit ``+1.73``): with the cap
  at ``+2.5`` the model alone tops out at risk ≈ ``0.62`` ("suspicious"), so a correct
  block always needs a corroborating structural, brand or reputation signal. This is
  the precision guard — on realistic data the byte-CNN over-fires on long or unusual but
  legitimate URLs, so it is treated as corroboration, not a verdict.
* Known dataset caveat: the model over-scores long legitimate URLs. URLs longer than
  ``LONG_URL_CHARS`` characters therefore get a much lower positive ceiling
  (``LONG_URL_MAX_WEIGHT = +1.0``) and a reduced confidence, leaving the benign
  reputation evidence free to balance it. Negative weights are unaffected.

If the model assets are missing or invalid the analyzer skips cleanly: it returns an
empty result with ``meta["ml_note"]`` explaining why, and never raises.
"""

from __future__ import annotations

import logging
import math
from typing import Any

from uniphish.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult, register
from uniphish.core.types import Artifact, ArtifactKind, Signal
from uniphish.url.model import ModelUnavailable, UrlModel, get_model

log = logging.getLogger("uniphish.analyzers.ml")

SHRINK: float = 0.6
MIN_WEIGHT: float = -2.5
MAX_WEIGHT: float = 1.5
LONG_URL_CHARS: int = 120
LONG_URL_MAX_WEIGHT: float = 0.8
LONG_URL_CONFIDENCE: float = 0.7
_EPS: float = 1e-6
_MIN_REPORTED: float = 0.1  # |weight| below this is noise and is not emitted
_TOP_K: int = 5

SIG_PHISHING = "ml.cnn.phishing"
SIG_BENIGN = "ml.cnn.benign"
SIG_SALIENT = "ml.cnn.salient_chars"


def ml_weight(prob: float, *, url_len: int = 0) -> float:
    """Map a phishing probability to a bounded log-odds weight (see module docstring)."""
    if not math.isfinite(prob):
        return 0.0
    p = min(max(prob, _EPS), 1.0 - _EPS)
    w = SHRINK * math.log(p / (1.0 - p))
    ceiling = LONG_URL_MAX_WEIGHT if url_len > LONG_URL_CHARS else MAX_WEIGHT
    return max(MIN_WEIGHT, min(ceiling, w))


def _skip(note: str) -> AnalyzerResult:
    return AnalyzerResult(meta={"ml_note": note})


@register
class MlAnalyzer(Analyzer):
    """Scores URLs with the byte-level CNN and (optionally) explains it by occlusion."""

    name = "ml"
    kinds = frozenset({ArtifactKind.URL})
    stage = 0
    requires_online = False
    blocking = True
    description = "Byte-level CNN URL classifier (NumPy runtime) with occlusion saliency"
    signals = {
        SIG_PHISHING: "Byte-level ML model rates this URL as likely phishing",
        SIG_BENIGN: "Byte-level ML model rates this URL as likely legitimate",
        SIG_SALIENT: "Characters that drove the ML model's score",
    }

    def applies(self, artifact: Artifact, ctx: AnalysisContext) -> bool:
        return bool(artifact.url)

    def analyze_sync(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        url = artifact.url
        if not url:
            return AnalyzerResult()
        try:
            model = get_model()
            prob = float(model.predict_one(url))
            info = model.info()
        except ModelUnavailable as exc:
            log.info("ML model unavailable, skipping: %s", exc)
            return _skip(f"ML model unavailable: {exc}")
        except Exception as exc:  # defensive: never fail the scan on an ML fault
            log.warning("ML scoring failed: %s", exc)
            return _skip(f"ML scoring failed: {type(exc).__name__}")

        weight = ml_weight(prob, url_len=len(url))
        long_url = len(url) > LONG_URL_CHARS
        signals: list[Signal] = []
        if abs(weight) >= _MIN_REPORTED:
            positive = weight > 0
            evidence: dict[str, Any] = {
                "prob": round(prob, 6),
                "weight_raw_shrink": SHRINK,
                "url_len": len(url),
            }
            spans = self._saliency(model, url) if ctx.options.explain else []
            if ctx.options.explain:
                evidence["top_chars"] = [s["text"] for s in spans]
            detail = (
                f"The byte-level model gives this URL a {prob:.1%} phishing probability."
                " It is one signal among many and is down-weighted, so it"
                " cannot decide alone."
            )
            if long_url and positive:
                detail += " Long URLs are over-scored by the model, so its weight is capped."
            signals.append(
                Signal(
                    id=SIG_PHISHING if positive else SIG_BENIGN,
                    title=(
                        "Byte-level ML model flags this URL as likely phishing"
                        if positive
                        else "Byte-level ML model finds this URL looks legitimate"
                    ),
                    detail=detail,
                    weight=weight,
                    category="ml",
                    analyzer=self.name,
                    confidence=LONG_URL_CONFIDENCE if (long_url and positive) else 1.0,
                    evidence=evidence,
                )
            )
            if positive and spans:
                top = spans[0]
                signals.append(
                    Signal(
                        id=SIG_SALIENT,
                        title="Characters that drove the ML model's score",
                        detail="Highlighted characters raised the model's phishing score most: "
                        + ", ".join(repr(s["text"]) for s in spans[:3])
                        + ".",
                        weight=0.0,
                        category="ml",
                        analyzer=self.name,
                        span=(top["start"], top["end"]),
                        evidence={"spans": spans},
                    )
                )
        return AnalyzerResult(signals=signals, meta={"ml_prob": prob, "ml_model": info})

    @staticmethod
    def _saliency(model: UrlModel, url: str) -> list[dict[str, Any]]:
        try:
            from uniphish.url.saliency import top_spans

            return [
                {"start": s.start, "end": s.end, "text": s.text, "delta": round(s.delta, 4)}
                for s in top_spans(url, _TOP_K, model)
            ]
        except Exception as exc:  # explanation is best-effort
            log.debug("saliency failed: %s", exc)
            return []
