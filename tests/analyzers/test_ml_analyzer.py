"""Tests for the ML analyzer (byte-level CNN signal)."""

from __future__ import annotations

import math

import pytest

from uniphish.analyzers import ml as mlmod
from uniphish.analyzers.ml import MlAnalyzer, ml_weight
from uniphish.core.analyzer import REGISTRY, AnalysisContext, AnalysisOptions
from uniphish.core.types import Artifact, ArtifactKind
from uniphish.url.model import ModelUnavailable

PHISH = "http://paypal-secure-login.verify-account.top/signin/update.php?id=1&session=abcdef"
BENIGN = "https://www.wikipedia.org/"


def run(url: str, explain: bool = False):
    ctx = AnalysisContext(options=AnalysisOptions(explain=explain))
    return MlAnalyzer().analyze_sync(Artifact.from_url(url), ctx)


def test_registered():
    assert REGISTRY["ml"] is MlAnalyzer
    assert MlAnalyzer.kinds == frozenset({ArtifactKind.URL})
    assert MlAnalyzer.blocking and MlAnalyzer.stage == 0


def test_phishing_style_url_positive():
    r = run(PHISH)
    assert r.meta["ml_prob"] > 0.5
    sig = r.signals[0]
    assert sig.id == "ml.cnn.phishing" and sig.category == "ml"
    assert 0 < sig.weight <= mlmod.MAX_WEIGHT
    assert "ml_model" in r.meta


def test_benign_url_not_positive():
    r = run(BENIGN)
    assert r.meta["ml_prob"] < 0.5
    assert all(s.weight <= 0 for s in r.signals)


def test_explain_gives_spans():
    r = run(PHISH, explain=True)
    sig = r.signals[0]
    assert sig.evidence["prob"] > 0.5
    assert isinstance(sig.evidence["top_chars"], list) and sig.evidence["top_chars"]
    sal = [s for s in r.signals if s.id == "ml.cnn.salient_chars"]
    assert sal and sal[0].span is not None
    s, e = sal[0].span
    assert 0 <= s < e <= len(PHISH)


def test_no_explain_no_spans():
    r = run(PHISH)
    assert not any(s.id == "ml.cnn.salient_chars" for s in r.signals)
    assert "top_chars" not in r.signals[0].evidence


def test_missing_model_skips(monkeypatch):
    def boom():
        raise ModelUnavailable("weights.bin missing")

    monkeypatch.setattr(mlmod, "get_model", boom)
    r = run(PHISH)
    assert r.signals == []
    assert "unavailable" in r.meta["ml_note"]


def test_unexpected_error_skips(monkeypatch):
    monkeypatch.setattr(mlmod, "get_model", lambda: (_ for _ in ()).throw(ValueError("x")))
    r = run(PHISH)
    assert r.signals == [] and "ml_note" in r.meta


def test_weight_mapping():
    assert ml_weight(0.5) == pytest.approx(0.0)
    assert ml_weight(0.9) == pytest.approx(0.6 * math.log(9), rel=1e-6)
    assert ml_weight(0.9) > 1.0
    assert ml_weight(1.0) == mlmod.MAX_WEIGHT
    assert ml_weight(0.0) == mlmod.MIN_WEIGHT
    assert ml_weight(0.1) < 0
    assert ml_weight(float("nan")) == 0.0
    assert ml_weight(1.0, url_len=500) == mlmod.LONG_URL_MAX_WEIGHT
    assert ml_weight(0.0, url_len=500) == mlmod.MIN_WEIGHT


def test_weight_monotonic():
    ws = [ml_weight(p / 100) for p in range(0, 101)]
    assert ws == sorted(ws)


def test_long_url_capped_and_lower_confidence(monkeypatch):
    class Fake:
        def predict_one(self, u):
            return 0.9999

        def info(self):
            return {}

    monkeypatch.setattr(mlmod, "get_model", lambda: Fake())
    r = run("https://example.com/" + "a" * 300)
    assert r.signals[0].weight == mlmod.LONG_URL_MAX_WEIGHT
    assert r.signals[0].confidence < 1.0


def test_unicode_and_odd_urls_do_not_raise():
    urls = ["http://раураl.test/login", "http://例え.test/ログイン", "x", "http://a/" + "%" * 700]
    for u in urls:
        r = run(u, explain=True)
        assert 0.0 <= r.meta["ml_prob"] <= 1.0
