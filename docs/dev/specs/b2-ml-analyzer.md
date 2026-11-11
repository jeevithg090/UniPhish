# Spec: ML analyzer (byte-level CNN) + saliency
OWN: uniphish/analyzers/ml.py, tests/analyzers/test_ml_analyzer.py.
Depends on uniphish.url.model (a4), uniphish.url.saliency (a4). If the model asset is
missing, the analyzer must SKIP cleanly (return empty result + a note), never crash.

@register class MlAnalyzer(Analyzer): name='ml'; kinds={ArtifactKind.URL}; stage=0;
blocking=True. Score the URL with UrlModel; convert probability to a calibrated log-odds
Signal in category 'ml':
- Map prob to weight: use logit(prob) shrunk toward 0 by a factor (e.g. 0.6) and clamped
  (say [-2.5, +4]) so the ML model contributes but never alone dominates a false positive;
  document the mapping. prob>=0.9 -> strong positive; prob<=0.1 -> mild negative.
- When options.explain, attach occlusion saliency: top_spans over the URL, and set
  Signal.evidence={'prob':..,'top_chars':[...]}, and put spans on a secondary signal so
  the UI can highlight which characters drove the score.
- meta: {'ml_prob': prob, 'ml_model': info()}. Indicator: none new.
Guard: the model over-scores long legitimate URLs (dataset caveat) — keep the max positive
weight modest and let the fused engine + benign reputation evidence balance it.
TESTS: a known phishing-style URL yields prob high + positive weight; a short benign one
low; explain=True yields saliency spans; missing-model path skips with a note (monkeypatch
ModelUnavailable).
