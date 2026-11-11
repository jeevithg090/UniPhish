# Spec: evaluation + red-team harness
OWN: uniphish/eval/__init__.py, uniphish/eval/benchmark.py, uniphish/eval/redteam.py,
uniphish/eval/datasets.py, tests/eval/test_eval.py, docs/evaluation.md. Depends on the
engine + url.model + url.confusables/brands + core.types. This produces the evidence that
makes the project credible.

datasets.py: build small, labelled, reproducible, SYNTHETIC-or-reserved benchmark sets
(no live malicious URLs committed): a multilingual look-alike set (homoglyph/idn/typo/
combosquat across scripts), a benign set (reserved + clearly-benign structures incl. tricky
legit cases: long legit URLs, legit IDNs, LOTS-hosted-but-benign, popular brands' own
domains), a smishing-text set, a prompt-injection set (direct/indirect/obfuscated), an
email set (spoofed vs aligned). Each item labelled; loader returns (artifact_spec, label).
benchmark.py: run the engine over a dataset; compute precision/recall/F1/accuracy, FPR/FNR,
per-category breakdown, confusion, latency (ms/scan, p50/p95), and a calibration view
(predicted risk vs observed). Save results/eval_*.json; a to_markdown(report) for the docs.
Emphasise the HONEST framing from docs/paper_vs_reality.md (don't overclaim). Include a
false-positive audit on legit cases (the hardest, most important metric).
redteam.py: attack the detector with evasions (homoglyph swap, zero-width/bidi insertion,
TLD swap, path padding, case randomization, encoding, unicode-tag smuggling for the
injection detector) and report evasion rate + which layer (ML vs rules vs fusion) recovers
each — the defense-in-depth story. Save results/robustness.json.
TESTS: datasets load + are labelled correctly; benchmark computes sane metrics on a tiny
set with the real engine (offline); redteam runs and reports recovery; no network; fast
(use a small N in tests). The full-size run is a CLI/`make eval`, not a unit test.
