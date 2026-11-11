# Legacy — UniPhish v1 (the research / paper-reproduction pipeline)

This directory preserves the **original UniPhish v1** code: the reproducible
implementation and audit of the IEEE *UniPhish* paper — a Unicode-native, byte-level
1D-CNN for multilingual phishing-URL detection, with the adversarial-training,
compression and evaluation pipeline behind the numbers in
[`../MODEL_CARD.md`](../MODEL_CARD.md) and
[`../docs/paper_vs_reality.md`](../docs/paper_vs_reality.md).

It is kept for **research heritage and reproducibility**, not as part of the v2 product.
UniPhish 2 (the `uniphish/` package) is a complete rewrite into a multi-vector,
explainable detection *platform*; it does not import anything here. The byte-level CNN
itself lives on in v2 as a dependency-free NumPy runtime at
[`../uniphish/url/model.py`](../uniphish/url/model.py), served from the same weights.

## Contents

| Path | What it was |
|---|---|
| `encoding.py`, `model.py` | UTF-8 byte encoder + Keras CNN (377,985 params) |
| `adversarial.py`, `train.py` | min-max adversarial training (Unicode homoglyph evasion) |
| `compress.py`, `calibrate.py` | pruning → distillation → int8 TFLite; temperature scaling |
| `evaluate.py`, `baselines.py` | per-family / cross-dataset evaluation vs ASCII-CNN / BiLSTM / RF |
| `homoglyphs.py`, `attacks.py` | confusables map + the red-team attack harness |
| `brands.py`, `classify_attack.py`, `reasons.py`, `enrich.py`, `explain.py`, `infer.py` | v1 heuristic layers, all superseded by `uniphish/url/*` and `uniphish/analyzers/*` |
| `threatintel.py`, `ioc_store.py` | v1 STIX/TAXII output, superseded by `uniphish/export/*` + `uniphish/store/*` |
| `api/` | v1 FastAPI demo, superseded by `uniphish/server/` |
| `data/` | v1 multilingual URL synthesizer + real-feed dataset builder |
| `scripts/` | v1 experiment / benchmark / CT-hunter / web-export scripts |

## Running it

These modules were written as a flat `uniphish.*` package and reference each other by
those paths, so running them as-is from this directory needs the import paths adjusted
(or a checkout of the v1 history). They require the TensorFlow training stack:

```bash
pip install -e '.[train]'
```

The full commit history of v1 is preserved in git; see the tags/commits prior to the
v2 rewrite.
