# UniPhish

**Unicode-native character-level 1D-CNN for real-time multilingual phishing URL detection.**

A reproducible reference implementation of the IEEE paper *"UniPhish: A Unicode-Native
Character-Level 1D-Convolutional Neural Network for Real-Time Multilingual Phishing URL
Detection in Messaging Applications."* The core idea: encode every URL as a **UTF-8 byte
sequence** so a **256-token vocabulary** gives complete Unicode coverage — no `[UNK]` token,
no per-script preprocessing — and a parallel multi-kernel 1D-CNN detects phishing patterns
across Latin, Arabic, CJK, Devanagari, Hangul, and mixed scripts from a single model.

```
"paypal.com"  ->  [112, 97, 121, 112, 97, 108, 46, 99, 111, 109, 0, ...]   (ASCII, 1 byte/char)
"банк.рф"     ->  [208,177, 208,176, 208,189, 208,186, ...]                (Cyrillic, 2 bytes/char)
```

---

## Status

| Phase | Component | State |
|---|---|---|
| 0 | Package scaffold, venv, tests, config | ✅ done (`pytest` green) |
| 1 | UTF-8 encoder + paper-spec Keras model | ✅ done (param count verified) |
| 2 | Reproducible data builder (synthetic + optional real feeds) | ✅ done |
| 3 | Training + adversarial min-max loss (Eq. 15) | ✅ done (runs end-to-end) |
| 5 | Evaluation (per-family metrics, FNR/FPR, adversarial sweep) | ✅ done |
| — | Inference + risk tiers (warn/block) | ✅ done |
| 4 | Baselines (ASCII-CNN, byte-BiLSTM, RF, Unicode-block CNN) | ⬜ next |
| 6 | Compression → distillation → int8 → TFLite | ⬜ next |
| 7 | Live demo: FastAPI `/scan` + browser-extension front-end | ⬜ next |
| — | Wire figure scripts to `results/results.json` | ⬜ next |

## Quickstart

```bash
make setup                       # venv + deps (TensorFlow, etc.)
make test                        # 12 unit tests
make data                        # build a small demo dataset
make train                       # adversarial training (use --epochs for a quick run)
make eval                        # writes results/results.json
make infer URL="https://paypa1.xyz/login"
```

For a real run, use the full-scale dataset and default epochs:

```bash
./.venv/bin/python -m data.build_dataset --per-family 40000
./.venv/bin/python -m uniphish.train        # cosine LR, early stop on val_macro_f1
./.venv/bin/python -m uniphish.evaluate
```

## Project layout

```
uniphish/            core package
  encoding.py        UTF-8 byte encoder (256 vocab, 600-byte window)
  model.py           parallel multi-kernel 1D-CNN (Keras functional)
  homoglyphs.py      Unicode confusables map + adversarial substitution
  adversarial.py     min-max trainer (clean + λ·adversarial loss)
  dataset.py         CSV -> byte tensors
  train.py           training driver (standard or adversarial)
  evaluate.py        per-family metrics, confusion, adversarial sweep
  infer.py           URL scorer + risk tiers (Keras or TFLite)
data/
  synth.py           multilingual URL synthesizer (6 script families)
  build_dataset.py   dedup, per-domain cap, stratified split, adv test set
configs/default.yaml all hyperparameters (mirrors paper Table III)
tests/               unit tests (encoder, homoglyphs, model)
```

## Reproducibility & honesty ("paper vs. reality")

This repo is meant to make the paper's claims **runnable and checkable**. Where reality
differs from the current paper text, we surface it rather than hide it:

1. **Parameter count.** The paper's Table III headlines **847,425** trainable parameters,
   but the architecture *as described* yields **377,985** (run `python -m uniphish.model`
   to see the summary). The component counts in the paper itself sum to ~378K. Recommend
   correcting the paper, or clarifying a larger architecture if 847K was intended.
2. **Dataset.** The real *MultiPhishDB* (Saudi NCA, CNCERT, CERT-In, KrCERT feeds) is
   **gated and not public**, and did not ship with the paper. To keep the project fully
   reproducible, `data/synth.py` **synthesizes** realistic URLs across the six script
   families using the exact phishing construction strategies from Section II-A, clearly
   labeled `source="synthetic"`. Optional real public feeds (PhishTank/OpenPhish/URLhaus/
   Tranco) can be blended via `--include-real`. **Any accuracy/latency/robustness number you
   report should come from a real run on real data, not from the paper's placeholder tables.**

As real experiments are run, discrepancies are tracked so the paper can be updated to match.

## Responsible use

UniPhish is a **defensive** security tool. The synthetic data generator produces
phishing-*style* strings for training a detector; it is not a phishing kit and generates no
live malicious infrastructure. Do not use the synthesizer or model to create or target real
victims. The homoglyph engine exists to make the detector *robust to* evasion, per the paper.

## Citation

If you use this code, please cite the UniPhish paper (Gangadhar et al., 2025).
