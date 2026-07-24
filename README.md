# UniPhish

**A Unicode-native, byte-level 1D-CNN for multilingual phishing-URL detection — with an honest reproduction study of the paper it implements.**

UniPhish encodes every URL as its **UTF-8 byte sequence** (256-token vocabulary, no
`[UNK]`), so a single 378K-parameter model handles Latin, Arabic, CJK, Devanagari,
Hangul and mixed-script URLs. It's adversarially trained against Unicode homoglyph
evasion, ships as a **0.40 MB int8 TFLite** model doing **sub-millisecond CPU
inference**, and comes with a live browser-extension demo.

```
"paypal.com"  ->  [112, 97, 121, 112, 97, 108, 46, 99, 111, 109, 0, ...]   (1 byte/char)
"банк.рф"     ->  [208,177, 208,176, 208,189, 208,186, ...]                (Cyrillic, 2 bytes/char)
```

> This repo implements the IEEE paper *UniPhish* **and audits it**. Two claims did not
> survive contact with real data — the parameter count and the "ASCII detectors are
> blind to non-Latin scripts" claim. Reporting that honestly is the point:
> see [`docs/paper_vs_reality.md`](docs/paper_vs_reality.md).

---

## Results (real runs, regenerable)

| Metric | Value |
|---|---|
| In-distribution macro-F1 (6 script families) | **0.9991** |
| **Cross-dataset real holdout (n=7,199)** — trained on our blend, tested on held-out real URLs | **0.9954** F1, FNR 0.0090 |
| Accuracy @ 20% Unicode homoglyph substitution | **0.995** (robust) |
| Model / latency (int8 TFLite, laptop CPU, 1 thread) | **0.40 MB / 0.76 ms per URL** |
| Parameters | 377,985 |

**Honest headline finding:** on realistic, structure-rich data an ASCII-vocabulary CNN
**ties** UniPhish (both ≈0.999 macro-F1) — the paper's blanket "multilingual gap" does
*not* reproduce, because phishing is largely detectable from ASCII-visible structure.
UniPhish is a strong, deployable detector; its byte-level design is best motivated by
*homoglyph/IDN robustness*, not a general accuracy advantage. Full analysis:
[`docs/paper_vs_reality.md`](docs/paper_vs_reality.md).

Live check (weights loaded into a fresh model):
```
safe   p=0.0000  https://www.sbi.co.in/
BLOCK  p=1.0000  https://paypa1.xyz/login
BLOCK  p=1.0000  https://аpple.com/verify            ← Cyrillic homoglyph
BLOCK  p=1.0000  https://नमस्ते-bank-verify.top/login   ← Devanagari
safe   p=0.0000  https://www.google.com/
```

---

## Quickstart

```bash
make setup                                  # venv + deps
make test                                   # 16 unit tests
python -m data.build_dataset --per-family 10000 --include-real   # build data (real + synthetic)
python -m uniphish.train                    # adversarial training (GPU recommended)
python -m uniphish.evaluate                 # in-dist + cross-dataset metrics
python -m uniphish.compress --weights artifacts/uniphish_adv.keras --out artifacts/uniphish.tflite
python -m scripts.benchmark                 # real size + latency
python -m scripts.run_experiments           # UniPhish vs ASCII-CNN / BiLSTM / RandomForest
```

GPU training is easiest on Kaggle/Colab (P100 ≈ 20 s/epoch). See
[`notebooks`](notebooks) once added, or the commands above.

### Live demo
```bash
UNIPHISH_MODEL=artifacts/uniphish_adv.keras uvicorn api.server:app --port 8000
```
Then load [`extension/`](extension) unpacked in Chrome (`chrome://extensions` →
Developer mode → Load unpacked). Risky links on any page get outlined; the popup
scans a pasted URL. See [`extension/README.md`](extension/README.md).

---

## What's inside

```
uniphish/
  encoding.py     UTF-8 byte encoder (256 vocab, 600-byte window)
  model.py        parallel multi-kernel 1D-CNN (377,985 params)
  homoglyphs.py   Unicode confusables map + adversarial substitution
  adversarial.py  min-max trainer (clean + λ·adversarial loss)
  train.py        training (cosine LR, macro-F1 early stop, checkpoint/resume)
  evaluate.py     per-family, FNR/FPR, adversarial sweep, cross-dataset
  baselines.py    ASCII-CNN, byte-BiLSTM, RandomForest (lexical)
  brands.py       brand-impersonation ID (Unicode TR39 skeleton + typo distance)
  reasons.py      plain-language reasons for a verdict
  explain.py      character-level saliency (occlusion)
  enrich.py       IDN decode + SSRF-safe redirect resolution + RDAP age + fused risk
  compress.py     -> quantized TFLite; optional distillation
  infer.py        URL scorer + risk tiers (Keras or TFLite)
data/             synthesizer + real feeds + dataset builder (+ DATASHEET.md)
scripts/          run_experiments.py (comparison), benchmark.py (size/latency)
api/              FastAPI scan service
extension/        Manifest V3 browser-extension demo
docs/             paper_vs_reality.md (the reproduction audit)
```

Docs: [MODEL_CARD.md](MODEL_CARD.md) · [data/DATASHEET.md](data/DATASHEET.md) ·
[docs/paper_vs_reality.md](docs/paper_vs_reality.md) · [PLAN.md](PLAN.md)

---

## Why this project is worth a look

- **Explainable verdicts:** every score comes with the **impersonated brand** (Unicode
  skeleton + typo distance), **plain-language reasons**, and a **character-level saliency**
  heatmap — via `POST /explain` and rendered in the extension popup. Not a black box.
- **Hybrid detection, not one model:** `POST /enrich` fuses the ML score with IDN/punycode
  decoding, SSRF-guarded redirect resolution, and RDAP domain-age into a transparent 0–100
  risk — so a homoglyph the model misses is still caught by the rules (defense in depth).
- **End-to-end ML engineering:** data pipeline → adversarial training → evaluation →
  compression → TFLite → live demo, reproducibly.
- **Adversarial ML:** min-max training against Unicode homoglyph evasion; robust to 20%
  character substitution.
- **On-device deployment:** 0.40 MB int8 TFLite, sub-ms CPU inference, browser extension.
- **Scientific integrity:** a reproduction study that *corrects* the source paper
  (parameter count; the overstated multilingual-gap claim) instead of rubber-stamping it.

---

## Responsible use
UniPhish is **defensive**. The synthesizer produces phishing-*style* strings to train a
detector; it builds no live malicious infrastructure and targets no real people. The
homoglyph engine exists to make the detector *robust to* evasion. See `MODEL_CARD.md`.

## License
MIT — see [LICENSE](LICENSE). If you use this, please cite the UniPhish paper
(Gangadhar et al., 2025).
