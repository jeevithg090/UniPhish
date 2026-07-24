# Paper vs. Reality

A running reconciliation between the UniPhish paper's claims and what the
reproducible implementation actually produces. Keeping this honest is a feature,
not an embarrassment: it turns the repo into a *reproduction study*, and every
number below is regenerable by anyone who clones and runs it.

## 1. Model size / parameter count

| | Paper (Table III) | This implementation |
|---|---|---|
| Trainable params | 847,425 | **377,985** |

The architecture *as described* (embedding 16,384 + conv 164,480 + FC1 164,096 +
FC2 32,896 + output 129) sums to 377,985 — verified with `python -m uniphish.model`.
The paper's 847,425 headline does not match its own described components.
**Recommendation:** correct the paper to 377,985 (or clarify a larger architecture).

## 2. The "multilingual security gap" claim (the important one)

The paper's central claim is that ASCII-vocabulary CNNs **collapse** on non-Latin
scripts (Table V: 62.1% Arabic, 58.7% CJK) while byte-level UniPhish holds ~98.7%.

**We did not reproduce this collapse.** On a realistic, balanced dataset (synthetic
multilingual + real OpenPhish/URLhaus/Umbrella feeds), an ASCII-CNN with the *same*
architecture **ties** UniPhish:

| model | arabic | cjk | devanagari | hangul | latin | other | macro-F1 |
|---|---|---|---|---|---|---|---|
| uniphish | 1.000 | 1.000 | 1.000 | 1.000 | 0.993 | 1.000 | **0.999** |
| ascii_cnn | 1.000 | 1.000 | 1.000 | 1.000 | 0.994 | 1.000 | **0.999** |
| byte_bilstm | 0.999 | 0.999 | 0.992 | 0.998 | 0.979 | 0.995 | 0.993 |
| random_forest | 0.995 | 0.995 | 0.997 | 0.994 | 0.970 | 0.993 | 0.991 |

**Why:** in realistic data the phishing signal is largely *structural* and
ASCII-visible (suspicious TLDs, subdomain stuffing, path patterns, URLhaus-style
URLs). An ASCII-CNN reads that fine even when it blanks non-Latin characters to
`[UNK]`; and when a phishing URL carries non-ASCII, "domain contains `[UNK]`" is
itself a usable signal. The blanket claim that ASCII detectors are *blind* to
non-Latin phishing is therefore **overstated** for structure-rich data.

**The honest, narrower truth:** byte-level encoding's specific benefit is expected
only where non-ASCII content is the *sole* discriminator — pure homoglyph/IDN
evasion against benign URLs that *also* contain non-Latin script. That controlled
experiment is future work; we do not claim a general multilingual accuracy
advantage the data doesn't support.

## 3. Dataset (MultiPhishDB)

The paper's MultiPhishDB (487,523 URLs, expert bilingual annotation, κ = 0.91) is
gated / not public and did not ship with the paper. This repo does **not** claim to
reproduce it. Instead it uses a documented, reproducible blend of a multilingual
**synthesizer** + real public feeds (OpenPhish, URLhaus, Cisco Umbrella). The
κ / human-annotation claims are **not** reproduced here — see `data/DATASHEET.md`.

## 4. Headline results (this implementation, real runs)

- In-distribution macro-F1: **0.9991**, FNR 0.0026, FPR 0.0000.
- **Cross-dataset real holdout (n = 7,199): acc/F1 0.9954, FNR 0.0090** — trained on
  our blend, tested on held-out real URLs. (Caveat: benign = Umbrella bare domains,
  phishing = URLhaus full URLs, so part of the separation is structural, not purely
  phishing semantics.)
- Adversarial (homoglyph substitution): clean 0.999 → **0.995 at 20%** — robust.

## 5. Deployment (measured, not the paper's placeholders)

| | Paper | This repo (measured) |
|---|---|---|
| Model size | 4.2 MB (int8) | **0.40 MB** TFLite (int8) |
| Latency | 0.31 ms (ARM) | **0.76 ms** (Mac CPU, 1 thread) |

Different hardware, but the order of magnitude holds: sub-millisecond, sub-megabyte.

## 6. Portability gotcha

A model saved on Kaggle's newer Keras fails `keras.models.load_model` on older
Keras (`quantization_config` kwarg on `Embedding`). Fix: rebuild the architecture
and `load_weights`, or ship the version-independent `.tflite`. Both are implemented
(`uniphish/compress.load_weights_into_fresh`, `uniphish/infer` TFLite path).
