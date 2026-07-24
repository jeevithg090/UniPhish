# Model Card — UniPhish

## Overview
UniPhish is a Unicode-native, character-(byte-)level 1D-CNN that classifies a URL
string as phishing or benign. It encodes each URL as its UTF-8 byte sequence
(256-token vocabulary, 600-byte window) and applies parallel multi-kernel
convolutions. **377,985 parameters; 0.40 MB as int8 TFLite.**

- **Input:** a URL string (any Unicode script).
- **Output:** phishing probability in [0, 1], mapped to risk tiers
  `safe < 0.5 ≤ warn < 0.9 ≤ block`.
- **Framework:** TensorFlow / Keras; TFLite for deployment.

## Intended use
- **Defensive** screening of URLs in messaging / browsing contexts (advisory
  warnings), especially for non-English scripts underserved by ASCII-only tools.
- A research / educational reference implementation of the UniPhish paper.

## Out of scope / not intended for
- Sole basis for blocking traffic without human/secondary review.
- Generating or targeting phishing (the repo builds no malicious infrastructure).
- Deciding on shortened URLs (`bit.ly/...`) without resolving redirects — the model
  only sees the string.

## Training data
Reproducible blend (see `data/DATASHEET.md`):
- **Synthetic** multilingual URLs across 6 script families with realistic phishing
  construction (SLD squatting, subdomain stuffing, path deception, homoglyph, IDN).
- **Real public feeds:** OpenPhish + URLhaus (phishing/malicious), Cisco Umbrella
  top-1M (benign). Balanced (~46% phishing); per-domain capping; SHA-256 dedup.
- Adversarial training: min-max objective on Unicode homoglyph substitutions.

## Evaluation (real runs; regenerable)
| Metric | Value |
|---|---|
| In-distribution macro-F1 | 0.9991 |
| Cross-dataset real holdout (n=7,199) F1 | 0.9954 |
| FNR (in-dist / cross-dataset) | 0.0026 / 0.0090 |
| Accuracy @ 20% homoglyph substitution | 0.995 |
| TFLite size / latency (Mac CPU, 1 thread) | 0.40 MB / 0.76 ms |

## Limitations & honest caveats
- **No general advantage over an ASCII-CNN was found** on this data — an ASCII-CNN
  ties UniPhish (~0.999 macro-F1). Phishing here is largely detectable from
  ASCII-visible structure. See `docs/paper_vs_reality.md §2`. Byte-level's benefit is
  expected to be narrow (pure homoglyph/IDN evasion), not a blanket accuracy gain.
- **Source separability:** benign (Umbrella bare domains) and phishing (URLhaus full
  URLs) differ structurally, so headline accuracy overstates pure phishing-semantic
  skill. A benign set with realistic paths would be a harder, fairer test.
- **Overconfident outputs** (probabilities cluster near 0/1); calibrate before using
  thresholds other than 0.5/0.9 in production.
- **Distribution shift:** phishing evolves; periodic retraining is required.
- Trained largely on synthetic + a few real feeds — not a substitute for a
  production threat-intel dataset.

## Ethical considerations
Defensive tool. The homoglyph engine exists to make detection *robust to* evasion.
Synthetic phishing strings are for training only; no live malicious content is created.
