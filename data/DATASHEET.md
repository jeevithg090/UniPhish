# Datasheet — UniPhish training data

Following the spirit of *Datasheets for Datasets* (Gebru et al.). This dataset is
**generated on demand** by `data/build_dataset.py`; nothing is redistributed here.

## Motivation
The paper's MultiPhishDB (487K URLs, expert bilingual annotation) is gated and not
public. To keep the project fully reproducible, we build a comparable-in-spirit
dataset from a multilingual synthesizer + open real feeds. Anyone can regenerate it.

## Composition
Two ingredients, blended and deduplicated:

1. **Synthetic multilingual URLs** (`data/synth.py`) across 6 script families
   (Latin non-English, Arabic, CJK, Devanagari, Hangul, other). Benign URLs use a
   large word bank for domain diversity; phishing URLs implement SLD squatting,
   subdomain stuffing, path deception, Unicode homoglyph substitution, and IDN
   punycode — the constructions described in the paper (Section II-A).
2. **Real public feeds** (`data/sources.py`, `--include-real`):
   - OpenPhish community feed — real phishing (label 1).
   - URLhaus online CSV — real malicious URLs (label 1).
   - Cisco Umbrella top-1M — real popular domains as benign (label 0).

Example composition (10k/family + real): ~57.7k URLs, **46% phishing** (balanced),
sources: ~48k synthetic, ~7k Umbrella benign, ~2.4k URLhaus, ~0.16k OpenPhish.

## Preprocessing
- URL normalization (scheme/case/trailing slash) + SHA-256 dedup.
- Per-(domain, class) cap of 50 to prevent domain memorization.
- Stratified 80/10/10 split by (script family, label).
- Adversarial test set: homoglyph substitution at 5/10/15/20%.
- **Cross-dataset holdout:** 30% of real feeds held out as `real_test.csv`, never
  used in training, for honest generalization measurement.

## Known limitations / biases
- **Benign vs phishing source mismatch:** benign (Umbrella) are bare domains;
  phishing (URLhaus) are full URLs. Models can exploit this structural difference,
  inflating accuracy relative to pure phishing-semantic difficulty.
- Synthetic phishing follows fixed templates; real-world creativity is broader.
- Real feeds skew Latin/English; non-Latin coverage is mostly synthetic.
- **No human annotation / κ agreement** — unlike the paper's MultiPhishDB. Labels are
  source-derived (feed = phishing, top-list = benign) or synthesizer-assigned.

## Legal / ethical
Feeds are used under their public terms for research. Synthetic phishing strings are
generated for training a *detector* and reference no real victims. Regenerate locally;
do not redistribute scraped feed contents.
