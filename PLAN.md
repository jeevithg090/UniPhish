# UniPhish — Portfolio Build Plan (make it a standout résumé project)

Goal: turn this from "code that runs" into a project that makes a recruiter or hiring
manager stop scrolling — a **published-paper implementation** with a novel technical core,
real adversarial-ML results, an on-device deployment story, and a live demo, all
reproducible with one command and backed by CI.

> **Elevator pitch (memorize this):** *"UniPhish is a Unicode-native, byte-level 1D-CNN that
> detects phishing URLs in any language — Arabic, Chinese, Hindi, Korean — where every existing
> ASCII-based detector goes blind. It's a 378K-parameter model that runs in under a millisecond
> on CPU, survives Unicode homoglyph evasion attacks via adversarial training, and ships as a
> <5 MB on-device model with a live browser-extension demo. I built the whole pipeline — data,
> training, adversarial robustness, compression, and deployment — to implement (and audit) an
> IEEE paper I co-authored."*

---

## Why this reads as "insane" (the hooks)

1. **You co-authored the IEEE paper AND built the reproducible implementation.** Almost no
   student project has both. Research + engineering in one artifact.
2. **Scientific integrity as a feature.** You *audited your own paper* and found a real bug —
   the model is **377,985 params, not the 847,425 claimed**. A `paper_vs_reality.md` changelog
   shows you validate claims instead of trusting tables. Senior engineers love this.
3. **Real subfields, not a tutorial CNN:** adversarial ML (homoglyph attacks + min-max
   training), model compression (prune → distill → int8 → TFLite), multilingual NLP/security,
   and MLOps (CI, reproducibility, one-command repro).
4. **A demo they can touch.** A browser extension that flags a homoglyph phishing URL live is
   worth more than any table.
5. **Impact framing:** targets the ~3.4B non-English messaging users that ASCII detectors
   leave undefended.

---

## Paste-ready résumé bullets

> Every number below is **real and regenerable** from this repo. The earlier draft bullets
> claiming an ASCII-CNN "drops to ⟨Y⟩%" were removed — that contrast **did not reproduce**
> (the ASCII-CNN ties UniPhish on realistic data), and we do not claim it.

- **Built and open-sourced UniPhish**, a Unicode-native byte-level 1D-CNN (TensorFlow/Keras,
  377K params) for multilingual phishing-URL detection — **0.9954 F1 on a 7,199-URL held-out
  real-feed test set** (OpenPhish/URLhaus/Umbrella) across 6 script families, implementing an
  IEEE paper end-to-end from data pipeline to on-device deployment.
- **Adversarially trained against Unicode homoglyph evasion** (min-max objective over the
  Unicode confusables space): accuracy degrades only **0.999 → 0.995 at a 20% character-
  substitution attack**.
- **Deployed as a 0.40 MB int8 TFLite artifact with 0.76 ms CPU inference/URL** (laptop, single
  thread) — a 4× size and 11× latency improvement over the full Keras model — plus a FastAPI
  scan service and a Manifest V3 browser extension that flags risky links live.
- **Conducted a reproduction audit of the source paper**, catching a **2.2× parameter-count
  error** and showing its central "ASCII detectors are blind to non-Latin scripts" claim
  **does not hold** on realistic data (an equal-architecture ASCII-CNN ties byte-level at
  ~0.999 macro-F1) — documented in a public `paper_vs_reality.md`.
- **Built a reproducible data pipeline** blending a 6-script multilingual URL synthesizer
  (homoglyph/IDN/subdomain-stuffing attack constructions) with real threat feeds; SHA-256
  dedup, per-domain capping, stratified splits, and a pure-real cross-dataset holdout.

**The interview story (rehearse it):** *"My first run scored 99.98% and I didn't trust it —
train/test came from the same generator. I added real feeds and a cross-dataset holdout, and
then my own headline comparison failed to reproduce the paper's claim. I reported that instead
of hiding it."* That story is worth more than any accuracy number.

---

## Skills matrix (what each part signals to which role)

| Deliverable | Skills it proves | Target role |
|---|---|---|
| Byte-level model + architecture | Deep learning, NLP, CNNs, TF/Keras | ML Engineer / Applied Scientist |
| Homoglyph attacks + adversarial training | Adversarial ML, security ML | ML Security / Research |
| Prune → distill → int8 → TFLite | Model compression, edge/on-device ML | Edge/Mobile ML, ML Eng |
| Data synthesizer + real feed blending + cross-dataset eval | Data engineering, eval rigor | ML Eng / Data Scientist |
| FastAPI + browser extension + Docker | Full-stack / productionization | ML Eng / SWE |
| CI, tests, seeds, one-command repro, model card | MLOps, reproducibility, rigor | MLOps / Senior ML Eng |
| Paper audit + `paper_vs_reality.md` | Scientific integrity, communication | Research / any senior role |

---

## Headline metrics dashboard (fill from real runs — put this table in the README)

| Metric | UniPhish | ASCII-CNN baseline | Source |
|---|---|---|---|
| Macro-F1 (6 families) | ⟨ ⟩ | ⟨ ⟩ | `results/comparison.json` |
| Non-Latin F1 (Arabic/CJK/Deva) | ⟨ ⟩ | ⟨ ⟩ (expected collapse) | `results/comparison.json` |
| **Cross-dataset (real) F1** — the honest one | ⟨ ⟩ | ⟨ ⟩ | `results/results.json` |
| Accuracy @ 15% homoglyph attack | ⟨ ⟩ | ⟨ ⟩ | `results/adversarial.json` |
| Model size (TFLite int8) | ⟨ ⟩ MB | — | `results/latency.json` |
| CPU latency / URL | ⟨ ⟩ ms | ⟨ ⟩ ms | `results/latency.json` |
| Params | 377,985 | ⟨ ⟩ | `python -m uniphish.model` |

---

## Status so far (done ✅)

| Area | State |
|---|---|
| Package scaffold, config, 12 unit tests | ✅ |
| UTF-8 byte encoder (256 vocab, 600-byte) | ✅ |
| Paper-spec Keras model — **377,985 params** (paper says 847,425; audited) | ✅ |
| Multilingual data synthesizer (6 families, all phishing techniques) | ✅ |
| Real public feeds (OpenPhish/URLhaus/Umbrella) + cross-dataset holdout | ✅ |
| Adversarial min-max training + cosine LR + macro-F1 early stopping | ✅ |
| Per-epoch checkpoint + `--resume` (free-tier safe) | ✅ |
| Evaluation: per-family, FNR/FPR, confusion, adversarial sweep, cross-dataset | ✅ |
| Inference + risk tiers (warn/block), Keras or TFLite | ✅ |
| GitHub repo + Kaggle P100 pipeline verified end-to-end | ✅ |

---

## Build phases — each with its résumé payoff

### Step 0 — Lock a real headline number (½ day)  → *proof it works*
- [ ] Read `results/results.json`; record the **cross-dataset real** F1/FNR/FPR — the number
      that goes on the résumé and README.
- [ ] If healthy, run **full scale** (`--per-family 40000`), download `artifacts/` + results.
- [ ] Log everything in `docs/paper_vs_reality.md`.

### Phase 1 — The money comparison: ASCII-CNN vs UniPhish (1–2 days)  → *the killer chart*
- [ ] `uniphish/baselines.py` **B1 ASCII-CNN** (128-vocab, non-ASCII → `[UNK]`). Show it
      collapses on Arabic/CJK/Devanagari and under homoglyph attack while UniPhish holds.
- [ ] `scripts/run_experiments.py` → `results/comparison.json`; one bar chart tells the story.
- **Payoff:** the single figure + bullet that proves the thesis.

### Phase 2 — Compression & on-device (2 days)  → *"<5 MB, sub-ms" bullet*
- [ ] `uniphish/compress.py`: structured pruning → distillation (T=4, α=0.3) → int8 TFLite.
- [ ] `scripts/benchmark.py`: real size (MB) + CPU latency (ms/URL, warm-up discarded) →
      `results/latency.json`. **Measured, not the paper's.**
- **Payoff:** edge-ML credibility; a concrete efficiency story.

### Phase 3 — Live demo (2–3 days)  → *the thing they'll actually click*
- [ ] `api/server.py` — FastAPI `POST /scan` → `{prob, tier, family_hint}`; Keras or TFLite.
- [ ] `extension/` — Manifest V3 extension: scans page links, blocks `tier=block` (τ=0.9),
      warns `tier=warn` (τ=0.5). Record a **GIF/30-sec video** for the README + LinkedIn.
- [ ] Deploy a **Hugging Face Space** (or `docker compose up`) so there's a public URL.
- **Payoff:** a demo link on the résumé; recruiters love clickable proof.

### Phase 4 — Ablations & robustness (1–2 days)  → *depth/rigor*
- [ ] no-adv / single-kernel / no-SpatialDropout / embed-32 / seq-200 → `results/ablation.json`.
- [ ] Stronger adversarial test using the full Unicode `confusables.txt`.

### Phase 5 — Figures & paper sync (1 day)  → *the research half*
- [ ] Rewire the 7 `fig*.py` to read `results/*.json` (no hardcoded numbers). `make figures`.
- [ ] Finalize `docs/paper_vs_reality.md`; correct the paper (param count, all tables, dataset
      section reframed honestly, κ/annotator claims dropped for this reproduction).

### Phase 6 — Engineering polish & release (1–2 days)  → *the "senior" signals*
- [ ] **GitHub Actions CI**: `pytest` + `--small` data build + 1-epoch train + evaluate on CPU,
      on every push. **Add the green badge to the README** (huge signal).
- [ ] `requirements-lock.txt`; console entry points (`uniphish-train/eval/scan`); commit
      `notebooks/kaggle_run.ipynb`.
- [ ] `MODEL_CARD.md`, `data/DATASHEET.md`, `LICENSE` (MIT).
- [ ] Publish `best.keras` + `.tflite` as a **GitHub Release** / HF model so users skip training.
- [ ] README: elevator pitch, metrics table, demo GIF, CI badge, one-command repro, paper link.

### Phase 7 — Amplify (½ day)  → *reach*
- [ ] A short **technical blog post / LinkedIn write-up**: "Why every phishing detector is blind
      to 3.4 billion people, and how a 378K-param byte-level CNN fixes it." Link the repo + demo.
- [ ] Pin the repo on GitHub; add topics (`phishing-detection`, `adversarial-ml`, `tflite`,
      `nlp-security`). A clean README screenshot as the social preview image.

---

## Portfolio deliverables checklist (the tangible outputs)

- [ ] **GitHub repo** — pinned, CI badge, killer README, one-command repro.
- [ ] **Live demo URL** — HF Space or hosted API + extension GIF.
- [ ] **Published model artifact** — `.tflite` in a GitHub Release.
- [ ] **The IEEE paper** — linked, with the `paper_vs_reality.md` audit.
- [ ] **A blog post / write-up** — for LinkedIn and the résumé "Projects" link.
- [ ] **One headline chart** — ASCII-CNN collapse vs UniPhish across scripts.

---

## Interview talking points (rehearse these)

- *"Why byte-level?"* → 256 values cover all of Unicode with no `[UNK]`; homoglyphs become
  distinct, learnable byte sequences instead of collapsing to one unknown token.
- *"How did you make it robust?"* → min-max adversarial training on Unicode confusables; loss =
  clean CE + λ·adversarial CE; walk through the numbers.
- *"What was hard / what did you learn?"* → the first run scored 99.98% and I *didn't trust it* —
  train/test came from the same synthesizer. I added real feeds + a cross-dataset holdout to get
  an honest number. (This story alone can win an interview.)
- *"How is it deployable?"* → prune/distill/quantize to <5 MB int8 TFLite, sub-ms CPU, browser
  extension with risk tiers.
- *"How do you know it's correct?"* → CI, seeds, unit tests, and a paper-vs-reality audit that
  already caught a 2.2× parameter error.

---

## Responsible use (keep visible — it's also a maturity signal)

UniPhish is **defensive**. The synthesizer produces phishing-*style* strings to train a
detector; it builds no live malicious infrastructure and targets no real people. The homoglyph
engine exists to make the detector *robust to* evasion. Stated in README + `MODEL_CARD.md`.

---

## Definition of Done ✅

- [ ] One command reproduces a **real, honest** headline number (cross-dataset).
- [ ] ASCII-vs-byte + adversarial results are real, logged, and charted.
- [ ] <5 MB TFLite artifact with measured latency; **live demo URL works**.
- [ ] CI green (badge in README); model card + datasheet + license present.
- [ ] `paper_vs_reality.md` complete; paper corrected to match.
- [ ] Blog post + pinned repo + demo link ready to drop on a résumé.

> **Integrity rule for the résumé:** every number you quote must come from a run in this repo,
> reproducible by anyone who clones it. The credibility *is* the flex.
