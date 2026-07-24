# UniPhish — Project Plan

What we do **after the first real Kaggle run** to turn this from "code that runs" into a
strong, publication-grade, reproducible artifact + demo that credibly backs the paper.

> **North star:** anyone can clone the repo, run one command, and reproduce every number
> and figure in the paper on real data — plus try a live URL scanner. Where reality differs
> from the paper text, the repo says so and the paper gets corrected.

---

## Definition of "a very good project"

A reviewer / recruiter / collaborator opening the repo should find, in order:

1. A clear README with a one-command reproduction and honest results.
2. Real, logged experimental results (not placeholder tables) with seeds and configs.
3. The central claim demonstrated: **byte-level UniPhish beats an ASCII-CNN on non-Latin
   scripts and under homoglyph attack**, with numbers.
4. A working demo (API + browser extension) and a <5 MB TFLite artifact.
5. Green CI, tests, a model card, a dataset datasheet, and a license.
6. A short "paper vs. reality" changelog showing scientific integrity.

---

## Status so far (done ✅)

| Area | State |
|---|---|
| Package scaffold, config, 12 unit tests | ✅ |
| UTF-8 byte encoder (256 vocab, 600-byte) | ✅ |
| Paper-spec Keras model — **377,985 params** (paper says 847,425; discrepancy logged) | ✅ |
| Reproducible multilingual data synthesizer (6 families, all phishing techniques) | ✅ |
| Adversarial min-max training (Eq. 15) + cosine LR + macro-F1 early stopping | ✅ |
| Per-epoch checkpoint + `--resume` (free-tier safe) | ✅ |
| Evaluation: per-family metrics, FNR/FPR, confusion, adversarial sweep → `results.json` | ✅ |
| Inference + risk tiers (warn/block), Keras or TFLite | ✅ |
| GitHub repo + Kaggle GPU pipeline verified end-to-end | ✅ |

---

## Step 0 — Right after this run: validate & interpret (½ day)

- [ ] Read the real `results/results.json`: macro-F1, per-family F1, FNR/FPR, adversarial sweep.
- [ ] Sanity checks: does the model actually learn (F1 ≫ 0.5)? Is Devanagari the weakest
      family (paper's claim)? Does adversarial accuracy degrade gracefully, not collapse?
- [ ] Record real numbers in `docs/paper_vs_reality.md` (params already logged; add metrics,
      latency, sizes as they come in).
- [ ] If learning looks healthy, launch **full scale** (`--per-family 40000`) as a committed
      Kaggle run; download `artifacts/` + `results/results.json`.
- [ ] Commit the frozen `results.json` and a `configs/` snapshot for the recorded run.

---

## Phase 4 — Baselines (the experiments that prove the thesis) (2–3 days)

The paper's whole argument rests on the ASCII-vs-byte contrast. Implement in `uniphish/baselines.py`:

- [ ] **B1 ASCII-CNN** — same architecture, 128-token ASCII vocab, non-ASCII → `[UNK]`.
      *This is the money comparison:* expect it to collapse on Arabic/CJK/Devanagari and under
      homoglyph attack, while UniPhish holds.
- [ ] **B2 byte-BiLSTM** — 2-layer BiLSTM on the same byte input (arch ablation).
- [ ] **B4 Random Forest (lexical)** — ~48 hand-engineered URL features.
- [ ] **B5 Unicode-block CNN** — block-id + offset embedding (byte vs block ablation).
- [ ] (Optional) **B3 mBERT** — heavy; run once for the accuracy/latency ceiling, or cite as N/A.
- [ ] A single `scripts/run_experiments.py` that trains all models on one dataset and writes a
      combined `results/comparison.json` (the source for the main results table).

**Acceptance:** a reproducible table showing ASCII-CNN ≪ UniPhish on non-Latin + adversarial.

---

## Phase 5b — Ablations & robustness (1–2 days)

- [ ] Ablation runs (config flags already exist): no-adv, single-kernel k=3, no-SpatialDropout,
      embed-dim 32, seq-len 200. Emit `results/ablation.json`.
- [ ] Adversarial: confirm the full-scale UniPhish+adv vs UniPhish(no-adv) gap at 15%/20%.
- [ ] Optional: real Unicode `confusables.txt` (via `homoglyphs.fetch_confusables`) for a
      stronger adversarial test than the built-in map.

---

## Phase 6 — Compression & mobile (`uniphish/compress.py`) (2–3 days)

- [ ] Stage 1: structured filter pruning (5 rounds × 20%, fine-tune 3 epochs each).
- [ ] Stage 2: knowledge distillation to a small student (T=4, α=0.3).
- [ ] Stage 3: post-training int8 quantization → **TFLite** with representative-dataset calibration.
- [ ] `scripts/benchmark.py`: measure real size (MB) and CPU latency (ms/URL, warm-up discarded)
      for every model → `results/latency.json`. **Report measured numbers, not the paper's.**

**Acceptance:** a `.tflite` artifact with its *actual* size + latency, and `infer.py` runs it.

---

## Phase 7 — Live demo (2–3 days)

- [ ] `api/server.py` — FastAPI `POST /scan` {url} → {prob, tier, family_hint}; loads Keras or
      TFLite; `GET /health`. Batch endpoint for throughput.
- [ ] `extension/` — Manifest V3 browser extension: scans links on a page, badges risky ones,
      shows an interstitial for `tier=block` (τ=0.9) and a banner for `warn` (τ=0.5), calling the
      local API. Ship a short screen-capture GIF in the README.
- [ ] A tiny hosted/HF-Spaces demo *or* a `docker compose up` that serves API + a demo page.

**Acceptance:** paste a homoglyph phishing URL → it gets flagged live.

---

## Phase 8 — Figures & paper sync (1 day)

- [ ] Rewrite the 7 `fig*.py` scripts to read `results/*.json` instead of hardcoded numbers
      (fig1 architecture stays static; fig2 training curves from `history.json`; fig3 latency
      from `latency.json`; fig4 adversarial from the sweep; fig5 per-script; fig7 confusion).
- [ ] `make figures` regenerates all PDFs/PNGs from recorded results.
- [ ] Finalize `docs/paper_vs_reality.md` and update the paper: parameter count (→377,985),
      all metric tables, latency/size tables, dataset section (say "synthetic + public feeds,
      reproducible" honestly), and κ / annotation claims (drop or reframe — no human annotators
      exist in this reproduction).

---

## Phase 9 — Data realism (optional but strong) (1–2 days)

- [ ] Flesh out `data/sources.py`: URLhaus (open CSV), OpenPhish community feed, Tranco top-list
      (benign), PhishTank (needs free API key). Graceful offline fallback to pure synthetic.
- [ ] Blend real + synthetic with `--include-real`; document provenance & dates in
      `data/DATASHEET.md` (a Gebru-style datasheet).
- [ ] Re-run the headline experiment on the blended set; note deltas vs pure-synthetic.

---

## Phase 10 — Engineering & reproducibility (1–2 days)

- [ ] `requirements-lock.txt` (frozen exact versions) + note Kaggle's preinstalled TF is used on GPU.
- [ ] **GitHub Actions CI**: `pytest` + a `--small` data build + 1-epoch train + evaluate on CPU
      (smoke test) on every push. Badge in README.
- [ ] Commit the Kaggle/Colab notebook (`notebooks/kaggle_run.ipynb`) so the cloud run is versioned.
- [ ] Deterministic seeds end-to-end; document expected variance.
- [ ] `pip install -e .` console entry points: `uniphish-train`, `uniphish-eval`, `uniphish-scan`.

---

## Phase 11 — Documentation & release (1 day)

- [ ] `MODEL_CARD.md` (intended use, training data, metrics, limitations, ethical considerations).
- [ ] `data/DATASHEET.md` (dataset composition, synthesis method, caveats).
- [ ] `LICENSE` (MIT for code; state that synthetic data is generated, not scraped victims).
- [ ] Publish `best.keras` + `.tflite` as a **GitHub Release** (or Hugging Face) so users needn't retrain.
- [ ] README: results table, demo GIF, CI badge, one-command repro, citation.

---

## Responsible use (keep visible)

- UniPhish is **defensive**. The synthesizer produces phishing-*style* strings to train a
  detector; it creates no live malicious infrastructure and targets no real people.
- The homoglyph engine exists to make the detector *robust to* evasion, per the paper — not to
  build attacks. State this in README + MODEL_CARD.

---

## Suggested order (fastest path to "impressive")

1. **Step 0** (interpret this run) →
2. **Phase 4 B1 ASCII-CNN only** (the one comparison that proves the point) →
3. **Full-scale run** of UniPhish vs B1 →
4. **Phase 6 TFLite** (real size/latency) →
5. **Phase 7 demo** →
6. rest of baselines / ablations / figures / docs.

That sequence gives a defensible headline result + a demo within about a week of focused work,
then hardens into a full artifact.

---

## Definition of Done ✅

- [ ] One command reproduces the headline result on real data.
- [ ] ASCII-vs-byte and adversarial results are real and logged.
- [ ] <5 MB TFLite artifact with measured latency; live demo works.
- [ ] CI green; model card + datasheet + license present.
- [ ] `paper_vs_reality.md` complete and the paper updated to match.
