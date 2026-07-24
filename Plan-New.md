# Plan-New — from "good ML project" to a standout security product

The goal of this document: additions that make a security-savvy reviewer stop and think
*"this person builds like a security engineer AND a product owner"* — not another URL
classifier. Every feature below is grounded in the code that already exists
(`uniphish/model.py`, `infer.py`, `homoglyphs.py`, `api/`, `extension/`).

---

## The honest gap (why the current project isn't yet "insane")

Today UniPhish is a well-engineered **string classifier**: paste a URL, get a probability.
That is table stakes. A reviewer from a security team immediately asks the questions a
real detector must answer, and which we currently can't:

1. **"*Why* is this phishing?"** — we return a black-box number, no reasons. SOC analysts
   and end users both need the *why*.
2. **"What is it impersonating?"** — we don't say "this mimics `paypal.com`." That's the
   actionable part.
3. **"What about signals the URL string can't show?"** — domain age, redirects behind
   shorteners, punycode/IDN decoding, TLS. Real detectors fuse these; we ignore them.
4. **"Where does the user's data go?"** — we POST every URL to a server. Google Safe
   Browsing and SmartScreen do too, and users pay for it in privacy.
5. **"Is there a product?"** — a demo endpoint isn't a product people use.

## The market problem (sharpened)

- **~3.4B non-English messaging users have effectively no phishing protection.**
- Every mainstream tool is **server-based** (your browsing is sent to Google/Microsoft),
  **English-centric**, **opaque** (just "dangerous", no reason), and weak on **homoglyph /
  IDN** attacks that dominate multilingual phishing.
- **The unmet need = a private (on-device), explainable, multilingual phishing shield.**
  Nobody ships that combination. That is the wedge.

## Vision (the one-liner to put on the project)

> **UniPhish Shield — the first on-device, explainable, multilingual anti-phishing engine.
> Nothing leaves your browser. It tells you *why* a link is dangerous, in your language,
> and *what brand* it's trying to impersonate.**

---

## Feature tracks

Each feature notes: **what**, **why it impresses**, **market problem solved**, **how to
build (on existing code)**, **acceptance**, and the **résumé bullet** it unlocks.

### Track A — Explainability ("the why") — *highest wow-per-effort, build first*

**A1. Byte-level saliency.** Gradient×input (or occlusion) over the embedding to score how
much each byte/character pushed the verdict. Render a heatmap over the URL string.
- *Why it impresses:* turns a black box into an analyst tool; explainable-AI is rare in
  student projects and prized in security ML.
- *Market problem:* users/analysts can't trust or act on an opaque score.
- *Build:* `uniphish/explain.py` — `tf.GradientTape` on the embedding output of the loaded
  model; aggregate |grad·emb| per byte → per character; return spans + weights.
- *Acceptance:* for `https://pаypаl.com/login`, the Cyrillic `а` bytes light up.

**A2. Human-readable reasons.** A rules layer that converts structure into plain language:
"Cyrillic character disguised as 'a'", "brand name in subdomain, not the real domain",
"suspicious TLD `.top`", "punycode domain", "IP address instead of a domain".
- *Why:* the difference between "0.98" and "here's exactly why" is the difference between a
  toy and a product.
- *Build:* `uniphish/reasons.py`, reusing `homoglyphs.py` + URL parsing.

**A3. Brand-impersonation identification.** Given a suspect domain, name the legitimate
brand it mimics, using the **Unicode skeleton** algorithm (TR39 confusables — we already
have the confusables map) + edit distance against a brand list.
- *Why:* "impersonates **paypal**" is the single most actionable output a phishing tool can
  give. This is what makes security people nod.
- *Build:* `uniphish/brands.py` — skeleton(domain) vs skeleton(brand); Levenshtein; return
  best match + confidence.
- *Acceptance:* `pаypаl.com` → impersonates `paypal` (confusable); `paypa1.xyz` →
  impersonates `paypal` (typo).

### Track B — Hybrid security enrichment (signals the string can't show)

**B1. IDN / punycode decoding + confusable score.** Decode `xn--…` to Unicode, compute a
homoglyph "confusable risk" vs the brand list.
- *Build:* `idna` (already a dep) + Track A3 skeleton. `uniphish/enrich.py`.

**B2. URL unshortening / redirect-chain resolution.** Follow `bit.ly`/`t.co` to the real
destination and score *that* (the paper lists this as an unsolved limitation).
- *Why:* closes a real evasion gap; shows systems thinking.
- *Build:* server-side `HEAD`/`GET` with redirect capping + timeout + **SSRF guardrails**
  (block private IPs/localhost) — call out the security caution explicitly.

**B3. Domain-age lookup (RDAP).** Freshly registered domains are a top phishing signal.
Query free RDAP (`rdap.org`) for registration date → age in days.
- *Build:* `uniphish/enrich.py`; cache + graceful offline fallback.

**B4. Fused, calibrated risk score.** Combine ML probability + enrichment signals into a
single 0–100 risk with a reason list and a **calibrated** confidence.
- *Why:* production detectors are ensembles, not one model; this shows detection-engineering
  maturity. Also fixes the current 0/1 overconfidence.
- *Build:* temperature-scaling calibration on a validation split
  (`uniphish/calibrate.py`) + a transparent weighted fusion.

### Track C — On-device & privacy (the product differentiator)

**C1. In-browser inference (zero server).** Run the model *inside* the extension via
TF.js / ONNX-Runtime-Web (WASM) so **no URL ever leaves the device**.
- *Why it impresses:* this is the headline product claim and a real privacy win over Safe
  Browsing/SmartScreen. Technically credible (we already export TFLite; convert to
  TF.js/ONNX). "Phishing protection that never sees your browsing."
- *Build:* convert `artifacts/uniphish.tflite` → TF.js (`tflite`→`tfjs`) or ONNX-web; a
  byte-encoder in JS (trivial — UTF-8 bytes); ship weights in the extension.
- *Acceptance:* extension flags links with the API server **off**.

**C2. Abstention / escalation tier.** When calibrated confidence is low, don't guess —
surface "uncertain, verify manually" (or optionally escalate to server enrichment).
- *Why:* mature security UX never auto-blocks on a coin-flip.

### Track D — Product surfaces (make it real, make it clickable)

**D1. Telegram bot** — forward a suspicious link to `@UniPhishBot`, get an instant verdict +
explanation + brand-impersonation, **in the message's language.**
- *Why it impresses:* directly realizes the paper's *messaging-app* thesis with a real,
  demoable user surface; recruiters can try it in 10 seconds.
- *Market problem:* messaging is exactly where multilingual phishing lands and where no
  gateway scans links.
- *Build:* `bot/telegram_bot.py` (`python-telegram-bot`), reusing `infer` + enrichment.

**D2. Hosted public demo.** A page (HF Space / Gradio or static + on-device model) where
anyone pastes a URL and sees score + heatmap + brand match + domain age.
- *Why:* a live URL on the résumé beats any table.

**D3. Explainable, localized interstitial.** Upgrade the extension block screen to explain
the threat in plain language **in the user's UI language** ("This link uses a Cyrillic 'а'
to look like apple.com") + a one-click "report" feedback loop.
- *Why:* user education > silent blocking; the feedback loop shows human-in-the-loop ML.

### Track E — Model security / red-team (maturity signal)

**E1. Adversarial attack harness.** A tool that *attacks* our own model (homoglyph swap,
character insertion, TLD swap, path padding, zero-width chars) and reports evasion rate.
- *Why:* red-teaming your own model is exactly what security-ML teams screen for.
- *Build:* `uniphish/attacks.py` + `scripts/redteam.py` → `results/robustness.json`.

**E2. Security section in the model card** — documented attack surface, evasion rates,
mitigations. Extends `MODEL_CARD.md`.

---

## Prioritized build order (max impressiveness per unit effort)

1. **Track A (A1 saliency + A2 reasons + A3 brand impersonation)** — visible, unique, fast;
   instantly upgrades every surface (API/extension/bot) from "score" to "explained verdict."
2. **Track B enrichment + B4 fused calibrated risk** — the security depth.
3. **Track C1 on-device inference** — the privacy headline; kills the "you send data to a
   server" objection.
4. **Track D1 Telegram bot + D2 hosted demo** — the clickable, on-thesis product.
5. **Track E red-team harness** — the maturity capstone.

A focused week gets 1–3; a second week gets 4–5.

## Résumé bullets these unlock (all real once built)

- **Built an explainable phishing-detection engine** that highlights the exact characters
  driving each verdict (byte-level saliency) and **names the impersonated brand** via the
  Unicode TR39 confusable-skeleton algorithm.
- **Designed a hybrid detection pipeline** fusing a byte-level CNN with live enrichment —
  IDN/punycode decoding, redirect-chain resolution (with SSRF guards), and RDAP domain-age —
  into a single calibrated risk score.
- **Shipped fully on-device inference** (TF.js/WASM in a browser extension): multilingual
  phishing detection with **zero user data leaving the device** — a privacy advantage over
  server-based Safe Browsing/SmartScreen.
- **Launched a Telegram anti-phishing bot** that scans forwarded links and explains the
  threat in the user's language — realizing the target use case (messaging apps) end-to-end.
- **Red-teamed the model** with a homoglyph/insertion/TLD-swap attack harness and published
  the evasion-rate report and mitigations.

## Why a reviewer will be impressed (not "generic")

- It **explains** and **attributes** (brand impersonation), like a real detection product.
- It **fuses ML with security signals** — detection engineering, not just "train a CNN."
- It is **private by design** (on-device) — a genuine, defensible product differentiator.
- It has a **real user surface** (Telegram bot) tied to a **real underserved market**.
- It **red-teams itself** and documents the attack surface — security maturity.

## Honesty guardrails (keep the credibility that makes it strong)

- Keep `docs/paper_vs_reality.md` accurate; never re-introduce the disproven
  "ASCII-CNN collapses" claim.
- Enrichment that follows redirects must have **SSRF protection** (block private/loopback
  IPs) — and say so; it's a security feature, not an afterthought.
- On-device numbers (size/latency in-browser) must be **measured**, like everything else.
- Brand-impersonation and reasons are **heuristic aids**, labeled as such — not ground truth.
