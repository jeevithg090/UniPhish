// Log-odds evidence fusion (port of uniphish/core/scoring.py + analyzers/ml.py::ml_weight).
//
// Model: logit = PRIOR + sum(contribution(signal)); risk = sigmoid(logit).  A signal's
// contribution is weight x confidence x damping.  Within one `category` the strongest
// malicious signal counts fully, the next by DECAY, then DECAY^2 ... (same for benign
// evidence), so six correlated lexical cues cannot pose as one strong proof, while
// independent evidence families (brand + unicode + url + ml) add up.  Because fusion is
// additive, every verdict decomposes exactly into per-signal contributions.

(function (global) {
  "use strict";

  const PRIOR_LOGIT = -2.0;   // ~12% base rate for an arbitrary link
  const DECAY = 0.55;
  const LOGIT_CLAMP = 12.0;

  // Python Settings defaults; the user can move them in the options page.
  const DEFAULT_THRESHOLDS = Object.freeze({ warn: 0.5, block: 0.85 });

  // ML signal shaping (identical constants to uniphish/analyzers/ml.py)
  const ML = Object.freeze({ SHRINK: 0.6, MIN_WEIGHT: -2.5, MAX_WEIGHT: 4.0, LONG_URL_CHARS: 120,
    LONG_URL_MAX_WEIGHT: 2.5, LONG_URL_CONFIDENCE: 0.7, MIN_REPORTED: 0.1 });

  function sigmoid(x) {
    return x >= 0 ? 1 / (1 + Math.exp(-x)) : Math.exp(x) / (1 + Math.exp(x));
  }

  function logit(p, eps) {
    const e = eps === undefined ? 1e-6 : eps;
    const q = Math.min(Math.max(p, e), 1 - e);
    return Math.log(q / (1 - q));
  }

  /** Bounded log-odds weight for a CNN probability (the model is overconfident; shrink it). */
  function mlWeight(prob, urlLen) {
    if (!Number.isFinite(prob)) return 0;
    const w = ML.SHRINK * logit(prob);
    const ceiling = (urlLen || 0) > ML.LONG_URL_CHARS ? ML.LONG_URL_MAX_WEIGHT : ML.MAX_WEIGHT;
    return Math.max(ML.MIN_WEIGHT, Math.min(ceiling, w));
  }

  // Rule evidence that is *intrinsically* deceptive. The raw CNN over-scores many ordinary URLs
  // (documented caveat in MODEL_CARD.md: long, unfamiliar-but-legitimate URLs), so on its own it
  // must not be able to warn or block: its weight is capped unless one of these rule signals
  // (|weight x confidence| >= CORROBORATION_MIN) agrees with it.
  const CORROBORATION_MIN = 1.0;
  const UNCORROBORATED_ML_CAP = 1.0;
  const CORROBORATING = /^(brand\.(?!official)|unicode\.(?!punycode$)|url\.(ip_obfuscation|at_redirect|double_extension|suspicious_file_ext|dangerous_scheme|open_redirect|dynamic_dns|suspicious_tld|credential_lure_host|many_subdomains)$)/;

  /** True when a non-ML rule signal independently supports a phishing verdict. */
  function corroborated(signals) {
    return signals.some((s) => s.weight > 0 && s.category !== "ml" && CORROBORATING.test(s.id) &&
      s.weight * (s.confidence === undefined ? 1 : s.confidence) >= CORROBORATION_MIN);
  }

  /** Set `contribution` on every signal (mutates) and return their sum. */
  function applyContributions(signals) {
    const groups = new Map();
    for (const s of signals) {
      const key = s.category + (s.weight >= 0 ? "+" : "-");
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(s);
    }
    let total = 0;
    for (const members of groups.values()) {
      members.sort((a, b) => Math.abs(b.weight * b.confidence) - Math.abs(a.weight * a.confidence));
      members.forEach((s, rank) => {
        const c = s.weight * s.confidence * Math.pow(DECAY, rank);
        s.contribution = Math.round(c * 10000) / 10000;
        total += c;
      });
    }
    return total;
  }

  function normThresholds(th) {
    const warn = th && Number.isFinite(th.warn) ? th.warn : DEFAULT_THRESHOLDS.warn;
    let block = th && Number.isFinite(th.block) ? th.block : DEFAULT_THRESHOLDS.block;
    if (block < warn) block = warn;
    return { warn, block };
  }

  function tierOf(risk, th) {
    const t = normThresholds(th);
    return risk >= t.block ? "block" : risk >= t.warn ? "warn" : "safe";
  }

  function fuse(signals, th) {
    const total = Math.max(-LOGIT_CLAMP, Math.min(LOGIT_CLAMP, PRIOR_LOGIT + applyContributions(signals)));
    const risk = sigmoid(total);
    return { logit: Math.round(total * 10000) / 10000, risk: Math.round(risk * 10000) / 10000,
      score: Math.round(risk * 100), tier: tierOf(risk, th) };
  }

  const api = { corroborated, CORROBORATION_MIN, UNCORROBORATED_ML_CAP, PRIOR_LOGIT, DECAY, DEFAULT_THRESHOLDS, ML, sigmoid, logit, mlWeight, applyContributions, fuse, tierOf, normThresholds };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhishFusion = api;
})(typeof self !== "undefined" ? self : this);
