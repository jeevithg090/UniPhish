// The on-device verdict engine: rules + byte-CNN + log-odds fusion.
//
// This is the single entry point every UI surface (content script via the service worker,
// popup, interstitial, context menu) uses, so a given URL always yields the same verdict.
// Nothing here touches the network: the model weights and data bundle are packaged with the
// extension, and "nothing leaves your device" is a property of this module.
//
//   const engine = UniPhishEngine.createEngine({ data, model });
//   const v = engine.score("https://pаypal.com/login", { thresholds, allowlist });
//   v => { url, tier: "safe"|"warn"|"block", risk, score, logit, prob, brand, techniques,
//          primary, signals: [{id,title,detail,weight,confidence,category,span,params,contribution}],
//          host, trusted, modelUsed }

(function (global) {
  "use strict";

  const req = (name, globalName) =>
    (typeof module !== "undefined" && module.exports && typeof require === "function")
      ? require(name) : global[globalName];
  const Rules = req("./rules.js", "UniPhishRules");
  const Fusion = req("./fusion.js", "UniPhishFusion");
  const Sal = req("./saliency.js", "UniPhishSaliency");
  const UrlLib = req("./urlparse.js", "UniPhishUrl");

  const CACHE_MAX = 4000;
  const MAX_INPUT = 8192;

  function hostTrusted(host, allowlist) {
    if (!host || !allowlist || !allowlist.length) return null;
    for (const raw of allowlist) {
      const d = String(raw || "").trim().toLowerCase().replace(/^\*?\./, "");
      if (d && (host === d || host.endsWith("." + d))) return d;
    }
    return null;
  }

  function createEngine({ data, model }) {
    const rules = Rules.createRules(data);
    const cache = new Map(); // `${thresholds}|${allow}|${url}` -> verdict (insertion-ordered LRU-ish)

    /** Score one URL. Never throws; unparseable input yields a safe-tier "invalid" verdict. */
    function score(url, opts) {
      const o = opts || {};
      const text = String(url == null ? "" : url).slice(0, MAX_INPUT);
      const th = Fusion.normThresholds(o.thresholds);
      const allow = o.allowlist || [];
      const key = th.warn + "|" + th.block + "|" + allow.join(",") + "|" + text;
      if (!o.noCache && cache.has(key)) return cache.get(key);

      // Show (and explain) an IDN host in its Unicode form: the user must see the look-alike
      // letters, not "xn--pypal-4ve". The model still scores the string exactly as given.
      const pre = UrlLib.parseUrl(text);
      let shown = text;
      if (pre.valid && pre.punycode && pre.hostSpan && pre.hostUnicode && pre.hostUnicode !== pre.host &&
          pre.input.slice(pre.hostSpan[0], pre.hostSpan[1]).toLowerCase() === pre.host) {
        shown = pre.input.slice(0, pre.hostSpan[0]) + pre.hostUnicode + pre.input.slice(pre.hostSpan[1]);
      }
      const a = rules.analyze(shown);
      const p = a.parsed;
      const modelInput = pre.valid ? pre.input : p.input;
      if (p.valid && p.isLocal) {
        // Loopback / private / intranet hosts cannot be phished from outside: never warn.
        const local = { url: text, input: p.input, href: p.href || "", valid: true, local: true, tier: "safe", risk: 0, score: 0,
          logit: Fusion.PRIOR_LOGIT, prob: null, brand: null, techniques: [], primary: null, signals: [],
          host: p.hostUnicode || p.host, hostAscii: p.host, scheme: p.scheme, trusted: false,
          modelUsed: false, thresholds: th };
        if (!o.noCache) cache.set(key, local);
        return local;
      }
      const signals = a.signals.map((s) => Object.assign({}, s));
      let prob = null;
      let modelUsed = false;

      const scorable = p.valid && (p.scheme === "http" || p.scheme === "https" || p.scheme === "ftp");
      if (scorable && model && model.loaded) {
        try {
          prob = model.predict(modelInput);
          modelUsed = true;
          let w = Fusion.mlWeight(prob, modelInput.length);
          const agrees = Fusion.corroborated(signals);
          const capped = w > Fusion.UNCORROBORATED_ML_CAP && !agrees;
          if (capped) w = Fusion.UNCORROBORATED_ML_CAP;
          // Structural deception (look-alike host, '@' trick, brand in a sub-domain ...) is not
          // outweighed by the model saying the string "looks ordinary": its false-negative rate on
          // such tricks is exactly what the rules exist to cover.
          if (w < 0 && agrees) w = 0;
          if (Math.abs(w) >= Fusion.ML.MIN_REPORTED) {
            const positive = w > 0;
            const long = modelInput.length > Fusion.ML.LONG_URL_CHARS;
            signals.push({
              id: positive ? "ml.cnn.phishing" : "ml.cnn.benign",
              title: Rules.TITLES[positive ? "ml.cnn.phishing" : "ml.cnn.benign"],
              detail: `The on-device byte-level model gives this URL a ${(prob * 100).toFixed(1)}% phishing probability. It is one signal among many and cannot decide alone` +
                (capped ? " (its weight is capped because no rule-based evidence agrees)." : "."),
              weight: w, confidence: long && positive ? Fusion.ML.LONG_URL_CONFIDENCE : 1,
              category: "ml", span: null, params: { pct: (prob * 100).toFixed(1), capped: capped ? "1" : "" }, evidence: { prob, capped },
            });
          }
        } catch (_) { prob = null; modelUsed = false; }
      }

      const trustedBy = scorable ? hostTrusted(p.host, allow) : null;
      if (trustedBy) {
        signals.push({ id: "rep.user_allowlist", title: Rules.TITLES["rep.user_allowlist"],
          detail: `You added ${trustedBy} to your trusted sites.`, weight: -8, confidence: 1,
          category: "reputation", span: null, params: { domain: trustedBy }, evidence: {} });
      }

      const fused = scorable || signals.length ? Fusion.fuse(signals, th) : Fusion.fuse([], th);
      signals.sort((x, y) => Math.abs(y.contribution || 0) - Math.abs(x.contribution || 0));
      const brand = a.brand ? { id: a.brand.brand, name: a.brand.name, technique: a.brand.technique,
        confidence: a.brand.confidence, official: !!a.brand.official, legit: a.brand.legit } : null;

      const verdict = {
        url: text, input: p.input, href: p.href || "", valid: p.valid && scorable, tier: fused.tier, risk: fused.risk,
        score: fused.score, logit: fused.logit, prob, brand, techniques: a.techniques, primary: a.primary,
        signals, host: p.hostUnicode || p.host, hostAscii: p.host, scheme: p.scheme,
        trusted: !!trustedBy, modelUsed, thresholds: th,
      };
      if (!verdict.valid && p.valid === false) verdict.tier = "safe";
      if (!o.noCache) {
        if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value);
        cache.set(key, verdict);
      }
      return verdict;
    }

    /** Per-character occlusion saliency for the popup heat-map (requires the model). */
    function saliency(url, maxChars) {
      if (!model || !model.loaded) return null;
      const p = rules.analyze(url).parsed;
      const text = p.input || String(url);
      const result = Sal.occlusion(model, text, maxChars);
      return { text, base: result.base, chars: result.chars, spans: Sal.topSpans(text, result) };
    }

    return { score, saliency, rules, clearCache: () => cache.clear() };
  }

  const api = { createEngine, hostTrusted };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhishEngine = api;
})(typeof self !== "undefined" ? self : this);
