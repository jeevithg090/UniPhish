// Defanged text reports and the optional server client.
//
// `defang()` neutralises a URL so it can be pasted into chat / tickets without becoming a
// live link (hxxps://evil[.]example/...).  `buildReport()` produces the plain-text report
// behind the interstitial's "Copy report" action.
//
// The server client (`deepScan`, `ping`, `submitReport`) is the ONLY code in the extension
// that can reach the network.  It never runs unless the user enabled deep analysis AND
// configured an https (or localhost) endpoint AND granted that origin in the browser's
// permission prompt; callers must check `settings.deepEnabled` first.

(function (global) {
  "use strict";

  function defang(url) {
    return String(url || "")
      .replace(/^http/i, "hxxp")
      .replace(/^ftp:/i, "fxp:")
      .replace(/\./g, "[.]")
      .replace(/:\/\//, "[://]")
      .replace(/@/g, "[@]");
  }

  /** Plain-text report. `reasons` are already-rendered strings (English for reports). */
  function buildReport(verdict, reasons, now) {
    const lines = [
      "UniPhish on-device report",
      `Time (UTC): ${(now || new Date()).toISOString()}`,
      `URL (defanged): ${defang(verdict.href || verdict.input || verdict.url)}`,
      `Verdict: ${verdict.tier} (${verdict.score}/100)`,
    ];
    if (verdict.brand && !verdict.brand.official) lines.push(`Impersonated brand: ${verdict.brand.name} (${verdict.brand.technique})`);
    if (verdict.techniques && verdict.techniques.length) lines.push(`Techniques: ${verdict.techniques.join(", ")}`);
    if (reasons && reasons.length) {
      lines.push("Reasons:");
      reasons.forEach((r) => lines.push(`- ${r}`));
    }
    lines.push("Scored entirely on-device; no data was sent anywhere to produce this report.");
    return lines.join("\n");
  }

  function headers(settings) {
    const h = { "Content-Type": "application/json", Accept: "application/json" };
    if (settings.apiKey) h["X-API-Key"] = settings.apiKey;
    return h;
  }

  async function request(settings, method, path, body, opts) {
    const o = opts || {};
    const f = o.fetch || (typeof fetch === "function" ? fetch : null);
    if (!f) throw new Error("fetch unavailable");
    if (!settings || !settings.endpoint) throw new Error("no endpoint configured");
    const ctrl = typeof AbortController === "function" ? new AbortController() : null;
    const timer = ctrl ? setTimeout(() => ctrl.abort(), o.timeoutMs || 15000) : null;
    try {
      const res = await f(settings.endpoint + path, {
        method, headers: headers(settings), body: body ? JSON.stringify(body) : undefined,
        credentials: "omit", cache: "no-store", redirect: "error", signal: ctrl ? ctrl.signal : undefined,
      });
      if (!res.ok) throw new Error("HTTP " + res.status);
      return await res.json();
    } catch (e) {
      throw new Error(e && e.name === "AbortError" ? "timeout" : String((e && e.message) || e));
    } finally { if (timer) clearTimeout(timer); }
  }

  /** Normalise a UniPhish Verdict JSON into the few fields the popup shows. */
  function normalizeVerdict(v) {
    const sigs = Array.isArray(v && v.signals) ? v.signals : [];
    return {
      score: Number.isFinite(v && v.score) ? v.score : Math.round(((v && v.risk) || 0) * 100),
      level: String((v && v.level) || ""),
      summary: String((v && v.summary) || "").slice(0, 600),
      brand: v && v.brand && v.brand.name ? String(v.brand.name) : "",
      signals: sigs.slice(0, 8).map((s) => ({
        title: String((s && s.title) || "").slice(0, 120),
        detail: String((s && s.detail) || "").slice(0, 300),
        weight: Number(s && s.weight) || 0,
      })),
    };
  }

  const deepScan = async (settings, url, opts) =>
    normalizeVerdict(await request(settings, "POST", "/v1/scan/url", { url, options: { explain: true } }, opts));
  const submitReport = async (settings, url, opts) =>
    normalizeVerdict(await request(settings, "POST", "/v1/scan/url", { url, options: { explain: true, persist: true } }, opts));
  const ping = (settings, opts) => request(settings, "GET", "/v1/health", null, opts);

  const api = { defang, buildReport, deepScan, submitReport, ping, normalizeVerdict };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhishReport = api;
})(typeof self !== "undefined" ? self : this);
