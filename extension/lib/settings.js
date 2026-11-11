// Extension settings: defaults, validation and storage.
//
// Why a dedicated module: settings come from an options form and from chrome.storage (which
// any extension page can write), so every read goes through `sanitize()` -- thresholds are
// clamped and ordered, the trusted-site list is normalised to bare hostnames, and the optional
// server endpoint must be an https origin (plain http only for localhost) so an API key can
// never be sent in clear text to a remote machine.

(function (global) {
  "use strict";

  const KEY = "settings";
  const DEFAULTS = Object.freeze({
    scanLinks: true,       // outline risky links on web pages
    intercept: true,       // show the warning page when a "block" link is clicked
    navCheck: false,       // also warn on direct navigation (needs optional webNavigation permission)
    warn: 0.5,             // risk >= warn  -> "suspicious"   (Python default)
    block: 0.85,           // risk >= block -> "dangerous"    (Python default)
    lang: "auto",
    allowlist: [],         // trusted registrable domains
    deepEnabled: false,    // optional server-side deep analysis (OFF by default)
    endpoint: "",          // e.g. https://uniphish.example.com
    apiKey: "",
  });

  const HOST_RE = /^(?=.{1,253}$)([a-z0-9¡-￿]([a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?)(\.[a-z0-9¡-￿]([a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?)*$/;
  const LANGS = ["auto", "en", "es", "fr", "de", "pt", "ru", "zh", "ja", "hi", "ar"];

  /** "https://Example.com:8443/path" / "*.example.com" / "example.com" -> "example.com" (or ""). */
  function normalizeDomain(input) {
    let s = String(input || "").trim().toLowerCase();
    if (!s) return "";
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "").replace(/^\*\./, "").replace(/^\./, "");
    s = s.split(/[/?#]/)[0].replace(/^[^@]*@/, "").replace(/:\d+$/, "").replace(/\.$/, "");
    return HOST_RE.test(s) && s.includes(".") ? s : (s === "localhost" ? s : "");
  }

  /** Validate a server address. Returns {ok:true, value} or {ok:false, error:"invalid"|"http"}. */
  function normalizeEndpoint(input) {
    const raw = String(input || "").trim();
    if (!raw) return { ok: true, value: "" };
    let u;
    try { u = new URL(raw); } catch (_) { return { ok: false, error: "invalid" }; }
    if (u.protocol !== "https:" && u.protocol !== "http:") return { ok: false, error: "invalid" };
    if (u.username || u.password) return { ok: false, error: "invalid" };
    const local = u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
    if (u.protocol === "http:" && !local) return { ok: false, error: "http" };
    return { ok: true, value: u.origin + u.pathname.replace(/\/+$/, "") };
  }

  function clamp(n, lo, hi, dflt) {
    const x = typeof n === "number" ? n : parseFloat(n);
    return Number.isFinite(x) ? Math.min(hi, Math.max(lo, x)) : dflt;
  }

  /** Coerce arbitrary stored data into a valid settings object. Never throws. */
  function sanitize(raw) {
    const r = raw && typeof raw === "object" ? raw : {};
    const out = Object.assign({}, DEFAULTS, { allowlist: [] });
    out.scanLinks = r.scanLinks === undefined ? DEFAULTS.scanLinks : !!r.scanLinks;
    out.intercept = r.intercept === undefined ? DEFAULTS.intercept : !!r.intercept;
    out.navCheck = !!r.navCheck;
    out.warn = clamp(r.warn, 0.05, 0.95, DEFAULTS.warn);
    out.block = clamp(r.block, 0.06, 0.99, DEFAULTS.block);
    if (out.block < out.warn) out.block = Math.min(0.99, out.warn);
    out.lang = LANGS.includes(r.lang) ? r.lang : "auto";
    const list = Array.isArray(r.allowlist) ? r.allowlist : String(r.allowlist || "").split(/[\s,]+/);
    const seen = new Set();
    for (const d of list.slice(0, 500)) {
      const n = normalizeDomain(d);
      if (n && !seen.has(n)) { seen.add(n); out.allowlist.push(n); }
    }
    const ep = normalizeEndpoint(r.endpoint);
    out.endpoint = ep.ok ? ep.value : "";
    out.apiKey = typeof r.apiKey === "string" ? r.apiKey.trim().slice(0, 512) : "";
    out.deepEnabled = !!r.deepEnabled && !!out.endpoint;
    return out;
  }

  function hasStorage() {
    return typeof chrome !== "undefined" && chrome.storage && chrome.storage.local;
  }

  async function load() {
    if (!hasStorage()) return sanitize({});
    try {
      const got = await chrome.storage.local.get(KEY);
      return sanitize(got && got[KEY]);
    } catch (_) { return sanitize({}); }
  }

  async function save(settings) {
    const clean = sanitize(settings);
    if (hasStorage()) await chrome.storage.local.set({ [KEY]: clean });
    return clean;
  }

  const api = { KEY, DEFAULTS, LANGS, sanitize, normalizeDomain, normalizeEndpoint, load, save };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhishSettings = api;
})(typeof self !== "undefined" ? self : this);
