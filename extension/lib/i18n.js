// Tiny localisation layer: explainable reasons and warning pages in the user's language.
//
// Why not chrome.i18n?  Verdict reasons are *templates filled with attacker-controlled
// specifics* ("this link uses the Cyrillic letter «а» to look like «a»").  A flat
// {key: "text {param}"} JSON per language keeps the templates readable for translators,
// works identically in Node tests, and lets the user override the language in Settings.
//
// Safety: `t()` and `reason()` return PLAIN TEXT.  Callers must assign it with
// `textContent` (never innerHTML) because parameters (hostnames, characters, brand labels)
// come from the page being analysed.
//
// Coverage: English is complete.  The other nine locales (es fr de pt ru zh ja hi ar) cover
// the safety-critical surfaces (popup, link tooltips, warning page, reasons); any missing key
// falls back to English.  Arabic is rendered right-to-left (`dir()`).

(function (global) {
  "use strict";

  const SUPPORTED = ["en", "es", "fr", "de", "pt", "ru", "zh", "ja", "hi", "ar"];
  const NATIVE_NAMES = { en: "English", es: "Español", fr: "Français", de: "Deutsch", pt: "Português",
    ru: "Русский", zh: "中文", ja: "日本語", hi: "हिन्दी", ar: "العربية" };
  const RTL = new Set(["ar", "he", "fa", "ur"]);

  /** Map "pt-BR", "zh_CN", "en-GB" ... to a supported base language (default "en"). */
  function normalizeLang(tag) {
    const base = String(tag || "").toLowerCase().split(/[-_]/)[0];
    return SUPPORTED.includes(base) ? base : "en";
  }

  function detectLang() {
    try {
      if (typeof chrome !== "undefined" && chrome.i18n && chrome.i18n.getUILanguage) {
        return normalizeLang(chrome.i18n.getUILanguage());
      }
    } catch (_) { /* fall through */ }
    try { if (typeof navigator !== "undefined") return normalizeLang(navigator.language); } catch (_) { /* ignore */ }
    return "en";
  }

  /**
   * @param {(lang: string) => Promise<Object<string,string>>} loader  returns the message table
   */
  function createI18n(loader) {
    const tables = {};
    let lang = "en";
    let names = null;

    async function ensure(l) {
      if (tables[l]) return;
      try { tables[l] = (await loader(l)) || {}; } catch (_) { tables[l] = {}; }
    }

    function scriptName(code) {
      try {
        if (!names) names = new Intl.DisplayNames([lang], { type: "script" });
        return names.of(code) || code;
      } catch (_) { return code; }
    }

    function format(template, params) {
      return String(template).replace(/\{(\w+)\}/g, (_, k) => {
        const v = params && params[k];
        if (v === undefined || v === null) return "";
        if (k === "script") return scriptName(String(v));
        if (k === "scripts") return String(v).split(",").map((c) => scriptName(c.trim())).join(", ");
        return String(v);
      });
    }

    function lookup(key) {
      const own = tables[lang] && tables[lang][key];
      return own !== undefined ? own : tables.en && tables.en[key];
    }

    const api = {
      /** Load English (fallback) plus `pref` ("auto" or a language tag). Returns the language used. */
      async use(pref) {
        lang = !pref || pref === "auto" ? detectLang() : normalizeLang(pref);
        names = null;
        await ensure("en");
        await ensure(lang);
        return lang;
      },
      get lang() { return lang; },
      dir() { return RTL.has(lang) ? "rtl" : "ltr"; },
      has(key) { return lookup(key) !== undefined; },
      /** Translate `key`; unknown keys return the key itself so gaps are visible in tests. */
      t(key, params) {
        const tpl = lookup(key);
        return tpl === undefined ? key : format(tpl, params);
      },
      /** Localised one-sentence reason for a verdict signal (falls back to its English detail). */
      reason(signal) {
        const p = signal.params || {};
        const base = "r." + signal.id;
        const own = (k) => (tables[lang] ? tables[lang][k] : undefined);
        const en = (k) => (tables.en ? tables.en[k] : undefined);
        // With a concrete look-alike character prefer the ".char" sentence, but only fall back
        // to English for it if this language has no sentence at all for the signal.
        let tpl = p.char ? own(base + ".char") : undefined;
        if (tpl === undefined) tpl = own(base);
        if (tpl === undefined && p.char) tpl = en(base + ".char");
        if (tpl === undefined) tpl = en(base);
        return tpl === undefined ? String(signal.detail || signal.title || signal.id) : format(tpl, p);
      },
      scriptName,
    };
    return api;
  }

  /** Apply data-i18n / data-i18n-placeholder / data-i18n-title attributes under `root`. */
  function applyDom(i18n, root) {
    const doc = root.ownerDocument || root;
    root.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = i18n.t(el.getAttribute("data-i18n")); });
    root.querySelectorAll("[data-i18n-placeholder]").forEach((el) => { el.setAttribute("placeholder", i18n.t(el.getAttribute("data-i18n-placeholder"))); });
    root.querySelectorAll("[data-i18n-title]").forEach((el) => { el.setAttribute("title", i18n.t(el.getAttribute("data-i18n-title"))); });
    if (doc.documentElement) {
      doc.documentElement.setAttribute("lang", i18n.lang);
      doc.documentElement.setAttribute("dir", i18n.dir());
    }
  }

  const api = { createI18n, applyDom, normalizeLang, detectLang, SUPPORTED, NATIVE_NAMES };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhishI18n = api;
})(typeof self !== "undefined" ? self : this);
