// UniPhish block interstitial: explain, in the user's language and with the concrete
// look-alike characters shown, why a link was stopped; offer back / proceed / report.
//
// Everything is recomputed on-device from the single `u` query parameter; the page trusts
// nothing else.  `u` is attacker-influenced: it is rendered with textContent only and is only
// ever navigated to if it parses as http(s).
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const UI = self.UniPhishUI;
  const BASE = chrome.runtime.getURL("");

  let settings, i18n, verdict = null, target = "";

  function setNote(id, text) { $(id).textContent = text; }

  function goBack() {
    if (history.length > 1) { history.back(); return; }
    chrome.tabs.getCurrent((tab) => {
      void chrome.runtime.lastError;
      if (tab && typeof tab.id === "number") chrome.tabs.remove(tab.id); else window.close();
    });
  }

  async function proceed(trustSite) {
    if (!verdict || !/^https?:\/\//i.test(target)) { setNote("notice", i18n.t("inter.not_http")); return; }
    if (trustSite && verdict.hostAscii) {
      const list = new Set(settings.allowlist);
      list.add(verdict.hostAscii);
      settings = await UniPhishSettings.save(Object.assign({}, settings, { allowlist: [...list] }));
    }
    await new Promise((resolve) => chrome.runtime.sendMessage({ type: "allow", url: target }, () => { void chrome.runtime.lastError; resolve(); }));
    location.replace(target);
  }

  async function copyReport() {
    const text = UniPhishReport.buildReport(verdict, UI.englishReasons(verdict));
    try {
      await navigator.clipboard.writeText(text);
      setNote("reportnote", i18n.t("inter.copied"));
    } catch (_) {
      // Clipboard API can be blocked: fall back to a selectable textarea.
      const ta = UI.el("textarea", { readonly: "readonly", rows: "8", class: "reportbox" });
      ta.value = text;
      $("reportnote").textContent = "";
      $("reportnote").appendChild(ta);
      ta.select();
    }
  }

  async function sendToServer() {
    setNote("reportnote", i18n.t("popup.deep_running"));
    try {
      const origin = new URL(settings.endpoint).origin + "/*";
      if (!(await chrome.permissions.contains({ origins: [origin] }))) throw new Error("permission");
      await UniPhishReport.submitReport(settings, verdict.href || verdict.input);
      setNote("reportnote", i18n.t("inter.report_sent"));
    } catch (e) {
      setNote("reportnote", i18n.t("inter.report_failed", { error: String((e && e.message) || e) }));
    }
  }

  async function main() {
    settings = await UniPhishSettings.load();
    i18n = UniPhishI18n.createI18n(UniPhishBoot.localeLoader(BASE));
    await i18n.use(settings.lang);
    UniPhishI18n.applyDom(i18n, document);
    document.title = "UniPhish — " + i18n.t("inter.title");

    target = (new URLSearchParams(location.search).get("u") || "").slice(0, 2048);
    $("back").addEventListener("click", goBack);
    $("confirm").addEventListener("change", (e) => { $("proceed").disabled = !e.target.checked; $("trust").disabled = !e.target.checked; });
    $("proceed").addEventListener("click", () => proceed(false));
    $("trust").addEventListener("click", () => proceed(true));
    $("copy").addEventListener("click", () => { if (verdict) copyReport(); });
    if (settings.deepEnabled && settings.endpoint) {
      $("api").hidden = false;
      $("api").addEventListener("click", () => { if (verdict) sendToServer(); });
    }
    if (!target) { $("lead").textContent = i18n.t("inter.no_url"); return; }

    let loaded;
    try { loaded = await UniPhishBoot.loadEngine(BASE); } catch (_) { return; }
    verdict = loaded.engine.score(target, { thresholds: { warn: settings.warn, block: settings.block }, allowlist: settings.allowlist, noCache: true });

    const text = verdict.input || target;
    UI.urlView($("urlview"), text, null, UI.ruleSpans(verdict));
    try {
      const sal = loaded.engine.saliency(text);
      if (sal) UI.urlView($("urlview"), text, sal, UI.ruleSpans(verdict));
    } catch (_) { /* best effort */ }

    if (verdict.brand && !verdict.brand.official) {
      const b = $("brand");
      b.hidden = false;
      b.textContent = i18n.t("inter.impersonating", { brand: verdict.brand.name, legit: (verdict.brand.legit || []).slice(0, 2).join(", ") });
    }
    UI.reasonList($("reasons"), i18n, verdict, 10);

    $("gsb").setAttribute("href", "https://safebrowsing.google.com/safebrowsing/report_phish/?url=" + encodeURIComponent(verdict.href || verdict.input));
    if (verdict.tier !== "block") {
      $("safenow").hidden = false;
      $("safenow").textContent = i18n.t("tier." + verdict.tier) + " — " + i18n.t("popup.score", { score: verdict.score });
    }
  }

  main();
})();
