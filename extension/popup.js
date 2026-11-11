// UniPhish popup: paste a URL -> on-device verdict, reasons, impersonated brand, character
// saliency and a risk gauge.  Optional deep analysis against the user's own UniPhish server
// is OFF by default and never runs unless the user switched it on in Settings.
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const UI = self.UniPhishUI;
  const BASE = chrome.runtime.getURL("");
  const EXAMPLES = [
    ["pаypal.example", "https://pаypal.example/login"],
    ["paypal.com.secure-login.example", "http://paypal.com.secure-login.example/verify"],
    ["192.0.2.1", "http://192.0.2.1/signin"],
    ["www.paypal.com", "https://www.paypal.com/signin"],
  ];

  let settings = UniPhishSettings.sanitize({});
  let i18n = null;
  let engine = null;
  let current = null;           // last scanned URL string
  let scanToken = 0;

  async function boot() {
    settings = await UniPhishSettings.load();
    i18n = UniPhishI18n.createI18n(UniPhishBoot.localeLoader(BASE));
    await i18n.use(settings.lang);
    UniPhishI18n.applyDom(i18n, document);
    renderExamples();
    $("deep-toggle").checked = settings.deepEnabled;

    const params = new URLSearchParams(location.search);
    const initial = (params.get("u") || "").slice(0, 2048);
    if (params.has("u")) document.querySelector(".foot").classList.add("foot--windowed");

    const status = $("status");
    status.title = i18n.t("privacy.note");
    try {
      const loaded = await UniPhishBoot.loadEngine(BASE);
      engine = loaded.engine;
      status.className = "pill pill--on";
    } catch (_) {
      status.className = "pill pill--off";
      status.textContent = "!";
    }

    if (initial) { $("url").value = initial; scan(initial); }
    else prefillFromTab();
    refreshPageStats();
  }

  function prefillFromTab() {
    try {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        void chrome.runtime.lastError;
        const t = tabs && tabs[0];
        if (t && typeof t.url === "string" && /^https?:\/\//i.test(t.url) && !$("url").value) {
          $("url").value = t.url.slice(0, 2048);
          scan(t.url);
        }
      });
    } catch (_) { /* no tabs access: manual entry */ }
  }

  function renderExamples() {
    const box = $("examples");
    box.textContent = "";
    box.appendChild(UI.el("span", { class: "note", text: i18n.t("popup.examples") + ":" }));
    for (const [label, url] of EXAMPLES) {
      const b = UI.el("button", { type: "button", class: "chip", text: label });
      b.addEventListener("click", () => { $("url").value = url; scan(url); });
      box.appendChild(b);
    }
  }

  function thresholds() { return { warn: settings.warn, block: settings.block }; }

  function scan(raw) {
    const url = String(raw || "").trim();
    if (!url) return;
    current = url;
    const token = ++scanToken;
    const box = $("result");
    if (!engine) { box.hidden = false; $("tier").textContent = i18n.t("popup.model_loading"); return; }
    const v = engine.score(url, { thresholds: thresholds(), allowlist: settings.allowlist, noCache: true });
    render(v, token);
    if (settings.deepEnabled && v.valid) runDeep(v.href || v.input || url);
    else $("deep-result").hidden = true;
  }

  function render(v, token) {
    const box = $("result");
    box.hidden = false;
    box.className = "result r-" + v.tier;
    $("tier").textContent = !v.valid && !v.local ? i18n.t("popup.invalid") : i18n.t("tier." + v.tier);
    $("gauge").textContent = "";
    $("gauge").appendChild(UI.gauge(v.risk, v.thresholds, i18n.t("gauge.risk") + " " + v.score + "/100"));

    const brand = $("brand");
    if (v.brand && v.brand.official) { brand.hidden = false; brand.className = "brand ok"; brand.textContent = i18n.t("popup.official", { brand: v.brand.name }); }
    else if (v.brand && v.tier !== "safe") { brand.hidden = false; brand.className = "brand bad"; brand.textContent = i18n.t("popup.impersonates", { brand: v.brand.name }); }
    else brand.hidden = true;

    const trusted = $("trusted");
    trusted.hidden = !v.trusted;
    trusted.textContent = v.trusted ? i18n.t("popup.trusted") : "";

    // URL view: rule underlines immediately, saliency heat after (it is a few ms).
    const text = v.input || v.url;
    UI.urlView($("urlview"), text, null, UI.ruleSpans(v));
    const hint = $("heathint");
    hint.hidden = true;
    if (v.valid && !v.local && engine) {
      setTimeout(() => {
        if (token !== scanToken) return;
        try {
          const sal = engine.saliency(text);
          if (sal && UI.urlView($("urlview"), text, sal, UI.ruleSpans(v))) {
            hint.hidden = false;
            hint.textContent = i18n.t("popup.heat") + " — " + i18n.t("popup.heat_hint");
          }
        } catch (_) { /* saliency is best effort */ }
      }, 0);
    }

    if (v.local) {
      const ul = $("reasons"); ul.textContent = "";
      ul.appendChild(UI.el("li", { class: "good", text: i18n.t("popup.local") }));
    } else UI.reasonList($("reasons"), i18n, v, 8);

    const trust = $("trust");
    const host = v.hostAscii;
    if (host && v.valid && !v.local && (v.tier !== "safe" || v.trusted)) {
      trust.hidden = false;
      trust.textContent = i18n.t(v.trusted ? "popup.untrust" : "popup.trust");
      trust.onclick = async () => {
        const list = new Set(settings.allowlist);
        if (v.trusted) { for (const d of [...list]) if (host === d || host.endsWith("." + d)) list.delete(d); }
        else list.add(host);
        settings = await UniPhishSettings.save(Object.assign({}, settings, { allowlist: [...list] }));
        scan(current);
      };
    } else trust.hidden = true;
  }

  // ---- optional deep analysis ---------------------------------------------------------
  async function hasEndpointPermission() {
    try {
      const origin = new URL(settings.endpoint).origin + "/*";
      return await chrome.permissions.contains({ origins: [origin] });
    } catch (_) { return false; }
  }

  async function runDeep(url) {
    const out = $("deep-result"), note = $("deep-note");
    out.hidden = true;
    if (!settings.deepEnabled || !settings.endpoint) return;
    note.hidden = false;
    note.textContent = i18n.t("popup.deep_running");
    const token = scanToken;
    try {
      if (!(await hasEndpointPermission())) throw new Error("permission");
      const r = await UniPhishReport.deepScan(settings, url);
      if (token !== scanToken) return;
      out.textContent = "";
      out.appendChild(UI.el("h2", { text: i18n.t("popup.deep_result") + " — " + r.score + "/100" + (r.level ? " (" + r.level + ")" : "") }));
      if (r.summary) out.appendChild(UI.el("p", { text: r.summary }));
      const ul = UI.el("ul", { class: "reasons" });
      for (const s of r.signals.filter((x) => x.weight > 0).slice(0, 5)) ul.appendChild(UI.el("li", { class: "bad", text: s.title }));
      out.appendChild(ul);
      out.hidden = false;
      note.textContent = i18n.t("popup.deep_sent", { endpoint: settings.endpoint });
    } catch (e) {
      note.textContent = i18n.t("popup.deep_failed", { error: String((e && e.message) || e) });
    }
  }

  $("deep-toggle").addEventListener("change", async (ev) => {
    const note = $("deep-note");
    if (ev.target.checked) {
      if (!settings.endpoint || !(await hasEndpointPermission())) {
        ev.target.checked = false;
        note.hidden = false;
        note.textContent = i18n.t("popup.deep_off");
        chrome.runtime.openOptionsPage();
        return;
      }
    }
    settings = await UniPhishSettings.save(Object.assign({}, settings, { deepEnabled: ev.target.checked }));
    note.hidden = true;
    if (settings.deepEnabled && current) runDeep(current); else $("deep-result").hidden = true;
  });

  // ---- page stats -----------------------------------------------------------------------
  function showStats(s) {
    $("pagestats").textContent = s ? i18n.t("popup.page_stats", { blocked: s.blocked, warned: s.warned }) : "";
  }

  function refreshPageStats(rescan) {
    try {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        void chrome.runtime.lastError;
        const t = tabs && tabs[0];
        if (!t || typeof t.id !== "number") return;
        chrome.tabs.sendMessage(t.id, { type: rescan ? "rescan" : "stats" }, (resp) => {
          void chrome.runtime.lastError;
          showStats(resp);
        });
      });
    } catch (_) { /* ignore */ }
  }

  $("form").addEventListener("submit", (ev) => { ev.preventDefault(); scan($("url").value); });
  $("rescan").addEventListener("click", () => refreshPageStats(true));
  $("open-options").addEventListener("click", () => chrome.runtime.openOptionsPage());

  boot();
})();
