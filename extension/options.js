// UniPhish options page: thresholds, language, trusted sites, optional server for deep analysis.
// Optional browser permissions (webNavigation, the server's origin) are requested here, from
// a user gesture, so the extension ships with the smallest possible permission set.
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const BASE = chrome.runtime.getURL("");
  let settings, i18n;

  function pct(v) { return Math.round(v * 100); }

  function renderSliderLabels() {
    $("warnLabel").textContent = i18n.t("opt.warn_threshold", { value: $("warn").value });
    $("blockLabel").textContent = i18n.t("opt.block_threshold", { value: $("block").value });
  }

  function fill(s) {
    $("scanLinks").checked = s.scanLinks;
    $("intercept").checked = s.intercept;
    $("navCheck").checked = s.navCheck;
    $("warn").value = pct(s.warn);
    $("block").value = pct(s.block);
    $("lang").value = s.lang;
    $("allowlist").value = s.allowlist.join("\n");
    $("deepEnabled").checked = s.deepEnabled;
    $("endpoint").value = s.endpoint;
    $("apiKey").value = s.apiKey;
    renderSliderLabels();
  }

  function collect() {
    return {
      scanLinks: $("scanLinks").checked, intercept: $("intercept").checked, navCheck: $("navCheck").checked,
      warn: Number($("warn").value) / 100, block: Number($("block").value) / 100, lang: $("lang").value,
      allowlist: $("allowlist").value, deepEnabled: $("deepEnabled").checked,
      endpoint: $("endpoint").value, apiKey: $("apiKey").value,
    };
  }

  async function requestOrigin(endpoint) {
    const origin = new URL(endpoint).origin + "/*";
    if (await chrome.permissions.contains({ origins: [origin] })) return true;
    return chrome.permissions.request({ origins: [origin] });
  }

  async function save(ev) {
    if (ev) ev.preventDefault();
    const note = $("deepNote");
    const raw = collect();
    const ep = UniPhishSettings.normalizeEndpoint(raw.endpoint);
    if (!ep.ok) {
      note.textContent = i18n.t(ep.error === "http" ? "opt.endpoint_http" : "opt.endpoint_invalid");
      return;
    }
    raw.endpoint = ep.value;
    if ((raw.deepEnabled || ep.value) && ep.value) {
      let granted = false;
      try { granted = await requestOrigin(ep.value); } catch (_) { /* invalid origin */ }
      if (!granted) {
        raw.deepEnabled = false;
        $("deepEnabled").checked = false;
        note.textContent = i18n.t("opt.perm_denied", { origin: new URL(ep.value).origin });
      }
    }
    const previousLang = settings.lang;
    settings = await UniPhishSettings.save(raw);
    fill(settings);
    $("saved").textContent = i18n.t("opt.saved");
    setTimeout(() => { $("saved").textContent = ""; }, 2500);
    if (previousLang !== settings.lang) location.reload();
  }

  async function onNavToggle(ev) {
    const err = $("navError");
    err.hidden = true;
    if (!ev.target.checked) return;
    let ok = false;
    try { ok = await chrome.permissions.request({ permissions: ["webNavigation"] }); } catch (_) { ok = false; }
    if (!ok) { ev.target.checked = false; err.hidden = false; err.textContent = i18n.t("opt.nav_denied"); }
  }

  async function testConnection() {
    const note = $("deepNote");
    const ep = UniPhishSettings.normalizeEndpoint($("endpoint").value);
    if (!ep.ok || !ep.value) { note.textContent = i18n.t(ep.error === "http" ? "opt.endpoint_http" : "opt.endpoint_invalid"); return; }
    try {
      if (!(await requestOrigin(ep.value))) { note.textContent = i18n.t("opt.perm_denied", { origin: new URL(ep.value).origin }); return; }
      await UniPhishReport.ping({ endpoint: ep.value, apiKey: $("apiKey").value.trim() });
      note.textContent = i18n.t("opt.test_ok");
    } catch (e) {
      note.textContent = i18n.t("opt.test_fail", { error: String((e && e.message) || e) });
    }
  }

  async function main() {
    settings = await UniPhishSettings.load();
    i18n = UniPhishI18n.createI18n(UniPhishBoot.localeLoader(BASE));
    await i18n.use(settings.lang);
    UniPhishI18n.applyDom(i18n, document);
    document.title = i18n.t("opt.title");

    const sel = $("lang");
    const auto = document.createElement("option");
    auto.value = "auto"; auto.textContent = i18n.t("opt.lang_auto");
    sel.appendChild(auto);
    for (const code of UniPhishI18n.SUPPORTED) {
      const o = document.createElement("option");
      o.value = code; o.textContent = UniPhishI18n.NATIVE_NAMES[code];
      sel.appendChild(o);
    }
    fill(settings);

    $("form").addEventListener("submit", save);
    $("warn").addEventListener("input", () => {
      if (Number($("block").value) < Number($("warn").value)) $("block").value = $("warn").value;
      renderSliderLabels();
    });
    $("block").addEventListener("input", () => {
      if (Number($("warn").value) > Number($("block").value)) $("warn").value = $("block").value;
      renderSliderLabels();
    });
    $("reset").addEventListener("click", () => {
      $("warn").value = pct(UniPhishSettings.DEFAULTS.warn);
      $("block").value = pct(UniPhishSettings.DEFAULTS.block);
      renderSliderLabels();
    });
    $("navCheck").addEventListener("change", onNavToggle);
    $("test").addEventListener("click", testConnection);
  }

  main();
})();
