// UniPhish content script: outline risky links on the page, entirely on-device.
//
// Flow: collect <a href> targets -> ask the extension's service worker to score them
// (on-device model + rules; nothing leaves the browser) -> mark suspicious ("warn") and
// dangerous ("block") links and, for dangerous ones, route clicks through the warning page.
//
// Hostile-page hardening: the page cannot read our results (they live in a WeakMap in this
// isolated world), cannot make us navigate anywhere (only the service worker opens the
// interstitial, and only for http(s)), and DOM attributes we set are cosmetic.
(function () {
  "use strict";
  if (window.top !== window) return; // top frame only
  if (typeof chrome === "undefined" || !chrome.runtime || !chrome.runtime.id) return;

  const L = self.UniPhishLinks;
  const BATCH = 150;
  const MAX_LINKS = 1500;
  const DEBOUNCE_MS = 600;

  const processed = new Set();          // URLs already sent for scoring
  const flagged = new Map();            // url -> {tier, score, label}
  const marked = new WeakMap();         // anchor -> {url, tier}
  let intercept = true;
  let enabled = true;
  let timer = null;
  let scheduled = false;

  const safeSend = (msg) => new Promise((resolve) => {
    try { chrome.runtime.sendMessage(msg, (r) => { void chrome.runtime.lastError; resolve(r); }); }
    catch (_) { resolve(undefined); }
  });

  function anchors(root) {
    return root.querySelectorAll ? root.querySelectorAll("a[href]") : [];
  }

  function applyMark(a, info) {
    a.setAttribute("data-uniphish", info.tier);
    if (!a.hasAttribute("data-uniphish-title")) a.setAttribute("data-uniphish-title", a.getAttribute("title") || "");
    const original = a.getAttribute("data-uniphish-title");
    a.setAttribute("title", original ? original + " — " + info.label : info.label);
    marked.set(a, { url: L.scannableUrl(a.href, location.host), tier: info.tier });
  }

  function paint(root) {
    for (const a of anchors(root)) {
      const url = L.scannableUrl(a.href, location.host);
      const info = url && flagged.get(url);
      if (info) applyMark(a, info);
    }
  }

  async function scan(root) {
    if (!enabled) return;
    const fresh = [];
    for (const a of anchors(root)) {
      if (processed.size + fresh.length >= MAX_LINKS) break;
      const url = L.scannableUrl(a.href, location.host);
      if (url && !processed.has(url)) { processed.add(url); fresh.push(url); }
    }
    if (!fresh.length) return;
    for (const part of L.chunk([...new Set(fresh)], BATCH)) {
      const resp = await safeSend({ type: "scoreBatch", urls: part });
      if (!resp || !Array.isArray(resp.results)) continue;
      intercept = resp.intercept !== false;
      for (const r of resp.results) {
        if (r && (r.tier === "warn" || r.tier === "block") && typeof r.url === "string") {
          flagged.set(r.url, { tier: r.tier, score: r.score, label: String(r.label || "") });
        }
      }
    }
    paint(document);
    const t = L.tally(flagged);
    safeSend({ type: "pageStats", blocked: t.blocked, warned: t.warned });
  }

  function schedule() {
    if (scheduled || !enabled) return;
    scheduled = true;
    clearTimeout(timer);
    timer = setTimeout(() => { scheduled = false; scan(document); }, DEBOUNCE_MS);
  }

  // ---- click interception for dangerous links ------------------------------------------
  function onClick(ev) {
    if (!intercept || !enabled || !ev.isTrusted) return;
    if (ev.type === "click" && ev.button !== 0) return;
    if (ev.type === "auxclick" && ev.button !== 1) return;
    const a = ev.target && ev.target.closest ? ev.target.closest("a[href]") : null;
    if (!a) return;
    const rec = marked.get(a);
    if (!rec || rec.tier !== "block") return;
    // The page may have rewritten the href after we scored it: only intercept what we scored.
    if (L.scannableUrl(a.href, location.host) !== rec.url) return;
    ev.preventDefault();
    ev.stopImmediatePropagation();
    const newTab = ev.type === "auxclick" || ev.ctrlKey || ev.metaKey || ev.shiftKey || a.target === "_blank";
    safeSend({ type: "openInterstitial", url: rec.url, newTab });
  }

  document.addEventListener("click", onClick, true);
  document.addEventListener("auxclick", onClick, true);

  // ---- messages from the popup -----------------------------------------------------------
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (sender.id !== chrome.runtime.id || !msg) return false;
    if (msg.type === "stats") { sendResponse(L.tally(flagged)); return false; }
    if (msg.type === "rescan") {
      processed.clear(); flagged.clear();
      document.querySelectorAll("[data-uniphish]").forEach((a) => a.removeAttribute("data-uniphish"));
      scan(document).then(() => sendResponse(L.tally(flagged)));
      return true;
    }
    return false;
  });

  // ---- start ---------------------------------------------------------------------------------
  chrome.storage.local.get("settings", (got) => {
    void chrome.runtime.lastError;
    const s = (got && got.settings) || {};
    enabled = s.scanLinks !== false;
    intercept = s.intercept !== false;
    if (!enabled) return;
    scan(document);
    try {
      new MutationObserver((muts) => {
        for (const m of muts) if (m.addedNodes && m.addedNodes.length) { schedule(); break; }
      }).observe(document.documentElement, { childList: true, subtree: true });
    } catch (_) { /* no observer: static scan only */ }
  });
})();
