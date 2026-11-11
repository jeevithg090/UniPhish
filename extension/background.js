// UniPhish service worker (Manifest V3).
//
// Responsibilities
//   * scoring service for the content script: batches of link URLs -> on-device verdicts
//     (rules + byte-CNN + fusion; nothing is sent over the network);
//   * toolbar badge counts per tab;
//   * context menu "Scan link with UniPhish";
//   * opening the block interstitial, and (only if the user granted the optional
//     "webNavigation" permission) warning on direct navigation to dangerous addresses.
//
// The worker holds no persistent state: the engine is rebuilt from packaged files after the
// browser suspends it, and the short-lived "proceed anyway" allowances live in
// chrome.storage.session.  No remote code, no eval, no network requests.

/* global importScripts, chrome */
importScripts(
  "model.js", "lib/urlparse.js", "lib/confusables.js", "lib/lists.js", "lib/brands.js",
  "lib/rules.js", "lib/fusion.js", "lib/saliency.js", "lib/engine.js", "lib/i18n.js",
  "lib/settings.js", "lib/boot.js"
);

const BASE = chrome.runtime.getURL("");
const INTERSTITIAL = chrome.runtime.getURL("interstitial.html");
const ALLOW_TTL_MS = 10 * 60 * 1000;
const MAX_BATCH = 400;

let settingsCache = null;
let i18nCache = null; // { lang pref, i18n }
const memAllowed = new Map();

// ---- shared state --------------------------------------------------------------------
async function getSettings() {
  if (!settingsCache) settingsCache = await UniPhishSettings.load();
  return settingsCache;
}

async function getI18n() {
  const s = await getSettings();
  if (!i18nCache || i18nCache.pref !== s.lang) {
    const i18n = UniPhishI18n.createI18n(UniPhishBoot.localeLoader(BASE));
    await i18n.use(s.lang);
    i18nCache = { pref: s.lang, i18n };
  }
  return i18nCache.i18n;
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes[UniPhishSettings.KEY]) return;
  settingsCache = UniPhishSettings.sanitize(changes[UniPhishSettings.KEY].newValue);
  i18nCache = null;
  getEngine().then(({ engine }) => engine.clearCache()).catch(() => {});
  setupContextMenu();
});

function getEngine() { return UniPhishBoot.loadEngine(BASE); }

function scoreOpts(s) { return { thresholds: { warn: s.warn, block: s.block }, allowlist: s.allowlist }; }

// ---- "proceed anyway" allowances (survive worker restarts, cleared when the browser closes) --
async function allowUrl(url) {
  const until = Date.now() + ALLOW_TTL_MS;
  memAllowed.set(url, until);
  try { if (chrome.storage.session) await chrome.storage.session.set({ ["allow:" + url]: until }); } catch (_) { /* memory only */ }
}

async function isAllowed(url) {
  const now = Date.now();
  const mem = memAllowed.get(url);
  if (mem && mem > now) return true;
  try {
    if (chrome.storage.session) {
      const got = await chrome.storage.session.get("allow:" + url);
      const until = got["allow:" + url];
      if (until && until > now) return true;
    }
  } catch (_) { /* ignore */ }
  return false;
}

// ---- messages -----------------------------------------------------------------------
function topReason(i18n, verdict) {
  const sig = verdict.signals.find((s) => s.weight > 0 && s.category !== "ml" && (s.contribution || 0) > 0) ||
    verdict.signals.find((s) => s.weight > 0 && (s.contribution || 0) > 0);
  return sig ? i18n.reason(sig) : "";
}

async function scoreBatch(urls) {
  const [{ engine }, settings, i18n] = await Promise.all([getEngine(), getSettings(), getI18n()]);
  const opts = scoreOpts(settings);
  const out = [];
  for (const url of urls.slice(0, MAX_BATCH)) {
    if (typeof url !== "string") continue;
    const v = engine.score(url, opts);
    if (v.tier === "safe") continue;
    const key = v.tier === "block" ? "link.block" : "link.warn";
    out.push({ url, tier: v.tier, score: v.score,
      label: i18n.t(key, { score: v.score, reason: topReason(i18n, v) }) });
  }
  return { results: out, intercept: settings.intercept };
}

function setBadge(tabId, blocked, warned) {
  if (typeof tabId !== "number") return;
  const total = blocked + warned;
  chrome.action.setBadgeText({ tabId, text: total ? String(total > 99 ? "99+" : total) : "" });
  if (total) chrome.action.setBadgeBackgroundColor({ tabId, color: blocked ? "#c62828" : "#b26a00" });
}

async function openInterstitial(url, tabId, newTab) {
  const target = INTERSTITIAL + "?u=" + encodeURIComponent(String(url).slice(0, 2048));
  if (newTab || typeof tabId !== "number") await chrome.tabs.create({ url: target });
  else await chrome.tabs.update(tabId, { url: target });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg !== "object") return false;
  // Only our own extension's pages and content scripts may talk to the worker.
  if (sender.id !== chrome.runtime.id) return false;
  switch (msg.type) {
    case "scoreBatch":
      if (!Array.isArray(msg.urls)) return false;
      scoreBatch(msg.urls).then(sendResponse).catch(() => sendResponse({ results: [], intercept: false }));
      return true;
    case "pageStats":
      setBadge(sender.tab && sender.tab.id, Number(msg.blocked) || 0, Number(msg.warned) || 0);
      return false;
    case "openInterstitial":
      if (typeof msg.url === "string" && /^https?:\/\//i.test(msg.url)) {
        openInterstitial(msg.url, sender.tab && sender.tab.id, !!msg.newTab).catch(() => {});
      }
      return false;
    case "allow":
      if (typeof msg.url === "string") allowUrl(msg.url).then(() => sendResponse({ ok: true }));
      else sendResponse({ ok: false });
      return true;
    default:
      return false;
  }
});

// ---- context menu ---------------------------------------------------------------------
async function setupContextMenu() {
  try {
    const i18n = await getI18n();
    await chrome.contextMenus.removeAll();
    chrome.contextMenus.create({ id: "uniphish-scan-link", title: i18n.t("menu.scan"), contexts: ["link"] });
  } catch (_) { /* menus unavailable */ }
}

chrome.runtime.onInstalled.addListener(() => { setupContextMenu(); });
chrome.runtime.onStartup.addListener(() => { setupContextMenu(); });

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId !== "uniphish-scan-link" || !info.linkUrl) return;
  const url = chrome.runtime.getURL("popup.html") + "?u=" + encodeURIComponent(String(info.linkUrl).slice(0, 2048));
  chrome.windows.create({ url, type: "popup", width: 440, height: 680 });
});

// ---- optional direct-navigation check (needs the optional "webNavigation" permission) ------
let navListening = false;

async function onBeforeNavigate(details) {
  if (details.frameId !== 0 || !/^https?:\/\//i.test(details.url)) return;
  try {
    if (await isAllowed(details.url)) return;
    const [{ engine }, settings] = await Promise.all([getEngine(), getSettings()]);
    if (!settings.navCheck) return;
    const v = engine.score(details.url, scoreOpts(settings));
    if (v.tier === "block") await openInterstitial(details.url, details.tabId, false);
  } catch (_) { /* never block browsing on an internal error */ }
}

// The listener is registered once (synchronously at worker start, as MV3 requires) whenever the
// optional permission is present; the handler itself checks `settings.navCheck` on each event.
function registerNavigationListener() {
  if (navListening || !chrome.webNavigation || !chrome.webNavigation.onBeforeNavigate) return;
  chrome.webNavigation.onBeforeNavigate.addListener((d) => { onBeforeNavigate(d); });
  navListening = true;
}
registerNavigationListener();
if (chrome.permissions && chrome.permissions.onAdded) chrome.permissions.onAdded.addListener(registerNavigationListener);
