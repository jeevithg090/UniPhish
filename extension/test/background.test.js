"use strict";
// Loads the REAL background.js (and its importScripts chain) into a vm sandbox with a mocked
// `chrome`, then drives it through its public surface: runtime messages, context menu,
// badge, interstitial routing and the optional navigation check.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { ROOT } = require("./helpers");

const EXT_ID = "testextid";
const ORIGIN = `chrome-extension://${EXT_ID}/`;

function makeChrome(opts) {
  const o = opts || {};
  const log = { badge: [], badgeColor: [], tabsUpdate: [], tabsCreate: [], windows: [], menus: [] };
  const listeners = { message: null, menuClick: null, nav: null, permAdded: null, storageChanged: null };
  const local = Object.assign({}, o.storage || {});
  const session = {};
  const chromeMock = {
    runtime: {
      id: EXT_ID,
      getURL: (p) => ORIGIN + p,
      onMessage: { addListener: (f) => { listeners.message = f; } },
      onInstalled: { addListener: () => {} },
      onStartup: { addListener: () => {} },
    },
    storage: {
      local: { get: async (k) => ({ [k]: local[k] }), set: async (obj) => Object.assign(local, obj) },
      session: { get: async (k) => ({ [k]: session[k] }), set: async (obj) => Object.assign(session, obj) },
      onChanged: { addListener: (f) => { listeners.storageChanged = f; } },
    },
    contextMenus: {
      removeAll: async () => { log.menus.length = 0; },
      create: (m) => { log.menus.push(m); },
      onClicked: { addListener: (f) => { listeners.menuClick = f; } },
    },
    action: {
      setBadgeText: (a) => log.badge.push(a),
      setBadgeBackgroundColor: (a) => log.badgeColor.push(a),
    },
    tabs: {
      update: async (id, p) => { log.tabsUpdate.push([id, p]); },
      create: async (p) => { log.tabsCreate.push(p); },
    },
    windows: { create: (p) => log.windows.push(p) },
    permissions: { onAdded: { addListener: (f) => { listeners.permAdded = f; } } },
  };
  if (o.webNavigation) chromeMock.webNavigation = { onBeforeNavigate: { addListener: (f) => { listeners.nav = f; } } };
  return { chromeMock, log, listeners, local, session };
}

async function loadBackground(opts) {
  const c = makeChrome(opts);
  const fileFetch = async (url) => {
    assert.ok(url.startsWith(ORIGIN), "background fetched something outside the package: " + url);
    const file = path.join(ROOT, url.slice(ORIGIN.length));
    const buf = fs.readFileSync(file);
    return {
      ok: true, status: 200,
      json: async () => JSON.parse(buf.toString("utf8")),
      arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength),
    };
  };
  const sandbox = { console, URL, URLSearchParams, TextEncoder, Intl, Math, JSON, Map, Set, WeakMap, Promise, Float32Array, Uint8Array,
    Uint8ClampedArray, Int32Array, setTimeout, clearTimeout, chrome: c.chromeMock, fetch: fileFetch };
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.importScripts = (...files) => {
    for (const f of files) vm.runInContext(fs.readFileSync(path.join(ROOT, f), "utf8"), ctx, { filename: f });
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(ROOT, "background.js"), "utf8"), ctx, { filename: "background.js" });
  const send = (msg, sender) => new Promise((resolve) => {
    const s = sender || { id: EXT_ID, tab: { id: 7 } };
    const async = c.listeners.message(msg, s, resolve);
    if (!async) resolve(undefined);
  });
  const tick = () => new Promise((r) => setTimeout(r, 25));
  return Object.assign(c, { ctx, send, tick });
}

const plain = (x) => JSON.parse(JSON.stringify(x)); // vm-realm objects fail strict deepEqual
const PHISH = "https://pаypal.example/login";
const MILD = "http://198.51.100.23/x";

test("scoreBatch returns only flagged links with localised labels, safe ones omitted", async () => {
  const bg = await loadBackground();
  const r = await bg.send({ type: "scoreBatch", urls: [PHISH, MILD, "https://www.paypal.com/signin", "https://example.com/", 42, null] });
  const byUrl = Object.fromEntries(r.results.map((x) => [x.url, x]));
  assert.equal(Object.keys(byUrl).length, 2);
  assert.equal(byUrl[PHISH].tier, "block");
  assert.equal(byUrl[MILD].tier, "warn");
  assert.match(byUrl[PHISH].label, /^UniPhish: likely phishing \(\d+\/100\)\. .*Cyrillic.*PayPal/);
  assert.equal(r.intercept, true);
});

test("labels follow the user's language setting", async () => {
  const bg = await loadBackground({ storage: { settings: { lang: "es" } } });
  const r = await bg.send({ type: "scoreBatch", urls: [PHISH] });
  assert.match(r.results[0].label, /^UniPhish: probable phishing/);
  assert.match(r.results[0].label, /«а» \(cirílico, U\+0430\)/i);
});

test("thresholds and trusted sites from settings are applied", async () => {
  const bg = await loadBackground({ storage: { settings: { warn: 0.95, block: 0.99, allowlist: ["198.51.100.23"] } } });
  const r = await bg.send({ type: "scoreBatch", urls: [MILD, PHISH] });
  assert.deepEqual(plain(r.results.map((x) => x.url)), [PHISH]);
});

test("batch size is bounded", async () => {
  const bg = await loadBackground();
  const urls = Array.from({ length: 1000 }, (_, i) => `http://198.51.100.${(i % 200) + 1}/p${i}`);
  const r = await bg.send({ type: "scoreBatch", urls });
  assert.ok(r.results.length <= 400);
});

test("messages from other extensions / malformed messages are ignored", async () => {
  const bg = await loadBackground();
  assert.equal(await bg.send({ type: "scoreBatch", urls: [PHISH] }, { id: "someoneelse" }), undefined);
  assert.equal(await bg.send({ type: "scoreBatch", urls: "nope" }), undefined);
  assert.equal(await bg.send(null), undefined);
  assert.equal(await bg.send({ type: "unknown" }), undefined);
});

test("pageStats sets a per-tab badge: red when something is blocked, amber for warnings only, cleared at zero", async () => {
  const bg = await loadBackground();
  await bg.send({ type: "pageStats", blocked: 2, warned: 3 });
  assert.deepEqual(plain(bg.log.badge.pop()), { tabId: 7, text: "5" });
  assert.equal(bg.log.badgeColor.pop().color, "#c62828");
  await bg.send({ type: "pageStats", blocked: 0, warned: 4 });
  bg.log.badge.pop();
  assert.equal(bg.log.badgeColor.pop().color, "#b26a00");
  await bg.send({ type: "pageStats", blocked: 0, warned: 0 });
  assert.deepEqual(plain(bg.log.badge.pop()), { tabId: 7, text: "" });
  await bg.send({ type: "pageStats", blocked: 500, warned: 0 });
  assert.equal(bg.log.badge.pop().text, "99+");
});

test("openInterstitial routes only http(s) links to the packaged warning page", async () => {
  const bg = await loadBackground();
  await bg.send({ type: "openInterstitial", url: PHISH });
  await bg.tick();
  assert.equal(bg.log.tabsUpdate.length, 1);
  const [tabId, upd] = bg.log.tabsUpdate[0];
  assert.equal(tabId, 7);
  assert.ok(upd.url.startsWith(ORIGIN + "interstitial.html?u="));
  assert.equal(new URL(upd.url).searchParams.get("u"), PHISH);
  await bg.send({ type: "openInterstitial", url: PHISH, newTab: true });
  await bg.tick();
  assert.equal(bg.log.tabsCreate.length, 1);
  for (const bad of ["javascript:alert(1)", "data:text/html,x", "chrome://settings", "file:///etc/passwd", 5]) {
    await bg.send({ type: "openInterstitial", url: bad });
  }
  await bg.tick();
  assert.equal(bg.log.tabsUpdate.length, 1);
  assert.equal(bg.log.tabsCreate.length, 1);
});

test("context menu: localised title on install; click opens the popup in a small window", async () => {
  const bg = await loadBackground({ storage: { settings: { lang: "de" } } });
  await bg.send({ type: "scoreBatch", urls: [] }); // warms i18n
  await bg.ctx.setupContextMenu();
  assert.equal(bg.log.menus.length, 1);
  assert.deepEqual(plain(bg.log.menus[0].contexts), ["link"]);
  assert.equal(bg.log.menus[0].title, "Link mit UniPhish prüfen");
  bg.listeners.menuClick({ menuItemId: "uniphish-scan-link", linkUrl: PHISH });
  assert.equal(bg.log.windows.length, 1);
  assert.equal(bg.log.windows[0].type, "popup");
  assert.equal(new URL(bg.log.windows[0].url).searchParams.get("u"), PHISH);
  bg.listeners.menuClick({ menuItemId: "other", linkUrl: PHISH });
  bg.listeners.menuClick({ menuItemId: "uniphish-scan-link" });
  assert.equal(bg.log.windows.length, 1);
});

test("navigation check is inert without the optional permission (no webNavigation API)", async () => {
  const bg = await loadBackground({ storage: { settings: { navCheck: true } } });
  assert.equal(bg.listeners.nav, null);
});

test("navigation check: blocks dangerous top-level navigations only when enabled; honours 'proceed anyway'", async () => {
  const waitFor = async (fn) => { for (let i = 0; i < 100 && !fn(); i++) await new Promise((r) => setTimeout(r, 20)); };
  const on = await loadBackground({ webNavigation: true, storage: { settings: { navCheck: true } } });
  assert.equal(typeof on.listeners.nav, "function");
  await on.send({ type: "scoreBatch", urls: [] }); // warm the engine so negative checks below are meaningful
  on.listeners.nav({ frameId: 1, url: PHISH, tabId: 3 });                 // sub-frame: ignored
  on.listeners.nav({ frameId: 0, url: "https://example.com/", tabId: 3 }); // safe: ignored
  on.listeners.nav({ frameId: 0, url: "chrome://x", tabId: 3 });          // not http(s): ignored
  on.listeners.nav({ frameId: 0, url: MILD, tabId: 3 });                  // warn only: ignored
  await new Promise((r) => setTimeout(r, 400));
  assert.equal(on.log.tabsUpdate.length, 0);
  on.listeners.nav({ frameId: 0, url: PHISH, tabId: 3 });
  await waitFor(() => on.log.tabsUpdate.length === 1);
  assert.equal(on.log.tabsUpdate.length, 1);
  assert.equal(on.log.tabsUpdate[0][0], 3);
  assert.ok(on.log.tabsUpdate[0][1].url.startsWith(ORIGIN + "interstitial.html"));
  // user clicks "proceed anyway": the interstitial asks the worker to allow the URL
  const ack = await on.send({ type: "allow", url: PHISH });
  assert.deepEqual(plain(ack), { ok: true });
  on.listeners.nav({ frameId: 0, url: PHISH, tabId: 3 });
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(on.log.tabsUpdate.length, 1, "allowed URL must not be intercepted again");
  assert.ok(on.session["allow:" + PHISH] > Date.now());

  const off = await loadBackground({ webNavigation: true, storage: { settings: { navCheck: false } } });
  await off.send({ type: "scoreBatch", urls: [] });
  off.listeners.nav({ frameId: 0, url: PHISH, tabId: 3 });
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(off.log.tabsUpdate.length, 0);
});

test("the worker only ever fetches packaged files (asserted inside the fetch mock)", async () => {
  const bg = await loadBackground();
  await bg.send({ type: "scoreBatch", urls: [PHISH] });
});
