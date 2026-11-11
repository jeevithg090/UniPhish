"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const S = require(path.join(__dirname, "..", "lib/settings.js"));

test("defaults: link scanning on, deep analysis OFF, no endpoint, Python thresholds", () => {
  const d = S.sanitize(undefined);
  assert.equal(d.scanLinks, true);
  assert.equal(d.deepEnabled, false);
  assert.equal(d.endpoint, "");
  assert.equal(d.navCheck, false);
  assert.equal(d.warn, 0.5);
  assert.equal(d.block, 0.85);
});

test("thresholds are clamped, parsed and ordered", () => {
  assert.equal(S.sanitize({ warn: -5 }).warn, 0.05);
  assert.equal(S.sanitize({ warn: "0.7" }).warn, 0.7);
  assert.equal(S.sanitize({ warn: "junk" }).warn, 0.5);
  const s = S.sanitize({ warn: 0.9, block: 0.2 });
  assert.ok(s.block >= s.warn);
});

test("deep analysis requires a valid endpoint", () => {
  assert.equal(S.sanitize({ deepEnabled: true }).deepEnabled, false);
  assert.equal(S.sanitize({ deepEnabled: true, endpoint: "https://uniphish.example.com/" }).deepEnabled, true);
});

test("endpoint validation: https required except for localhost; no credentials in the URL", () => {
  assert.deepEqual(S.normalizeEndpoint("https://uniphish.example.com/"), { ok: true, value: "https://uniphish.example.com" });
  assert.deepEqual(S.normalizeEndpoint("https://host.example/api/"), { ok: true, value: "https://host.example/api" });
  assert.deepEqual(S.normalizeEndpoint("http://localhost:8000"), { ok: true, value: "http://localhost:8000" });
  assert.deepEqual(S.normalizeEndpoint("http://127.0.0.1:8000"), { ok: true, value: "http://127.0.0.1:8000" });
  assert.deepEqual(S.normalizeEndpoint("http://uniphish.example.com"), { ok: false, error: "http" });
  assert.deepEqual(S.normalizeEndpoint("ftp://x.example"), { ok: false, error: "invalid" });
  assert.deepEqual(S.normalizeEndpoint("https://user:pw@x.example"), { ok: false, error: "invalid" });
  assert.deepEqual(S.normalizeEndpoint("javascript:alert(1)"), { ok: false, error: "invalid" });
  assert.deepEqual(S.normalizeEndpoint(""), { ok: true, value: "" });
  assert.equal(S.sanitize({ endpoint: "http://evil.example", deepEnabled: true }).endpoint, "");
});

test("trusted-site list is normalised to bare hostnames and de-duplicated", () => {
  const s = S.sanitize({ allowlist: "https://Example.com/path\n*.corp.example, example.com\nnot a domain\n\nlocalhost" });
  assert.deepEqual(s.allowlist, ["example.com", "corp.example", "localhost"]);
  assert.equal(S.normalizeDomain("http://user@Sub.Example.org:8080/x?y#z"), "sub.example.org");
  assert.equal(S.normalizeDomain("<script>"), "");
  assert.equal(S.sanitize({ allowlist: Array(2000).fill("a.example") }).allowlist.length, 1);
});

test("unknown languages fall back to auto; hostile stored values never throw", () => {
  assert.equal(S.sanitize({ lang: "xx" }).lang, "auto");
  assert.equal(S.sanitize({ lang: "ar" }).lang, "ar");
  for (const bad of [null, 5, "str", [], { allowlist: { a: 1 } }, { apiKey: { x: 1 } }, { endpoint: 5 }]) assert.doesNotThrow(() => S.sanitize(bad));
  assert.equal(S.sanitize({ apiKey: "x".repeat(5000) }).apiKey.length, 512);
});

test("load/save round-trip through chrome.storage.local", async () => {
  const store = {};
  global.chrome = { storage: { local: {
    get: async (k) => ({ [k]: store[k] }),
    set: async (o) => Object.assign(store, o),
  } } };
  try {
    const saved = await S.save({ warn: 0.4, allowlist: ["a.example"], endpoint: "https://s.example", deepEnabled: true });
    assert.equal(saved.deepEnabled, true);
    const loaded = await S.load();
    assert.deepEqual(loaded, saved);
    store[S.KEY] = { warn: "garbage", deepEnabled: true };
    assert.equal((await S.load()).deepEnabled, false);
  } finally { delete global.chrome; }
});
