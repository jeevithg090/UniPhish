"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { engine } = require("./helpers");

test("verdict shape and explainable decomposition", () => {
  const e = engine();
  const v = e.score("https://pаypal.example/login");
  assert.equal(v.tier, "block");
  assert.ok(v.score >= 85 && v.risk >= 0.85);
  assert.equal(v.brand.name, "PayPal");
  assert.equal(v.brand.official, false);
  assert.ok(v.modelUsed && v.prob > 0.5);
  // contributions sum (with the prior) to the fused logit
  const total = -2 + v.signals.reduce((a, s) => a + s.contribution, 0);
  assert.ok(Math.abs(Math.max(-12, Math.min(12, total)) - v.logit) < 0.01);
  // signals are ordered by influence
  const mags = v.signals.map((s) => Math.abs(s.contribution));
  assert.deepEqual(mags, [...mags].sort((a, b) => b - a));
});

test("the raw model alone can never warn or block (known over-scoring on benign URLs)", () => {
  const e = engine();
  for (const u of ["https://www.mysmallbakery.co.uk/order-online/cakes?category=birthday&page=2",
    "https://some-unknown-shop.example.net/products/blue-widget-12345", "https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz/edit"]) {
    const v = e.score(u);
    assert.equal(v.tier, "safe", u);
    const ml = v.signals.find((s) => s.id === "ml.cnn.phishing");
    if (ml) assert.ok(ml.weight <= 1.0 + 1e-9, `ml weight ${ml.weight} not capped for ${u}`);
  }
});

test("model corroborated by rule evidence contributes its full weight", () => {
  const e = engine();
  const v = e.score("https://secure-paypal-login.example/verify");
  const ml = v.signals.find((s) => s.id === "ml.cnn.phishing");
  assert.ok(ml && ml.weight > 1.0);
});

test("a benign model reading never cancels structural deception", () => {
  const e = engine();
  const v = e.score("http://paypal.com@evil.example/");
  assert.ok(!v.signals.some((s) => s.id === "ml.cnn.benign"));
  assert.notEqual(v.tier, "safe");
});

test("rules still work with no model loaded", () => {
  const e = engine(false);
  const v = e.score("https://pаypal.example/login");
  assert.equal(v.modelUsed, false);
  assert.equal(v.prob, null);
  assert.equal(v.tier, "block");
});

test("local and private addresses are never flagged", () => {
  const e = engine();
  for (const u of ["http://localhost:3000/login", "http://192.168.1.1/admin", "http://10.0.0.5/signin", "http://[::1]/", "http://nas.local/"]) {
    const v = e.score(u);
    assert.equal(v.tier, "safe", u);
    assert.equal(v.local, true);
  }
});

test("thresholds are honoured", () => {
  const e = engine();
  const u = "http://198.51.100.23/x"; // IP host: warn-level evidence
  const dflt = e.score(u, { noCache: true });
  assert.equal(dflt.tier, "warn");
  assert.equal(e.score(u, { noCache: true, thresholds: { warn: 0.95, block: 0.99 } }).tier, "safe");
  assert.equal(e.score(u, { noCache: true, thresholds: { warn: 0.1, block: 0.2 } }).tier, "block");
});

test("user allowlist demotes a flagged host (and its sub-domains) but not look-alikes", () => {
  const e = engine();
  const u = "http://198.51.100.23/x";
  assert.equal(e.score(u, { noCache: true }).tier, "warn");
  const t = e.score(u, { noCache: true, allowlist: ["198.51.100.23"] });
  assert.equal(t.tier, "safe"); assert.equal(t.trusted, true);
  assert.equal(e.score("https://a.corp.example/x", { allowlist: ["corp.example"] }).trusted, true);
  assert.equal(e.score("https://evilcorp.example/x", { allowlist: ["corp.example"] }).trusted, false);
});

test("invalid input yields a safe, flagged-invalid verdict instead of throwing", () => {
  const e = engine();
  for (const u of ["", "not a url at all", "http://", null, undefined, "\u0000"]) {
    const v = e.score(u);
    assert.equal(v.tier, "safe");
    assert.equal(v.valid, false);
  }
  assert.equal(e.score(42).tier, "safe"); // "42" parses as the (private) address 0.0.0.42
});

test("fuzz: random strings never throw and always return a coherent verdict", () => {
  const e = engine();
  let seed = 12345;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const alphabet = "abcXYZ019-._~:/?#[]@!$&'()*+,;=%аο中​‮😀 ";
  for (let i = 0; i < 400; i++) {
    let s = rnd() < 0.5 ? "http://" : "";
    const n = Math.floor(rnd() * 80);
    for (let j = 0; j < n; j++) s += alphabet[Math.floor(rnd() * alphabet.length)];
    const v = e.score(s, { noCache: true });
    assert.ok(["safe", "warn", "block"].includes(v.tier));
    assert.ok(v.risk >= 0 && v.risk <= 1 && Number.isFinite(v.logit));
  }
});

test("cache returns identical verdicts and clearCache works", () => {
  const e = engine();
  const a = e.score("https://example.com/a"), b = e.score("https://example.com/a");
  assert.equal(a, b);
  e.clearCache();
  assert.notEqual(e.score("https://example.com/a"), a);
});

test("saliency returns per-character data and spans for scorable URLs only", () => {
  const e = engine();
  const s = e.saliency("http://paypal.com.secure-login.example/verify");
  assert.ok(s.chars.length > 20 && Array.isArray(s.spans));
  assert.equal(engine(false).saliency("http://x.example/"), null);
});
