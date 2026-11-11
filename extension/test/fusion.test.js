"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const F = require(path.join(__dirname, "..", "lib/fusion.js"));

const sig = (id, weight, category, confidence = 1) => ({ id, weight, category, confidence });

test("prior: no evidence means ~12% risk", () => {
  const r = F.fuse([]);
  assert.equal(r.logit, -2);
  assert.equal(r.score, 12);
  assert.equal(r.tier, "safe");
});

test("same-category evidence is damped (DECAY^rank), different categories add", () => {
  const same = [sig("a", 2, "url"), sig("b", 2, "url"), sig("c", 2, "url")];
  F.applyContributions(same);
  assert.deepEqual(same.map((s) => s.contribution), [2, 1.1, 0.605]);
  const mixed = [sig("a", 2, "url"), sig("b", 2, "brand")];
  const total = F.applyContributions(mixed);
  assert.equal(total, 4);
});

test("benign and malicious evidence are damped separately", () => {
  const s = [sig("m", 3, "url"), sig("g", -3, "url")];
  assert.equal(F.applyContributions(s), 0);
});

test("confidence scales the contribution", () => {
  const s = [sig("a", 4, "brand", 0.5)];
  assert.equal(F.applyContributions(s), 2);
});

test("tiers follow the thresholds, which are repaired when inverted", () => {
  assert.equal(F.tierOf(0.49, { warn: 0.5, block: 0.85 }), "safe");
  assert.equal(F.tierOf(0.5, { warn: 0.5, block: 0.85 }), "warn");
  assert.equal(F.tierOf(0.85, { warn: 0.5, block: 0.85 }), "block");
  assert.deepEqual(F.normThresholds({ warn: 0.9, block: 0.2 }), { warn: 0.9, block: 0.9 });
  assert.deepEqual(F.normThresholds({}), F.DEFAULT_THRESHOLDS);
});

test("fusion clamps the logit and is monotone in evidence", () => {
  assert.equal(F.fuse([sig("x", 500, "url")]).logit, 12);
  assert.equal(F.fuse([sig("x", -500, "url")]).logit, -12);
  assert.ok(F.fuse([sig("a", 1, "url")]).risk < F.fuse([sig("a", 2, "url")]).risk);
});

test("mlWeight matches the Python analyzer's shrink/clamp/long-URL rules", () => {
  const near = (a, b) => Math.abs(a - b) < 0.02;
  assert.ok(near(F.mlWeight(0.9), 1.318));
  assert.ok(near(F.mlWeight(0.99), 2.757));
  assert.equal(F.mlWeight(0.99999), 4.0);
  assert.ok(near(F.mlWeight(0.1), -1.318));
  assert.equal(F.mlWeight(1e-9), -2.5);
  assert.equal(F.mlWeight(0.99999, 500), 2.5);
  assert.equal(F.mlWeight(NaN), 0);
});

test("corroboration: only intrinsically deceptive rule evidence unlocks the full model weight", () => {
  assert.equal(F.corroborated([sig("url.lots_hosting", 0.8, "url")]), false);
  assert.equal(F.corroborated([sig("url.credential_lure_path", 0.7, "url")]), false);
  assert.equal(F.corroborated([sig("url.long_url", 0.3, "url")]), false);
  assert.equal(F.corroborated([sig("ml.cnn.phishing", 4, "ml")]), false);
  assert.equal(F.corroborated([sig("brand.official", 3, "brand")]), false);
  assert.equal(F.corroborated([sig("unicode.punycode", 0.5, "unicode")]), false);
  assert.equal(F.corroborated([sig("brand.typosquat", 3, "brand", 0.9)]), true);
  assert.equal(F.corroborated([sig("brand.typosquat", 3, "brand", 0.2)]), false); // too unsure
  assert.equal(F.corroborated([sig("url.at_redirect", 3, "url")]), true);
  assert.equal(F.corroborated([sig("unicode.mixed_script_host", 2, "unicode")]), true);
});
