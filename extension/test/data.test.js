"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const cp = require("child_process");
const { ROOT, readJson } = require("./helpers");

const REPO = path.resolve(ROOT, "..");

test("bundled model weights are byte-identical to the platform's canonical copy", () => {
  const a = fs.readFileSync(path.join(ROOT, "model/weights.bin"));
  const canonical = path.join(REPO, "uniphish/assets/model/weights.bin");
  if (!fs.existsSync(canonical)) return;
  assert.ok(a.equals(fs.readFileSync(canonical)));
  assert.equal(a.length, 1511940);
});

test("brand bundle: well-formed and lowercase-normalised", () => {
  const { brands } = readJson("data/brands.json");
  assert.ok(brands.length >= 600, `only ${brands.length} brands`);
  const seen = new Set();
  for (const b of brands) {
    assert.ok(b.i && b.n && Array.isArray(b.d), b.i);
    assert.ok(!seen.has(b.i), "duplicate id " + b.i); seen.add(b.i);
    for (const d of b.d) assert.equal(d, d.toLowerCase());
    for (const t of b.t) assert.match(t, /^[a-z0-9]{4,40}$/, `${b.i}: ${t}`);
  }
  const pp = brands.find((b) => b.i === "paypal");
  assert.ok(pp.d.includes("paypal.com"));
  assert.ok(brands.find((b) => b.i === "google").u.includes("sites.google.com"));
});

test("confusables bundle: only non-ASCII -> printable ASCII prototypes", () => {
  const { m, v } = readJson("data/confusables.json");
  assert.ok(v);
  assert.equal(m["а"], "a");
  assert.equal(m["о"], "o");
  assert.equal(m["ο"], "o");
  const entries = Object.entries(m);
  assert.ok(entries.length > 1500);
  for (const [k, val] of entries) {
    assert.ok(k.codePointAt(0) >= 0x80);
    assert.match(val, /^[\x21-\x7e]+$/);
  }
});

test("lists bundle: TLD risk, LOTS, shorteners, dyndns, suffixes, top sites, lure vocabulary", () => {
  const L = readJson("data/lists.json");
  assert.ok(L.tld.tk >= 1 && L.tld.top > 0);
  assert.ok(L.lots.some((r) => r[0] === "pages.dev"));
  assert.ok(L.lots.length >= 150);
  assert.ok(L.short.includes("bit.ly"));
  assert.ok(L.dyn.includes("duckdns.org"));
  assert.ok(L.psl.uk.includes("co") && L.psl.au.includes("com"));
  assert.equal(L.top.length, 10000);
  assert.equal(L.top[0], "google.com");
  assert.ok(L.lure.tok.login > 0 && Object.keys(L.lure.tok).length > 500);
  assert.ok(L.ctx.includes("verify"));
});

test("payload budget: data bundle + weights stay small", () => {
  const sizes = {};
  let total = 0;
  const walk = (dir) => {
    for (const e of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
      const rel = path.join(dir, e.name);
      if (e.isDirectory()) { if (!["test", "tools", "node_modules"].includes(e.name)) walk(rel); }
      else { const s = fs.statSync(path.join(ROOT, rel)).size; total += s; sizes[rel] = s; }
    }
  };
  walk(".");
  assert.ok(sizes["data/brands.json"] < 150_000);
  assert.ok(sizes["data/lists.json"] < 350_000);
  assert.ok(sizes["data/confusables.json"] < 40_000);
  assert.ok(total < 2_600_000, `extension payload is ${total} bytes`);
});

test("data/ is up to date with uniphish/assets (tools/build_data.py --check)", (t) => {
  const py = path.join(REPO, ".venv/bin/python");
  if (!fs.existsSync(py)) return t.skip("no .venv python");
  const r = cp.spawnSync(py, [path.join(ROOT, "tools/build_data.py"), "--check"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr || r.stdout);
});
