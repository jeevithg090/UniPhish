"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { ROOT, engine } = require("./helpers");
const I = require(path.join(ROOT, "lib/i18n.js"));
const Rules = require(path.join(ROOT, "lib/rules.js"));
const C = require("./corpus");

const readLocale = (l) => JSON.parse(fs.readFileSync(path.join(ROOT, "locales", l + ".json"), "utf8"));
const loader = async (l) => readLocale(l);
const placeholders = (s) => [...String(s).matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

test("every supported language has a locale file", () => {
  for (const l of I.SUPPORTED) assert.ok(fs.existsSync(path.join(ROOT, "locales", l + ".json")), l);
});

test("translations keep exactly the English placeholders (no dropped/renamed parameters)", () => {
  const en = readLocale("en");
  for (const l of I.SUPPORTED.filter((x) => x !== "en")) {
    const loc = readLocale(l);
    for (const [k, v] of Object.entries(loc)) {
      assert.ok(k in en, `${l}: unknown key ${k}`);
      assert.deepEqual(placeholders(v), placeholders(en[k]), `${l}:${k} placeholders differ`);
      assert.ok(String(v).trim().length > 0, `${l}:${k} empty`);
    }
  }
});

test("non-English locales cover every safety-critical surface (popup/warning page/link tooltips/core reasons)", () => {
  const required = ["tier.safe", "tier.warn", "tier.block", "popup.scan", "popup.reasons", "link.block", "link.warn", "menu.scan",
    "inter.title", "inter.lead", "inter.back", "inter.proceed", "inter.report", "r.brand.homoglyph", "r.brand.homoglyph.char",
    "r.brand.subdomain", "r.unicode.confusable_host", "r.unicode.mixed_script_host", "r.url.ip_host", "r.url.at_redirect", "r.url.suspicious_tld"];
  for (const l of I.SUPPORTED) for (const k of required) assert.ok(readLocale(l)[k], `${l} missing ${k}`);
});

test("English has a reason template for every signal the rules and engine can emit", () => {
  const en = readLocale("en");
  const emit = Object.keys(Rules.TITLES).filter((id) => id !== "url.credential_lure_path" || true);
  for (const id of emit) assert.ok(en["r." + id], `no English reason for ${id}`);
});

test("English phrasing: the Cyrillic-a example reads as specified", async () => {
  const i18n = I.createI18n(loader);
  await i18n.use("en");
  const v = engine().score(`https://p${C.CYR_A}ypal.example/login`);
  const sig = v.signals.find((s) => s.id === "brand.homoglyph");
  const text = i18n.reason(sig);
  assert.match(text, /Cyrillic/);
  assert.ok(text.includes(C.CYR_A) && text.includes("a") && text.includes("PayPal"));
});

test("every locale renders every reason of every corpus phishing URL without leftover braces", async () => {
  const e = engine();
  for (const l of I.SUPPORTED) {
    const i18n = I.createI18n(loader);
    await i18n.use(l);
    for (const [u] of C.phishing) for (const s of e.score(u).signals) {
      const t = i18n.reason(s);
      assert.ok(t && !/[{}]/.test(t), `${l} ${s.id}: ${t}`);
    }
  }
});

test("fallback: missing keys fall back to English, unknown keys return the key, reason() falls back to detail", async () => {
  const i18n = I.createI18n(async (l) => (l === "en" ? { a: "English {x}" } : { }));
  await i18n.use("de");
  assert.equal(i18n.t("a", { x: "1" }), "English 1");
  assert.equal(i18n.t("nope"), "nope");
  assert.equal(i18n.reason({ id: "zz.unknown", detail: "Detail text" }), "Detail text");
});

test("language selection: auto-detect and tag normalisation", () => {
  assert.equal(I.normalizeLang("pt-BR"), "pt");
  assert.equal(I.normalizeLang("zh_CN"), "zh");
  assert.equal(I.normalizeLang("sv"), "en");
  assert.equal(I.normalizeLang(""), "en");
});

test("Arabic is right-to-left, others left-to-right", async () => {
  const ar = I.createI18n(loader); await ar.use("ar");
  const en = I.createI18n(loader); await en.use("en");
  assert.equal(ar.dir(), "rtl"); assert.equal(en.dir(), "ltr");
});

test("script names are localised with Intl.DisplayNames", async () => {
  const de = I.createI18n(loader); await de.use("de");
  assert.match(de.t("r.unicode.mixed_script_host", { scripts: "Latn,Cyrl" }), /Kyrillisch/);
});

test("templates never interpolate as markup: output is plain text (callers use textContent)", async () => {
  const i18n = I.createI18n(loader); await i18n.use("en");
  const t = i18n.reason({ id: "url.shortener", params: { host: "<img src=x onerror=alert(1)>" } });
  assert.ok(t.includes("<img"), "attacker text is preserved verbatim as text, never altered into markup");
  // and no UI source assigns reasons via innerHTML (see manifest.test.js)
});
