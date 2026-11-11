"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { loadData, engine } = require("./helpers");
const Rules = require(path.join(__dirname, "..", "lib/rules.js"));
const C = require("./corpus");

const rules = Rules.createRules(loadData());
const ids = (url) => rules.analyze(url).signals.map((s) => s.id);
const has = (url, id) => assert.ok(ids(url).includes(id), `${id} missing for ${url}: ${ids(url)}`);
const lacks = (url, id) => assert.ok(!ids(url).includes(id), `${id} unexpectedly present for ${url}`);

test("homoglyph hosts: Cyrillic/Greek letters imitating a brand", () => {
  has(`https://p${C.CYR_A}ypal.example/login`, "brand.homoglyph");
  has(`https://p${C.CYR_A}ypal.example/login`, "unicode.mixed_script_host");
  has(`https://g${C.GRK_O}${C.GRK_O}gle.example/`, "brand.homoglyph");
  has("http://xn--pypal-4ve.example/signin", "unicode.punycode_lookalike");
});

test("the signal names the offending character and script (for the localised explanation)", () => {
  const sig = rules.analyze(`https://p${C.CYR_A}ypal.example/`).signals.find((s) => s.id === "brand.homoglyph");
  assert.equal(sig.params.char, C.CYR_A);
  assert.equal(sig.params.like, "a");
  assert.equal(sig.params.script, "Cyrl");
  assert.equal(sig.params.brand, "PayPal");
  // the span points at the look-alike label inside the URL as typed
  const url = `https://p${C.CYR_A}ypal.example/`;
  assert.equal(url.slice(...sig.span), `p${C.CYR_A}ypal`);
});

test("whole-script confusable label and top-domain skeleton (all Cyrillic apple)", () => {
  const u = "https://аррӏе.com/";
  has(u, "unicode.whole_script_confusable");
  has(u, "unicode.skeleton_matches_top_domain");
  has(u, "brand.homoglyph");
});

test("invisible, bidi, delimiter-lookalike and combining-mark hosts", () => {
  has("https://pay\u200bpal.example/", "unicode.invisible_char");
  // the WHATWG parser refuses bidi controls in hosts outright, so such a link can never load
  assert.equal(rules.analyze("https://pay\u202epal.example/").parsed.valid, false);
  has("https://exam∕ple.example/", "unicode.dangerous_char");
  has("https://pay\u0338pal.example/", "unicode.combining_mark");
});

test("legitimate IDNs are not flagged as spoofs", () => {
  for (const u of ["https://müller.example/", "https://例え.テスト/", "https://www.банк.рф/",
    "https://مثال.إختبار/", "https://한글.도메인/", "https://उदाहरण.परीक्षा/"]) {
    const bad = ids(u).filter((id) => id.startsWith("unicode.") && id !== "unicode.punycode");
    assert.deepEqual(bad, [], u);
  }
});

test("mixed Latin + CJK is allowed (highly-restrictive), Latin + Cyrillic is not", () => {
  assert.equal(Rules.isMixedLabel("shop商店"), false);
  assert.equal(Rules.isMixedLabel("テスト-例"), false);
  assert.equal(Rules.isMixedLabel("pаypal"), true);
  assert.equal(Rules.isMixedLabel("αbc"), true);
});

test("brand techniques: subdomain, typosquat, bitsquat/edit, combosquat, path", () => {
  has("http://paypal.com.secure-login.example/verify", "brand.subdomain");
  has("https://login.microsoftonline.com.evil.example/oauth2", "brand.subdomain");
  has("https://paypa1.example/login", "brand.typosquat");
  has("https://secure-paypal-login.example/verify", "brand.combosquat");
  has("https://totally-unrelated.example/paypal/signin/verify", "brand.path");
  const best = rules.analyze("https://login.microsoftonline.com.evil.example/oauth2").brand;
  assert.equal(best.name, "Microsoft");
  assert.equal(best.technique, "subdomain");
});

test("official hosts produce only legitimacy evidence", () => {
  for (const u of ["https://www.paypal.com/signin", "https://login.microsoftonline.com/common/oauth2/authorize",
    "https://accounts.google.com/signin", "https://www.amazon.co.uk/gp/css/homepage.html"]) {
    const a = rules.analyze(u);
    assert.ok(a.brand && a.brand.official, u);
    assert.deepEqual(a.signals.filter((s) => s.weight > 0).map((s) => s.id).filter((i) => i !== "url.open_redirect"), [], u);
    assert.ok(a.signals.some((s) => s.id === "brand.official" && s.weight < 0), u);
  }
});

test("user-content subdomains of a brand are NOT official (sites.google.com)", () => {
  const a = rules.analyze("https://sites.google.com/view/anything");
  assert.ok(!(a.brand && a.brand.official));
  assert.ok(a.signals.some((s) => s.id === "url.lots_hosting"));
  assert.ok(!a.signals.some((s) => s.id === "rep.top_site"), "LOTS hosts never earn top-site credit");
});

test("phishing on a LOTS platform gets no reputation bonus and is flagged", () => {
  const a = rules.analyze("https://paypal-verify.pages.dev/signin");
  assert.ok(a.signals.some((s) => s.id === "url.lots_hosting"));
  assert.ok(a.signals.some((s) => s.id.startsWith("brand.")));
  assert.ok(!a.signals.some((s) => s.weight < 0));
});

test("popular sites are exempt from fuzzy brand matching (no false typosquat)", () => {
  assert.ok(!ids("https://www.applebees.com/menu").some((i) => i.startsWith("brand.")));
});

test("structure: IP, obfuscated IP, '@', shortener, dyndns, tld, subdomains, ext, encoding, port", () => {
  has("http://198.51.100.23/x", "url.ip_host");
  has("http://0xC6.0x33.0x64.0x17/x", "url.ip_obfuscation");
  lacks("http://0xC6.0x33.0x64.0x17/x", "url.ip_host");
  has("http://paypal.com@evil.example/", "url.at_redirect");
  has("https://bit.ly/3abc", "url.shortener");
  has("https://myhost.duckdns.org/", "url.dynamic_dns");
  has("https://something.xyz/", "url.suspicious_tld");
  has("https://a.b.c.d.e.example.com/", "url.many_subdomains");
  has("https://dl.example/invoice.pdf.exe", "url.double_extension");
  has("https://dl.example/update.scr", "url.suspicious_file_ext");
  has("https://example.com/a%252Fb", "url.double_encoding");
  has("https://example.com:8443/x", "url.non_standard_port");
  has("https://example.com/redirect?url=https://other.example/landing", "url.open_redirect");
  lacks("https://example.com/redirect?url=https://example.com/landing", "url.open_redirect");
  lacks("https://example.com/?next=/dashboard", "url.open_redirect");
});

test("credential-lure words in host and path are weak, capped evidence", () => {
  const a = rules.analyze("https://secure-login-verify-account-update.example/signin/verify/password");
  for (const s of a.signals.filter((x) => x.id.startsWith("url.credential_lure"))) assert.ok(s.weight <= 2.0);
  has("https://secure-login-verify-account-update.example/", "url.credential_lure_host");
});

test("dangerous schemes", () => {
  has("javascript:alert(1)", "url.dangerous_scheme");
  has("data:text/html;base64,PGh0bWw+", "url.dangerous_scheme");
});

test("signal weights stay on the documented scale and carry required fields", () => {
  for (const [u] of C.phishing) {
    for (const s of rules.analyze(u).signals) {
      assert.ok(s.weight >= -4 && s.weight <= 8, `${s.id} weight ${s.weight}`);
      assert.match(s.id, /^[a-z]+(\.[a-z0-9_]+)+$/);
      assert.ok(s.title.length <= 70, `${s.id} title too long`);
      assert.ok(["brand", "unicode", "url", "reputation"].includes(s.category), s.id);
      assert.ok(s.confidence > 0 && s.confidence <= 1);
      assert.ok(typeof s.detail === "string" && s.detail.length > 0);
    }
  }
});

test("the analyser never throws on hostile input", () => {
  const nasty = ["", " ", "http://", "http://%", "http://[::", "http://a..b/", "http://-.-/", "\u0000", "http://\ud800.example/",
    "http://" + "a.".repeat(500) + "com/", "http://example.com/" + "%".repeat(5000), "http://xn--/", "http://xn--a-.example/",
    "https://" + "а".repeat(300) + ".example", "ftp://x.example/a.exe", "file:///etc/passwd", "mailto:a@b.c", "http://example.com/?" + "u=http://x.y&".repeat(400)];
  for (const u of nasty) assert.doesNotThrow(() => rules.analyze(u), JSON.stringify(u.slice(0, 30)));
});

test("analysis of a large page's worth of links is fast", () => {
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < 300; i++) rules.analyze(`https://site${i}.example.net/path/${i}/page?id=${i}`);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.ok(ms < 4000, `300 URLs took ${ms.toFixed(0)} ms`);
});

test("labelled synthetic corpus: every phishing URL is warn/block, every benign URL is safe", () => {
  const e = engine();
  const miss = C.phishing.filter(([u]) => e.score(u, { noCache: true }).tier === "safe").map(([u]) => u);
  const fp = C.benign.filter((u) => e.score(u, { noCache: true }).tier !== "safe");
  // the single structural '@' trick scores 73 (warn) by design; everything else must be caught
  assert.deepEqual(miss, [], "missed phishing: " + miss.join(", "));
  assert.deepEqual(fp, [], "false positives: " + fp.join(", "));
  const blocked = C.phishing.filter(([u]) => e.score(u, { noCache: true }).tier === "block").length;
  assert.ok(blocked / C.phishing.length >= 0.8, `only ${blocked}/${C.phishing.length} reached block`);
});
