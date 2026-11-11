"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const R = require(path.join(__dirname, "..", "lib/report.js"));
const Links = require(path.join(__dirname, "..", "lib/links.js"));
const { engine } = require("./helpers");

test("defang neutralises scheme, dots and '@'", () => {
  assert.equal(R.defang("https://evil.example/a?b=c@d"), "hxxps[://]evil[.]example/a?b=c[@]d");
  assert.equal(R.defang("http://1.2.3.4/"), "hxxp[://]1[.]2[.]3[.]4/");
  assert.ok(!/https?:\/\//i.test(R.defang("http://x.example")));
});

test("report is plain text, defanged, deterministic and says nothing was sent", () => {
  const v = engine().score("http://paypal.com.secure-login.example/verify");
  const text = R.buildReport(v, ["reason one"], new Date("2026-01-02T03:04:05Z"));
  assert.match(text, /2026-01-02T03:04:05.000Z/);
  assert.match(text, /hxxp\[:\/\/\]paypal\[\.\]com/);
  assert.ok(!/https?:\/\//i.test(text));
  assert.match(text, /Impersonated brand: PayPal/);
  assert.match(text, /no data was sent/);
});

function mockFetch(handler) {
  const calls = [];
  const f = async (url, init) => { calls.push({ url, init }); return handler(url, init); };
  f.calls = calls;
  return f;
}
const ok = (body) => ({ ok: true, status: 200, json: async () => body });

test("deepScan: posts to the user's endpoint with key header, no cookies, no redirects", async () => {
  const f = mockFetch(() => ok({ score: 91, level: "malicious", summary: "bad", brand: { name: "PayPal" },
    signals: [{ title: "t", detail: "d", weight: 3 }, { title: "x".repeat(500), detail: "y", weight: -1 }] }));
  const r = await R.deepScan({ endpoint: "https://uniphish.example.com", apiKey: "k123" }, "https://x.example/", { fetch: f });
  const c = f.calls[0];
  assert.equal(c.url, "https://uniphish.example.com/v1/scan/url");
  assert.equal(c.init.method, "POST");
  assert.equal(c.init.headers["X-API-Key"], "k123");
  assert.equal(c.init.credentials, "omit");
  assert.equal(c.init.redirect, "error");
  assert.deepEqual(JSON.parse(c.init.body), { url: "https://x.example/", options: { explain: true } });
  assert.equal(r.score, 91); assert.equal(r.brand, "PayPal");
  assert.ok(r.signals[1].title.length <= 120, "server text is length-bounded");
});

test("deepScan: no key header when none configured; HTTP errors and missing endpoint are reported", async () => {
  const f = mockFetch(() => ok({ risk: 0.5 }));
  const r = await R.deepScan({ endpoint: "http://localhost:8000", apiKey: "" }, "https://x.example/", { fetch: f });
  assert.equal(f.calls[0].init.headers["X-API-Key"], undefined);
  assert.equal(r.score, 50);
  await assert.rejects(R.deepScan({ endpoint: "https://s.example" }, "u", { fetch: mockFetch(() => ({ ok: false, status: 401 })) }), /HTTP 401/);
  await assert.rejects(R.deepScan({ endpoint: "" }, "u", { fetch: mockFetch(() => ok({})) }), /no endpoint/);
});

test("deepScan: timeouts surface as 'timeout'", async () => {
  const f = (url, init) => new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" }))));
  await assert.rejects(R.deepScan({ endpoint: "https://s.example" }, "u", { fetch: f, timeoutMs: 20 }), /timeout/);
});

test("submitReport asks the server to persist; ping uses GET /v1/health", async () => {
  const f = mockFetch(() => ok({ score: 1 }));
  await R.submitReport({ endpoint: "https://s.example" }, "https://x.example/", { fetch: f });
  assert.deepEqual(JSON.parse(f.calls[0].init.body).options, { explain: true, persist: true });
  await R.ping({ endpoint: "https://s.example" }, { fetch: f });
  assert.equal(f.calls[1].init.method, "GET");
  assert.ok(f.calls[1].url.endsWith("/v1/health"));
  assert.equal(f.calls[1].init.body, undefined);
});

test("links: only external http(s) links are scanned", () => {
  assert.equal(Links.scannableUrl("https://a.example/x#frag", "b.example"), "https://a.example/x");
  assert.equal(Links.scannableUrl("https://B.example/x", "b.example"), null, "same host skipped");
  for (const h of ["javascript:alert(1)", "mailto:a@b.c", "tel:123", "#top", "", "ftp://x.example", "data:text/html,x", "http://", "https://" + "a".repeat(3000) + ".example"]) {
    assert.equal(Links.scannableUrl(h, "b.example"), null, h.slice(0, 30));
  }
  assert.equal(Links.scannableUrl(undefined, "b.example"), null);
});

test("links: chunk and tally", () => {
  assert.deepEqual(Links.chunk([1, 2, 3, 4, 5], 2), [[1, 2], [3, 4], [5]]);
  assert.deepEqual(Links.chunk([], 3), []);
  assert.deepEqual(Links.tally(new Map([["a", { tier: "block" }], ["b", { tier: "warn" }], ["c", { tier: "warn" }]])), { blocked: 1, warned: 2 });
});
