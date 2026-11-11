"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const U = require(path.join(__dirname, "..", "lib/urlparse.js"));

test("parses scheme-less input, protocol-relative input and host:port", () => {
  assert.equal(U.parseUrl("paypal.com/login").host, "paypal.com");
  assert.equal(U.parseUrl("//a.example/x").host, "a.example");
  const p = U.parseUrl("localhost:8080/a");
  assert.equal(p.host, "localhost"); assert.equal(p.port, "8080");
});

test("never throws and rejects garbage", () => {
  for (const s of ["", "   ", "http://", "http://a b.com", ":::", "http://[::1", null, undefined, 42, "\u0000", "http://" + "a".repeat(10000)]) {
    assert.doesNotThrow(() => U.parseUrl(s));
  }
  assert.equal(U.parseUrl("http://a b.com").valid, false);
  assert.equal(U.parseUrl("").valid, false);
});

test("IP forms: dotted, hex, integer, octal are normalised and flagged obfuscated", () => {
  assert.equal(U.parseUrl("http://192.0.2.1/").ipObfuscated, false);
  for (const raw of ["http://0xC0.0x00.0x02.0x01/", "http://3221225985/", "http://0300.0.2.1/", "http://192.0.513/"]) {
    const p = U.parseUrl(raw);
    assert.equal(p.isIp, true, raw);
    assert.equal(p.host, "192.0.2.1", raw);
    assert.equal(p.ipObfuscated, true, raw);
  }
  assert.equal(U.parseUrl("http://[2001:db8::1]:8080/").ipVersion, 6);
});

test("userinfo ('@' trick) is separated from the real host", () => {
  const p = U.parseUrl("https://paypal.com@evil.example/x");
  assert.equal(p.host, "evil.example");
  assert.equal(p.userinfo, "paypal.com");
  assert.equal(p.input.slice(...p.userinfoSpan), "paypal.com");
  assert.equal(p.input.slice(...p.hostSpan), "evil.example");
});

test("punycode round-trips and non-ASCII detection works for both spellings", () => {
  const a = U.parseUrl("https://pаypal.example/");
  assert.equal(a.host, "xn--pypal-4ve.example");
  assert.equal(a.hostUnicode, "pаypal.example");
  assert.equal(a.hasNonAsciiHost, true);
  const b = U.parseUrl("http://xn--pypal-4ve.example/");
  assert.equal(b.hostUnicode, "pаypal.example");
  assert.equal(b.punycode, true);
  assert.equal(U.toUnicodeHost("xn--mnchen-3ya.de"), "münchen.de");
  assert.equal(U.toUnicodeHost("xn--80ak6aa92e.com"), "аррӏе.com");
  assert.equal(U.toUnicodeHost("xn--!!!.com"), "xn--!!!.com"); // malformed stays as-is
});

test("zero-width characters are visible in the raw host even though the parser strips them", () => {
  const p = U.parseUrl("https://pay\u200bpal.example/");
  assert.equal(p.hasNonAsciiHost, true);
});

test("splitHost uses multi-label suffixes, platform suffixes and unknown TLDs", () => {
  const psl = { uk: new Set(["co", "org"]), au: new Set(["com"]) };
  assert.deepEqual(U.splitHost("www.bbc.co.uk", psl), { sub: ["www"], sld: "bbc", suffix: "co.uk" });
  assert.deepEqual(U.splitHost("a.b.example.com.au", psl), { sub: ["a", "b"], sld: "example", suffix: "com.au" });
  assert.deepEqual(U.splitHost("x.evil.test", psl), { sub: ["x"], sld: "evil", suffix: "test" });
  assert.deepEqual(U.splitHost("x.y.pages.dev", psl, "pages.dev"), { sub: ["x"], sld: "y", suffix: "pages.dev" });
  assert.deepEqual(U.splitHost("pages.dev", psl, "pages.dev"), { sub: [], sld: "pages", suffix: "dev" });
  assert.deepEqual(U.splitHost("localhost", psl), { sub: [], sld: "localhost", suffix: "" });
});

test("local / private hosts are recognised", () => {
  for (const u of ["http://localhost:3000/", "http://127.0.0.1/", "http://10.1.2.3/", "http://172.16.0.1/", "http://192.168.1.1/",
    "http://169.254.1.1/", "http://[::1]/", "http://intranet/", "http://nas.local/", "http://app.localhost/"]) {
    assert.equal(U.parseUrl(u).isLocal, true, u);
  }
  for (const u of ["http://8.8.8.8/", "http://172.32.0.1/", "http://example.com/", "http://192.0.2.1/"]) {
    assert.equal(U.parseUrl(u).isLocal, false, u);
  }
});

test("non-http schemes parse without a host", () => {
  const p = U.parseUrl("javascript:alert(1)");
  assert.equal(p.valid, true); assert.equal(p.scheme, "javascript"); assert.equal(p.host, "");
});
