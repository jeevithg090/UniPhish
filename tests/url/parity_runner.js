// Parity oracle for the NumPy UniPhish runtime (uniphish/url/model.py).
//
// Loads the canonical on-device model (extension/model.js) with the shipped weights and
// prints, as JSON, the phishing probability for a fixed set of diverse URLs. The Python
// test tests/url/test_model_parity.py runs this with node (skipping if node is absent),
// then asserts the pure-NumPy forward pass reproduces each probability within 1e-4.
//
// The URL list lives HERE so there is one source of truth: the test consumes the urls
// AND the probs emitted below. All URLs use reserved/example domains or synthetic
// look-alikes — nothing live. Run standalone:  node tests/url/parity_runner.js

"use strict";
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..", "..");
const UniPhish = require(path.join(root, "extension", "model.js"));
const modelDir = path.join(root, "extension", "model");

const manifest = JSON.parse(fs.readFileSync(path.join(modelDir, "manifest.json"), "utf8"));
const raw = fs.readFileSync(path.join(modelDir, "weights.bin"));
// Copy into a fresh, 4-byte-aligned ArrayBuffer (a pooled Buffer may be mis-aligned).
const ab = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength);
const W = new Float32Array(ab);

// ~25 diverse URLs: Latin, Cyrillic, Arabic, CJK, Devanagari, Hangul, mixed homoglyphs,
// punycode, IP / obfuscated-IP hosts, a >600-byte URL (truncation), and short strings.
const longUrl = "https://example.com/" + "a".repeat(700) + "/login";
const urls = [
  "https://example.com/",
  "http://example.org/login",
  "a.co",
  "http://t.test/x",
  "https://www.example.com/account/settings?ref=1",
  "http://paypal.com.secure-login.example/verify",
  "https://login.microsoftonline.com.evil.example/oauth2/authorize",
  "http://xn--pypal-4ve.example/signin",                        // punycode look-alike
  "https://pаypаl.example/login",                     // Cyrillic a homoglyph
  "https://пример.example/вход",   // Cyrillic (primer/vhod)
  "https://بنك.example/تسجيل-الدخول", // Arabic
  "https://银行.example/登录",                  // CJK (bank/login)
  "https://例え.example/ログイン",      // Japanese
  "https://उदाहरण.example/लॉगिन",  // Devanagari
  "https://예시.example/로그인",            // Hangul
  "http://192.168.0.1/login",
  "http://0xC0A80001/",                                         // obfuscated IPv4
  "http://[2001:db8::1]/admin",
  "https://secure-update.example.invalid/account/verify.php?id=abc123",
  "https://bit.example/3xZ9",
  "ftp://files.example.net/pub/readme.txt",
  "https://example.com/" + "path/".repeat(40),
  longUrl,
  "https://xn--80ak6aa92e.example/",                            // punycode (apple-ish)
  "https://mail.example.co.uk/owa/?realm=corp",
  "http://update-account.example.test/~r/portal",
];

const out = urls.map((u) => ({ url: u, prob: UniPhish.forward(manifest, W, u) }));
process.stdout.write(JSON.stringify(out));
