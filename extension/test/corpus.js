"use strict";
// Synthetic, inert labelled corpus. Domains are reserved (.example/.test/.invalid) or are
// plain strings that are never fetched; "hxxp" style defanging is unnecessary because tests
// only parse the strings. Homoglyph characters are written as \u escapes so a reader can see
// exactly which code point is used.
const CYR_A = "а";  // Cyrillic small a
const CYR_O = "о";  // Cyrillic small o
const CYR_E = "е";  // Cyrillic small e
const GRK_O = "ο";  // Greek small omicron

const phishing = [
  [`https://p${CYR_A}ypal.example/login`, "homoglyph"],
  [`https://${CYR_A}pple.example/id/verify`, "homoglyph"],
  [`https://micr${CYR_O}soft.example/signin`, "homoglyph"],
  [`https://g${GRK_O}${GRK_O}gle.example/accounts/login`, "homoglyph"],
  [`https://amaz${CYR_O}n.example/ap/signin`, "homoglyph"],
  ["http://xn--pypal-4ve.example/signin", "homoglyph"],
  ["http://paypal.com.secure-login.example/verify", "subdomain"],
  ["https://login.microsoftonline.com.evil.example/oauth2/authorize", "subdomain"],
  ["https://appleid.apple.com.account-verify.example/", "subdomain"],
  ["https://paypa1.example/login", "typosquat"],
  ["https://arnazon.example/signin", "typosquat"],
  ["https://netf1ix-billing.example/update-payment", "combosquat"],
  ["https://secure-paypal-login.example/verify", "combosquat"],
  ["https://apple-id-verify-account.example/", "combosquat"],
  ["http://paypal.com@evil.example/", "at_redirect"],
  ["http://0x7f000001.example@198.51.100.7/", "at_redirect"],
  ["http://198.51.100.23/paypal/login.php", "ip"],
  ["http://0xC6.0x33.0x64.0x17/signin", "ip_obfuscation"],
  ["https://paypal-verify.pages.dev/signin", "lots"],
  ["https://login-microsoftonline.web.app/", "lots"],
  ["https://secure-login-verify-account-update.xyz/", "lure"],
  ["https://update-your-bank-password.top/login", "lure"],
];

const benign = [
  "https://www.paypal.com/signin",
  "https://accounts.google.com/signin/v2/identifier?continue=https://mail.google.com/mail/",
  "https://login.microsoftonline.com/common/oauth2/authorize",
  "https://appleid.apple.com/sign-in",
  "https://www.amazon.com/dp/B08N5WRWNW?ref=cm_sw_r_cp_ud_dp_ABCDEFG123&th=1",
  "https://en.wikipedia.org/wiki/Phishing",
  "https://github.com/anthropics/claude-code",
  "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster",
  "https://www.bbc.co.uk/news/world-europe-12345678",
  "https://www.nytimes.com/2024/01/01/world/europe/story.html",
  "https://www.reddit.com/r/programming/comments/abc/title/",
  "https://news.ycombinator.com/item?id=12345",
  "https://docs.python.org/3/library/re.html",
  "https://www.wikipedia.org/",
  "https://example.com/",
  "https://example.org/some/long/path/to/an/article?id=12345&ref=newsletter&utm_source=mail",
  "https://www.mysmallbakery.co.uk/order-online/cakes?category=birthday&page=2",
  "https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz/edit",
  "https://müller.example/kontakt",
  "https://www.банк.рф/",   // legitimate all-Cyrillic domain under the Cyrillic .rf TLD
  "https://例え.テスト/",
  "http://localhost:3000/login",
  "http://192.168.1.1/admin",
];

module.exports = { phishing, benign, CYR_A, CYR_O, CYR_E, GRK_O };
