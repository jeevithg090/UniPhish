// Pure helpers for the content script: which links to scan and how to summarise results.
//
// Kept out of content.js so they can be unit-tested in Node without a DOM.

(function (global) {
  "use strict";

  const MAX_HREF = 2048;

  /**
   * Absolute http(s) URL string for an anchor's resolved href, or null if it should not be
   * scanned (non-web scheme, same host as the page, overlong, or unparseable).
   * `pageHost` is location.host: links within the current site are not scanned.
   */
  function scannableUrl(href, pageHost) {
    if (typeof href !== "string" || !href || href.length > MAX_HREF) return null;
    if (!/^https?:\/\//i.test(href)) return null;
    let u;
    try { u = new URL(href); } catch (_) { return null; }
    if (pageHost && u.host.toLowerCase() === String(pageHost).toLowerCase()) return null;
    u.hash = ""; // fragments never change the destination host/path
    return u.href;
  }

  /** Split an array into chunks of at most `n`. */
  function chunk(arr, n) {
    const out = [];
    for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n));
    return out;
  }

  /** Count unique flagged URLs by tier from a url->{tier} map. */
  function tally(flagged) {
    let blocked = 0, warned = 0;
    for (const v of flagged.values()) { if (v.tier === "block") blocked++; else if (v.tier === "warn") warned++; }
    return { blocked, warned };
  }

  const api = { scannableUrl, chunk, tally, MAX_HREF };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhishLinks = api;
})(typeof self !== "undefined" ? self : this);
