// Hostile-input-safe URL parsing for the on-device scorer.
//
// Why: every rule needs the *same* view of a link the browser will use (the WHATWG URL
// parser) plus facts the parser hides: the raw authority text (to spot obfuscated IPs and
// invisible characters the parser silently strips), the Unicode form of an IDN host, and the
// split into sub-domain / registrable label / public suffix.  This module never throws and
// never fetches anything.
//
// Spans: all offsets returned (hostSpan, userinfoSpan, pathSpan) index into `parsed.input`,
// which is the string the UI shows (the pasted text, with "http://" prepended if the user
// omitted a scheme).

(function (global) {
  "use strict";

  const SCHEME_RE = /^[a-z][a-z0-9+.\-]*:/i;
  const MAX_URL = 8192;
  const PUNY_BASE = 36, T_MIN = 1, T_MAX = 26, SKEW = 38, DAMP = 700;

  function adapt(delta, numPoints, first) {
    delta = first ? Math.floor(delta / DAMP) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((PUNY_BASE - T_MIN) * T_MAX) >> 1) {
      delta = Math.floor(delta / (PUNY_BASE - T_MIN));
      k += PUNY_BASE;
    }
    return k + Math.floor(((PUNY_BASE - T_MIN + 1) * delta) / (delta + SKEW));
  }

  /** RFC 3492 decode of one label body (without the "xn--" prefix); null if malformed. */
  function punyDecode(input) {
    const out = [];
    let basic = input.lastIndexOf("-");
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) {
      if (input.charCodeAt(j) >= 0x80) return null;
      out.push(input.charCodeAt(j));
    }
    let n = 128, bias = 72, i = 0;
    for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      const oldi = i;
      for (let w = 1, k = PUNY_BASE; ; k += PUNY_BASE) {
        if (idx >= input.length) return null;
        const c = input.charCodeAt(idx++);
        const digit = c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : PUNY_BASE;
        if (digit >= PUNY_BASE) return null;
        i += digit * w;
        const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
        if (digit < t) break;
        w *= PUNY_BASE - t;
      }
      const len = out.length + 1;
      bias = adapt(i - oldi, len, oldi === 0);
      n += Math.floor(i / len);
      i %= len;
      if (n > 0x10ffff) return null;
      out.splice(i++, 0, n);
    }
    try { return String.fromCodePoint(...out); } catch (_) { return null; }
  }

  /** "xn--pypal-4ve.example" -> "pаypal.example"; labels that fail to decode stay as-is. */
  function toUnicodeHost(host) {
    return host.split(".").map((label) => {
      if (label.slice(0, 4).toLowerCase() !== "xn--") return label;
      const d = punyDecode(label.slice(4).toLowerCase());
      return d === null ? label : d;
    }).join(".");
  }

  /** Split host labels into {sub, sld, suffix} using the bundled multi-label suffix table. */
  function splitHost(host, psl, lotsSuffix) {
    const labels = host.split(".").filter(Boolean);
    if (labels.length === 0) return { sub: [], sld: "", suffix: "" };
    if (labels.length === 1) return { sub: [], sld: labels[0], suffix: "" };
    let k = 1;
    const table = (psl && psl[labels[labels.length - 1]]) || null;
    if (table) {
      const set = table instanceof Set ? table : new Set(table);
      for (const n of [3, 2]) { // longest multi-label suffix first (e.g. "co.uk" -> k = 2)
        if (labels.length > n && set.has(labels.slice(-n, -1).join("."))) { k = n; break; }
      }
    }
    // A private "platform" suffix (pages.dev, github.io ...) behaves as the suffix too.
    if (lotsSuffix) {
      const n = lotsSuffix.split(".").length;
      if (n > k && labels.length > n) k = n;
    }
    return {
      sub: labels.slice(0, labels.length - k - 1),
      sld: labels[labels.length - k - 1],
      suffix: labels.slice(-k).join("."),
    };
  }

  /** Loopback / private / link-local / single-label hosts: not reachable by an outside attacker. */
  function isLocalHost(host, ipVersion) {
    if (!host) return false;
    if (ipVersion === 4) {
      const [a, b] = host.split(".").map(Number);
      return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
    }
    if (ipVersion === 6) return host === "::1" || host === "::" || /^f[cd]/i.test(host) || /^fe[89ab]/i.test(host);
    return !host.includes(".") || /\.(localhost|local|internal|lan|home\.arpa|intranet)$/.test(host) || host === "localhost";
  }

  function emptyParsed(input, raw) {
    return {
      valid: false, raw, input, scheme: "", userinfo: "", host: "", hostUnicode: "",
      rawHost: "", port: "", path: "", query: "", hash: "", isIp: false, ipVersion: 0,
      ipObfuscated: false, isLocal: false, hasNonAsciiHost: false, punycode: false, hostSpan: null,
      userinfoSpan: null, pathSpan: null, href: "",
    };
  }

  /** Parse any user/page supplied string. Never throws. */
  function parseUrl(raw) {
    const text = String(raw == null ? "" : raw).trim().slice(0, MAX_URL);
    let input = text;
    if (input.startsWith("//")) input = "http:" + input;
    else if (input && !SCHEME_RE.test(input)) input = "http://" + input;
    // "host:8080/x" looks like a scheme to SCHEME_RE: treat "word:digits" as host:port.
    else if (/^[^/?#@:]+:\d+([/?#]|$)/.test(input)) input = "http://" + input;

    const out = emptyParsed(input, text);
    if (!input) return out;
    let u;
    try { u = new URL(input); } catch (_) { return out; }

    out.scheme = u.protocol.replace(/:$/, "").toLowerCase();
    out.href = u.href;
    out.path = u.pathname;
    out.query = u.search;
    out.hash = u.hash;
    out.port = u.port;
    out.userinfo = u.username + (u.password ? ":" + u.password : "");
    if (out.scheme !== "http" && out.scheme !== "https" && out.scheme !== "ftp") {
      out.valid = true; // data:, javascript:, ... carry no host
      return out;
    }
    if (!u.hostname) return out;
    out.valid = true;

    // ---- raw authority (what the user actually sees, before parser normalisation) ----
    const sep = input.indexOf("//");
    const aStart = sep >= 0 ? sep + 2 : 0;
    let aEnd = input.length;
    for (const ch of "/?#\\") {
      const i = input.indexOf(ch, aStart);
      if (i !== -1 && i < aEnd) aEnd = i;
    }
    let hStart = aStart;
    const authority = input.slice(aStart, aEnd);
    const at = authority.lastIndexOf("@");
    if (at !== -1) {
      hStart = aStart + at + 1;
      out.userinfoSpan = [aStart, aStart + at];
    }
    let hEnd = aEnd;
    const hostPart = input.slice(hStart, aEnd);
    if (hostPart.startsWith("[")) {
      const close = hostPart.indexOf("]");
      if (close !== -1) hEnd = hStart + close + 1;
    } else {
      const colon = hostPart.lastIndexOf(":");
      if (colon > -1 && /^\d*$/.test(hostPart.slice(colon + 1))) hEnd = hStart + colon;
    }
    out.rawHost = input.slice(hStart, hEnd);
    out.hostSpan = hEnd > hStart ? [hStart, hEnd] : null;
    if (aEnd < input.length && input[aEnd] !== "?" && input[aEnd] !== "#") {
      const rest = input.slice(aEnd).search(/[?#]/);
      out.pathSpan = [aEnd, rest === -1 ? input.length : aEnd + rest];
    }

    const hostname = u.hostname.toLowerCase();
    out.host = hostname.replace(/^\[|\]$/g, "");
    if (hostname.startsWith("[")) {
      out.isIp = true; out.ipVersion = 6;
    } else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      out.isIp = true; out.ipVersion = 4;
      // The parser turned something like 0x7f.1 / 2130706433 / 0177.0.0.1 into dotted decimal.
      out.ipObfuscated = out.rawHost.toLowerCase() !== hostname;
    }
    out.isLocal = isLocalHost(out.host, out.ipVersion);
    out.punycode = out.host.split(".").some((l) => l.startsWith("xn--"));
    out.hostUnicode = out.isIp ? out.host : toUnicodeHost(out.host);
    // Anything non-ASCII in what the user sees OR the decoded host counts (the parser strips
    // zero-width characters, so the raw authority is checked too).
    out.hasNonAsciiHost = !out.isIp &&
      (/[^\x00-\x7f]/.test(out.hostUnicode) || /[^\x00-\x7f]/.test(out.rawHost));
    return out;
  }

  /** The URL's registrable "site" (sld + suffix), lowercase ASCII where possible. */
  function registrable(parts) {
    return parts.sld && parts.suffix ? parts.sld + "." + parts.suffix : parts.sld;
  }

  const api = { parseUrl, splitHost, toUnicodeHost, punyDecode, registrable, isLocalHost };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhishUrl = api;
})(typeof self !== "undefined" ? self : this);
