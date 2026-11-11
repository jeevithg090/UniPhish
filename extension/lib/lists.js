// Threat-intel reference lists, on-device (port of uniphish/assets/lists.py).
//
// Why: TLD risk, "living-off-trusted-sites" hosts, shorteners, dynamic-DNS zones, popular
// sites and the multilingual lure vocabulary are data, not code.  They are generated from
// uniphish/assets by tools/build_data.py into data/lists.json and wrapped here with the same
// semantics as the Python accessors:
//   * suffix matching is label-boundary safe ("pages.dev" matches "x.pages.dev" and
//     "pages.dev" but never "evilpages.dev");
//   * a LOTS match means the caller must NOT grant reputation / top-site credit;
//   * every function is total on hostile input.

(function (global) {
  "use strict";

  const MAX_HOST = 253;
  const MAX_TEXT = 4096;

  function suffixes(host) {
    const out = [];
    let h = host;
    for (;;) {
      out.push(h);
      const i = h.indexOf(".");
      if (i < 0) break;
      h = h.slice(i + 1);
    }
    return out;
  }

  function stripAccents(s) {
    return s.normalize("NFD").replace(/\p{M}+/gu, "");
  }

  function createLists(data) {
    const d = data || {};
    const tld = new Map(Object.entries(d.tld || {}));
    const shorteners = new Set((d.short || []).map((x) => x.toLowerCase()));
    const dyn = new Set((d.dyn || []).map((x) => x.toLowerCase()));
    const top = new Map();
    (d.top || []).forEach((dom, i) => { if (!top.has(dom)) top.set(dom, i + 1); });
    const psl = {};
    for (const [k, v] of Object.entries(d.psl || {})) psl[k] = new Set(v);
    const contextWords = new Set(d.ctx || []);
    const lots = new Map();
    for (const row of d.lots || []) {
      const [match, kind, name, path] = row;
      const key = match.toLowerCase();
      if (!lots.has(key)) lots.set(key, []);
      lots.get(key).push({ match: key, kind, name, path: path || "" });
    }
    const lureTok = new Map(Object.entries((d.lure && d.lure.tok) || {}));
    const lureSub = Object.entries((d.lure && d.lure.sub) || {});

    function matchSuffix(set, host) {
      if (!host || host.length > MAX_HOST) return null;
      for (const s of suffixes(host)) if (set.has(s)) return s;
      return null;
    }

    return {
      psl,
      contextWords,
      /** Log-odds risk for a TLD / suffix (final label only), or null. */
      tldRisk(suffix) {
        if (!suffix) return null;
        const last = String(suffix).toLowerCase().replace(/^\./, "").split(".").pop();
        return tld.has(last) ? tld.get(last) : null;
      },
      /** {match, kind, name} for an abused trusted platform, longest suffix wins. */
      lotsMatch(host, path) {
        if (!host || host.length > MAX_HOST) return null;
        const p = path || "/";
        for (const s of suffixes(host)) {
          const entries = lots.get(s);
          if (!entries) continue;
          for (const e of entries) {
            if (!e.path) return e;
            const pre = e.path.endsWith("/") ? e.path : e.path + "/";
            if (p === e.path || p.startsWith(pre)) return e;
          }
        }
        return null;
      },
      isShortener(host) { return matchSuffix(shorteners, host) !== null; },
      isDyndns(host) { return matchSuffix(dyn, host) !== null; },
      /** Rank (1..10000) in the bundled top list, or null. Caller supplies the registrable domain. */
      topRank(registrable) { return (registrable && top.get(registrable)) || null; },
      /** Lure-vocabulary hits in `text` (host labels / path), de-duplicated, strongest first. */
      lures(text) {
        const t = String(text || "").slice(0, MAX_TEXT).toLowerCase();
        if (!t) return [];
        const hits = new Map();
        const consider = (tok) => {
          if (!tok) return;
          for (const key of tok === stripAccents(tok) ? [tok] : [tok, stripAccents(tok)]) {
            const w = lureTok.get(key);
            if (w !== undefined && !hits.has(key)) hits.set(key, w);
          }
        };
        for (const tok of t.split(/[^\p{L}\p{N}-]+/u).slice(0, 256)) {
          consider(tok);
          if (tok.includes("-")) for (const piece of tok.split("-")) consider(piece);
        }
        for (const [term, w] of lureSub) if (t.includes(term) && !hits.has(term)) hits.set(term, w);
        return [...hits.entries()].map(([term, weight]) => ({ term, weight }))
          .sort((a, b) => b.weight - a.weight);
      },
    };
  }

  const api = { createLists, suffixes };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhishLists = api;
})(typeof self !== "undefined" ? self : this);
