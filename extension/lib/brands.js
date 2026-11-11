// Brand impersonation detection, on-device (port of uniphish/url/brands.py).
//
// Answers the most actionable phishing question: *which brand does this URL pretend to be,
// and by what trick?*  The bundled brand list (data/brands.json, generated from
// uniphish/assets/brands.yaml) supplies official domains, user-content domains and folded
// keyword terms; the confusables skeleton supplies look-alike folding.
//
// Techniques (candidate.technique): official, homoglyph, idn, bitsquat, typosquat,
// combosquat, subdomain, path.  Confidences are hand-set priors per evidence type (same
// values as the Python implementation), not fitted probabilities; the fusion layer scales
// signal weight by confidence.  False-positive guards: official/CDN hosts and a brand's own
// user-content hosts are never flagged for that brand; sites in the bundled top-10k list that
// are not shared hosting are exempt from the fuzzy techniques (applebees.com).

(function (global) {
  "use strict";

  const MAX_TOKENS = 64;
  const MAX_LABEL = 63;
  const MAX_PATH = 2048;
  const POPULAR_RANK = 10000; // bundled list is the top 10k (Python uses 20k)
  const TECH_PRIORITY = { homoglyph: 0, idn: 1, bitsquat: 2, typosquat: 3, subdomain: 4, combosquat: 5, path: 6 };

  const fold = (s) => String(s).toLowerCase().replace(/[^a-z0-9]/g, "");
  const stripMarks = (s) => s.normalize("NFD").replace(/\p{M}/gu, "");

  // Scratch rows for osa(): strings here are <= 40 chars, so no per-call allocation is needed.
  const ROW = 64;
  const rows = [new Int32Array(ROW), new Int32Array(ROW), new Int32Array(ROW)];

  /** Optimal-string-alignment distance, or k+1 when it exceeds k. */
  function osa(a, b, k) {
    const n = a.length, m = b.length;
    if (Math.abs(n - m) > k) return k + 1;
    if (n >= ROW || m >= ROW) return k + 1;
    let prev2 = rows[0], prev = rows[1], cur = rows[2];
    for (let j = 0; j <= m; j++) prev[j] = j;
    for (let i = 1; i <= n; i++) {
      cur[0] = i;
      let rowMin = i;
      const ai = a.charCodeAt(i - 1);
      for (let j = 1; j <= m; j++) {
        const cost = ai === b.charCodeAt(j - 1) ? 0 : 1;
        let v = prev[j] + 1;
        const ins = cur[j - 1] + 1; if (ins < v) v = ins;
        const sub = prev[j - 1] + cost; if (sub < v) v = sub;
        if (i > 1 && j > 1 && ai === b.charCodeAt(j - 2) && a.charCodeAt(i - 2) === b.charCodeAt(j - 1)) {
          const tr = prev2[j - 2] + 1; if (tr < v) v = tr;
        }
        cur[j] = v;
        if (v < rowMin) rowMin = v;
      }
      if (rowMin > k) return k + 1;
      const t = prev2; prev2 = prev; prev = cur; cur = t;
    }
    return prev[m];
  }

  /** 37-bucket character histogram ([a-z0-9] + other). One edit moves the L1 distance by <= 2. */
  function bagOf(str) {
    const bag = new Uint8Array(37);
    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);
      const idx = c >= 97 && c <= 122 ? c - 97 : c >= 48 && c <= 57 ? 26 + c - 48 : 36;
      if (bag[idx] < 255) bag[idx]++;
    }
    return bag;
  }
  function bagDist(x, y) {
    let d = 0;
    for (let i = 0; i < 37; i++) d += x[i] > y[i] ? x[i] - y[i] : y[i] - x[i];
    return d;
  }

  function isBitflip(a, b) {
    if (a.length !== b.length) return false;
    let diffs = 0, x = 0;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) { diffs++; x = a.charCodeAt(i) ^ b.charCodeAt(i); }
    }
    return diffs === 1 && (x & (x - 1)) === 0;
  }

  /**
   * @param {{brands: Array}} brandData  data/brands.json
   * @param {object} lists               createLists(...) result
   * @param {object} conf                createConfusables(...) result
   * @param {object} urlLib              lib/urlparse.js exports (for splitHost)
   */
  function createBrandMatcher(brandData, lists, conf, urlLib) {
    const brands = (brandData && brandData.brands) || [];
    const byId = new Map();
    const officialMap = new Map(); // official registrable-ish domain -> brand
    const hostMap = new Map();     // login / CDN hosts outside official domains -> brand
    const ucMap = new Map();       // user-content domain -> owner brand
    const nativeNames = [];

    for (const b of brands) {
      byId.set(b.i, b);
      for (const d of b.d || []) officialMap.set(d.toLowerCase(), b);
      for (const h of b.h || []) hostMap.set(h.toLowerCase(), b);
      for (const u of b.u || []) ucMap.set(u.toLowerCase(), b);
      for (const x of b.x || []) nativeNames.push([x.normalize("NFKC").toLowerCase(), b]);
    }
    nativeNames.sort((a, b) => b[0].length - a[0].length);

    const lookup = (map, host) => {
      let h = host;
      for (;;) {
        const hit = map.get(h);
        if (hit) return hit;
        const i = h.indexOf(".");
        if (i < 0) return null;
        h = h.slice(i + 1);
      }
    };

    function userContentOwner(host) { return host ? lookup(ucMap, host) : null; }

    /** {brand, cdn} when `host` is an official / login / CDN host of a brand. */
    function officialFor(host) {
      if (!host) return null;
      if (userContentOwner(host)) return null;
      const b = lookup(officialMap, host);
      if (b) return { brand: b, cdn: false };
      const c = lookup(hostMap, host);
      return c ? { brand: c, cdn: true } : null;
    }

    // ---- term index ------------------------------------------------------------------
    const acc = new Map();
    function add(b, text, kw, suffix) {
      if (!text || text.length > 40 || text.length < (kw ? 4 : 5) || !/^[a-z0-9]+$/.test(text)) return;
      const key = b.i + "\u0000" + text;
      let slot = acc.get(key);
      if (!slot) { slot = { brand: b, text, kw: false, suffixes: new Set() }; acc.set(key, slot); }
      slot.kw = slot.kw || kw;
      if (suffix) slot.suffixes.add(suffix);
    }
    for (const b of brands) {
      for (const t of b.t || []) add(b, fold(t), true);
      for (const d of b.d || []) {
        const p = urlLib.splitHost(d.toLowerCase(), lists.psl);
        if (p.sld && p.suffix && p.sub.length === 0) add(b, fold(p.sld), false, p.suffix);
      }
    }
    const exact = new Map(), exactSkel = new Map(), bySkel = new Map(), byLen = new Map();
    const affix = [];
    const allTexts = new Set();
    const topSkeletons = new Set();
    const push = (m, k, v) => { const a = m.get(k); if (a) a.push(v); else m.set(k, [v]); };
    for (const slot of acc.values()) {
      const t = { brand: slot.brand, text: slot.text, kw: slot.kw, suffixes: slot.suffixes,
                  skel: conf.brandSkeleton(slot.text) };
      t.bag = bagOf(t.skel);
      push(bySkel, t.skel, t);
      allTexts.add(t.text);
      if (t.kw) { push(exact, t.text, t); push(exactSkel, t.skel, t); }
      if (t.text.length >= 5 && (t.kw || t.text.length >= 6)) push(byLen, t.skel.length, t);
      if (t.kw && t.text.length >= 5) affix.push(t);
      if (!t.kw && t.text.length >= 5) topSkeletons.add(t.skel);
      if (t.kw && t.text.length >= 5) topSkeletons.add(t.skel);
    }

    function hasContext(text) {
      const low = String(text).toLowerCase().slice(0, 2000);
      const toks = low.match(/[a-z0-9]+/g) || [];
      for (let i = 0; i < toks.length && i < MAX_TOKENS * 4; i++) if (lists.contextWords.has(toks[i])) return true;
      return lists.lures(low).length > 0;
    }

    // ---- token scanning ------------------------------------------------------------------
    function scan(text, concat, useFold) {
      const src = useFold ? conf.brandSkeleton(String(text).slice(0, 2000)) : String(text);
      const toks = (src.toLowerCase().match(/[a-z0-9]+/g) || []).slice(0, MAX_TOKENS);
      const table = useFold ? exactSkel : exact;
      const best = new Map();
      const rec = (h) => {
        const cur = best.get(h.term.brand.i);
        if (!cur || (h.mode === "token" && cur.mode !== "token") ||
            (h.term.text.length > cur.term.text.length && h.mode === cur.mode)) best.set(h.term.brand.i, h);
      };
      const n = toks.length;
      for (let i = 0; i < n; i++) {
        let accTok = "";
        for (let j = i; j < Math.min(i + 3, n); j++) {
          accTok += toks[j];
          for (const t of table.get(accTok) || []) rec({ term: t, mode: "token", extra: n - (j - i + 1), remainder: "" });
        }
      }
      if (concat) {
        for (const tok of toks) {
          if (tok.length < 5 || tok.length > MAX_LABEL) continue;
          for (const t of affix) {
            const key = useFold ? t.skel : t.text;
            const pos = tok.indexOf(key);
            if (pos < 0 || tok === key) continue;
            const atEdge = pos === 0 || pos + key.length === tok.length;
            if (!atEdge && key.length < 6) continue;
            const rem = tok.slice(0, pos) + tok.slice(pos + key.length);
            rec({ term: t, mode: "affix", extra: rem.length, remainder: rem });
          }
        }
      }
      return [...best.values()];
    }

    const mk = (b, technique, conf0, evidence, meta) => ({
      brand: b.i, name: b.n, technique,
      confidence: Math.round(Math.max(0, Math.min(0.99, conf0)) * 100) / 100,
      legit: (b.d || []).slice(0, 8), evidence, official: false, meta: meta || {},
    });
    const adjust = (c, t, bonus) => {
      if (t.text.length <= 4) c -= 0.1;
      if (t.brand.a) c = Math.min(c, 0.6);
      return c + (bonus || 0);
    };
    const realSub = (b, dotted) => (b.d || []).some((d) => dotted.includes("." + d + "."));

    function idnCandidates(p, parts, excl) {
      const out = [];
      const punycode = p.input.toLowerCase().includes("xn--");
      const how = punycode ? "punycode host decoding to" : "non-ASCII host";
      for (const label of [...parts.sub, parts.sld]) {
        if (!label || !/[^\x00-\x7f]/.test(label)) continue;
        const sk = stripMarks(conf.brandSkeleton(label));
        const done = new Set();
        for (const v of new Set([sk, sk.replace(/-/g, "")])) {
          for (const t of bySkel.get(v) || []) {
            if (excl.has(t.brand.i) || done.has(t.brand.i) || v !== t.skel) continue;
            done.add(t.brand.i);
            out.push(mk(t.brand, "homoglyph", t.brand.a ? 0.8 : 0.97,
              `${how} '${label}', which renders as '${t.text}' (confusable skeleton '${v}')`,
              { label, term: t.text }));
          }
        }
        if (done.size) continue;
        for (const h of scan(sk, true, false)) {
          const t = h.term;
          if (excl.has(t.brand.i) || done.has(t.brand.i)) continue;
          if ((t.brand.a || t.text.length <= 4) && !hasContext(sk)) continue;
          done.add(t.brand.i);
          out.push(mk(t.brand, "idn", adjust(h.mode === "token" ? 0.85 : 0.78, t),
            `${how} '${label}', which contains '${t.text}' after folding look-alike characters`,
            { label, term: t.text }));
        }
        if (done.size) continue;
        const flat = sk.replace(/-/g, "");
        const flatBag = bagOf(flat);
        for (let ln = flat.length - 1; ln <= flat.length + 1; ln++) {
          for (const t of byLen.get(ln) || []) {
            if (excl.has(t.brand.i) || t.brand.a || done.has(t.brand.i)) continue;
            if (bagDist(flatBag, t.bag) > 2) continue;
            if (osa(flat, t.skel, 1) <= 1) {
              done.add(t.brand.i);
              out.push(mk(t.brand, "idn", 0.75, `${how} '${label}', one edit away from '${t.text}'`,
                { label, term: t.text }));
            }
          }
        }
      }
      const folded = p.hostUnicode.normalize("NFKC").toLowerCase();
      for (const [native, b] of nativeNames) {
        if (!excl.has(b.i) && folded.includes(native) && !out.some((m) => m.brand === b.i)) {
          out.push(mk(b, "idn", 0.7, `host contains ${b.n}'s native-script name '${native}' on an unrelated domain`,
            { label: native, term: native }));
        }
      }
      return out;
    }

    function typoCandidates(label, suffix, excl, isSld, tldBonus) {
      const out = [];
      const variants = [[label, ""]];
      if (label.includes("-")) variants.unshift([label.replace(/-/g, ""), "hyphen"]);
      const seen = new Set();
      for (const [v, tag] of variants) {
        if (/[^\x00-\x7f]/.test(v) || v.length < 4 || v.length > 40) continue;
        if (allTexts.has(v) && !tag) {
          if (!isSld) continue;
          for (const t of exact.get(v) || []) {
            const b = t.brand;
            if (excl.has(b.i) || seen.has(b.i) || b.a || v.length < 5) continue;
            seen.add(b.i);
            out.push(mk(b, "typosquat", 0.45 + (tldBonus ? 0.2 : 0),
              `'${v}' is ${b.n}'s name on an unrelated domain (.${suffix || "?"} instead of its official domains)`,
              { term: v, kind: "tld_swap" }));
          }
          continue;
        }
        const sk = conf.brandSkeleton(v);
        if (sk.length < 5) continue;
        for (const t of bySkel.get(sk) || []) {
          const b = t.brand;
          if (excl.has(b.i) || seen.has(b.i) || b.a || t.text.length < 5) continue;
          if (v === t.text && !tag) continue;
          seen.add(b.i);
          if (tag) {
            out.push(mk(b, "typosquat", 0.8 + tldBonus, `'${label}' is '${t.text}' split by a hyphen`,
              { term: t.text, kind: "hyphen" }));
          } else {
            out.push(mk(b, "typosquat", 0.9 + tldBonus,
              `'${v}' reads as '${t.text}' once look-alike letters/digits are folded`,
              { term: t.text, kind: "fold" }));
          }
        }
        if (allTexts.has(v)) continue;
        const skBag = bagOf(sk);
        for (let ln = sk.length - 2; ln <= sk.length + 2; ln++) {
          for (const t of byLen.get(ln) || []) {
            const b = t.brand;
            if (excl.has(b.i) || seen.has(b.i) || b.a) continue;
            const k = t.skel.length >= 9 ? 2 : 1;
            if (bagDist(skBag, t.bag) > 2 * k) continue;
            const d = osa(sk, t.skel, k);
            if (d > k) continue;
            seen.add(b.i);
            if (d === 1 && t.suffixes.has(suffix) && isBitflip(v, t.text)) {
              out.push(mk(b, "bitsquat", 0.85 + tldBonus,
                `'${v}.${suffix}' differs from ${t.text}.${suffix} by a single flipped bit`, { term: t.text }));
            } else {
              out.push(mk(b, "typosquat", (d === 1 ? 0.8 : 0.65) + tldBonus,
                `'${v}' is ${d} edit${d > 1 ? "s" : ""} away from '${t.text}'`, { term: t.text, distance: d, kind: "edit" }));
            }
          }
        }
      }
      return out;
    }

    function dedupe(cands) {
      const best = new Map();
      for (const c of cands) {
        const key = c.brand + "|" + c.technique;
        const cur = best.get(key);
        if (!cur || c.confidence > cur.confidence) best.set(key, c);
      }
      return [...best.values()].sort((a, b) =>
        (b.confidence - a.confidence) || ((TECH_PRIORITY[a.technique] ?? 9) - (TECH_PRIORITY[b.technique] ?? 9)) ||
        (a.brand < b.brand ? -1 : a.brand > b.brand ? 1 : 0));
    }

    /**
     * All brand-impersonation hypotheses for a parsed URL, strongest first. Returns
     * [official] for official/login/CDN hosts.
     * @param {object} p      parseUrl() result
     * @param {object} parts  splitHost() result
     * @param {object} ctx    {lots, rank, risk} precomputed by the caller (rules.js)
     */
    function candidates(p, parts, ctx) {
      const host = p.host;
      if (!host) return [];
      if (!p.isIp) {
        const off = officialFor(host);
        if (off) {
          const what = off.cdn ? "asset CDN host" : "official host";
          return [{ brand: off.brand.i, name: off.brand.n, technique: "official", confidence: 0.99,
            legit: (off.brand.d || []).slice(0, 8), official: true, meta: {},
            evidence: `${host} is an ${what} of ${off.brand.n}` }];
        }
      }
      const owner = !p.isIp ? userContentOwner(host) : null;
      const lots = ctx.lots;
      const platform = !!(owner || lots);
      const excl = new Set(owner ? [owner.i] : []);
      const popular = !platform && ctx.rank != null && ctx.rank <= POPULAR_RANK;
      const bonus = (ctx.risk || 0) >= 0.8 ? 0.04 : 0;
      const pathText = safeDecode(p.path.slice(0, MAX_PATH)).toLowerCase();
      const hostText = parts.sld ? [...parts.sub, parts.sld].join(".") : "";
      const ctxWord = hasContext(hostText + " " + pathText);
      const cands = [];
      const reg = parts.sld && parts.suffix ? parts.sld + "." + parts.suffix : host;

      if (parts.sld && !p.isIp) {
        if (p.hasNonAsciiHost) cands.push(...idnCandidates(p, parts, excl));
        const asciiSub = parts.sub.filter((x) => !/[^\x00-\x7f]/.test(x)).join(" ");
        const scans = [["sub", asciiSub], [platform ? "sub" : "sld", /[^\x00-\x7f]/.test(parts.sld) ? "" : parts.sld]];
        const dotted = "." + parts.sub.join(".") + ".";
        for (const [where, text] of scans) {
          if (!text) continue;
          let hits = scan(text, true, false);
          const known = new Set(hits.map((h) => h.term.brand.i));
          hits = hits.concat(scan(text, true, true).filter((h) => !known.has(h.term.brand.i)));
          for (const h of hits) {
            const t = h.term, b = t.brand;
            if (excl.has(b.i)) continue;
            if ((b.a || t.text.length <= 4) && !ctxWord) continue;
            if (where === "sub") {
              let conf0, ev;
              // The brand's real domain spelled out in the sub-domain is the classic AiTM /
              // phishing-kit pattern (login.microsoftonline.com.evil.test): strongest evidence.
              const real = (b.d || []).some((d) => dotted.includes("." + d + "."));
              if (real) {
                conf0 = 0.95;
                ev = `${b.n}'s real domain is spelled out inside the sub-domain of ${reg}`;
              } else if (h.mode === "token") {
                conf0 = ctxWord ? 0.85 : 0.8;
                ev = `'${t.text}' appears as a sub-domain label of ${reg}, which is not a ${b.n} domain`;
              } else {
                conf0 = hasContext(h.remainder) ? 0.75 : 0.7;
                ev = `sub-domain contains '${t.text}' glued to '${h.remainder}' on ${reg}`;
              }
              if (platform && !realSub(b, dotted)) ev += " (shared hosting platform: anyone can create this)";
              cands.push(mk(b, "subdomain", adjust(conf0, t, bonus), ev, { term: t.text, registrable: reg, real }));
              continue;
            }
            if (popular) continue;
            if (h.mode === "token" && h.extra === 0) {
              if (b.a || t.text.length < 5) continue;
              cands.push(mk(b, "typosquat", 0.45 + (bonus ? 0.2 : 0),
                `'${t.text}' is ${b.n}'s name on an unrelated domain (.${parts.suffix || "?"})`,
                { term: t.text, kind: "tld_swap" }));
            } else if (h.mode === "token") {
              cands.push(mk(b, "combosquat", adjust(ctxWord ? 0.88 : 0.8, t, bonus),
                `'${parts.sld}' combines '${t.text}' with extra words on an unrelated domain`,
                { term: t.text, label: parts.sld }));
            } else {
              let c;
              if (hasContext(h.remainder)) c = 0.82;
              else if (/^\d+$/.test(h.remainder)) c = 0.7;
              else if (t.text.length >= 7) c = 0.55;
              else continue; // short brand + arbitrary text: too many real words
              cands.push(mk(b, "combosquat", adjust(c, t, bonus),
                `'${parts.sld}' embeds '${t.text}' plus '${h.remainder}'`, { term: t.text, label: parts.sld }));
            }
          }
        }
        if (!popular) {
          const targets = platform ? [...parts.sub, parts.sld] : [parts.sld];
          for (const lab of targets) cands.push(...typoCandidates(lab, parts.suffix, excl, lab === parts.sld, bonus));
        }
      }

      if (pathText && !popular) {
        for (const h of scan(pathText, false, false)) {
          const t = h.term, b = t.brand;
          if (excl.has(b.i) || ((b.a || t.text.length <= 4) && !ctxWord)) continue;
          let c = ctxWord ? 0.55 : 0.35;
          if (platform) c += 0.15;
          if ((b.d || []).some((d) => pathText.includes(d))) c += 0.15;
          c = Math.min(c, 0.75);
          cands.push(mk(b, "path", adjust(c, t, 0),
            `'${t.text}' appears in the path of ${host || "an IP address"}, which is not a ${b.n} domain`,
            { term: t.text }));
        }
      }
      return dedupe(cands);
    }

    return { candidates, officialFor, userContentOwner, topSkeletons, byId, hasContext, size: brands.length };
  }

  function safeDecode(s) {
    try { return decodeURIComponent(s); } catch (_) { return s; }
  }

  const api = { createBrandMatcher, osa, isBitflip };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhishBrands = api;
})(typeof self !== "undefined" ? self : this);
