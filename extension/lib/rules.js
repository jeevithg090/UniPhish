// On-device port of the key UniPhish URL rule signals (uniphish/analyzers/url.py).
//
// Why: the byte-level CNN alone is overconfident and cannot say *why* a link is dangerous.
// The Python platform fuses it with explainable rule evidence; this module ports the signals
// that matter most for links and keeps the same signal ids, categories and log-odds scale
// (+6..+8 decisive, +3..+5 strong, +1..+2 moderate, +0.2..+1 weak, -1..-4 legitimacy), so a
// verdict in the browser and one from the API read the same way.
//
// Ported: homoglyph / confusable / mixed-script / whole-script / invisible / bidi / combining /
// digit-lookalike hosts, punycode, '@' trick, IP and obfuscated-IP hosts, brand homoglyph /
// typosquat / bitsquat / combosquat / subdomain / path impersonation, shorteners, dynamic DNS,
// LOTS hosting, open-redirect parameters, abused TLDs, deep sub-domains, credential-lure words,
// dangerous file extensions, double encoding, dangerous schemes, plus legitimacy evidence
// (official brand host, top-ranked site).  Everything is pure and offline.
//
// Every signal carries `params`: the concrete specifics (offending characters, brand, host)
// that lib/i18n.js interpolates into a localised sentence, and an English `detail` fallback.

(function (global) {
  "use strict";

  const req = (name, globalName) =>
    (typeof module !== "undefined" && module.exports && typeof require === "function")
      ? require(name) : global[globalName];
  const UrlLib = req("./urlparse.js", "UniPhishUrl");
  const ListsLib = req("./lists.js", "UniPhishLists");
  const ConfLib = req("./confusables.js", "UniPhishConfusables");
  const BrandLib = req("./brands.js", "UniPhishBrands");

  // ---- weights (signed log-odds; identical to the Python analyzer) -------------------
  const BRAND_WEIGHT = { homoglyph: 4.5, idn: 4.0, bitsquat: 3.5, typosquat: 3.0,
    combosquat: 2.5, subdomain: 2.5, path: 1.5 };
  const OFFICIAL_WEIGHT = -3.0;
  const BRAND_SIGNAL_MIN = 0.35;
  const MAX_BRAND_SIGNALS = 6;
  const LURE_CAP = 2.0;
  const SUSPICIOUS_TLD_MIN = 0.5;
  const LONG_URL = 100;
  const MANY_HYPHENS = 4;
  const OPEN_REDIRECT_PARAM_WEIGHT = 1.2;

  const TITLES = {
    "brand.homoglyph": "Domain imitates a brand using look-alike characters",
    "brand.idn": "Internationalised domain imitates a brand",
    "brand.typosquat": "Domain is a typo-variant of a brand",
    "brand.bitsquat": "Domain differs from a brand by one flipped bit",
    "brand.combosquat": "Brand name combined with extra words in the domain",
    "brand.subdomain": "Brand name placed in a sub-domain of an unrelated site",
    "brand.path": "Brand name appears in the URL path of an unrelated site",
    "brand.official": "URL belongs to the brand's official domain",
    "unicode.skeleton_matches_top_domain": "Host is a look-alike of a popular domain",
    "unicode.whole_script_confusable": "A whole host label in another script reads as Latin",
    "unicode.mixed_script_host": "Host mixes characters from multiple writing systems",
    "unicode.confusable_host": "Host contains characters that imitate ASCII letters",
    "unicode.invisible_char": "Host contains invisible characters",
    "unicode.bidi_control": "Host contains bidirectional control characters",
    "unicode.dangerous_char": "Host contains characters that imitate URL delimiters",
    "unicode.combining_mark": "Host stacks combining marks on Latin letters",
    "unicode.digit_lookalike": "Host contains characters that imitate digits",
    "unicode.punycode_lookalike": "Punycode host decodes to a look-alike domain",
    "unicode.punycode": "Host uses punycode (xn--) encoding",
    "url.ip_host": "Link uses a raw IP address as the host",
    "url.ip_obfuscation": "IP address written in an obfuscated numeric form",
    "url.at_redirect": "Deceptive text before '@' in the URL",
    "url.shortener": "URL uses a link-shortening service",
    "url.dynamic_dns": "Host is on a dynamic-DNS service",
    "url.lots_hosting": "Hosted on a legitimate platform anyone can publish on",
    "url.open_redirect": "URL passes a redirect target to another site",
    "url.suspicious_tld": "Top-level domain is frequently abused for phishing",
    "url.many_subdomains": "Excessive sub-domain labels hide the real domain",
    "url.credential_lure_host": "Host contains sign-in / security lure words",
    "url.credential_lure_path": "Path contains sign-in / security lure words",
    "url.suspicious_file_ext": "Path points at a dangerous downloadable file",
    "url.double_extension": "File in the path uses a deceptive double extension",
    "url.dangerous_scheme": "URL uses a data:/javascript: scheme carrying inline content",
    "url.double_encoding": "URL uses double percent-encoding to hide content",
    "url.random_label": "Host label looks randomly generated",
    "url.non_standard_port": "Connection uses a non-standard port",
    "url.long_url": "Unusually long URL",
    "url.many_hyphens": "Unusually many hyphens in the host",
    "rep.top_site": "Host is a very popular, well-known site",
    "rep.user_allowlist": "You marked this site as trusted",
    "ml.cnn.phishing": "On-device model rates this URL as likely phishing",
    "ml.cnn.benign": "On-device model finds this URL looks legitimate",
  };

  // signal id -> attack technique (subset of uniphish/url/techniques.py TAXONOMY)
  const TECHNIQUE_OF = {
    "brand.homoglyph": "homoglyph", "brand.idn": "idn_homograph", "brand.typosquat": "typosquat",
    "brand.bitsquat": "typosquat", "brand.combosquat": "combosquat",
    "brand.subdomain": "subdomain_stuffing", "brand.path": "path_deception",
    "unicode.skeleton_matches_top_domain": "idn_homograph", "unicode.whole_script_confusable": "idn_homograph",
    "unicode.mixed_script_host": "idn_homograph", "unicode.confusable_host": "homoglyph",
    "unicode.punycode_lookalike": "idn_homograph", "unicode.punycode": "punycode",
    "url.ip_host": "ip_host", "url.ip_obfuscation": "ip_obfuscation", "url.at_redirect": "at_redirect",
    "url.shortener": "url_shortener", "url.dynamic_dns": "dynamic_dns", "url.lots_hosting": "lots_hosting",
    "url.open_redirect": "open_redirect_abuse", "url.suspicious_tld": "suspicious_tld",
    "url.many_subdomains": "excessive_subdomains", "url.dangerous_scheme": "data_uri",
    "url.credential_lure_path": "credential_path",
  };

  // ---- Unicode helpers ---------------------------------------------------------------
  const SCRIPT_NAMES = ["Latin", "Cyrillic", "Greek", "Armenian", "Hebrew", "Arabic", "Devanagari",
    "Bengali", "Gurmukhi", "Gujarati", "Tamil", "Telugu", "Kannada", "Malayalam", "Sinhala", "Thai",
    "Lao", "Tibetan", "Georgian", "Ethiopic", "Khmer", "Myanmar", "Mongolian", "Han", "Hiragana",
    "Katakana", "Hangul", "Bopomofo", "Cherokee", "Coptic", "Thaana", "Syriac"];
  const SCRIPT_RX = SCRIPT_NAMES.map((n) => [n, new RegExp("\\p{Script_Extensions=" + n + "}", "u")]);
  const ISO = { Latin: "Latn", Cyrillic: "Cyrl", Greek: "Grek", Armenian: "Armn", Hebrew: "Hebr", Arabic: "Arab",
    Devanagari: "Deva", Bengali: "Beng", Gurmukhi: "Guru", Gujarati: "Gujr", Tamil: "Taml", Telugu: "Telu",
    Kannada: "Knda", Malayalam: "Mlym", Sinhala: "Sinh", Thai: "Thai", Lao: "Laoo", Tibetan: "Tibt",
    Georgian: "Geor", Ethiopic: "Ethi", Khmer: "Khmr", Myanmar: "Mymr", Mongolian: "Mong", Han: "Hani",
    Hiragana: "Hira", Katakana: "Kana", Hangul: "Hang", Bopomofo: "Bopo", Cherokee: "Cher", Coptic: "Copt",
    Thaana: "Thaa", Syriac: "Syrc" };
  const CJK_OK = [["Latin", "Han", "Hiragana", "Katakana"], ["Latin", "Han", "Bopomofo"], ["Latin", "Han", "Hangul"]];
  // Scripts whose country TLDs make an all-that-script label legitimate.
  const NATIVE_TLDS = {
    Cyrillic: new Set(["ru", "su", "ua", "by", "bg", "kz", "mk", "rs", "mn", "kg", "tj", "uz", "xn--p1ai", "xn--j1amh", "xn--90a3ac", "xn--80asehdb", "xn--d1acj3b", "рф", "укр", "срб", "бг", "мкд"]),
    Greek: new Set(["gr", "cy", "xn--qxam", "ελ"]),
    Armenian: new Set(["am", "xn--y9a3aq", "հայ"]),
  };
  const INVISIBLE_RX = /[\u00ad\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180e\u200b\u2060-\u2064\u3164\ufe00-\ufe0f\ufeff\uffa0]|[\u{e0000}-\u{e0fff}]/u;
  const BIDI_RX = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/;
  const DANGEROUS_RX = /[⁄∕⧸／․‧ꓸː∶꞉։׃ǃ﹒：︓]/;

  function scriptsOfChar(ch) {
    if (/[A-Za-z]/.test(ch)) return ["Latin"];
    if (/[0-9\-]/.test(ch)) return null;
    const hit = [];
    for (const [name, rx] of SCRIPT_RX) if (rx.test(ch)) hit.push(name);
    return hit.length ? hit : null;
  }

  /** {resolved: [scripts], union: Set} for one label. Resolved empty + union>1 = mixed. */
  function labelScripts(label) {
    let resolved = null;
    const union = new Set();
    for (const ch of label) {
      const s = scriptsOfChar(ch);
      if (!s) continue;
      s.forEach((x) => union.add(x));
      resolved = resolved === null ? s.slice() : resolved.filter((x) => s.includes(x));
    }
    return { resolved: resolved || [], union };
  }

  /** {char, like, script(ISO)} for the first look-alike character in `text`, or {}. */
  function firstConfusable(conf, text) {
    const c = conf.confusableChars(text.normalize("NFC"))[0];
    if (!c) return {};
    const sc = scriptsOfChar(c.char);
    return { char: c.char, like: c.like, cp: "U+" + c.char.codePointAt(0).toString(16).toUpperCase().padStart(4, "0"), script: sc ? ISO[sc[0]] || "" : "" };
  }

  function isMixedLabel(label) {
    const { resolved, union } = labelScripts(label);
    if (resolved.length > 0 || union.size <= 1) return false;
    const names = [...union];
    return !CJK_OK.some((ok) => names.every((n) => ok.includes(n)));
  }

  const SUSPICIOUS_EXT = new Set(["exe", "scr", "bat", "cmd", "com", "pif", "msi", "msp", "dll", "js", "jse",
    "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "psm1", "lnk", "iso", "img", "vhd", "vhdx", "jar", "apk",
    "dmg", "pkg", "reg", "cpl", "docm", "xlsm", "pptm", "xlam", "appx", "msix"]);
  const DOC_EXT = new Set(["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "rtf", "csv", "html", "htm"]);
  const REDIRECT_PARAMS = new Set(["url", "u", "redirect", "redirect_url", "redirect_uri", "redirecturl",
    "return", "returnurl", "return_url", "return_to", "returnto", "next", "dest", "destination", "goto",
    "target", "link", "out", "continue", "to", "r", "q", "forward", "location", "redir", "ref_url", "service"]);

  const sig = (id, weight, category, detail, params, extra) => Object.assign({
    id, title: TITLES[id] || id, detail, weight, confidence: 1, category, span: null,
    params: params || {}, evidence: {},
  }, extra || {});

  function findSpan(hay, needle) {
    if (!needle) return null;
    let i = hay.indexOf(needle);
    if (i < 0) i = hay.toLowerCase().indexOf(needle.toLowerCase());
    return i >= 0 ? [i, i + needle.length] : null;
  }

  /**
   * Build a rule analyser from the loaded data bundle.
   * @param {{brands: object, lists: object, confusables: object}} data
   */
  function createRules(data) {
    const lists = ListsLib.createLists(data.lists);
    const conf = ConfLib.createConfusables(data.confusables);
    const matcher = BrandLib.createBrandMatcher(data.brands, lists, conf, UrlLib);

    function brandSpan(p, parts, cand) {
      const input = p.input;
      switch (cand.technique) {
        case "homoglyph": case "idn": {
          const label = cand.meta.label;
          return (label && findSpan(input, label)) || p.hostSpan;
        }
        case "typosquat": case "combosquat": case "bitsquat":
          return findSpan(input, parts.sld) || p.hostSpan;
        case "subdomain":
          return (parts.sub.length && findSpan(input, parts.sub.join("."))) || p.hostSpan;
        case "path": {
          const base = p.hostSpan ? p.hostSpan[1] : 0;
          const sp = cand.meta.term ? findSpan(input.slice(base), cand.meta.term) : null;
          return sp ? [base + sp[0], base + sp[1]] : null;
        }
        default: return p.hostSpan;
      }
    }

    function brandSignals(p, parts, cands) {
      if (!cands.length) return { signals: [], best: null };
      const best = cands[0];
      if (best.official) {
        return {
          signals: [sig("brand.official", OFFICIAL_WEIGHT, "brand", best.evidence + ".",
            { brand: best.name, host: p.host }, { confidence: best.confidence, span: p.hostSpan,
              title: `URL belongs to ${best.name}'s official domain`.slice(0, 70) })],
          best,
        };
      }
      const out = [];
      for (const c of cands) {
        if (c.official || c.confidence < BRAND_SIGNAL_MIN) continue;
        const id = "brand." + c.technique;
        if (!TITLES[id]) continue;
        out.push(sig(id, BRAND_WEIGHT[c.technique] || 2.0, "brand", `${c.name}: ${c.evidence}.`,
          Object.assign({ brand: c.name }, c.meta, { host: p.host, legit: c.legit.slice(0, 3).join(", ") },
            (c.technique === "homoglyph" || c.technique === "idn") && c.meta.label ? firstConfusable(conf, c.meta.label) : {}),
          { confidence: c.confidence, span: brandSpan(p, parts, c), evidence: { brand: c.brand, technique: c.technique },
            title: `${TITLES[id]} (${c.name})`.slice(0, 70) }));
        if (out.length >= MAX_BRAND_SIGNALS) break;
      }
      return { signals: out, best: best.confidence >= 0.3 ? best : null };
    }

    function hostCharSpan(p, conflist) {
      if (!p.hostSpan) return null;
      const shown = p.input.slice(p.hostSpan[0], p.hostSpan[1]);
      if (conflist.length && shown.toLowerCase() === p.hostUnicode) {
        return [p.hostSpan[0] + conflist[0].index, p.hostSpan[0] + conflist[conflist.length - 1].index + conflist[conflist.length - 1].char.length];
      }
      return p.hostSpan;
    }

    function unicodeSignals(p, parts) {
      if (p.isIp || !p.hostUnicode || !p.hasNonAsciiHost) return [];
      const text = p.hostUnicode.normalize("NFC");
      const raw = p.rawHost || "";
      const labels = text.split(".");
      const tld = labels[labels.length - 1] || "";
      const reasons = new Set();
      const scriptsSeen = new Set();

      for (const label of labels) {
        const { union } = labelScripts(label);
        union.forEach((s) => scriptsSeen.add(s));
        if (isMixedLabel(label)) reasons.add("mixed_script");
        // A label written entirely in a script under that script's own country TLD
        // (банк.рф, ελ) is how real sites there are named: never "confusable" by itself.
        const script = labelScripts(label).resolved[0];
        const native = !!(script && NATIVE_TLDS[script] && NATIVE_TLDS[script].has(tld));
        // whole-script confusable: no ASCII letters, every letter has an ASCII prototype
        if (label && !native && !/[A-Za-z]/.test(label) && /[^\x00-\x7f]/.test(label)) {
          const sk = conf.skeleton(label);
          if (script && script !== "Latin" && /^[\x21-\x7e]+$/.test(sk) && /[a-z]/i.test(sk) && label.length >= 2) {
            reasons.add("whole_script_confusable");
            reasons.add("_whole:" + script);
          }
        }
        if (!native && conf.confusableChars(label).some((c) => /^[0-9]$/.test(c.like) && !/\p{Nd}/u.test(c.char))) {
          reasons.add("digit_lookalike");
        }
        if (/[A-Za-z]\p{M}/u.test(label) || /\p{M}{2,}/u.test(label)) reasons.add("combining_mark_on_latin");
      }
      if (INVISIBLE_RX.test(text) || INVISIBLE_RX.test(raw)) reasons.add("invisible_char");
      if (BIDI_RX.test(text) || BIDI_RX.test(raw)) reasons.add("bidi_control");
      if (DANGEROUS_RX.test(text) || DANGEROUS_RX.test(raw)) reasons.add("dangerous_char");

      const confs = conf.confusableChars(text);

      if (parts.sld && /[^\x00-\x7f]/.test(parts.sld)) {
        const sk = conf.brandSkeleton(parts.sld.normalize("NFD").replace(/\p{M}/gu, ""));
        if (sk.length >= 5 && matcher.topSkeletons.has(sk)) reasons.add("skeleton_matches_top_domain");
      }

      const spoofReasons = [...reasons].filter((r) => !r.startsWith("_"));
      const isSpoof = spoofReasons.length > 0;
      const confSpan = hostCharSpan(p, confs);
      const hostSpan = confSpan || p.hostSpan;
      const scripts = [...scriptsSeen].map((n) => ISO[n] || n).join(",");
      const first = firstConfusable(conf, text);
      const out = [];
      const map = {
        skeleton_matches_top_domain: ["unicode.skeleton_matches_top_domain", 3.5],
        whole_script_confusable: ["unicode.whole_script_confusable", 3.5],
        mixed_script: ["unicode.mixed_script_host", 2.0],
        invisible_char: ["unicode.invisible_char", 3.0],
        bidi_control: ["unicode.bidi_control", 3.0],
        dangerous_char: ["unicode.dangerous_char", 3.0],
        combining_mark_on_latin: ["unicode.combining_mark", 2.0],
        digit_lookalike: ["unicode.digit_lookalike", 2.0],
      };
      const why = {
        skeleton_matches_top_domain: "its skeleton matches a popular domain",
        whole_script_confusable: "a whole label in another script reads as Latin",
        mixed_script: "it mixes characters from multiple writing systems",
        invisible_char: "it hides invisible (zero-width) characters",
        bidi_control: "it embeds bidirectional-override control characters",
        dangerous_char: "it uses characters that imitate URL delimiters",
        combining_mark_on_latin: "it stacks combining marks on Latin letters",
        digit_lookalike: "it uses letters that imitate digits",
      };
      const likes = confs.slice(0, 6).map((c) => `${c.char}→${c.like}`).join(", ");
      const wholeScript = [...reasons].find((r) => r.startsWith("_whole:"));
      for (const r of spoofReasons.sort()) {
        const [id, w] = map[r] || [];
        if (!id) continue;
        out.push(sig(id, w, "unicode", `The host '${p.hostUnicode}' is a spoofing risk because ${why[r]}.`,
          Object.assign({ host: p.hostUnicode, scripts, chars: likes },
            first, wholeScript ? { script: ISO[wholeScript.slice(7)] || "" } : {}),
          { span: hostSpan, evidence: { reason: r } }));
      }
      const strong = ["skeleton_matches_top_domain", "whole_script_confusable", "mixed_script"];
      if (confs.length && isSpoof && !strong.some((r) => reasons.has(r))) {
        out.push(sig("unicode.confusable_host", 3.0, "unicode",
          `The host '${p.hostUnicode}' uses look-alike characters (${likes}).`,
          Object.assign({ host: p.hostUnicode, chars: likes }, first), { span: confSpan || hostSpan }));
      }
      if (p.punycode) {
        out.push(isSpoof
          ? sig("unicode.punycode_lookalike", 3.0, "unicode",
            `The punycode host ${p.host} decodes to '${p.hostUnicode}', a spoofing risk.`,
            { host: p.host, unicode: p.hostUnicode }, { span: p.hostSpan })
          : sig("unicode.punycode", 0.5, "unicode", `The host ${p.host} is punycode-encoded ('${p.hostUnicode}').`,
            { host: p.host, unicode: p.hostUnicode }, { span: p.hostSpan }));
      }
      return out;
    }

    function openRedirect(p) {
      if (!p.query || p.query.length < 8) return null;
      let params;
      try { params = new URLSearchParams(p.query); } catch (_) { return null; }
      const here = UrlLib.registrable(UrlLib.splitHost(p.host, lists.psl));
      let n = 0;
      for (const [k, v] of params) {
        if (++n > 64) break;
        if (!REDIRECT_PARAMS.has(k.toLowerCase())) continue;
        if (!/^(https?:)?\/\//i.test(v.trim())) continue;
        const d = UrlLib.parseUrl(v.trim());
        if (!d.valid || !d.host) continue;
        const there = UrlLib.registrable(UrlLib.splitHost(d.host, lists.psl));
        if (there && there !== here) return { param: k, dest: d.host };
      }
      return null;
    }

    function structureSignals(p, parts, official, lots) {
      const out = [];
      const add = (id, w, detail, params, extra) => out.push(sig(id, w, "url", detail, params, extra));
      const host = p.host;
      if (p.ipObfuscated) {
        add("url.ip_obfuscation", 3.0, `The host is an obfuscated numeric form of the IP address ${host}.`,
          { ip: host, raw: p.rawHost }, { span: p.hostSpan });
      } else if (p.isIp) {
        add("url.ip_host", 1.5, `The link points at the raw IP address ${host} instead of a domain name.`,
          { ip: host }, { span: p.hostSpan });
      }
      if (p.userinfo && /[a-z0-9-]+\.[a-z]{2,}|^https?:/i.test(p.userinfo)) {
        add("url.at_redirect", 3.0, `Text before '@' ('${p.userinfo}') looks like the destination, but the browser connects to ${host}.`,
          { userinfo: p.userinfo, host }, { span: p.userinfoSpan });
      }
      if (!p.isIp) {
        if (lists.isShortener(host)) add("url.shortener", 1.0, `${host} is a link shortener, which hides the real destination.`, { host }, { span: p.hostSpan });
        if (lists.isDyndns(host)) add("url.dynamic_dns", 1.5, `${host} sits on a dynamic-DNS zone anyone can register a name in.`, { host }, { span: p.hostSpan });
        // Weight 0.8 (Python: 1.5): without the page content to confirm, a link to a big
        // platform (docs.google.com, github.io) must not warn by itself.
        if (lots) add("url.lots_hosting", 0.8, `Hosted on ${lots.name}, a legitimate ${lots.kind} platform anyone can publish on (no reputation credit is given for the host).`,
          { platform: lots.name }, { span: p.hostSpan });
        const risk = lists.tldRisk(parts.suffix || host);
        if (risk !== null && risk >= SUSPICIOUS_TLD_MIN) {
          const tld = (parts.suffix || host).split(".").pop();
          add("url.suspicious_tld", Math.round(Math.min(risk, 2.0) * 100) / 100, `.${tld} is a top-level domain with a high phishing-abuse rate.`, { tld });
        }
        if (parts.sub.length >= 4) add("url.many_subdomains", 1.0, `${parts.sub.length} sub-domain labels push the real domain out of view.`, { count: parts.sub.length }, { span: p.hostSpan });
        const hostLures = lists.lures([...parts.sub, parts.sld].join(" "));
        if (hostLures.length) {
          const w = Math.min(LURE_CAP, hostLures.reduce((a, h) => a + h.weight, 0));
          add("url.credential_lure_host", Math.round(w * 100) / 100, "The host uses sign-in / verification vocabulary: " + hostLures.slice(0, 5).map((h) => h.term).join(", ") + ".",
            { words: hostLures.slice(0, 5).map((h) => h.term).join(", ") }, { span: p.hostSpan });
        }
        const lab = parts.sld;
        if (lab && lab.length >= 8 && /^[a-z0-9]+$/.test(lab) && !lists.isShortener(host)) {
          const vowels = (lab.match(/[aeiouy]/g) || []).length;
          const digits = (lab.match(/[0-9]/g) || []).length;
          if (vowels === 0 || (lab.length >= 10 && digits / lab.length >= 0.3 && digits / lab.length <= 0.7)) {
            add("url.random_label", 0.5, "A host label looks algorithmically generated (high entropy / no vowels).", { label: lab }, { span: p.hostSpan });
          }
        }
        const hy = ((p.hostUnicode || host).match(/-/g) || []).length; // decoded: "xn--" is not squatting
        if (hy >= MANY_HYPHENS) add("url.many_hyphens", 0.3, `The host contains ${hy} hyphens, a common squatting pattern.`, { count: hy }, { span: p.hostSpan });
      }
      let decPath = p.path;
      try { decPath = decodeURIComponent(p.path); } catch (_) { /* keep raw */ }
      const pathLures = lists.lures(decPath.slice(0, 1024));
      if (pathLures.length) {
        const w = Math.min(LURE_CAP, pathLures.reduce((a, h) => a + h.weight, 0));
        add("url.credential_lure_path", Math.round(w * 100) / 100, "The path uses sign-in / verification vocabulary: " + pathLures.slice(0, 5).map((h) => h.term).join(", ") + ".",
          { words: pathLures.slice(0, 5).map((h) => h.term).join(", ") }, { span: p.pathSpan });
      }
      const fname = decPath.split("/").pop() || "";
      const segs = fname.toLowerCase().split(".");
      if (segs.length >= 2) {
        const ext = segs[segs.length - 1];
        if (SUSPICIOUS_EXT.has(ext)) {
          const dbl = segs.length >= 3 && DOC_EXT.has(segs[segs.length - 2]);
          const sp = findSpan(p.input, fname);
          add(dbl ? "url.double_extension" : "url.suspicious_file_ext", dbl ? 2.5 : 2.0,
            dbl ? `The path downloads a file whose real type is .${ext} behind a harmless-looking extension.`
              : `The path points at a .${ext} file, an executable / script type commonly used to deliver malware.`,
            { ext: "." + ext }, { span: sp });
        }
      }
      if (/%25[0-9a-f]{2}/i.test(p.path + p.query)) add("url.double_encoding", 1.0, "The URL is doubly percent-encoded, a common way to hide its real content from filters.", {});
      if (p.port && p.port !== "80" && p.port !== "443") add("url.non_standard_port", 0.5, `The URL forces a non-standard port (${p.port}).`, { port: p.port });
      if (p.input.length > LONG_URL) add("url.long_url", 0.3, `The URL is ${p.input.length} characters long, which can hide its true target.`, { len: p.input.length });
      const orx = openRedirect(p);
      if (orx) add("url.open_redirect", OPEN_REDIRECT_PARAM_WEIGHT, `The '${orx.param}' parameter forwards visitors to ${orx.dest}, borrowing this site's reputation.`, { param: orx.param, dest: orx.dest });
      if (official) return out.filter((s) => s.id === "url.open_redirect");
      return out;
    }

    /** Analyse one URL string. Never throws. */
    function analyze(raw) {
      const p = UrlLib.parseUrl(raw);
      const res = { parsed: p, parts: null, signals: [], brand: null, candidates: [], techniques: [], primary: null, meta: {} };
      try {
        if (!p.valid) return res;
        if (p.scheme !== "http" && p.scheme !== "https" && p.scheme !== "ftp") {
          if (p.scheme === "data" || p.scheme === "javascript") {
            res.signals.push(sig("url.dangerous_scheme", 3.0, "url",
              `The URL uses the ${p.scheme}: scheme, which carries executable / markup content inline rather than pointing at a host.`, { scheme: p.scheme }));
          }
          return res;
        }
        const lots = p.isIp ? null : lists.lotsMatch(p.host, p.path);
        const parts = p.isIp ? { sub: [], sld: "", suffix: "" } : UrlLib.splitHost(p.host, lists.psl, lots && lots.match);
        res.parts = parts;
        const asciiReg = parts.sld && parts.suffix ? parts.sld + "." + parts.suffix : "";
        const rank = !lots && !matcher.userContentOwner(p.host) && asciiReg ? lists.topRank(asciiReg) : null;
        // Brand logic uses the Unicode-decoded labels (so homoglyph labels are visible to it).
        const uparts = p.isIp ? parts : UrlLib.splitHost(p.hostUnicode, lists.psl, lots && lots.match);
        const risk = lists.tldRisk(parts.suffix || p.host);
        const cands = matcher.candidates(p, uparts, { lots, rank: lists.topRank(asciiReg), risk });
        res.candidates = cands;
        const official = !!(cands.length && cands[0].official);
        const b = brandSignals(p, uparts, cands);
        res.brand = b.best;
        res.signals.push(...b.signals);
        res.signals.push(...unicodeSignals(p, uparts));
        res.signals.push(...structureSignals(p, uparts, official, lots));
        if (rank !== null && !official && !lots) {
          res.signals.push(sig("rep.top_site", rank <= 1000 ? -3.0 : -2.0, "reputation",
            `${asciiReg} is ranked #${rank} among the world's most visited sites.`, { rank, domain: asciiReg }));
        }
        const techs = [];
        for (const s of res.signals) { const t = TECHNIQUE_OF[s.id]; if (t && !techs.includes(t)) techs.push(t); }
        res.techniques = techs;
        res.primary = techs[0] || null;
        res.meta = { host: p.hostUnicode || p.host, hostAscii: p.host, registrable: asciiReg, tld: (parts.suffix || "").split(".").pop(), isIp: p.isIp, official, lots: lots ? lots.name : null, rank };
      } catch (err) {
        res.meta.error = String(err && err.message || err);
      }
      return res;
    }

    return { analyze, matcher, lists, conf, titles: TITLES };
  }

  const api = { createRules, TITLES, isMixedLabel, labelScripts, BRAND_WEIGHT, OFFICIAL_WEIGHT };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhishRules = api;
})(typeof self !== "undefined" ? self : this);
