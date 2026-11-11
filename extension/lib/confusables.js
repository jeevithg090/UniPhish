// UTS #39 confusable skeletons and squatting folds, on-device.
//
// Why: the core homoglyph defence is "collapse look-alike characters to the ASCII letter
// they imitate, then compare with brand names".  The prototype table is the Unicode
// Consortium's confusables.txt, trimmed by extension/tools/build_data.py to the ~2,200
// non-ASCII characters whose prototype is plain printable ASCII (24 KB) - exactly the set
// that can spoof a Latin domain label.  Mirrors uniphish/url/confusables.py.

(function (global) {
  "use strict";

  const MULTI = [[/rn/g, "m"], [/vv/g, "w"], [/cl/g, "d"]];
  const LEET = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a" };

  /** @param {{m: Object<string,string>}} data  parsed data/confusables.json */
  function createConfusables(data) {
    const table = new Map(Object.entries((data && data.m) || {}));

    /** UTS #39 skeleton: NFD -> prototype map -> NFD. */
    function skeleton(s) {
      if (!s) return "";
      let out = "";
      for (const ch of String(s).normalize("NFD")) {
        const proto = table.get(ch);
        out += proto === undefined ? ch : proto;
      }
      return out.normalize("NFD");
    }

    /** Skeleton plus leet digits and multi-glyph folds (rn->m, vv->w, cl->d), lowercased. */
    function brandSkeleton(s) {
      let out = skeleton(s).toLowerCase();
      for (const [rx, repl] of MULTI) out = out.replace(rx, repl);
      let r = "";
      for (const ch of out) r += LEET[ch] || ch;
      return r;
    }

    /** [{index, char, like}] for every non-ASCII char in `s` that imitates printable ASCII.
     *  `index` is a UTF-16 offset into `s`. */
    function confusableChars(s) {
      const out = [];
      let i = 0;
      for (const ch of String(s)) {
        if (ch.codePointAt(0) >= 0x80) {
          let proto = table.get(ch);
          if (proto === undefined) {
            const sk = skeleton(ch);
            if (sk && /^[\x21-\x7e]+$/.test(sk) && sk !== ch) proto = sk;
          }
          if (proto !== undefined) out.push({ index: i, char: ch, like: proto });
        }
        i += ch.length;
      }
      return out;
    }

    return { skeleton, brandSkeleton, confusableChars, has: (ch) => table.has(ch), size: table.size };
  }

  const api = { createConfusables };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhishConfusables = api;
})(typeof self !== "undefined" ? self : this);
