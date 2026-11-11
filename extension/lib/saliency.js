// Occlusion saliency for the on-device byte CNN: "which characters move the score?"
//
// Port of uniphish/url/saliency.py.  Each character's UTF-8 bytes are replaced by the pad
// byte (the model's neutral baseline, no position shift), the URL is re-scored, and the drop
// in the pre-sigmoid LOGIT is that character's delta (positive = pushed toward phishing).
// Logit space is used because the model saturates: on a URL it is 99.99% sure about, every
// probability delta is ~0.  Occlusion is per character (all of its bytes at once), so a
// Cyrillic or CJK homoglyph is one unit.  Cost: one forward pass per character (~1 ms each thanks to the cached
// conv tables in model.js): ~50 ms for a typical 50-character URL, ~0.5 s at the 160-character
// cap (DEFAULT_MAX_CHARS), so it runs after the verdict is already on screen.

(function (global) {
  "use strict";

  const DEFAULT_MAX_CHARS = 160;
  const LOGIT_FLOOR = 0.1;

  function utf8Len(cp) {
    return cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
  }

  /**
   * @param {UniPhishModel} model  loaded model (needs encode/logitSeq)
   * @param {string} url
   * @returns {{base: number, chars: Array<{index:number, char:string, delta:number, scored:boolean}>}}
   *   `index` is a UTF-16 offset into `url`; chars beyond maxChars / the 600-byte window have
   *   delta 0 and scored=false.
   */
  function occlusion(model, url, maxChars) {
    const limit = maxChars === undefined ? DEFAULT_MAX_CHARS : maxChars;
    const { seq, n } = model.encode(url);
    const base = model.logitSeq(seq, n);
    const chars = [];
    let bytePos = 0, idx = 0, count = 0;
    const L = seq.length;
    const work = new Uint8Array(L);
    for (const ch of String(url)) {
      const cp = ch.codePointAt(0);
      const start = bytePos;
      const end = bytePos + utf8Len(cp);
      let delta = 0, scored = false;
      if (count < limit && start < L) {
        work.set(seq);
        work.fill(0, start, Math.min(end, L));
        delta = base - model.logitSeq(work, n);
        scored = true;
      }
      chars.push({ index: idx, char: ch, delta, scored });
      bytePos = end;
      idx += ch.length;
      count++;
    }
    return { base, chars };
  }

  /** Merge adjacent incriminating chars into the strongest `k` spans {start,end,text,delta}. */
  function topSpans(url, result, k, minFrac) {
    const K = k === undefined ? 5 : k;
    const frac = minFrac === undefined ? 0.25 : minFrac;
    const chars = result.chars;
    const maxDelta = chars.reduce((m, c) => Math.max(m, c.delta), 0);
    if (maxDelta <= 0) return [];
    const threshold = Math.max(LOGIT_FLOOR, frac * maxDelta);
    const spans = [];
    let i = 0;
    while (i < chars.length) {
      if (chars[i].delta >= threshold) {
        let j = i, peak = 0;
        while (j < chars.length && chars[j].delta >= threshold) { peak = Math.max(peak, chars[j].delta); j++; }
        const start = chars[i].index;
        const end = chars[j - 1].index + chars[j - 1].char.length;
        spans.push({ start, end, text: url.slice(start, end), delta: peak });
        i = j;
      } else i++;
    }
    return spans.sort((a, b) => b.delta - a.delta).slice(0, K);
  }

  const api = { occlusion, topSpans, DEFAULT_MAX_CHARS };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhishSaliency = api;
})(typeof self !== "undefined" ? self : this);
