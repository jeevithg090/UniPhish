// UniPhish on-device byte-level CNN (pure JavaScript, no TensorFlow.js, no server).
//
// Runs the exact forward pass of the Python runtime (uniphish/url/model.py): UTF-8 bytes
// truncated/zero-padded to 600 -> byte embedding (256x64) -> five parallel Conv1D branches
// (kernels 2..6 x 128) + ReLU + global max-pool -> dense 640->256->128->1 -> sigmoid.
// URLs are scored entirely in the browser; nothing leaves the device.
//
// What changed vs. the original demo implementation (results are numerically identical
// to float32 rounding, verified against the NumPy runtime in tests/url/test_model_parity.py
// and extension/test/model.test.js):
//
//  * Embedding-conv fusion.  conv(emb[byte]) is linear in the one-hot byte, so for every
//    (kernel, offset, byte) the partial sum  sum_c emb[byte][c] * w[offset][c][f]  is
//    computed once (lazily, only for bytes actually seen) and cached.  A window then costs
//    k*F additions instead of k*D*F multiply-adds (64x less work).
//  * Pad-window collapse.  Every window lying entirely in the zero padding is identical, so
//    only one of them is evaluated.  The max-pool therefore still sees exactly the same
//    set of values; only redundant duplicates are skipped.  A 60-byte URL goes from ~100M
//    multiply-adds to well under 1M, which is what makes per-link scoring and per-character
//    occlusion saliency practical in a service worker.
//
// Public API (environment-agnostic; CommonJS export for Node, global `UniPhish` in browsers):
//   forward(manifest, W, url)        -> phishing probability in [0, 1]   (original signature)
//   logit(manifest, W, url)          -> pre-sigmoid logit
//   UniPhishModel                    -> setWeights(manifest, W) / predict(url) / logit(url) /
//                                       encode(url) / logitSeq(seq, n) / tier(p)
// (lib/boot.js fetches the packaged manifest + weights and calls setWeights.)

(function (global) {
  "use strict";

  const compiledCache = new WeakMap(); // Float32Array W -> Compiled (manifest identity checked)

  function tensor(manifest, W, name) {
    const t = manifest.tensors.find((x) => x.name === name);
    if (!t) throw new Error("model tensor missing: " + name);
    return W.subarray(t.offset, t.offset + t.size);
  }

  function sigmoid(x) {
    return x >= 0 ? 1 / (1 + Math.exp(-x)) : Math.exp(x) / (1 + Math.exp(x));
  }

  /** Weights bound to a manifest, plus the lazily-built per-byte conv tables. */
  class Compiled {
    constructor(manifest, W) {
      this.manifest = manifest;
      this.L = manifest.maxLen;
      this.D = manifest.embedDim;
      this.F = manifest.filters;
      this.emb = tensor(manifest, W, "emb");
      this.kernels = manifest.kernels.map((k) => ({
        k,
        w: tensor(manifest, W, `conv${k}_w`), // (k, D, F) C-order
        b: tensor(manifest, W, `conv${k}_b`), // (F,)
      }));
      this.table = this.kernels.map(({ k }) =>
        Array.from({ length: k }, () => new Float64Array(256 * this.F)));
      this.filled = new Uint8Array(256);
      // Dense head in float64: V8 does arithmetic in doubles, so float32 storage costs a
      // conversion per multiply-add (measured ~3x slower).  Same values, widened once.
      const wide = (name) => Float64Array.from(tensor(manifest, W, name));
      this.fc1 = [wide("fc1_w"), wide("fc1_b")];
      this.fc2 = [wide("fc2_w"), wide("fc2_b")];
      this.out = [wide("phish_prob_w"), wide("phish_prob_b")];
    }

    /** Fill table[kernel][offset][byte*F + f] for one byte value (idempotent). */
    ensure(byte) {
      if (this.filled[byte]) return;
      const { D, F, emb } = this;
      for (let ki = 0; ki < this.kernels.length; ki++) {
        const { k, w } = this.kernels[ki];
        for (let i = 0; i < k; i++) {
          const T = this.table[ki][i];
          const wBase = i * D * F;
          for (let f = 0; f < F; f++) {
            let s = 0;
            for (let c = 0; c < D; c++) s += emb[byte * D + c] * w[wBase + c * F + f];
            T[byte * F + f] = s;
          }
        }
      }
      this.filled[byte] = 1;
    }

    /** UTF-8 bytes of ``url`` truncated / zero-padded to L. Returns {seq, n}. */
    encode(url) {
      const raw = new TextEncoder().encode(String(url));
      const seq = new Uint8Array(this.L);
      const n = Math.min(raw.length, this.L);
      seq.set(raw.subarray(0, n));
      return { seq, n };
    }

    /** Pre-sigmoid logit for a padded byte sequence whose real content is seq[0:n). */
    logitSeq(seq, n) {
      const { L, F } = this;
      const nReal = Math.max(0, Math.min(n === undefined ? L : n, L));
      for (let p = 0; p < nReal; p++) this.ensure(seq[p]);
      this.ensure(0);

      const z = new Float64Array(this.kernels.length * F);
      const acc = new Float64Array(F);
      for (let ki = 0; ki < this.kernels.length; ki++) {
        const { k, b } = this.kernels[ki];
        const tabs = this.table[ki];
        const positions = L - k + 1;
        // Windows starting at p >= nReal are entirely padding and identical: evaluate one.
        const last = Math.min(nReal, positions - 1);
        const zBase = ki * F; // z starts at 0: the ReLU floor of the max-pool
        for (let p = 0; p <= last; p++) {
          acc.set(b);
          // position-major so the inner loop over filters is contiguous in memory
          for (let i = 0; i < k; i++) {
            const tab = tabs[i];
            const base = seq[p + i] * F;
            for (let f = 0; f < F; f++) acc[f] += tab[base + f];
          }
          for (let f = 0; f < F; f++) if (acc[f] > z[zBase + f]) z[zBase + f] = acc[f];
        }
      }
      const h1 = dense(z, this.fc1[0], this.fc1[1], this.manifest.fc[0], true);
      const h2 = dense(h1, this.fc2[0], this.fc2[1], this.manifest.fc[1], true);
      return dense(h2, this.out[0], this.out[1], 1, false)[0];
    }
  }

  function dense(x, w, b, outDim, doRelu) {
    const inDim = x.length;
    const out = new Float64Array(outDim);
    for (let o = 0; o < outDim; o++) out[o] = b[o];
    // Row-major (in, out) weights: accumulate input-by-input for sequential memory access.
    for (let i = 0; i < inDim; i++) {
      const xi = x[i];
      if (xi === 0) continue;
      const row = i * outDim;
      for (let o = 0; o < outDim; o++) out[o] += xi * w[row + o];
    }
    if (doRelu) for (let o = 0; o < outDim; o++) if (out[o] < 0) out[o] = 0;
    return out;
  }

  function compile(manifest, W) {
    let c = compiledCache.get(W);
    if (!c || c.manifest !== manifest) {
      c = new Compiled(manifest, W);
      compiledCache.set(W, c);
    }
    return c;
  }

  function logit(manifest, W, url) {
    const c = compile(manifest, W);
    const { seq, n } = c.encode(url);
    return c.logitSeq(seq, n);
  }

  function forward(manifest, W, url) {
    return sigmoid(logit(manifest, W, url));
  }

  /** Default tiers on the *raw* model probability (the fused engine uses its own). */
  function rawTier(p) { return p >= 0.9 ? "block" : p >= 0.5 ? "warn" : "safe"; }

  class UniPhishModel {
    /** Bind already-loaded weights (used by Node tests and the service worker). */
    setWeights(manifest, W) {
      let expected = 0;
      for (const t of manifest.tensors) expected = Math.max(expected, t.offset + t.size);
      if (W.length < expected) {
        throw new Error(`weights.bin too short: ${W.length} floats, manifest needs ${expected}`);
      }
      this.manifest = manifest;
      this.W = W;
      this.compiled = compile(manifest, W);
      return this;
    }
    get loaded() { return !!this.compiled; }
    predict(url) { return forward(this.manifest, this.W, url); }
    logit(url) { return logit(this.manifest, this.W, url); }
    encode(url) { return this.compiled.encode(url); }
    logitSeq(seq, n) { return this.compiled.logitSeq(seq, n); }
    tier(p) { return rawTier(p); }
  }

  const api = { forward, logit, UniPhishModel, sigmoid };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhish = api;
})(typeof self !== "undefined" ? self : this);
