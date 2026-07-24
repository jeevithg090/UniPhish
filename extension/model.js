// Zero-dependency on-device UniPhish inference (Track C).
// Runs the exact byte-level CNN forward pass in pure JS — no TensorFlow.js, no
// server. URLs are scored entirely in the browser; nothing leaves the device.
//
// forward(manifest, W, url) is environment-agnostic (used by the extension and by
// the Node parity test). UniPhishModel wraps it with fetch-based weight loading.

(function (global) {
  function tensor(manifest, W, name) {
    const t = manifest.tensors.find((x) => x.name === name);
    return W.subarray(t.offset, t.offset + t.size);
  }

  function relu(x) { return x > 0 ? x : 0; }
  function sigmoid(x) { return 1 / (1 + Math.exp(-x)); }

  function forward(manifest, W, url) {
    const L = manifest.maxLen, D = manifest.embedDim, F = manifest.filters;
    const emb = tensor(manifest, W, "emb");

    // UTF-8 byte sequence, truncated/zero-padded to L
    const raw = new TextEncoder().encode(url);
    const seq = new Uint8Array(L);
    seq.set(raw.subarray(0, L));

    // parallel multi-kernel conv1d -> relu -> global max pool
    const z = new Float32Array(manifest.kernels.length * F);
    let branch = 0;
    for (const k of manifest.kernels) {
      const w = tensor(manifest, W, `conv${k}_w`);   // (k, D, F) C-order
      const b = tensor(manifest, W, `conv${k}_b`);   // (F,)
      const positions = L - k + 1;
      for (let f = 0; f < F; f++) {
        let maxv = 0;                                  // relu floor
        for (let p = 0; p < positions; p++) {
          let s = b[f];
          for (let i = 0; i < k; i++) {
            const embBase = seq[p + i] * D;
            const wBase = i * D * F + f;               // + c*F
            for (let c = 0; c < D; c++) s += emb[embBase + c] * w[wBase + c * F];
          }
          if (s > maxv) maxv = s;
        }
        z[branch * F + f] = maxv;
      }
      branch++;
    }

    // dense head: fc1 -> relu -> fc2 -> relu -> out -> sigmoid
    const h1 = dense(z, tensor(manifest, W, "fc1_w"), tensor(manifest, W, "fc1_b"),
                     manifest.fc[0], true);
    const h2 = dense(h1, tensor(manifest, W, "fc2_w"), tensor(manifest, W, "fc2_b"),
                     manifest.fc[1], true);
    const out = dense(h2, tensor(manifest, W, "phish_prob_w"),
                      tensor(manifest, W, "phish_prob_b"), 1, false);
    return sigmoid(out[0]);
  }

  function dense(x, w, b, outDim, doRelu) {
    const inDim = x.length;
    const out = new Float32Array(outDim);
    for (let o = 0; o < outDim; o++) {
      let s = b[o];
      for (let i = 0; i < inDim; i++) s += x[i] * w[i * outDim + o];
      out[o] = doRelu ? relu(s) : s;
    }
    return out;
  }

  class UniPhishModel {
    async load(baseUrl) {
      this.manifest = await (await fetch(baseUrl + "manifest.json")).json();
      const buf = await (await fetch(baseUrl + "weights.bin")).arrayBuffer();
      this.W = new Float32Array(buf);
    }
    predict(url) { return forward(this.manifest, this.W, url); }
    tier(p) { return p >= 0.9 ? "block" : p >= 0.5 ? "warn" : "safe"; }
  }

  const api = { forward, UniPhishModel };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhish = api;
})(typeof self !== "undefined" ? self : this);
