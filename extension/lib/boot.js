// Loads the packaged data bundle + CNN weights and builds the on-device engine.
//
// Shared by the service worker, popup and interstitial so every surface scores identically.
// All fetches target `chrome.runtime.getURL(...)` -- files shipped inside the extension; no
// remote code and no network.  Memoised per JS realm.

(function (global) {
  "use strict";

  let pending = null;

  async function getJson(fetchFn, base, name) {
    const res = await fetchFn(base + name);
    if (!res.ok) throw new Error(`failed to load ${name}: ${res.status}`);
    return res.json();
  }

  /** @returns {Promise<{engine, model, data}>} */
  function loadEngine(baseUrl, fetchFn) {
    if (pending) return pending;
    const f = fetchFn || fetch.bind(globalThis);
    pending = (async () => {
      const [brands, lists, confusables, manifest, weightsRes] = await Promise.all([
        getJson(f, baseUrl, "data/brands.json"),
        getJson(f, baseUrl, "data/lists.json"),
        getJson(f, baseUrl, "data/confusables.json"),
        getJson(f, baseUrl, "model/manifest.json"),
        f(baseUrl + "model/weights.bin"),
      ]);
      if (!weightsRes.ok) throw new Error("failed to load model/weights.bin");
      const model = new global.UniPhish.UniPhishModel().setWeights(manifest, new Float32Array(await weightsRes.arrayBuffer()));
      const data = { brands, lists, confusables };
      const engine = global.UniPhishEngine.createEngine({ data, model });
      return { engine, model, data };
    })();
    pending.catch(() => { pending = null; }); // allow a retry after a transient failure
    return pending;
  }

  /** Locale loader for lib/i18n.js. */
  function localeLoader(baseUrl, fetchFn) {
    const f = fetchFn || fetch.bind(globalThis);
    return async (lang) => (await f(baseUrl + "locales/" + lang + ".json")).json();
  }

  const api = { loadEngine, localeLoader };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.UniPhishBoot = api;
})(typeof self !== "undefined" ? self : this);
