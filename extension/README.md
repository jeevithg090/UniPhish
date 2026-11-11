# UniPhish browser extension (Manifest V3, on-device)

Phishing protection that runs **entirely in your browser**. Every verdict is computed
on-device from a byte-level CNN plus a port of UniPhish's explainable URL rules; there is no
server in the loop and no telemetry. The only network request the extension can ever make is
the *optional* "deep analysis" call to a UniPhish server **you** configure (off by default).

What it does

* **Link marking** - a content script scores every external link on the page and outlines
  suspicious (dashed amber) and dangerous (solid red) ones, with a localised tooltip that says
  *why* ("This link uses the Cyrillic letter "а" (Cyrl, U+0430) to look like "a" - it imitates
  PayPal"). Links are re-scanned as the page changes.
* **Warning page** - clicking a dangerous link opens an explainable, localised interstitial:
  the real destination with the look-alike characters highlighted, the impersonated brand and
  its real domains, the reasons, *Go back*, *Proceed anyway* (behind an explicit confirmation),
  and report actions (copy a defanged report, Google Safe Browsing form, or your own server).
* **Popup** - paste a URL (or scan the current tab): verdict, risk gauge, impersonated brand,
  reasons, and a per-character *saliency* heat-map (which characters pushed the CNN toward
  "phishing", via occlusion) with look-alike characters underlined.
* **Context menu** - "Scan link with UniPhish" on any link; **badge** shows how many risky
  links a page has.
* **Settings** - sensitivity thresholds, language, trusted sites, optional API endpoint + key,
  optional direct-navigation warnings.
* **Languages** - English, Español, Français, Deutsch, Português, Русский, 中文, 日本語, हिन्दी,
  العربية (RTL). The popup, tooltips, warning page and all core reasons are localised; the
  Settings page and rarely-seen messages fall back to English.

## Load it (Chrome / Edge / Brave, Chromium >= 110)

1. `chrome://extensions` -> enable **Developer mode**.
2. **Load unpacked** -> select this `extension/` folder.
3. Pin the icon. Click it: the pill reads **On-device**. Try the example chips.
4. Open any page with links; risky ones get outlined. A synthetic test page and an automated
   check are provided in `test/e2e/run_e2e.py`.

No build step is needed to *run* the extension: everything it loads is committed
(`data/`, `model/`, `icons/`). Firefox is not covered (MV3 service-worker differences).

## How the verdict is computed (all on-device)

```
URL ──► parse (WHATWG URL + raw-authority facts + punycode decode)
   ├─► rules  (lib/rules.js, lib/brands.js)   signed log-odds signals, same ids/weights as
   │                                          uniphish/analyzers/url.py
   ├─► CNN    (model.js, model/*)             byte-level 1D-CNN, same weights as the Python runtime
   └─► fusion (lib/fusion.js)                 logit = -2 + Σ weight·confidence·0.55^rank(per category)
                                              risk = sigmoid(logit) -> safe / warn / block
```

* **Rules ported** from `uniphish/analyzers/url.py`: homoglyph / confusable / mixed-script /
  whole-script / invisible / combining-mark / digit-lookalike hosts, punycode, `@` trick, IP and
  obfuscated-IP hosts, brand homoglyph / typosquat / bitsquat / combosquat / sub-domain / path
  impersonation, shorteners, dynamic DNS, living-off-trusted-sites hosting (no reputation credit),
  open-redirect parameters, abused TLDs, deep sub-domains, credential-lure words (multilingual),
  dangerous file extensions / double extensions, double encoding, `data:`/`javascript:`; plus
  legitimacy evidence (official brand host, top-10k site).
* **Fusion** is the Python scorer's log-odds model: prior -2.0, per-category damping 0.55,
  thresholds 0.50 (suspicious) / 0.85 (dangerous), user-adjustable in Settings. Every verdict
  decomposes exactly into per-signal contributions (`verdict.signals[].contribution`).
* **Deliberate deviations from the Python engine** (documented because they change results):
  1. The raw CNN can never *warn or block on its own*. Its weight is capped at +1.0 unless a
     rule signal that is intrinsically deceptive (look-alike host, brand impersonation, `@`
     trick, ...) agrees, and a benign model reading never cancels such a signal. Reason: the
     model over-scores ordinary long URLs (MODEL_CARD.md caveat); in testing it alone put a
     bakery's order page and Google Docs links at 88-97% risk.
  2. `url.lots_hosting` weighs +0.8 (Python: +1.5): without page content, a link to
     docs.google.com must not warn by itself.
  3. Open-redirect detection uses a generic parameter heuristic at +1.2 (Python: curated
     endpoint list at +2.0).
  4. Loopback / private / link-local / single-label hosts are never flagged.
  5. "Popular site" exemption and top-site credit use the bundled top **10k** (Python: 20k / 100k).

## Data and model bundling

Nothing is fetched at run time except files packaged inside the extension.

| Path | What | Size |
|---|---|---|
| `model/weights.bin`, `model/manifest.json` | the CNN (377,985 params, float32), byte-identical to `uniphish/assets/model/` | 1,511,940 B |
| `data/brands.json` | 680 brands: official / login / CDN / user-content domains, folded terms | ~100 KB |
| `data/lists.json` | TLD risk, 209 LOTS hosts, shorteners, dyndns, multi-label public suffixes, top-10k domains, lure vocabulary (~1.2k terms, 30 languages) | ~246 KB (91 KB gzipped) |
| `data/confusables.json` | UTS #39 prototypes for the 2,245 non-ASCII chars that imitate ASCII | ~24 KB |
| code + locales + icons | | ~0.3 MB |

**Total package ≈ 2.1 MB** (1.5 MB of it is the model). The data files are *generated*, not
hand-edited, from the platform's canonical assets:

```bash
.venv/bin/python extension/tools/build_data.py          # regenerate extension/data/
.venv/bin/python extension/tools/build_data.py --check  # fail if data/ is stale (also run by npm test)
.venv/bin/python extension/tools/make_icons.py          # regenerate icons/
```

To ship a retrained model, replace `model/` (see `scripts/export_web.py`) - `model.js` reads the
manifest generically.

### Performance (Node 26, Apple silicon)

* CNN forward: ~1 ms per URL. The original implementation spent ~100 M multiply-adds per URL;
  `model.js` now caches per-byte conv tables and collapses the identical all-padding windows, with
  numerically equivalent output (verified against both the original naive pass and the NumPy
  runtime in `tests/url/test_model_parity.py`).
* Full verdict (parse + rules + CNN + fusion): ~2.5 ms per URL, so a 300-link page scores in
  about a second off the main thread. Saliency: ~50 ms for a typical URL, ~0.5 s at its 160-char cap.

## Permissions (kept minimal)

| Permission | Why |
|---|---|
| `storage` | settings |
| `contextMenus` | "Scan link with UniPhish" |
| `activeTab` | the popup can read the current tab's URL after you click the icon |
| content script on `http(s)://*/*` | required to read page links; it never sends page content anywhere |
| *optional* `webNavigation` | only if you enable "also warn when I open a dangerous address directly"; requested from the Settings page |
| *optional* host access to your server's origin | only if you configure deep analysis; requested from the Settings page |

No `tabs`, `scripting`, `webRequest`, `<all_urls>` host permission, remote code, `eval`,
`web_accessible_resources` or externally-connectable pages. Extension pages run under
`script-src 'self'; object-src 'none'`. All attacker-influenced strings are rendered with
`textContent` only. The content script cannot be made to navigate: only the service worker opens
the warning page, and only for http(s) URLs. `test/manifest.test.js` enforces these properties.

## Optional deep analysis (off by default)

Settings -> *Deep analysis*: enter your UniPhish server address (https, or http only for
localhost) and optional API key, tick *Enable*, and grant the browser's origin prompt. The popup's
*Deep analysis* switch then sends the URL **you scan** (never page content, never automatically)
to `POST {endpoint}/v1/scan/url` with an `X-API-Key` header, `credentials: omit`, `redirect: error`
and a 15 s timeout, and shows the server's verdict beside the on-device one. The warning page can
also send a report (`options.persist = true`). The popup tells you which server received the URL.

## Tests

```bash
cd extension && npm test            # 105 Node tests, no dependencies (node --test)
.venv/bin/python extension/test/e2e/run_e2e.py [--shots DIR]   # real Chromium, 25 checks
.venv/bin/python -m pytest tests/url/test_model_parity.py -q   # JS model == NumPy runtime
```

Coverage: model parity (vs NumPy fixtures + the original naive pass), saliency, URL parsing and
punycode (cross-checked against Node's IDNA), every rule and the labelled synthetic corpus
(22 phishing / 23 benign, zero misses, zero false positives), fusion maths, engine behaviour
(model cap, corroboration, allowlist, local hosts, fuzzing), i18n (placeholder parity in all 10
locales, rendering every reason in every language), settings validation, the optional server
client, the **real** `background.js` driven through a mocked `chrome` (messages, badge, context
menu, interstitial routing, navigation check, allowances), manifest/CSP/static-analysis guards,
and data freshness. All fixtures are synthetic and inert (reserved `.example`/`.test` hosts and
documentation IP ranges).

## Known limitations

* The corpus above is small and synthetic: it proves the rules behave as designed, **not** a
  real-world detection or false-positive rate. The CNN's published metrics (MODEL_CARD.md) come
  from its own data distribution and over-state real-world precision.
* A model-only detection (a phishing URL with no brand, Unicode or structural tell) is capped
  below the warn threshold on purpose; novel pure-lexical phishing can slip through.
* Links are scored from their URL alone. Redirect chains, shorteners and page content are not
  followed (that needs the server-side engine). Same-site links are not scanned.
* Direct navigation (typing a URL) is only checked if the optional permission is granted.
* Saliency highlights what the *CNN* keyed on, which is not always what a human finds
  incriminating (it often lights up `login`); the rule-based underlines are the authoritative cue.
* Settings-page strings are English-only; reasons missing from a locale fall back to English.
  Translations were written by the project, not native-reviewed.
* Chromium browsers only; tested with Chromium (Playwright) on macOS.
