# UniPhish browser extension (demo)

A Manifest V3 extension with two paths:

- **Popup — fully on-device.** The pasted-URL scanner runs the model *inside your
  browser* (`model.js` + `model/weights.bin`, a hand-written forward pass, no
  TensorFlow.js, no server). **No URL ever leaves your device.** It also shows the
  impersonated brand and reasons (`analyze.js`) offline. Status pill: **on-device ●**.
- **Page scanning — via the local API** (optional). Outlining every link on a page is
  too heavy for pure-JS, so it uses the API if running; the popup heatmap does too.

## Run it (on-device popup — no server needed)

1. Export the web model once: `python -m scripts.export_web` (creates `model/`).
2. Load the extension: Chrome → `chrome://extensions` → **Developer mode** →
   **Load unpacked** → select this `extension/` folder.
3. Click the icon; the pill reads **on-device ●**. Try the example URLs — scored in
   your browser, nothing sent anywhere.

## Optional: page scanning + saliency heatmap (needs the API)
```bash
UNIPHISH_MODEL=artifacts/uniphish_adv.keras uvicorn api.server:app --port 8000
```
Then browse any page and risky links get outlined; the popup adds a saliency heatmap.

The content script talks to the API through the background service worker
(so an `https` page can still reach `http://localhost:8000`). If the API is not
running, the extension stays silent — it never blocks your browsing.
