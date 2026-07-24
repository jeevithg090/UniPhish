# UniPhish browser extension (demo)

A Manifest V3 extension that scans every link on a page with the local UniPhish
model and outlines the risky ones — **red** for likely phishing (`p ≥ 0.9`),
**amber** for suspicious (`p ≥ 0.5`). The popup also scans a pasted URL.

## Run it

1. Start the API with a trained model:
   ```bash
   UNIPHISH_MODEL=artifacts/uniphish_adv.keras uvicorn api.server:app --port 8000
   ```
2. Load the extension: Chrome → `chrome://extensions` → enable **Developer mode**
   → **Load unpacked** → select this `extension/` folder.
3. Click the UniPhish icon. The status pill shows **API ● live** when connected.
   Try the example URLs, or browse any page and watch risky links get outlined.

The content script talks to the API through the background service worker
(so an `https` page can still reach `http://localhost:8000`). If the API is not
running, the extension stays silent — it never blocks your browsing.
