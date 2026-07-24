// Service worker: talks to the local UniPhish API (content scripts can't hit
// http://localhost from an https page due to mixed-content; the worker can).

const API = "http://localhost:8000";

async function scanBatch(urls) {
  const res = await fetch(`${API}/scan/batch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ urls }),
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "scan") {
    scanBatch(msg.urls)
      .then((results) => sendResponse({ ok: true, results }))
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true; // keep the message channel open for async response
  }
  if (msg.type === "scanOne") {
    scanBatch([msg.url])
      .then((r) => sendResponse({ ok: true, result: r[0] }))
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
  if (msg.type === "health") {
    fetch(`${API}/health`)
      .then((r) => r.json())
      .then((h) => sendResponse({ ok: true, health: h }))
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
});
