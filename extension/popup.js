const $ = (id) => document.getElementById(id);

function setStatus(ok) {
  const el = $("status");
  el.textContent = ok ? "API ● live" : "API ● off";
  el.className = "status " + (ok ? "status--on" : "status--off");
}

function render(result) {
  const box = $("result");
  box.className = "result r-" + result.tier;
  const pct = (result.prob * 100).toFixed(1);
  const label = { safe: "Looks safe", warn: "Suspicious", block: "Likely phishing" }[result.tier];
  box.innerHTML =
    `<div class="label">${label}</div>` +
    `<div class="score">${pct}%</div>` +
    `<div class="u">${result.url}</div>`;
}

function scan(url) {
  if (!url) return;
  chrome.runtime.sendMessage({ type: "scanOne", url }, (resp) => {
    if (!resp || !resp.ok) {
      const box = $("result");
      box.className = "result r-warn";
      box.innerHTML = `<div class="label">API not reachable</div>` +
        `<div class="u">Start it: <code>uvicorn api.server:app --port 8000</code></div>`;
      return;
    }
    render(resp.result);
  });
}

$("scan").addEventListener("click", () => scan($("url").value.trim()));
$("url").addEventListener("keydown", (e) => { if (e.key === "Enter") scan($("url").value.trim()); });
document.querySelectorAll(".ex").forEach((b) =>
  b.addEventListener("click", () => { $("url").value = b.dataset.url; scan(b.dataset.url); })
);

$("rescan").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (tab) chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
  });
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "pageStats") {
    $("pagestats").textContent = `${msg.blocked} blocked · ${msg.warned} warned`;
  }
});

// health check on open
chrome.runtime.sendMessage({ type: "health" }, (resp) => setStatus(resp && resp.ok));
