const $ = (id) => document.getElementById(id);

function setStatus(ok) {
  const el = $("status");
  el.textContent = ok ? "API ● live" : "API ● off";
  el.className = "status " + (ok ? "status--on" : "status--off");
}

function esc(s) {
  return s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function heatmap(sal) {
  if (!sal || !sal.chars || !sal.chars.length) return "";
  const max = Math.max(0.0001, ...sal.chars.map((c) => c.weight));
  const spans = sal.chars
    .map((c) => {
      const a = Math.max(0, Math.min(1, c.weight / max));
      const bg = a > 0.05 ? `background:rgba(239,68,68,${a.toFixed(2)})` : "";
      return `<span style="${bg}">${esc(c.char)}</span>`;
    })
    .join("");
  return `<div class="heat" title="Redder = pushed the verdict toward phishing">${spans}</div>`;
}

function render(r) {
  const box = $("result");
  box.className = "result r-" + r.tier;
  const pct = (r.prob * 100).toFixed(1);
  const label = { safe: "Looks safe", warn: "Suspicious", block: "Likely phishing" }[r.tier];

  let html = `<div class="head"><span class="label">${label}</span><span class="score">${pct}%</span></div>`;

  if (r.brand) {
    const verb = { homoglyph: "disguised as", typo: "lookalike of", subdomain: "hides real domain from" }[r.brand.type] || "impersonates";
    html += `<div class="brand">🎯 ${verb} <b>${esc(r.brand.brand)}</b></div>`;
  }
  html += heatmap(r.saliency);
  if (r.reasons && r.reasons.length) {
    html += "<ul class='reasons'>" +
      r.reasons.map((x) => `<li class="sev-${x.severity}">${esc(x.text)}</li>`).join("") +
      "</ul>";
  }
  box.innerHTML = html;
}

function scan(url) {
  if (!url) return;
  $("result").className = "result r-warn";
  $("result").innerHTML = "<div class='head'><span class='label'>Scanning…</span></div>";
  chrome.runtime.sendMessage({ type: "explainOne", url }, (resp) => {
    if (!resp || !resp.ok) {
      $("result").className = "result r-warn";
      $("result").innerHTML =
        `<div class="label">API not reachable</div>` +
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

chrome.runtime.sendMessage({ type: "health" }, (resp) => setStatus(resp && resp.ok));
