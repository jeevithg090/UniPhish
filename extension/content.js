// Scan every http(s) link on the page and outline the risky ones.
(function () {
  const anchors = Array.from(document.querySelectorAll('a[href^="http"]'));
  if (!anchors.length) return;

  const byUrl = new Map();
  for (const a of anchors) {
    if (!byUrl.has(a.href)) byUrl.set(a.href, []);
    byUrl.get(a.href).push(a);
  }
  const urls = Array.from(byUrl.keys()).slice(0, 300); // safety cap

  chrome.runtime.sendMessage({ type: "scan", urls }, (resp) => {
    if (!resp || !resp.ok) return; // API not running: stay silent
    let blocked = 0, warned = 0;
    for (const r of resp.results) {
      for (const a of byUrl.get(r.url) || []) {
        a.classList.remove("uniphish-warn", "uniphish-block");
        const pct = (r.prob * 100).toFixed(0);
        if (r.tier === "block") {
          a.classList.add("uniphish-block");
          a.title = `⚠ UniPhish: likely phishing (${pct}%)`;
          blocked++;
        } else if (r.tier === "warn") {
          a.classList.add("uniphish-warn");
          a.title = `UniPhish: suspicious (${pct}%)`;
          warned++;
        }
      }
    }
    chrome.runtime.sendMessage({ type: "pageStats", blocked, warned, total: urls.length });
  });
})();
