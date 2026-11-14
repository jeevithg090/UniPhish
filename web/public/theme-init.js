// Applies a saved light/dark choice before first paint (no flash of the wrong theme).
// Kept as a same-origin file because the server's CSP forbids inline scripts.
try {
  var t = localStorage.getItem("uniphish-theme");
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
} catch (e) {}
