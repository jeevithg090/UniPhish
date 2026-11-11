// Shared DOM rendering helpers for the popup and the warning page.
//
// SECURITY: every string rendered here may come from an attacker (hostnames, look-alike
// characters, brand labels inside reasons).  This module builds DOM nodes and sets
// `textContent` only -- it never uses innerHTML -- so a hostile URL cannot inject markup.

(function (global) {
  "use strict";

  const SVG_NS = "http://www.w3.org/2000/svg";

  function el(tag, props, children) {
    const node = document.createElement(tag);
    if (props) for (const [k, v] of Object.entries(props)) {
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else node.setAttribute(k, v);
    }
    for (const c of children || []) node.appendChild(c);
    return node;
  }

  function svg(tag, attrs) {
    const n = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
    return n;
  }

  /** Semicircular risk gauge (0..1) with warn/block tick marks. Returns an <svg>. */
  function gauge(risk, thresholds, label) {
    const W = 120, H = 70, cx = 60, cy = 60, r = 48;
    const pt = (f, rad) => {
      const a = Math.PI * (1 - f);
      return [cx + rad * Math.cos(a), cy - rad * Math.sin(a)];
    };
    const arc = (f0, f1) => {
      const [x0, y0] = pt(f0, r), [x1, y1] = pt(f1, r);
      return `M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 0 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
    };
    const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H, "aria-hidden": "true" });
    const track = svg("path", { d: arc(0, 1), class: "g-track", fill: "none", "stroke-width": 10, "stroke-linecap": "round" });
    root.appendChild(track);
    const f = Math.max(0.001, Math.min(1, risk));
    const tier = risk >= thresholds.block ? "block" : risk >= thresholds.warn ? "warn" : "safe";
    root.appendChild(svg("path", { d: arc(0, f), class: "g-fill g-" + tier, fill: "none", "stroke-width": 10, "stroke-linecap": "round" }));
    for (const t of [thresholds.warn, thresholds.block]) {
      const [x0, y0] = pt(t, r - 8), [x1, y1] = pt(t, r + 8);
      root.appendChild(svg("line", { x1: x0, y1: y0, x2: x1, y2: y1, class: "g-tick", "stroke-width": 1.5 }));
    }
    const [nx, ny] = pt(f, r - 14);
    root.appendChild(svg("line", { x1: cx, y1: cy, x2: nx, y2: ny, class: "g-needle", "stroke-width": 2.5, "stroke-linecap": "round" }));
    root.appendChild(svg("circle", { cx, cy, r: 4, class: "g-hub" }));
    const text = svg("text", { x: cx, y: cy - 16, "text-anchor": "middle", class: "g-text" });
    text.textContent = String(Math.round(risk * 100));
    root.appendChild(text);
    root.setAttribute("role", "img");
    root.setAttribute("aria-label", label);
    root.removeAttribute("aria-hidden");
    return root;
  }

  /**
   * Render the URL with (a) occlusion-saliency heat per character and (b) look-alike
   * underlines from rule spans.  `spans` are [start,end) UTF-16 ranges into `text`.
   */
  function urlView(container, text, saliency, spans) {
    container.textContent = "";
    const heat = new Map();
    let max = 0;
    if (saliency) for (const c of saliency.chars) { if (c.delta > max) max = c.delta; }
    if (saliency && max > 0.1) for (const c of saliency.chars) if (c.delta > 0) heat.set(c.index, Math.min(1, c.delta / max));
    const mark = new Uint8Array(text.length);
    for (const s of spans || []) if (s) for (let i = Math.max(0, s[0]); i < Math.min(text.length, s[1]); i++) mark[i] = 1;
    let i = 0;
    for (const ch of text) {
      const node = el("span", { text: ch });
      const h = heat.get(i);
      if (h && h > 0.12) node.style.backgroundColor = `rgba(220, 38, 38, ${(0.15 + 0.6 * h).toFixed(2)})`;
      let nonAscii = ch.codePointAt(0) > 0x7f;
      if (mark[i] || nonAscii) node.className = mark[i] ? "mark" : "nonascii";
      if (nonAscii) node.title = "U+" + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
      container.appendChild(node);
      i += ch.length;
    }
    return heat.size > 0;
  }

  /** Rule-signal spans worth underlining (positive evidence located in the URL). */
  function ruleSpans(verdict) {
    return verdict.signals.filter((s) => s.span && s.weight > 0 && s.category !== "ml").map((s) => s.span);
  }

  /** Fill a <ul> with localised reasons, most influential first. */
  function reasonList(ul, i18n, verdict, max) {
    ul.textContent = "";
    // Human-readable order: concrete rule findings first, the opaque model score after them,
    // reassurance (legitimacy evidence) last.
    const rank = (s) => (s.weight > 0 ? (s.category === "ml" ? 1 : 0) : 2);
    const items = verdict.signals.filter((s) => Math.abs(s.contribution || 0) >= 0.05 || s.id === "brand.official")
      .map((s, i) => [s, i]).sort((a, b) => rank(a[0]) - rank(b[0]) || a[1] - b[1]).map((x) => x[0]);
    const shown = items.slice(0, max || 8);
    for (const s of shown) {
      ul.appendChild(el("li", { class: s.weight > 0 ? "bad" : "good", text: i18n.reason(s) }));
    }
    if (!shown.length) ul.appendChild(el("li", { class: "good", text: i18n.t("popup.no_reasons") }));
  }

  /** English reasons for the defanged copy-able report. */
  function englishReasons(verdict) {
    return verdict.signals.filter((s) => s.weight > 0 && (s.contribution || 0) > 0).map((s) => s.detail || s.title);
  }

  const api = { el, gauge, urlView, ruleSpans, reasonList, englishReasons };
  global.UniPhishUI = api;
})(typeof self !== "undefined" ? self : this);
