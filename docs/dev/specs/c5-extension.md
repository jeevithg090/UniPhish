# Spec: browser extension (Manifest V3, on-device)
OWN: everything under extension/ (you may rewrite the existing demo). Keep/upgrade the
on-device model.js forward pass (it already mirrors the Python CNN). Do NOT depend on a
server for the core verdict — privacy is the product claim ('nothing leaves your device').
tests: a node-based unit test for the JS URL feature/heuristic helper (extension/test/).

Build an MV3 extension that, fully on-device:
- content script: scans links on the page; outlines/annotates risky links (warn/block
  tiers) using an on-device scorer = the byte-CNN (model.js) + a PORT of the key rule
  signals (homoglyph/confusable host via a bundled compact confusables table, '@' trick,
  IP/obfuscated-IP host, punycode, abused TLD, LOTS host, brand homoglyph/typo vs a bundled
  brand list, shortener) fused with the same log-odds idea as the Python scorer. Reuse the
  bundled brands/tlds/lots data (ship compact JSON generated from uniphish/assets — you may
  write a small build step) — keep the extension payload small.
- popup: paste a URL -> on-device verdict with the explainable reason list, impersonated
  brand, char saliency highlight (occlusion using model.js), and a risk gauge. A toggle to
  optionally use a configured UniPhish API for deep analysis (off by default).
- block interstitial: an explainable, localized warning page ('this link uses a Cyrillic
  "а" to look like apple.com') with proceed/back + a report action.
- options page: thresholds, optional API endpoint+key, enable/disable deep scan.
- background service worker: context-menu 'Scan link with UniPhish', badge counts.
Keep manifest permissions minimal; MV3-compliant; no remote code. Document load steps in
extension/README.md. In your summary confirm the data/model bundling approach and size.
