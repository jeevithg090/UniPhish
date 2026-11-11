"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { ROOT, readJson } = require("./helpers");

const manifest = readJson("manifest.json");
const exists = (rel) => fs.existsSync(path.join(ROOT, rel));
const shipped = () => {
  const out = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
      const rel = path.join(dir, e.name);
      if (e.isDirectory()) { if (!["test", "tools", "node_modules", "data", "model"].includes(e.name)) walk(rel); }
      else out.push(rel);
    }
  };
  walk(".");
  return out;
};

test("Manifest V3 with a minimal, explicit permission set", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual([...manifest.permissions].sort(), ["activeTab", "contextMenus", "storage"]);
  assert.deepEqual(manifest.optional_permissions, ["webNavigation"]);
  assert.equal(manifest.host_permissions, undefined, "no install-time host permissions");
  assert.ok(manifest.optional_host_permissions.every((p) => /^(https:\/\/\*\/\*|http:\/\/(localhost|127\.0\.0\.1)\/\*)$/.test(p)));
  assert.ok(!manifest.permissions.includes("tabs") && !manifest.permissions.includes("scripting") && !manifest.permissions.includes("webRequest"));
  assert.equal(manifest.web_accessible_resources, undefined, "nothing is exposed to web pages");
  assert.equal(manifest.externally_connectable, undefined);
});

test("content script is limited to web pages, top frame, and has no broad scheme", () => {
  const cs = manifest.content_scripts;
  assert.equal(cs.length, 1);
  assert.deepEqual(cs[0].matches, ["http://*/*", "https://*/*"]);
  assert.notEqual(cs[0].all_frames, true);
  assert.deepEqual(cs[0].js, ["lib/links.js", "content.js"]);
});

test("strict extension-page CSP: no inline script, no eval, no remote script", () => {
  const csp = manifest.content_security_policy.extension_pages;
  assert.match(csp, /script-src 'self'/);
  assert.ok(!/unsafe-inline|unsafe-eval|wasm-unsafe-eval|https?:/.test(csp), csp);
  assert.match(csp, /object-src 'none'/);
});

test("every file named in the manifest exists", () => {
  const refs = [manifest.action.default_popup, manifest.options_ui.page, manifest.background.service_worker,
    ...Object.values(manifest.icons), ...Object.values(manifest.action.default_icon),
    ...manifest.content_scripts.flatMap((c) => [...c.js, ...c.css])];
  for (const r of refs) assert.ok(exists(r), r);
});

test("HTML pages only load local scripts/styles that exist; no inline script", () => {
  for (const page of ["popup.html", "options.html", "interstitial.html"]) {
    const html = fs.readFileSync(path.join(ROOT, page), "utf8");
    for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
      const src = /src="([^"]+)"/.exec(m[1]);
      assert.ok(src, `${page}: inline script`);
      assert.ok(!/^[a-z]+:|^\/\//i.test(src[1]), `${page}: remote script ${src[1]}`);
      assert.ok(exists(src[1]), `${page}: missing ${src[1]}`);
      assert.equal(m[2].trim(), "");
    }
    for (const m of html.matchAll(/<link\b[^>]*href="([^"]+)"/gi)) assert.ok(exists(m[1]) && !/^[a-z]+:/i.test(m[1]), `${page}: ${m[1]}`);
    assert.ok(!/\son\w+\s*=/i.test(html), `${page}: inline event handler`);
    assert.ok(!/javascript:/i.test(html), `${page}: javascript: URL`);
  }
});

test("background importScripts list exists and uses only packaged files", () => {
  const src = fs.readFileSync(path.join(ROOT, "background.js"), "utf8");
  const list = /importScripts\(([\s\S]*?)\);/.exec(src)[1];
  for (const m of list.matchAll(/"([^"]+)"/g)) assert.ok(exists(m[1]), m[1]);
});

test("static scan: no eval/Function/innerHTML/document.write, no remote code, no stray network APIs", () => {
  for (const rel of shipped().filter((f) => f.endsWith(".js"))) {
    const src = fs.readFileSync(path.join(ROOT, rel), "utf8");
    const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
    assert.ok(!/\beval\s*\(/.test(code), `${rel}: eval`);
    assert.ok(!/new\s+Function\s*\(/.test(code), `${rel}: new Function`);
    assert.ok(!/\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write\s*\(/.test(code), `${rel}: HTML sink`);
    assert.ok(!/importScripts\(\s*["']https?:/.test(code), `${rel}: remote importScripts`);
    assert.ok(!/\b(XMLHttpRequest|WebSocket|EventSource|sendBeacon)\b/.test(code), `${rel}: unexpected network API`);
    if (rel !== path.join("lib", "report.js") && rel !== path.join("lib", "boot.js")) {
      assert.ok(!/\bfetch\s*\(/.test(code), `${rel}: fetch outside report.js/boot.js`);
    }
  }
});

test("the only network-capable modules are the optional server client and the local-package loader", () => {
  const boot = fs.readFileSync(path.join(ROOT, "lib/boot.js"), "utf8");
  assert.ok(!/https?:\/\//.test(boot.replace(/\/\/.*$/gm, "")), "boot.js must only fetch packaged files");
  const report = fs.readFileSync(path.join(ROOT, "lib/report.js"), "utf8");
  assert.match(report, /credentials: "omit"/);
  assert.match(report, /redirect: "error"/);
});

test("no leftover legacy demo files that talk to a localhost API", () => {
  assert.ok(!exists("analyze.js"));
  const bg = fs.readFileSync(path.join(ROOT, "background.js"), "utf8");
  assert.ok(!/localhost:8000/.test(bg));
});
