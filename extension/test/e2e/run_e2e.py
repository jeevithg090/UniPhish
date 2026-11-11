#!/usr/bin/env python3
# ruff: noqa: E501  (long selector / URL literals read better on one line)
"""End-to-end smoke test: load the unpacked extension in real Chromium and drive it.

Not part of `npm test` (needs Playwright + a Chromium build); run it manually:

    .venv/bin/python extension/test/e2e/run_e2e.py [--shots DIR]

It serves a synthetic page (reserved .example hosts, never fetched) from 127.0.0.1, then
checks: content-script link marking and tooltips, click interception -> interstitial,
interstitial content / proceed gating, popup verdict rendering and the Settings page.
Exit status 0 = all checks passed.
"""

from __future__ import annotations

import argparse
import http.server
import socketserver
import sys
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

EXT = Path(__file__).resolve().parents[2]
CYR_A = "а"
PAGE = f"""<!doctype html><meta charset="utf-8"><title>UniPhish e2e</title>
<body><h1>Newsletter</h1>
<p><a id="phish" href="https://p{CYR_A}ypal.example/login">Verify your PayPal</a></p>
<p><a id="aitm" href="https://login.microsoftonline.com.evil.example/oauth2/authorize">Open Office</a></p>
<p><a id="ip" href="http://198.51.100.23/x">Download</a></p>
<p><a id="ok" href="https://www.paypal.com/signin">Official sign-in</a></p>
<p><a id="plain" href="https://example.com/">Example</a></p>
<p><a id="same" href="/local">Same site</a></p>
<div id="late"></div>
<script>setTimeout(function(){{var a=document.createElement('a');a.id='dyn';a.href='http://paypal.com@evil.example/';a.textContent='late';document.getElementById('late').appendChild(a);}},1500);</script>
</body>"""

results: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, bool(cond), detail))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--shots", default="", help="directory for screenshots")
    args = ap.parse_args()
    shots = Path(args.shots) if args.shots else None
    if shots:
        shots.mkdir(parents=True, exist_ok=True)

    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    with sync_playwright() as p, tempfile.TemporaryDirectory() as profile:
        ctx = p.chromium.launch_persistent_context(
            profile, channel="chromium", headless=True, viewport={"width": 1000, "height": 800},
            args=[f"--disable-extensions-except={EXT}", f"--load-extension={EXT}"])
        try:
            sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker", timeout=15000)
            ext_id = sw.url.split("/")[2]
            print("extension id:", ext_id)

            # ---- content script -------------------------------------------------------
            page = ctx.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(f"http://127.0.0.1:{port}/")
            page.wait_for_selector("a#phish[data-uniphish]", timeout=15000)
            attr = lambda sel: page.get_attribute(sel, "data-uniphish")  # noqa: E731
            check("homoglyph link marked block", attr("#phish") == "block", str(attr("#phish")))
            check("AiTM-style sub-domain link marked block", attr("#aitm") == "block", str(attr("#aitm")))
            check("raw-IP link marked warn", attr("#ip") == "warn", str(attr("#ip")))
            check("official link untouched", attr("#ok") is None)
            check("neutral link untouched", attr("#plain") is None)
            check("same-site link not scanned", attr("#same") is None)
            title = page.get_attribute("#phish", "title") or ""
            check("tooltip explains the look-alike letter", "Cyrillic" in title and "PayPal" in title, title)
            page.wait_for_selector("a#dyn[data-uniphish]", timeout=10000)
            check("dynamically added link is scanned", attr("#dyn") in ("warn", "block"), str(attr("#dyn")))
            if shots:
                page.screenshot(path=str(shots / "page.png"))
            check("no page errors from the content script", not errors, "; ".join(errors))

            # ---- interception -> interstitial -------------------------------------------
            page.click("#phish", no_wait_after=True)
            page.wait_for_url(f"chrome-extension://{ext_id}/interstitial.html*", timeout=10000)
            page.wait_for_selector("#reasons li", timeout=10000)
            check("interstitial shows the heading", "Dangerous site blocked" in page.inner_text("#title"))
            reasons = page.inner_text("#reasons")
            check("interstitial explains the Cyrillic letter", "Cyrillic" in reasons and "PayPal" in reasons, reasons)
            check("look-alike character is highlighted", page.locator("#urlview .mark").count() > 0)
            check("brand line shown", "PayPal" in page.inner_text("#brand"))
            check("proceed is disabled until confirmed", page.is_disabled("#proceed"))
            page.click("summary:has-text('mistake')")
            page.check("#confirm")
            check("proceed enabled after confirmation", not page.is_disabled("#proceed"))
            if shots:
                page.screenshot(path=str(shots / "interstitial.png"))
            page.go_back()

            # ---- popup ------------------------------------------------------------------
            pop = ctx.new_page()
            pop.set_viewport_size({"width": 420, "height": 760})
            pop.goto(f"chrome-extension://{ext_id}/popup.html?u=" + "http%3A%2F%2Fpaypal.com.secure-login.example%2Fverify")
            pop.wait_for_selector("#reasons li", timeout=10000)
            check("popup verdict is 'Likely phishing'", pop.inner_text("#tier") == "Likely phishing", pop.inner_text("#tier"))
            check("popup names the impersonated brand", "PayPal" in pop.inner_text("#brand"))
            check("popup renders a gauge", pop.locator("#gauge svg").count() == 1)
            check("popup lists reasons", pop.locator("#reasons li").count() >= 2)
            pop.wait_for_function("document.querySelectorAll('#urlview span').length > 10")
            if shots:
                pop.screenshot(path=str(shots / "popup.png"))
            pop.fill("#url", "https://www.paypal.com/signin")
            pop.click("#scan")
            pop.wait_for_function("document.getElementById('tier').textContent === 'Looks safe'", timeout=5000)
            check("popup: official site is safe", "official" in pop.inner_text("#brand").lower())
            pop.fill("#url", f"https://p{CYR_A}ypal.example/login")
            pop.click("#scan")
            pop.wait_for_function("document.getElementById('tier').textContent === 'Likely phishing'", timeout=5000)
            check("popup: Cyrillic homoglyph is flagged with its reason", "Cyrillic" in pop.inner_text("#reasons"))
            check("deep analysis is off by default", not pop.is_checked("#deep-toggle"))

            # ---- options ----------------------------------------------------------------
            opt = ctx.new_page()
            opt.goto(f"chrome-extension://{ext_id}/options.html")
            opt.wait_for_selector("#warn")
            check("options: default thresholds 50/85", opt.input_value("#warn") == "50" and opt.input_value("#block") == "85")
            check("options: deep analysis off", not opt.is_checked("#deepEnabled"))
            opt.select_option("#lang", "es")
            opt.click("#save")
            opt.wait_for_timeout(800)
            opt.reload()
            opt.wait_for_selector("#warn")
            sp = ctx.new_page()
            sp.goto(f"chrome-extension://{ext_id}/popup.html?u=" + "http%3A%2F%2Fpaypal.com.secure-login.example%2Fverify")
            sp.wait_for_selector("#reasons li", timeout=10000)
            check("saved language (es) localises the popup", sp.inner_text("#tier") == "Probable phishing"
                  and sp.inner_text("#scan") == "Analizar", sp.inner_text("#tier"))
            if shots:
                opt.screenshot(path=str(shots / "options.png"))
        finally:
            ctx.close()
            srv.shutdown()

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
