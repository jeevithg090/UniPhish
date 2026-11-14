"""Sandboxed headless-browser detonation of a URL or inline HTML (optional dependency).

Why this exists
---------------
Modern phishing is JavaScript-built: the credential form, the ClickFix clipboard write,
the Browser-in-the-Browser window and the client-side redirect to the real kit only
exist *after* the page runs. A purely static fetch (``uniphish.core.net.safe_fetch``)
never sees them, and cloaking kits deliberately serve a benign document to scanners and
assemble the attack in the DOM. This module renders the page in a **hardened, sandboxed
Playwright/Chromium** instance and reports what actually happened — the rendered DOM,
any clipboard writes, the navigation chain, console errors and an optional screenshot —
as inert data for the fetch analyzer to reason about.

Safety properties
-----------------
* **Nothing is executed on the host.** Only the browser runs the page, in its own
  sandbox (we never pass ``--no-sandbox`` unless an operator opts in via
  ``UNIPHISH_DETONATE_NO_SANDBOX``); downloads are refused, dialogs auto-dismissed.
* **No file: access and no SSRF.** A request router aborts ``file:`` / ``chrome:`` and
  any request to a loopback/private literal address, and — unless the caller enables
  sub-resources — every non-navigation request, so a detonation does not become an
  exfiltration or metadata-endpoint proxy.
* **Time- and size-bounded, fault-isolated.** The whole render runs under a hard
  deadline; the rendered DOM is truncated; the function never raises — a missing
  dependency, a launch failure or a navigation error is reported in ``error``.

This module is imported tolerantly by :mod:`uniphish.analyzers.fetch`; when Playwright
(or its browser) is absent, detonation is skipped with a note rather than breaking the
engine.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import os
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from uniphish.core.config import get_settings
from uniphish.core.net import is_public_ip

log = logging.getLogger("uniphish.intel.detonate")

__all__ = [
    "DetonationResult",
    "detonate",
    "playwright_available",
    "DEFAULT_TIMEOUT_S",
]

# --------------------------------------------------------------------------- limits
DEFAULT_TIMEOUT_S = 12.0
_SETTLE_MS = 1_200  # time granted to in-page JS after DOMContentLoaded
_MAX_DOM_CHARS = 3_000_000
_MAX_HTML_CHARS = 3_000_000
_MAX_CONSOLE = 50
_MAX_NAV = 25
_MAX_CLIPBOARD = 25
_MAX_DIALOGS = 25
_MAX_DOWNLOADS = 25
_DEADLINE_SLACK = 2.0  # launch/teardown grace on top of the render deadline

# Chromium flags that harden the instance without weakening its sandbox.
_HARDENED_ARGS: tuple[str, ...] = (
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-extensions",
    "--disable-features=TranslateUI,site-per-process",
    "--mute-audio",
    "--disable-background-timer-throttling",
    "--disable-renderer-backgrounding",
)

# Hostnames that must never be reached even if they are not IP literals.
_BLOCKED_NAMES = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "metadata", "metadata.google.internal"}
)
_ALLOWED_SCHEMES = frozenset({"http", "https", "data", "blob", "about"})

# Injected before any page script: records clipboard writes to a page global we read
# back after the render. We *replace* the clipboard API so capture works even in the
# insecure/opaque origins (``data:``, ``about:blank``) that set_content / inline HTML use.
_HOOK_JS = r"""
(() => {
  try {
    window.__uniphish_clip__ = [];
    const rec = (t) => {
      try {
        if (window.__uniphish_clip__.length < 64) {
          window.__uniphish_clip__.push(String(t).slice(0, 2048));
        }
      } catch (e) {}
    };
    try {
      const cb = {
        writeText: (t) => { rec(t); return Promise.resolve(); },
        write: () => { rec('[clipboard-item]'); return Promise.resolve(); },
        readText: () => Promise.resolve(''),
        read: () => Promise.resolve([]),
      };
      Object.defineProperty(navigator, 'clipboard', { value: cb, configurable: true });
    } catch (e) {}
    const orig = document.execCommand ? document.execCommand.bind(document) : null;
    document.execCommand = function (cmd) {
      try {
        if (String(cmd).toLowerCase() === 'copy') {
          const sel = (window.getSelection && window.getSelection().toString()) || '';
          rec(sel || '[execCommand copy]');
        }
      } catch (e) {}
      try { return orig ? orig.apply(document, arguments) : false; } catch (e) { return false; }
    };
  } catch (e) {}
})();
"""


@dataclass(slots=True)
class DetonationResult:
    """What a detonation observed. ``error`` is set on any failure; never raised."""

    start_url: str
    final_url: str | None = None
    dom_html: str = ""
    title: str = ""
    clipboard_writes: list[str] = field(default_factory=list)
    navigation_chain: list[str] = field(default_factory=list)
    console_errors: list[str] = field(default_factory=list)
    dialogs: list[str] = field(default_factory=list)
    download_urls: list[str] = field(default_factory=list)
    screenshot_path: str | None = None
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        """True when the page rendered without a launch/navigation error."""
        return self.error is None

    @property
    def redirected(self) -> bool:
        """True when script navigated the top frame away from the entry URL."""
        return bool(
            self.final_url
            and self.start_url
            and self.final_url != self.start_url
            and not self.start_url.startswith("data:")
        )


def playwright_available() -> bool:
    """True if the Playwright Python package is importable (browser may still be absent)."""
    try:
        import playwright.async_api  # noqa: F401
    except Exception:  # pragma: no cover - environment-dependent
        return False
    return True


def _no_sandbox() -> bool:
    return os.environ.get("UNIPHISH_DETONATE_NO_SANDBOX", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _launch_args() -> list[str]:
    args = list(_HARDENED_ARGS)
    if _no_sandbox():  # pragma: no cover - CI/container escape hatch only
        args.append("--no-sandbox")
    return args


def _host_is_blocked(url: str, *, allow_private: bool) -> bool:
    """True if a request to ``url`` must be aborted (file:/private host/SSRF guard)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    scheme = (parts.scheme or "").lower()
    if scheme in ("data", "blob", "about"):
        return False
    if scheme not in _ALLOWED_SCHEMES:
        return True
    host = (parts.hostname or "").strip().strip("[]").rstrip(".").lower()
    if not host:
        return True
    if allow_private:
        return False
    if host in _BLOCKED_NAMES:
        return True
    # Literal IPs that are not globally routable are refused; names are resolved by the
    # browser and cannot be pinned here, so hostile DNS is a documented residual risk of
    # the active-detonation path (mitigated by the per-request navigation-only policy).
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return not is_public_ip(host)


def _data_url(html: str) -> str:
    raw = html[:_MAX_HTML_CHARS].encode("utf-8", "replace")
    return "data:text/html;charset=utf-8;base64," + base64.b64encode(raw).decode("ascii")


async def detonate(
    *,
    url: str | None = None,
    html: str | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    settle_ms: int = _SETTLE_MS,
    capture_screenshot: bool = False,
    screenshot_path: str | None = None,
    allow_subresources: bool = False,
    allow_private: bool = False,
    user_agent: str | None = None,
) -> DetonationResult:
    """Render ``url`` (or inline ``html``) in a sandboxed browser and report what it did.

    Exactly one of ``url`` / ``html`` must be given. ``allow_subresources`` lets the page
    load external scripts/styles/images (off by default, so a detonation stays close to
    "offline" and cannot be used to exfiltrate); ``allow_private`` lifts the loopback /
    private-address block (trusted local targets only). Never raises: inspect ``error``.
    """
    if (url is None) == (html is None):
        return DetonationResult(
            start_url=url or "(inline)", error="exactly one of url/html required"
        )
    start_url = url if url is not None else "(inline html)"
    target = url if url is not None else _data_url(html or "")

    if not playwright_available():
        return DetonationResult(start_url=start_url, error="playwright not installed")

    try:
        return await asyncio.wait_for(
            _run(
                start_url=start_url,
                target=target,
                timeout_s=max(1.0, timeout_s),
                settle_ms=max(0, settle_ms),
                capture_screenshot=capture_screenshot,
                screenshot_path=screenshot_path,
                allow_subresources=allow_subresources,
                allow_private=allow_private,
                user_agent=user_agent or get_settings().user_agent,
            ),
            timeout=max(1.0, timeout_s) + _DEADLINE_SLACK,
        )
    except (asyncio.TimeoutError, TimeoutError):
        return DetonationResult(start_url=start_url, error="timeout")
    except Exception as exc:  # the engine must never see a detonation raise
        log.warning("detonate(%s) failed: %r", start_url, exc)
        return DetonationResult(start_url=start_url, error=f"unexpected: {type(exc).__name__}")


async def _run(
    *,
    start_url: str,
    target: str,
    timeout_s: float,
    settle_ms: int,
    capture_screenshot: bool,
    screenshot_path: str | None,
    allow_subresources: bool,
    allow_private: bool,
    user_agent: str,
) -> DetonationResult:
    from playwright.async_api import async_playwright

    res = DetonationResult(start_url=start_url)
    nav: list[str] = []
    console: list[str] = []
    dialogs: list[str] = []
    downloads: list[str] = []
    goto_ms = int(timeout_s * 1000)
    t0 = time.monotonic()

    async def _route(route, request) -> None:
        try:
            if _host_is_blocked(request.url, allow_private=allow_private):
                await route.abort()
                return
            if not allow_subresources and not request.is_navigation_request():
                await route.abort()
                return
            await route.continue_()
        except Exception:  # pragma: no cover - routing races on teardown
            with _suppress():
                await route.abort()

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=_launch_args())
        try:
            context = await browser.new_context(
                accept_downloads=False,
                java_script_enabled=True,
                service_workers="block",
                user_agent=user_agent,
                ignore_https_errors=True,
            )
            await context.add_init_script(_HOOK_JS)
            await context.route("**/*", _route)
            page = await context.new_page()

            def _on_nav(frame) -> None:
                if frame is page.main_frame and len(nav) < _MAX_NAV:
                    nav.append(frame.url)

            def _on_console(msg) -> None:
                if msg.type == "error" and len(console) < _MAX_CONSOLE:
                    console.append(str(msg.text)[:500])

            def _on_pageerror(err) -> None:
                if len(console) < _MAX_CONSOLE:
                    console.append(str(err)[:500])

            async def _on_dialog(dialog) -> None:
                if len(dialogs) < _MAX_DIALOGS:
                    dialogs.append(f"{dialog.type}: {str(dialog.message)[:300]}")
                with _suppress():
                    await dialog.dismiss()

            def _on_download(download) -> None:
                if len(downloads) < _MAX_DOWNLOADS:
                    downloads.append(str(download.url)[:2048])

            page.on("framenavigated", _on_nav)
            page.on("console", _on_console)
            page.on("pageerror", _on_pageerror)
            page.on("dialog", _on_dialog)
            page.on("download", _on_download)

            try:
                await page.goto(target, wait_until="domcontentloaded", timeout=goto_ms)
            except Exception as exc:
                res.error = f"navigation: {type(exc).__name__}"

            if settle_ms:
                with _suppress():
                    await page.wait_for_timeout(settle_ms)

            with _suppress():
                res.dom_html = (await page.content())[:_MAX_DOM_CHARS]
            with _suppress():
                res.title = str(await page.title())[:300]
            with _suppress():
                clip = await page.evaluate("window.__uniphish_clip__ || []")
                if isinstance(clip, list):
                    res.clipboard_writes = [str(c)[:2048] for c in clip[:_MAX_CLIPBOARD]]
            with _suppress():
                res.final_url = page.url
            if capture_screenshot and screenshot_path:
                with _suppress():
                    await page.screenshot(path=screenshot_path, full_page=False)
                    res.screenshot_path = screenshot_path
        finally:
            with _suppress():
                await browser.close()

    res.navigation_chain = nav
    res.console_errors = console
    res.dialogs = dialogs
    res.download_urls = downloads
    if res.final_url is None and nav:
        res.final_url = nav[-1]
    res.elapsed_ms = round((time.monotonic() - t0) * 1000, 2)
    return res


class _suppress:
    """Async-aware ``contextlib.suppress(Exception)`` that logs at debug level."""

    def __enter__(self) -> _suppress:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None and not issubclass(exc_type, (KeyboardInterrupt, SystemExit)):
            log.debug("detonate: suppressed %s", exc_type.__name__)
            return True
        return False
