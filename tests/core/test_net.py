"""Tests for the SSRF-proof network gateway (:mod:`uniphish.core.net`).

Everything here is offline: the resolver is injected and HTTP goes through
``httpx.MockTransport``, so no real socket is ever opened (the suite's conftest would
block it anyway). The focus is the security contract — an attacker-controlled host or
redirect must never reach an internal/metadata address, and no bomb or loop can hang
or exhaust the scanner.
"""

from __future__ import annotations

import asyncio
import gzip
import ipaddress

import httpx
import pytest
from hypothesis import given
from hypothesis import strategies as st

from uniphish.core import net
from uniphish.core.net import FetchResult, is_public_ip, safe_fetch

PUBLIC = "93.184.216.34"  # documentation-style public address used for pinning


def resolver_for(mapping: dict[str, dict[str, list[str]]]):
    """Build an injectable resolver from {host: {'A': [...], 'AAAA': [...]}}."""

    async def _resolve(host: str, rdtype: str, timeout: float) -> list[str]:
        return list(mapping.get(host, {}).get(rdtype, []))

    return _resolve


def const_resolver(ip: str = PUBLIC):
    async def _resolve(host: str, rdtype: str, timeout: float) -> list[str]:
        return [ip] if rdtype == "A" else []

    return _resolve


def ok_transport(capture: dict | None = None, *, status: int = 200,
                 headers: dict | None = None, content: bytes = b"ok") -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if capture is not None:
            capture["host_header"] = request.headers.get("host")
            capture["url_host"] = request.url.host
            capture["sni"] = request.extensions.get("sni_hostname")
            capture["method"] = request.method
        return httpx.Response(status, headers=headers or {}, content=content)

    return httpx.MockTransport(handler)


# --------------------------------------------------------------------- is_public_ip
PUBLIC_IPS = [
    "8.8.8.8", "1.1.1.1", "93.184.216.34", "140.82.121.3",
    "2606:2800:220:1:248:1893:25c8:1946", "2001:4860:4860::8888",
    "::ffff:8.8.8.8",            # IPv4-mapped public
]

NON_PUBLIC_IPS = [
    "0.0.0.0", "0.1.2.3",
    "10.0.0.1", "172.16.5.4", "172.31.255.255", "192.168.1.1",
    "127.0.0.1", "127.255.255.254",
    "169.254.169.254",           # cloud metadata
    "169.254.0.1",
    "100.64.0.1", "100.127.255.255",   # CGNAT
    "192.0.0.1", "192.0.2.5",    # IETF / TEST-NET-1
    "198.18.0.1", "198.19.255.255",    # benchmarking
    "198.51.100.7", "203.0.113.9",     # TEST-NET-2/3
    "224.0.0.1", "239.255.255.250",    # multicast
    "240.0.0.1", "255.255.255.255",    # reserved / broadcast
    "::", "::1",                  # unspecified / loopback
    "fe80::1", "fe80::dead:beef",       # link-local
    "fc00::1", "fd12:3456::1",    # ULA
    "ff02::1",                    # multicast
    "::ffff:127.0.0.1",          # IPv4-mapped loopback
    "::ffff:10.0.0.1",           # IPv4-mapped private
    "64:ff9b::7f00:1",           # NAT64 of 127.0.0.1
    "64:ff9b::808:808",          # NAT64 (prefix blocked outright)
    "2002:0a00:0001::",          # 6to4 wrapping 10.0.0.1
    "2001:db8::1",               # documentation
    "not-an-ip", "", "12345", "999.999.999.999",
]


@pytest.mark.parametrize("ip", PUBLIC_IPS)
def test_public_ips(ip):
    assert is_public_ip(ip) is True


@pytest.mark.parametrize("ip", NON_PUBLIC_IPS)
def test_non_public_ips(ip):
    assert is_public_ip(ip) is False


def test_is_public_ip_accepts_address_objects():
    assert is_public_ip(ipaddress.ip_address("8.8.8.8")) is True
    assert is_public_ip(ipaddress.ip_address("10.0.0.1")) is False


@given(st.integers(min_value=0, max_value=2**32 - 1))
def test_is_public_never_contradicts_flags_v4(value):
    addr = ipaddress.IPv4Address(value)
    if is_public_ip(addr):
        # A public verdict must never be given to a flagged address.
        assert not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


# ----------------------------------------------------------------------- resolve
async def test_resolve_injected():
    r = resolver_for({"a.test": {"A": ["1.2.3.4"], "AAAA": ["2001:4860::1"]}})
    assert await net.resolve("a.test", "A", resolver=r) == ["1.2.3.4"]
    assert await net.resolve_ips("a.test", resolver=r) == ["1.2.3.4", "2001:4860::1"]


async def test_resolve_ips_dedup_and_empty():
    r = resolver_for({"a.test": {"A": ["1.2.3.4", "1.2.3.4"]}})
    assert await net.resolve_ips("a.test", resolver=r) == ["1.2.3.4"]
    assert await net.resolve_ips("absent.test", resolver=r) == []


async def test_set_resolver_override():
    net.set_resolver(const_resolver("5.6.7.8"))
    try:
        assert await net.resolve("whatever.test", "A") == ["5.6.7.8"]
    finally:
        net.set_resolver(None)


# ----------------------------------------------------------------- happy-path fetch
async def test_fetch_pins_ip_and_preserves_host_and_sni():
    cap: dict = {}
    r = await safe_fetch(
        "https://example.com/login?q=1",
        transport=ok_transport(cap, headers={"content-type": "text/html; charset=UTF-8"},
                               content=b"<html>hi</html>"),
        resolver=const_resolver(PUBLIC),
    )
    assert isinstance(r, FetchResult) and r.ok and r.status == 200
    assert cap["url_host"] == PUBLIC           # connected to the pinned IP, not the name
    assert cap["host_header"] == "example.com"  # Host header preserved
    assert cap["sni"] == "example.com"          # TLS verifies against the real hostname
    assert r.ip == PUBLIC
    assert r.content_type == "text/html" and r.charset == "utf-8"
    assert r.text() == "<html>hi</html>"
    assert r.headers.get("content-type") == "text/html; charset=UTF-8"


async def test_http_no_sni_extension():
    cap: dict = {}
    await safe_fetch("http://example.com/", transport=ok_transport(cap),
                     resolver=const_resolver(PUBLIC))
    assert cap["sni"] is None  # plain HTTP has no SNI to override


async def test_ip_literal_fetch_allowed_when_public():
    r = await safe_fetch("https://8.8.8.8/", transport=ok_transport(),
                         resolver=const_resolver(PUBLIC))
    assert r.ok and r.ip == "8.8.8.8"


# --------------------------------------------------------------- SSRF: direct blocks
@pytest.mark.parametrize("url,reason_sub", [
    ("http://127.0.0.1/", "non-public"),
    ("http://169.254.169.254/latest/meta-data/", "non-public"),
    ("http://[::1]/", "non-public"),
    ("http://10.0.0.5/", "non-public"),
    ("https://[fd00::1]/", "non-public"),
])
async def test_direct_private_ip_blocked(url, reason_sub):
    r = await safe_fetch(url, transport=ok_transport(), resolver=const_resolver(PUBLIC))
    assert r.blocked_reason and reason_sub in r.blocked_reason
    assert r.body == b"" and not r.ok


async def test_hostname_resolving_to_private_blocked():
    r = await safe_fetch("https://evil.test/", transport=ok_transport(),
                         resolver=const_resolver("127.0.0.1"))
    assert r.blocked_reason and "non-public" in r.blocked_reason


# The gateway refuses every numeric/obfuscated encoding of an IP, so a loopback or
# metadata address cannot be smuggled past the public-IP check. Some are caught by our
# classifier ("obfuscation"), others are rejected by the URL parser ("invalid url");
# either way the destination is blocked and never fetched.
@pytest.mark.parametrize("host", [
    "2130706433",          # decimal 127.0.0.1
    "0x7f000001",          # hex 127.0.0.1
    "0177.0.0.1",          # octal
    "0x7f.0.0.1",          # dotted hex
    "127.1",               # short form
    "999.1.1.1",           # out of range numeric
])
async def test_numeric_host_obfuscation_blocked(host):
    cap: dict = {}
    r = await safe_fetch(f"http://{host}/", transport=ok_transport(cap),
                         resolver=const_resolver(PUBLIC))
    assert r.blocked_reason and not r.ok
    assert "host_header" not in cap  # the request was never sent to the transport


async def test_classifier_flags_numeric_obfuscation_reason():
    # For the forms the URL parser accepts, our own classifier is what blocks them.
    r = await safe_fetch("http://2130706433/", transport=ok_transport(),
                         resolver=const_resolver(PUBLIC))
    assert r.blocked_reason and "obfuscation" in r.blocked_reason


@pytest.mark.parametrize("url", ["ftp://a.test/", "file:///etc/passwd", "gopher://a.test/"])
async def test_scheme_blocked(url):
    r = await safe_fetch(url, transport=ok_transport(), resolver=const_resolver(PUBLIC))
    assert r.blocked_reason and "scheme" in r.blocked_reason


@pytest.mark.parametrize("port", [22, 25, 3306, 6379, 9200])
async def test_port_blocked(port):
    r = await safe_fetch(f"https://a.test:{port}/", transport=ok_transport(),
                         resolver=const_resolver(PUBLIC))
    assert r.blocked_reason and "port" in r.blocked_reason


async def test_allowed_ports_override():
    r = await safe_fetch("https://a.test:8443/", transport=ok_transport(),
                         resolver=const_resolver(PUBLIC))
    assert r.ok  # 8443 is in the default allow-list


async def test_allow_private_opt_in():
    r = await safe_fetch("http://127.0.0.1/", transport=ok_transport(),
                         resolver=const_resolver(PUBLIC), allow_private=True)
    assert r.ok


# --------------------------------------------------------------- DNS rebinding / pin
async def test_dns_rebinding_public_then_private_is_blocked():
    # A record is public, AAAA record is private: every resolved IP must be public,
    # so the whole destination is refused rather than racing the rebind.
    r = await safe_fetch(
        "https://rebind.test/",
        transport=ok_transport(),
        resolver=resolver_for({"rebind.test": {"A": [PUBLIC], "AAAA": ["::1"]}}),
    )
    assert r.blocked_reason and "non-public" in r.blocked_reason


async def test_connection_uses_pinned_ip_not_name():
    # Even if DNS were to change after validation, the socket targets the pinned IP:
    # the transport only ever sees the IP as the URL host.
    cap: dict = {}
    await safe_fetch("https://late-rebind.test/", transport=ok_transport(cap),
                     resolver=const_resolver(PUBLIC))
    assert cap["url_host"] == PUBLIC
    assert "late-rebind.test" not in str(cap["url_host"])


# ----------------------------------------------------------------------- redirects
def redirect_transport(script: dict[str, httpx.Response]) -> httpx.MockTransport:
    """Map request path -> response (so we can script redirect chains)."""

    def handler(request: httpx.Request) -> httpx.Response:
        return script.get(request.url.path, httpx.Response(200, content=b"end"))

    return httpx.MockTransport(handler)


async def test_redirect_followed_to_public():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "https://a.test/final"})
        return httpx.Response(200, content=b"final page")

    r = await safe_fetch("https://a.test/start", transport=httpx.MockTransport(handler),
                         resolver=const_resolver(PUBLIC))
    assert r.ok and r.body == b"final page"
    assert [h.status for h in r.chain] == [302, 200]


async def test_redirect_to_private_blocked():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://internal.test/admin"})

    r = await safe_fetch(
        "https://a.test/",
        transport=httpx.MockTransport(handler),
        resolver=resolver_for({"a.test": {"A": [PUBLIC]},
                               "internal.test": {"A": ["127.0.0.1"]}}),
    )
    assert r.blocked_reason and "non-public" in r.blocked_reason
    assert r.chain[0].status == 302  # first hop happened, second was refused


async def test_redirect_to_metadata_blocked():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(301, headers={"location": "http://169.254.169.254/"})

    r = await safe_fetch("https://a.test/", transport=httpx.MockTransport(handler),
                         resolver=const_resolver(PUBLIC))
    assert r.blocked_reason and "non-public" in r.blocked_reason


async def test_redirect_loop_detected():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://a.test/"})

    r = await safe_fetch("https://a.test/", transport=httpx.MockTransport(handler),
                         resolver=const_resolver(PUBLIC))
    assert r.error == "redirect loop"


async def test_too_many_redirects():
    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        return httpx.Response(302, headers={"location": f"https://a.test/{counter['n']}"})

    r = await safe_fetch("https://a.test/", transport=httpx.MockTransport(handler),
                         resolver=const_resolver(PUBLIC), max_redirects=3)
    assert r.error == "too many redirects"
    assert len(r.chain) == 4  # initial + 3 followed, then refused


async def test_redirects_disabled_returns_3xx():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://a.test/x"}, content=b"")

    r = await safe_fetch("https://a.test/", transport=httpx.MockTransport(handler),
                         resolver=const_resolver(PUBLIC), follow_redirects=False)
    assert r.status == 302 and r.error is None and r.blocked_reason is None


async def test_cross_origin_redirect_strips_credentials():
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append({"host": request.headers.get("host"),
                     "auth": request.headers.get("authorization"),
                     "cookie": request.headers.get("cookie")})
        if request.headers.get("host") == "a.test":
            return httpx.Response(302, headers={"location": "https://b.test/"})
        return httpx.Response(200, content=b"ok")

    r = await safe_fetch(
        "https://a.test/",
        headers={"Authorization": "Bearer secret", "Cookie": "sid=1"},
        transport=httpx.MockTransport(handler),
        resolver=resolver_for({"a.test": {"A": [PUBLIC]}, "b.test": {"A": ["1.1.1.1"]}}),
    )
    assert r.ok
    assert seen[0]["auth"] == "Bearer secret"       # sent to original origin
    assert seen[1]["auth"] is None                  # stripped cross-origin
    assert seen[1]["cookie"] is None


async def test_set_cookie_not_persisted_across_hops():
    # A Set-Cookie on one hop must never be replayed as a Cookie on the next: the
    # gateway persists no cookies (httpx's own jar is cleared each hop).
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("cookie"))
        if request.url.path == "/start":
            return httpx.Response(
                302,
                headers={"location": "https://a.test/next", "set-cookie": "sid=leak; Path=/"},
            )
        return httpx.Response(200, content=b"ok")

    r = await safe_fetch("https://a.test/start", transport=httpx.MockTransport(handler),
                         resolver=const_resolver(PUBLIC))
    assert r.ok
    assert seen == [None, None]  # the second hop did not carry the cookie forward


# --------------------------------------------------------------------- size / bombs
async def test_raw_byte_cap_truncates_stream():
    async def body():
        for _ in range(200):
            yield b"x" * 10_000  # 2 MB total, streamed in 10 KB chunks

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body())

    r = await safe_fetch("https://a.test/", transport=httpx.MockTransport(handler),
                         resolver=const_resolver(PUBLIC), max_bytes=25_000)
    assert r.truncated
    assert len(r.body) < 2_000_000  # stopped well short of the full stream


async def test_decompression_bomb_capped():
    bomb = gzip.compress(b"A" * 8_000_000)  # ~8 MB from a few KB
    assert len(bomb) < 100_000

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-encoding": "gzip",
                                            "content-type": "text/plain"}, content=bomb)

    r = await safe_fetch("https://a.test/", transport=httpx.MockTransport(handler),
                         resolver=const_resolver(PUBLIC),
                         max_bytes=1_000_000, max_decompressed_bytes=200_000)
    assert r.truncated and len(r.body) <= 200_000


async def test_small_body_not_truncated():
    r = await safe_fetch("https://a.test/", transport=ok_transport(content=b"tiny"),
                         resolver=const_resolver(PUBLIC))
    assert not r.truncated and r.body == b"tiny"


# ----------------------------------------------------------------------- timeouts
async def test_timeout_returns_error_not_raise():
    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200)

    r = await safe_fetch("https://a.test/", transport=httpx.MockTransport(handler),
                         resolver=const_resolver(PUBLIC), timeout=0.15)
    assert r.error == "timeout" and not r.ok


# ------------------------------------------------------------- never raises contract
async def test_connection_error_reported_not_raised():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    r = await safe_fetch("https://a.test/", transport=httpx.MockTransport(handler),
                         resolver=const_resolver(PUBLIC))
    assert r.error and r.error.startswith("connect:") and not r.ok


async def test_invalid_url_blocked_not_raised():
    r = await safe_fetch("https://", transport=ok_transport(), resolver=const_resolver(PUBLIC))
    assert (r.blocked_reason or r.error) and not r.ok


async def test_empty_dns_is_error():
    r = await safe_fetch("https://nowhere.test/", transport=ok_transport(),
                         resolver=resolver_for({}))
    assert r.error and r.error.startswith("dns:")


def test_global_and_host_limiters_are_per_loop():
    # Two separate event loops must each work (semaphores are keyed per loop, so a
    # dead loop's primitive is never reused). Run as a sync test to own the loops.
    async def one():
        return await safe_fetch("https://a.test/", transport=ok_transport(),
                                resolver=const_resolver(PUBLIC))

    r1 = asyncio.run(one())
    r2 = asyncio.run(one())
    assert r1.ok and r2.ok
