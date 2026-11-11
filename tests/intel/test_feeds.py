"""Offline tests for threat-feed importers and enrichment connectors.

Every HTTP exchange is served by ``httpx.MockTransport`` through the real
``core.net.safe_fetch`` (so SSRF validation, size caps and header handling are
exercised too); DNS is faked with a resolver returning a public documentation address.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from uniphish.intel import connectors as conn
from uniphish.intel import feeds as F
from uniphish.store import Store

PUBLIC_IP = "93.184.216.34"
SCAN_ID = "0a1b2c3d-1111-2222-3333-444455556666"


async def resolver(host: str, rdtype: str, timeout: float) -> list[str]:
    return [PUBLIC_IP] if rdtype == "A" else []


def transport(handler):
    return httpx.MockTransport(handler)


def serving(
    body: str | bytes, status: int = 200, ctype: str = "text/plain", seen: list | None = None
):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        content = body.encode() if isinstance(body, str) else body
        return httpx.Response(status, content=content, headers={"content-type": ctype})

    return transport(handler)


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def kw(t):
    return {"transport": t, "resolver": resolver}


# =========================================================================== validators
class TestValidators:
    def test_clean_url(self):
        assert F.clean_url(" https://bad.example/login?x=1 ") == "https://bad.example/login?x=1"
        assert F.clean_url('"http://bad.example/"') == "http://bad.example/"
        for bad in [
            "ftp://bad.example/",
            "javascript:alert(1)",
            "http://",
            "not a url",
            "http://bad.example/a b",
            "http://localhost/x",
            "http://10.0.0.1/x",
            "http://bad.example:99999/",
            "http://" + "a" * 3000 + ".example/",
            "",
            None,
            "http://single/x",
        ]:
            assert F.clean_url(bad) is None, bad
        assert F.clean_url("http://93.184.216.34/p") == "http://93.184.216.34/p"

    def test_clean_domain(self):
        assert F.clean_domain("Evil.Example.") == "evil.example"
        assert F.clean_domain("*.evil.example") == "evil.example"
        assert F.clean_domain("bücher.example") == "xn--bcher-kva.example"
        for bad in [
            "localhost",
            "a",
            "1.2.3.4",
            "-bad-.example",
            "a..example",
            "a b.example",
            "x" * 64 + ".example",
            "",
            None,
            "evil.123",
        ]:
            assert F.clean_domain(bad) is None, bad


# =========================================================================== importers
OPENPHISH = """\
https://login-secure.bank-verify.example/a
https://login-secure.bank-verify.example/a
http://10.0.0.5/internal
javascript:alert(1)
# comment
http://paypa1.example/signin
"""


class TestOpenPhish:
    def test_parse_dedups_and_validates(self):
        e = F.OpenPhishFeed().parse(OPENPHISH)
        assert [x.value for x in e] == [
            "https://login-secure.bank-verify.example/a",
            "http://paypa1.example/signin",
        ]
        assert all(x.type == "url" and x.source == "openphish" for x in e)

    async def test_fetch(self):
        seen: list[httpx.Request] = []
        f = F.OpenPhishFeed(**kw(serving(OPENPHISH, seen=seen)))
        entries = await f.fetch()
        assert len(entries) == 2
        assert seen[0].headers["host"] == "openphish.com"
        assert seen[0].url.host == PUBLIC_IP  # SSRF pin applied

    async def test_http_error_raises_feed_error(self):
        f = F.OpenPhishFeed(**kw(serving("nope", status=503)))
        with pytest.raises(F.FeedError, match="http 503"):
            await f.fetch()

    async def test_truncation_drops_partial_last_line(self):
        body = "https://a-phish.example/1\nhttps://b-phish.example/2\nhttps://c-phi"
        f = F.OpenPhishFeed(max_bytes=len(body) - 3, **kw(serving(body)))
        entries = await f.fetch()
        assert f.last_truncated is True
        assert all(e.value.endswith(("/1", "/2")) for e in entries)
        assert not any("c-phi" in e.value for e in entries)

    async def test_max_entries_cap(self):
        body = "\n".join(f"https://p{i}.example/x" for i in range(50))
        f = F.OpenPhishFeed(max_entries=10, **kw(serving(body)))
        assert len(await f.fetch()) == 10
        assert f.last_truncated

    async def test_private_destination_blocked(self):
        f = F.OpenPhishFeed(url="http://127.0.0.1/feed.txt", transport=serving("x"))
        with pytest.raises(F.FeedError, match="blocked"):
            await f.fetch()


URLHAUS_CSV = """\
################################################################
# abuse.ch URLhaus Database Dump (CSV - online URLs only)
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
################################################################
"1","2026-11-01 10:00:00","http://drop.example/bin.sh","online","2026-11-02","malware_download","elf","https://urlhaus.abuse.ch/url/1/","r1"
"2","2026-11-01 11:00:00","http://old.example/x","offline","2026-11-02","malware_download","","https://urlhaus.abuse.ch/url/2/","r1"
"3","2026-11-01 12:00:00","not-a-url","online","","malware_download","","","r1"
"""


class TestUrlhaus:
    def test_parse_csv(self):
        e = F.UrlhausFeed().parse(URLHAUS_CSV)
        assert [x.value for x in e] == ["http://drop.example/bin.sh"]
        assert e[0].first_seen == "2026-11-01T10:00:00Z"
        assert "malware_download" in e[0].reason

    def test_parse_plain_text(self):
        e = F.UrlhausFeed().parse("# t\nhttp://one.example/a\nhttp://two.example/b\n")
        assert len(e) == 2

    async def test_auth_key_header_and_redaction(self):
        seen: list[httpx.Request] = []
        f = F.UrlhausFeed(auth_key="SEKRET-KEY", **kw(serving(URLHAUS_CSV, seen=seen)))
        await f.fetch()
        assert seen[0].headers["auth-key"] == "SEKRET-KEY"
        assert "SEKRET-KEY" not in f.redact("failed with SEKRET-KEY")


PHISHTANK_CSV = (
    "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n"
    "1,http://pt-one.example/login,http://x.test/1,2026-11-03T08:00:00+00:00,yes,2026-11-03T09:00:00+00:00,yes,PayPal\n"
    "2,http://pt-two.example/login,http://x.test/2,2026-11-03T08:00:00+00:00,no,,yes,Other\n"
    "3,http://pt-three.example/login,http://x.test/3,2026-11-03T08:00:00+00:00,yes,,no,Other\n"
    '4,"http://pt-four.example/a,b",http://x.test/4,2026-11-03T08:00:00+00:00,yes,,yes,Other\n'
)


class TestPhishTank:
    def test_parse_only_verified_online(self):
        e = F.PhishTankFeed().parse(PHISHTANK_CSV)
        assert [x.value for x in e] == ["http://pt-one.example/login", "http://pt-four.example/a,b"]
        assert "PayPal" in e[0].reason
        assert e[0].first_seen == "2026-11-03T08:00:00Z"

    def test_bad_format(self):
        with pytest.raises(F.FeedError):
            F.PhishTankFeed().parse("<html>rate limited</html>")

    async def test_app_key_redacted_from_errors(self):
        f = F.PhishTankFeed(app_key="k3y/with+chars", **kw(serving("x", status=509)))
        assert "k3y" in (f.url or "")
        assert "k3y" not in f.display_url
        with pytest.raises(F.FeedError) as ei:
            await f.fetch()
        assert "k3y" not in f.redact(str(ei.value))


HOSTS = """\
# a hosts-style list
0.0.0.0 bad-one.example
127.0.0.1 localhost
bad-two.example
||adblock-bad.example^
bad-two.example
http://url-in-list.example/path
93.184.216.34
10.1.2.3
!comment
not valid!
BÜCHER-evil.example
"""


class TestBlocklist:
    def test_parse_formats(self):
        e = F.BlocklistFeed().parse(HOSTS)
        got = {(x.type, x.value) for x in e}
        assert got == {
            ("domain", "bad-one.example"),
            ("domain", "bad-two.example"),
            ("domain", "adblock-bad.example"),
            ("domain", "url-in-list.example"),
            ("ipv4", "93.184.216.34"),
            ("domain", "xn--bcher-evil-9db.example"),
        }
        assert len(e) == len(got)

    async def test_fetch(self):
        f = F.BlocklistFeed(url="https://lists.example/d.txt", name="mylist", **kw(serving(HOSTS)))
        assert len(await f.fetch()) == 6
        assert f.name == "mylist"


# =========================================================================== STIX / TAXII
def indicator(pattern: str, **extra):
    base = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--" + SCAN_ID,
        "created": "2026-11-01T00:00:00.000Z",
        "modified": "2026-11-01T00:00:00.000Z",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": "2026-11-01T00:00:00Z",
        "name": "phish",
    }
    base.update(extra)
    return base


SHA = "a" * 64


class TestStixPattern:
    def test_simple_terms(self):
        assert F.parse_stix_pattern("[url:value = 'http://bad.example/x']") == [
            ("url", "http://bad.example/x")
        ]
        assert F.parse_stix_pattern("[domain-name:value = 'bad.example']") == [
            ("domain", "bad.example")
        ]
        assert F.parse_stix_pattern("[ipv4-addr:value = '93.184.216.34']") == [
            ("ipv4", "93.184.216.34")
        ]
        assert F.parse_stix_pattern(f"[file:hashes.'SHA-256' = '{SHA}']") == [("sha256", SHA)]

    def test_or_and_in(self):
        p = "[domain-name:value = 'a.example' OR domain-name:value = 'b.example']"
        assert F.parse_stix_pattern(p) == [("domain", "a.example"), ("domain", "b.example")]
        p = "[domain-name:value IN ('c.example','d.example')]"
        assert F.parse_stix_pattern(p) == [("domain", "c.example"), ("domain", "d.example")]

    def test_unsupported_skipped(self):
        for p in [
            "[domain-name:value = 'a.example' AND url:value = 'http://a.example/']",
            "[NOT domain-name:value = 'a.example']",
            "[x-custom:foo = 'bar']",
            "[email-addr:value = 'a@b.example']",
            "[file:name = 'x.exe']",
            "",
            "garbage",
        ]:
            assert F.parse_stix_pattern(p) == [], p

    def test_and_inside_literal_is_fine(self):
        got = F.parse_stix_pattern("[url:value = 'http://bad.example/?a=1 AND b=2']")
        assert got == [("url", "http://bad.example/?a=1 AND b=2")]

    def test_hostile_input_bounded(self):
        assert F.parse_stix_pattern("[url:value = '" + "\\'" * 50_000 + "']") == []
        assert F.parse_stix_pattern("[" + "domain-name:value = 'x' OR " * 100) is not None

    def test_objects_filtering(self):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        objs = [
            indicator("[domain-name:value = 'ok.example']"),
            indicator("[domain-name:value = 'revoked.example']", revoked=True),
            indicator("[domain-name:value = 'expired.example']", valid_until=past),
            indicator("[domain-name:value = 'sigma.example']", pattern_type="sigma"),
            indicator("[ipv4-addr:value = '10.0.0.1']"),
            indicator("[ipv4-addr:value = '93.184.216.0/24']"),
            indicator("[ipv4-addr:value = '93.184.216.35/32']"),
            indicator("[file:hashes.'SHA-256' = 'zz']"),
            {"type": "malware", "pattern": "[domain-name:value = 'm.example']"},
            "junk",
            None,
        ]
        got = {(e.type, e.value) for e in F.parse_stix_objects(objs, "t")}
        assert got == {("domain", "ok.example"), ("ipv4", "93.184.216.35")}


def taxii_server(pages: list[dict], seen: list[httpx.Request]):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        nxt = request.url.params.get("next")
        page = pages[int(nxt) if nxt else 0]
        return httpx.Response(
            200, json=page, headers={"content-type": "application/taxii+json;version=2.1"}
        )

    return transport(handler)


class TestTaxii:
    async def test_pagination_and_headers(self):
        pages = [
            {
                "more": True,
                "next": "1",
                "objects": [indicator("[domain-name:value = 'one.example']")],
            },
            {
                "more": False,
                "objects": [
                    indicator("[url:value = 'http://two.example/p']"),
                    indicator("[domain-name:value = 'one.example']"),
                ],
            },
        ]
        seen: list[httpx.Request] = []
        f = F.TaxiiFeed(
            "https://taxii.example/api1/",
            "col-1",
            token="TOK123",
            added_after="2026-10-01T00:00:00Z",
            **kw(taxii_server(pages, seen)),
        )
        entries = await f.fetch()
        assert {(e.type, e.value) for e in entries} == {
            ("domain", "one.example"),
            ("url", "http://two.example/p"),
        }
        assert len(seen) == 2
        r = seen[0]
        assert r.url.path == "/api1/collections/col-1/objects/"
        assert r.url.params["match[type]"] == "indicator"
        assert r.url.params["added_after"] == "2026-10-01T00:00:00Z"
        assert r.headers["accept"].startswith("application/taxii+json;version=2.1")
        assert r.headers["authorization"] == "Bearer TOK123"
        assert seen[1].url.params["next"] == "1"
        assert "TOK123" not in f.redact("boom TOK123")

    def test_basic_auth_and_bad_collection(self):
        f = F.TaxiiFeed("https://t.example/r", "c1", username="u", password="p")
        assert f.headers["Authorization"].startswith("Basic ")
        assert "p" in f.secrets()
        with pytest.raises(ValueError):
            F.TaxiiFeed("https://t.example/r", "../etc")

    async def test_bad_json_is_feed_error(self):
        f = F.TaxiiFeed("https://t.example/r", "c1", **kw(serving("<html>", ctype="text/html")))
        with pytest.raises(F.FeedError, match="invalid JSON"):
            await f.fetch()

    async def test_page_budget_flags_truncation(self, monkeypatch):
        monkeypatch.setattr(F, "_TAXII_MAX_PAGES", 2)
        n = iter(range(100))

        def handler(request):
            i = next(n)
            return httpx.Response(
                200,
                json={
                    "more": True,
                    "next": str(i),
                    "objects": [indicator(f"[domain-name:value = 'd{i}.example']")],
                },
            )

        f = F.TaxiiFeed("https://t.example/r", "c1", **kw(transport(handler)))
        assert len(await f.fetch()) == 2
        assert f.last_truncated

    def test_parse_plain_bundle(self):
        f = F.TaxiiFeed("https://t.example/r", "c1")
        bundle = {
            "type": "bundle",
            "id": "bundle--" + SCAN_ID,
            "objects": [indicator("[domain-name:value = 'bundle.example']")],
        }
        assert [e.value for e in f.parse(json.dumps(bundle))] == ["bundle.example"]


# =========================================================================== store + orchestration
class TestStoreEntries:
    def test_writes_deny_rows(self, store):
        feed = F.OpenPhishFeed()
        entries = feed.parse(OPENPHISH)
        written, skipped = F.store_entries(store, feed, entries)
        assert (written, skipped) == (2, 0)
        row = store.lookup_reputation("url", "https://login-secure.bank-verify.example/a")
        assert row["verdict"] == "deny"
        assert row["source"] == "feed:openphish"
        assert row["weight"] == feed.weight
        assert row["expires_at"] is not None
        assert store.reputation_counts()["deny"] == 2

    def test_protected_domains_and_allowlist_respected(self, store):
        store.set_reputation("domain", "partner.example", "allow", source="operator")
        feed = F.BlocklistFeed()
        entries = [
            F.FeedEntry("domain", "google.com", "t"),  # top site
            F.FeedEntry("domain", "mail.google.com", "t"),  # subdomain of a top site
            F.FeedEntry("domain", "evil.github.io", "t"),  # LOTS platform
            F.FeedEntry("domain", "partner.example", "t"),  # operator allow
            F.FeedEntry("domain", "truly-bad.example", "t"),
            F.FeedEntry("url", "https://evil.github.io/phish", "t"),  # URLs on LOTS are fine
        ]
        written, skipped = F.store_entries(store, feed, entries)
        assert (written, skipped) == (2, 4)
        assert store.lookup_reputation("domain", "partner.example")["verdict"] == "allow"
        assert store.lookup_reputation("domain", "google.com") is None
        assert store.lookup_reputation("url", "https://evil.github.io/phish")["verdict"] == "deny"

    def test_batches(self, store, monkeypatch):
        monkeypatch.setattr(F, "BATCH_SIZE", 3)
        feed = F.BlocklistFeed()
        entries = [F.FeedEntry("domain", f"bad{i}.example", "t") for i in range(10)]
        assert F.store_entries(store, feed, entries) == (10, 0)
        assert store.reputation_counts()["deny"] == 10


def route(table: dict[str, tuple[int, str]]):
    def handler(request: httpx.Request) -> httpx.Response:
        status, body = table.get(request.headers["host"], (404, ""))
        return httpx.Response(status, content=body.encode())

    return transport(handler)


class TestUpdateAll:
    def feeds(self):
        t = route(
            {
                "openphish.com": (200, OPENPHISH),
                "urlhaus.abuse.ch": (200, URLHAUS_CSV),
                "lists.example": (200, HOSTS),
            }
        )
        return [
            F.OpenPhishFeed(**kw(t)),
            F.UrlhausFeed(**kw(t)),
            F.BlocklistFeed(url="https://lists.example/d.txt", name="bl", **kw(t)),
        ]

    async def test_offline_is_a_noop(self, store):
        s = await F.aupdate_all(False, feeds=self.feeds(), store=store)
        assert not s.online and s.ok
        assert {r.status for r in s.results} == {"skipped"}
        assert store.reputation_counts()["deny"] == 0

    async def test_default_follows_settings_offline(self, store):
        s = await F.aupdate_all(None, feeds=self.feeds(), store=store)
        assert not s.online

    async def test_online_imports_all(self, store):
        s = await F.aupdate_all(True, feeds=self.feeds(), store=store)
        assert s.ok, s.errors
        by = {r.feed: r for r in s.results}
        assert by["openphish"].written == 2
        assert by["urlhaus"].written == 1
        assert by["bl"].written == 6
        assert s.written == 9
        assert store.reputation_counts()["deny"] == 9
        d = s.to_dict()
        assert d["ok"] and len(d["feeds"]) == 3
        assert "openphish" in s.render()

    async def test_error_isolation(self, store):
        t = route({"openphish.com": (500, "boom"), "urlhaus.abuse.ch": (200, URLHAUS_CSV)})
        feeds = [
            F.OpenPhishFeed(**kw(t)),
            F.UrlhausFeed(**kw(t)),
            F.PhishTankFeed(app_key="TOPSECRET", **kw(t)),
        ]
        s = await F.aupdate_all(True, feeds=feeds, store=store)
        by = {r.feed: r for r in s.results}
        assert by["openphish"].status == "error" and "500" in by["openphish"].error
        assert by["urlhaus"].status == "ok" and by["urlhaus"].written == 1
        assert by["phishtank"].status == "error"
        assert "TOPSECRET" not in json.dumps(s.to_dict())
        assert not s.ok and set(s.errors) == {"openphish", "phishtank"}

    async def test_malformed_response_isolated(self, store):
        t = route({"data.phishtank.com": (200, "<html>nope</html>")})
        s = await F.aupdate_all(True, feeds=[F.PhishTankFeed(**kw(t))], store=store)
        assert s.results[0].status == "error"
        assert "format" in s.results[0].error

    async def test_unexpected_exception_isolated(self, store):
        class Boom(F.Feed):
            name = "boom"
            default_url = "https://x.example/"

            async def fetch(self):
                raise RuntimeError("kaboom")

        s = await F.aupdate_all(
            True, feeds=[Boom(), F.OpenPhishFeed(**kw(serving(OPENPHISH)))], store=store
        )
        assert [r.status for r in s.results] == ["error", "ok"]

    async def test_rate_limit_marker_and_force(self, store):
        t = serving(OPENPHISH)
        mk = lambda: [F.OpenPhishFeed(**kw(t))]  # noqa: E731
        first = await F.aupdate_all(True, feeds=mk(), store=store)
        assert first.results[0].status == "ok"
        second = await F.aupdate_all(True, feeds=mk(), store=store)
        assert second.results[0].status == "skipped"
        assert "fresh" in second.results[0].reason
        forced = await F.aupdate_all(True, feeds=mk(), store=store, force=True)
        assert forced.results[0].status == "ok"

    async def test_failed_run_not_marked_fresh(self, store):
        bad = [F.OpenPhishFeed(**kw(serving("x", status=500)))]
        assert (await F.aupdate_all(True, feeds=bad, store=store)).results[0].status == "error"
        good = [F.OpenPhishFeed(**kw(serving(OPENPHISH)))]
        assert (await F.aupdate_all(True, feeds=good, store=store)).results[0].status == "ok"

    def test_sync_wrapper(self, store):
        s = F.update_all(False, feeds=self.feeds(), store=store)
        assert not s.online

    async def test_sync_wrapper_inside_running_loop(self, store):
        s = await asyncio.to_thread(F.update_all, False, feeds=self.feeds(), store=store)
        assert not s.online
        s2 = F.update_all(False, feeds=self.feeds(), store=store)  # called within a loop
        assert not s2.online

    def test_default_feeds(self, monkeypatch):
        monkeypatch.delenv("PHISHTANK_APP_KEY", raising=False)
        names = [f.name for f in F.default_feeds()]
        assert names[:2] == ["openphish", "urlhaus"] and "phishtank" not in names
        monkeypatch.setenv("PHISHTANK_APP_KEY", "abc")
        assert "phishtank" in [f.name for f in F.default_feeds()]

    def test_cli_offline(self, capsys):
        assert F.main([]) == 0
        assert "offline" in capsys.readouterr().out


# =========================================================================== connectors
def vt_doc(mal=3, sus=1, **attrs):
    a = {
        "last_analysis_stats": {
            "malicious": mal,
            "suspicious": sus,
            "harmless": 60,
            "undetected": 10,
        },
        "reputation": -12,
        "last_analysis_date": 1_762_000_000,
        "categories": {"Forcepoint": "phishing", "Sophos": "phishing", "X": "suspicious"},
    }
    a.update(attrs)
    return {"data": {"type": "domain", "attributes": a}}


class TestVirusTotal:
    async def test_no_key_is_noop(self):
        calls: list = []
        c = conn.VirusTotalClient(transport=serving("{}", seen=calls), resolver=resolver)
        for r in (
            await c.lookup_domain("bad.example"),
            await c.lookup_url("http://bad.example/"),
            await c.lookup_file(SHA),
        ):
            assert r.status == "no_key" and not r.ok and not r.available
        assert calls == []

    async def test_domain(self):
        seen: list[httpx.Request] = []
        c = conn.VirusTotalClient(
            "VTKEY",
            transport=serving(json.dumps(vt_doc()), seen=seen, ctype="application/json"),
            resolver=resolver,
        )
        r = await c.lookup_domain("Bad.Example.")
        assert r.ok and r.kind == "domain" and r.indicator == "bad.example"
        assert (r.malicious, r.suspicious, r.harmless, r.undetected) == (3, 1, 60, 10)
        assert r.engines == 74 and r.reputation == -12
        assert r.categories == ("phishing", "suspicious")
        assert r.last_analysis == "2025-11-01T12:26:40Z"
        assert r.is_malicious() and not r.is_malicious(min_engines=5)
        assert seen[0].headers["x-apikey"] == "VTKEY"
        assert seen[0].url.path == "/api/v3/domains/bad.example"
        assert "VTKEY" not in str(seen[0].url)

    async def test_url_identifier(self):
        seen: list[httpx.Request] = []
        c = conn.VirusTotalClient(
            "k", transport=serving(json.dumps(vt_doc()), seen=seen), resolver=resolver
        )
        r = await c.lookup_url("http://bad.example/login")
        assert r.ok
        ident = seen[0].url.path.rsplit("/", 1)[1]
        assert "=" not in ident
        import base64

        assert base64.urlsafe_b64decode(ident + "==") == b"http://bad.example/login"

    async def test_file(self):
        doc = vt_doc(
            type_description="Win32 EXE",
            popular_threat_classification={"suggested_threat_label": "trojan.fake"},
        )
        c = conn.VirusTotalClient("k", transport=serving(json.dumps(doc)), resolver=resolver)
        r = await c.lookup_file(SHA.upper())
        assert r.ok and r.threat_label == "trojan.fake" and r.file_type == "Win32 EXE"
        assert r.permalink.endswith(SHA)

    async def test_not_found_rate_limit_auth_and_garbage(self):
        k = {"resolver": resolver}
        r = await conn.VirusTotalClient(
            "k", transport=serving("{}", status=404), **k
        ).lookup_domain("a.example")
        assert r.status == "not_found" and r.available and not r.ok and r.permalink
        r = await conn.VirusTotalClient(
            "k",
            transport=transport(lambda req: httpx.Response(429, headers={"retry-after": "30"})),
            **k,
        ).lookup_domain("a.example")
        assert r.status == "rate_limited" and r.retry_after == 30.0
        r = await conn.VirusTotalClient(
            "k", transport=serving("{}", status=401), **k
        ).lookup_domain("a.example")
        assert r.status == "error" and "API key" in r.error
        r = await conn.VirusTotalClient("k", transport=serving("<html>"), **k).lookup_domain(
            "a.example"
        )
        assert r.status == "error" and "malformed" in r.error
        r = await conn.VirusTotalClient(
            "k", transport=serving('{"data": {"attributes": {}}}'), **k
        ).lookup_domain("a.example")
        assert r.status == "error" and "shape" in r.error
        r = await conn.VirusTotalClient("k", transport=serving("[1,2]"), **k).lookup_domain(
            "a.example"
        )
        assert r.status == "error"

    async def test_invalid_input(self):
        c = conn.VirusTotalClient("k", transport=serving("{}"), resolver=resolver)
        for r in (
            await c.lookup_domain("not a domain"),
            await c.lookup_domain(""),
            await c.lookup_url("ftp://x.example/"),
            await c.lookup_url("garbage"),
            await c.lookup_file("xyz"),
            await c.lookup_file("g" * 64),
        ):
            assert r.status == "invalid_input" and not r.available

    async def test_cache_hits_only_for_success(self):
        n = {"c": 0}

        def handler(request):
            n["c"] += 1
            return httpx.Response(200, json=vt_doc())

        c = conn.VirusTotalClient("k", transport=transport(handler), resolver=resolver)
        await c.lookup_domain("a.example")
        await c.lookup_domain("a.example")
        assert n["c"] == 1
        n["c"] = 0
        bad = conn.VirusTotalClient(
            "k",
            transport=transport(
                lambda req: (n.__setitem__("c", n["c"] + 1), httpx.Response(500))[1]
            ),
            resolver=resolver,
        )
        await bad.lookup_domain("a.example")
        await bad.lookup_domain("a.example")
        assert n["c"] == 2

    async def test_network_failure_never_raises(self):
        def boom(request):
            raise httpx.ConnectError("down")

        c = conn.VirusTotalClient("k", transport=transport(boom), resolver=resolver)
        r = await c.lookup_domain("a.example")
        assert r.status == "error" and r.error

    async def test_key_from_settings(self, monkeypatch):
        from uniphish.core.config import reset_settings

        monkeypatch.setenv("VT_API_KEY", "envkey")
        reset_settings()
        assert conn.VirusTotalClient().has_key
        monkeypatch.delenv("VT_API_KEY")
        reset_settings()
        assert not conn.VirusTotalClient().has_key

    async def test_private_resolution_is_blocked(self):
        async def priv(host, rdtype, timeout):
            return ["10.0.0.9"] if rdtype == "A" else []

        c = conn.VirusTotalClient("k", transport=serving("{}"), resolver=priv)
        r = await c.lookup_domain("a.example")
        assert r.status == "error" and "blocked" in r.error


class TestUrlscan:
    SEARCH = {
        "total": 2,
        "has_more": False,
        "results": [
            {
                "_id": SCAN_ID,
                "page": {
                    "url": "http://bad.example/x",
                    "domain": "bad.example",
                    "ip": "93.184.216.34",
                    "country": "US",
                    "asn": "AS64500",
                },
                "task": {"time": "2026-11-05T10:00:00.000Z"},
            },
            {"_id": "not-a-uuid", "page": {}},
            "junk",
        ],
    }
    RESULT = {
        "page": {
            "url": "http://bad.example/x",
            "domain": "bad.example",
            "ip": "93.184.216.34",
            "server": "nginx",
        },
        "task": {"time": "2026-11-05T10:00:00.000Z"},
        "verdicts": {
            "overall": {
                "score": 100,
                "malicious": True,
                "categories": ["phishing"],
                "brands": [{"name": "PayPal"}, "Apple", {"name": "PayPal"}],
            }
        },
    }

    async def test_no_key(self):
        c = conn.UrlscanClient(transport=serving("{}"), resolver=resolver)
        assert (await c.search("x")).status == "no_key"
        assert (await c.search_domain("bad.example")).status == "no_key"
        assert (await c.result(SCAN_ID)).status == "no_key"

    async def test_search_parses(self):
        seen: list[httpx.Request] = []
        c = conn.UrlscanClient(
            "US", transport=serving(json.dumps(self.SEARCH), seen=seen), resolver=resolver
        )
        r = await c.search_domain("Bad.Example", size=5)
        assert r.ok and r.total == 2 and len(r.hits) == 1
        h = r.hits[0]
        assert (h.scan_id, h.domain, h.ip, h.country, h.asn) == (
            SCAN_ID,
            "bad.example",
            "93.184.216.34",
            "US",
            "AS64500",
        )
        assert h.report_url.endswith(f"/result/{SCAN_ID}/")
        assert seen[0].headers["api-key"] == "US"
        assert seen[0].url.params["q"] == 'page.domain:"bad.example"'
        assert seen[0].url.params["size"] == "5"

    async def test_result_parses(self):
        c = conn.UrlscanClient("k", transport=serving(json.dumps(self.RESULT)), resolver=resolver)
        r = await c.result(SCAN_ID)
        assert r.ok and r.malicious and r.score == 100
        assert r.brands == ("PayPal", "Apple") and r.categories == ("phishing",)
        assert r.server == "nginx" and r.domain == "bad.example"

    async def test_errors(self):
        k = {"resolver": resolver}
        assert (
            await conn.UrlscanClient("k", transport=serving("x"), **k).result("nope")
        ).status == "invalid_input"
        assert (
            await conn.UrlscanClient("k", transport=serving("{}", status=404), **k).result(SCAN_ID)
        ).status == "not_found"
        assert (
            await conn.UrlscanClient("k", transport=serving("{}", status=404), **k).search("x")
        ).status == "error"
        assert (
            await conn.UrlscanClient("k", transport=serving("[]"), **k).search("x")
        ).status == "error"
        assert (
            await conn.UrlscanClient("k", transport=serving("[]"), **k).result(SCAN_ID)
        ).status == "error"
        assert (
            await conn.UrlscanClient("k", transport=serving("{}"), **k).search("")
        ).status == "invalid_input"
        r = await conn.UrlscanClient("k", transport=serving("{}", status=429), **k).search("x")
        assert r.status == "rate_limited"


class TestSafeBrowsing:
    async def test_no_key_and_invalid(self):
        c = conn.GoogleSafeBrowsingClient(transport=serving("{}"), resolver=resolver)
        assert (await c.lookup("http://bad.example/")).status == "no_key"
        c2 = conn.GoogleSafeBrowsingClient("g", transport=serving("{}"), resolver=resolver)
        assert (await c2.lookup("javascript:1")).status == "invalid_input"

    async def test_unsafe(self):
        seen: list[httpx.Request] = []
        body = json.dumps(
            {
                "threats": [
                    {"threatTypes": ["SOCIAL_ENGINEERING", "MALWARE"]},
                    {"threatType": "UNWANTED_SOFTWARE"},
                    "junk",
                ]
            }
        )
        c = conn.GoogleSafeBrowsingClient(
            "GKEY", transport=serving(body, seen=seen), resolver=resolver
        )
        r = await c.lookup("http://bad.example/a?b=c")
        assert r.is_unsafe and r.threats == ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")
        assert seen[0].headers["x-goog-api-key"] == "GKEY"
        assert "GKEY" not in str(seen[0].url)
        assert seen[0].url.params["urls"] == "http://bad.example/a?b=c"

    async def test_clean_and_malformed(self):
        c = conn.GoogleSafeBrowsingClient("g", transport=serving("{}"), resolver=resolver)
        r = await c.lookup("http://fine.example/")
        assert r.ok and not r.is_unsafe and r.threats == ()
        c = conn.GoogleSafeBrowsingClient("g", transport=serving("not json"), resolver=resolver)
        assert (await c.lookup("http://fine.example/")).status == "error"
        c = conn.GoogleSafeBrowsingClient("g", transport=serving("[1]"), resolver=resolver)
        assert (await c.lookup("http://fine.example/")).status == "error"
        c = conn.GoogleSafeBrowsingClient(
            "g", transport=serving("{}", status=403), resolver=resolver
        )
        assert (await c.lookup("http://fine.example/")).status == "error"
