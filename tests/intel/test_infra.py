"""Offline tests for uniphish.intel (DNS, RDAP, TLS, ASN). No real network is used."""

from __future__ import annotations

import asyncio
import datetime as dt
import importlib.util
import json
import ssl
from pathlib import Path

import dns.exception
import pytest

from uniphish.core import net
from uniphish.core.net import FetchResult
from uniphish.intel import asn as asn_mod
from uniphish.intel import dns as dns_mod
from uniphish.intel import rdap as rdap_mod
from uniphish.intel import tls as tls_mod
from uniphish.intel.dns import DNSResult, RRSet, lookup_dns

_spec = importlib.util.spec_from_file_location("infra_test_certs",
                                               Path(__file__).with_name("certs.py"))
certs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(certs)  # type: ignore[union-attr]

NOW = dt.datetime(2026, 11, 10, 12, 0, tzinfo=dt.timezone.utc)


@pytest.fixture(autouse=True)
def _clean():
    dns_mod.clear_cache()
    net.set_resolver(None)
    dns_mod.set_rr_resolver(None)
    yield
    dns_mod.clear_cache()
    net.set_resolver(None)
    dns_mod.set_rr_resolver(None)


def make_rr(table: dict[tuple[str, str], RRSet | Exception]):
    async def rr(host: str, rdtype: str, timeout: float) -> RRSet:
        v = table.get((host, rdtype), RRSet())
        if isinstance(v, Exception):
            raise v
        return v
    return rr


def make_addr(table: dict[tuple[str, str], list[str]]):
    async def res(host: str, rdtype: str, timeout: float) -> list[str]:
        return table.get((host, rdtype), [])
    return res


# =========================================================================== DNS
class TestDNS:
    async def test_basic_records(self):
        rr = make_rr({
            ("login.evil.test", "A"): RRSet(("203.0.113.5",), 300),
            ("login.evil.test", "CNAME"): RRSet(("evil.test",), 60),
            ("evil.test", "MX"): RRSet(("10 mail.evil.test",), 300),
            ("evil.test", "NS"): RRSet(("ns1.evil.test", "ns2.evil.test"), 300),
            ("evil.test", "TXT"): RRSet(("v=spf1 -all",), 300),
        })
        addr = make_addr({("login.evil.test", "A"): ["203.0.113.5"],
                          ("login.evil.test", "AAAA"): ["2001:db8::5"]})
        r = await lookup_dns("Login.Evil.Test.", domain="evil.test", resolver=addr,
                             rr_resolver=rr)
        assert r.host == "login.evil.test"
        assert r.ips == ["203.0.113.5", "2001:db8::5"]
        assert r.a_ttl == 300 and r.cname == ["evil.test"]
        assert r.mx == ["10 mail.evil.test"] and not r.no_mx
        assert r.spf_present and not r.errors
        assert r.to_dict()["a_count"] == 1

    async def test_no_mx_only_when_query_succeeded(self):
        addr = make_addr({("a.test", "A"): ["9.9.9.10"]})
        ok = await lookup_dns("a.test", resolver=addr, rr_resolver=make_rr({}))
        assert ok.no_mx and ok.mx_checked

        failing = make_rr({("a.test", "MX"): dns.exception.Timeout()})
        bad = await lookup_dns("a.test", resolver=addr, rr_resolver=failing)
        assert not bad.no_mx and not bad.mx_checked
        assert bad.errors["MX"] == "timeout"

    async def test_null_mx_counts_as_no_mx(self):
        rr = make_rr({("a.test", "MX"): RRSet(("0 .",), 60)})
        r = await lookup_dns("a.test", resolver=make_addr({}), rr_resolver=rr)
        assert r.no_mx

    async def test_fast_flux_requires_spread_and_low_ttl(self):
        spread = [f"{o}.1.1.1" for o in (11, 22, 33, 44, 55)]
        addr = make_addr({("f.test", "A"): spread})
        r = await lookup_dns("f.test", resolver=addr,
                             rr_resolver=make_rr({("f.test", "A"): RRSet(tuple(spread), 60)}))
        assert r.fast_flux and r.distinct_networks == 5

        high = await lookup_dns("f.test", resolver=addr,
                                rr_resolver=make_rr({("f.test", "A"): RRSet(tuple(spread), 3600)}))
        assert not high.fast_flux

        clustered = [f"203.0.113.{i}" for i in range(1, 7)]
        r3 = await lookup_dns("g.test", resolver=make_addr({("g.test", "A"): clustered}),
                              rr_resolver=make_rr({("g.test", "A"): RRSet(tuple(clustered), 30)}))
        assert not r3.fast_flux  # many addresses, one network: CDN-like

    async def test_parking_indicator(self):
        rr = make_rr({("p.test", "NS"): RRSet(("ns1.sedoparking.com", "ns2.sedoparking.com"))})
        r = await lookup_dns("p.test", resolver=make_addr({}), rr_resolver=rr)
        assert r.is_parked and r.parked[0] == "ns:ns1.sedoparking.com"
        assert not DNSResult(host="x", domain="x", ns=["evilsedoparking.com"]).is_parked

    async def test_resolver_failures_are_errors_not_exceptions(self):
        async def boom(host, rdtype, timeout):
            raise dns.exception.Timeout()
        r = await lookup_dns("z.test", resolver=boom, rr_resolver=make_rr({}))
        assert not r.resolves and r.errors["A"] == "timeout" and r.errors["AAAA"] == "timeout"

    async def test_ip_literal_short_circuits(self):
        r = await lookup_dns("198.51.100.7")
        assert r.a == ["198.51.100.7"]
        r6 = await lookup_dns("[2001:db8::1]")
        assert r6.aaaa == ["2001:db8::1"]

    async def test_cache_used_only_without_injection(self):
        calls = {"n": 0}

        async def counting(host, rdtype, timeout):
            calls["n"] += 1
            return ["1.1.1.1"] if rdtype == "A" else []
        net.set_resolver(counting)
        dns_mod.set_rr_resolver(make_rr({}))
        await lookup_dns("c.test")
        first = calls["n"]
        await lookup_dns("c.test")
        assert calls["n"] == first  # second answer served from cache
        await lookup_dns("c.test", resolver=counting)
        assert calls["n"] > first   # explicit resolver bypasses the cache


# ========================================================================== RDAP
def _doc(reg="2026-11-08T10:00:00Z", **extra):
    d = {
        "objectClassName": "domain", "ldhName": "evil.test",
        "events": [{"eventAction": "registration", "eventDate": reg},
                   {"eventAction": "expiration", "eventDate": "2027-11-08T10:00:00Z"},
                   {"eventAction": "last changed", "eventDate": "2026-11-09T00:00:00Z"}],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.test."}],
        "status": ["client transfer prohibited"],
        "entities": [{"roles": ["registrar"],
                      "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                               ["fn", {}, "text", "Example Registrar"]]]}],
    }
    d.update(extra)
    return d


def _res(body=b"", status=200, **kw):
    base = dict(url="u", final_url="u", status=status, headers={}, body=body, truncated=False,
                chain=[], ip=None, elapsed_ms=1.0, error=None, blocked_reason=None,
                content_type="application/json", charset=None)
    base.update(kw)
    return FetchResult(**base)


class TestRDAP:
    def test_parse(self):
        info = rdap_mod.parse_rdap(_doc(), "evil.test", now=NOW)
        assert info.age_days == 2
        assert info.registrar == "Example Registrar"
        assert info.nameservers == ("ns1.example.test",)
        assert info.expires.year == 2027 and info.status

    def test_future_registration_ignored(self):
        info = rdap_mod.parse_rdap(_doc(reg="2030-01-01T00:00:00Z"), "evil.test", now=NOW)
        assert info.age_days is None and info.registered is None

    def test_date_only_and_missing_event(self):
        assert rdap_mod.parse_rdap(_doc(reg="2020-01-01"), "x.test", now=NOW).age_days > 2000
        info = rdap_mod.parse_rdap({"objectClassName": "domain", "events": []}, "x.test", now=NOW)
        assert info.age_days is None and "no registration event" in info.notes

    def test_not_a_domain_object(self):
        assert rdap_mod.parse_rdap({"objectClassName": "entity"}, "x.test") is None
        assert rdap_mod.parse_rdap([], "x.test") is None

    async def test_domain_age_success_and_disk_cache(self):
        calls: list[str] = []

        async def fetch(url, **kw):
            calls.append(url)
            return _res(json.dumps(_doc()).encode())
        info = await rdap_mod.domain_age("Evil.Test", fetch=fetch, now=NOW)
        assert info.age_days == 2 and calls == ["https://rdap.org/domain/evil.test"]
        again = await rdap_mod.domain_age("evil.test", fetch=fetch, now=NOW)
        assert again.age_days == 2 and again.registrar == "Example Registrar"
        assert len(calls) == 1  # served from DiskCache

    async def test_not_found_returns_none_and_is_negatively_cached(self):
        calls = {"n": 0}

        async def fetch(url, **kw):
            calls["n"] += 1
            return _res(b"{}", status=404)
        assert await rdap_mod.domain_age("nope.test", fetch=fetch) is None
        assert await rdap_mod.domain_age("nope.test", fetch=fetch) is None
        assert calls["n"] == 1

    async def test_bootstrap_fallback(self):
        seen: list[str] = []
        bootstrap = {"services": [[["test"], ["https://rdap.registry.example/"]]]}

        async def fetch(url, **kw):
            seen.append(url)
            if url.startswith("https://rdap.org/"):
                return _res(b"", status=0, error="connect: ConnectError")
            if url == rdap_mod.IANA_BOOTSTRAP_URL:
                return _res(json.dumps(bootstrap).encode())
            return _res(json.dumps(_doc()).encode())
        info = await rdap_mod.domain_age("evil.test", fetch=fetch, now=NOW)
        assert info is not None and info.source == "iana-bootstrap"
        assert seen[-1] == "https://rdap.registry.example/domain/evil.test"

    async def test_failures_degrade_to_none(self):
        async def blocked(url, **kw):
            return _res(b"", status=0, blocked_reason="non-public address")

        async def explode(url, **kw):
            raise RuntimeError("boom")
        assert await rdap_mod.domain_age("evil.test", fetch=blocked, use_cache=False) is None
        assert await rdap_mod.domain_age("evil.test", fetch=explode, use_cache=False) is None

        async def garbage(url, **kw):
            return _res(b"<html>not json</html>")
        assert await rdap_mod.domain_age("evil.test", fetch=garbage, use_cache=False) is None

    @pytest.mark.parametrize("bad", ["", "nodots", "a b.test", "-x.test", "x.test/../y",
                                     "http://evil.test", "a" * 70 + ".test"])
    async def test_rejects_malformed_domains(self, bad):
        async def fetch(url, **kw):  # pragma: no cover - must not be reached
            raise AssertionError("fetched a malformed domain")
        assert await rdap_mod.domain_age(bad, fetch=fetch) is None


# =========================================================================== TLS
class TestHostnameMatching:
    @pytest.mark.parametrize("host,names,ok", [
        ("a.example.com", ["a.example.com"], True),
        ("A.Example.com.", ["a.example.com"], True),
        ("a.example.com", ["*.example.com"], True),
        ("example.com", ["*.example.com"], False),
        ("a.b.example.com", ["*.example.com"], False),
        ("a.example.com", ["*.com"], False),
        ("evil.test", ["evil.test.attacker.test"], False),
        ("a.example.com", ["a*.example.com"], False),
        ("198.51.100.7", ["198.51.100.7"], True),
        ("198.51.100.7", ["*.51.100.7"], False),
        ("a.example.com", [], False),
    ])
    def test_cases(self, host, names, ok):
        assert tls_mod.hostname_matches(host, names) is ok


class TestParseCertificate:
    def test_lets_encrypt_fresh_wildcard(self):
        der, _ = certs.make_cert("evil.test", ["evil.test", "*.evil.test"], issuer_cn="R11",
                                 issuer_org="Let's Encrypt", age_days=2, now=NOW)
        t = tls_mod.parse_certificate(der, "www.evil.test", now=NOW)
        assert t.ok and t.is_lets_encrypt and t.free_ca and not t.self_signed
        assert t.age_days == 2 and t.days_remaining == 88 and not t.expired
        assert t.wildcard and t.san_count == 2 and t.covers_host is True
        assert len(t.cert_sha256) == 64

    def test_self_signed_and_mismatch(self):
        der, _ = certs.make_cert("localhost", ["localhost"], now=NOW)
        t = tls_mod.parse_certificate(der, "bank.test", now=NOW)
        assert t.self_signed and t.covers_host is False and not t.free_ca

    def test_no_san_means_no_cn_fallback(self):
        der, _ = certs.make_cert("bank.test", None, issuer_cn="Some CA", now=NOW)
        t = tls_mod.parse_certificate(der, "bank.test", now=NOW)
        assert t.covers_host is False and "certificate has no subjectAltName" in t.notes

    def test_expired(self):
        der, _ = certs.make_cert("e.test", ["e.test"], issuer_cn="CA", age_days=200,
                                 valid_days=90, now=NOW)
        t = tls_mod.parse_certificate(der, "e.test", now=NOW)
        assert t.expired and t.days_remaining < 0

    @pytest.mark.parametrize("blob", [b"", b"not a cert", b"\x30\x82\xff\xff", b"A" * 100_000])
    def test_garbage_never_raises(self, blob):
        t = tls_mod.parse_certificate(blob, "x.test")
        assert t.error and not t.ok


class TestFetchTls:
    async def test_refuses_private_resolution(self):
        async def connector(*a):  # pragma: no cover - must not connect
            raise AssertionError("connected to a private address")
        t = await tls_mod.fetch_tls(
            "evil.test", resolver=make_addr({("evil.test", "A"): ["10.0.0.5"]}),
            connector=connector)
        assert t.error and t.error.startswith("blocked") and not t.ok

    @pytest.mark.parametrize("host", ["2130706433", "0x7f.0.0.1", "127.1"])
    async def test_refuses_numeric_obfuscation(self, host):
        t = await tls_mod.fetch_tls(host)
        assert t.error and t.error.startswith("blocked")

    async def test_refuses_loopback_and_metadata_literals(self):
        for ip in ("127.0.0.1", "169.254.169.254", "[::1]"):
            t = await tls_mod.fetch_tls(ip)
            assert t.error and t.error.startswith("blocked"), ip

    async def test_port_allowlist(self):
        t = await tls_mod.fetch_tls("evil.test", port=22, ips=["9.9.9.10"])
        assert t.error and "port" in t.error

    async def test_mixed_public_and_private_refused(self):
        t = await tls_mod.fetch_tls("evil.test", ips=["9.9.9.10", "192.168.1.1"],
                                    connector=lambda *a: None)  # type: ignore[arg-type]
        assert t.error and "non-public" in t.error

    async def test_verified_path_pins_ip_and_sends_sni(self):
        der, _ = certs.make_cert("ok.test", ["ok.test"], issuer_cn="CA", age_days=40, now=NOW)
        seen = []

        async def connector(ip, port, name, verify, timeout):
            seen.append((ip, port, name, verify))
            return der
        t = await tls_mod.fetch_tls("ok.test", ips=["8.8.4.4", "8.8.8.8"],
                                    connector=connector, now=NOW)
        assert t.ok and t.verified and t.verify_error is None
        assert seen == [("8.8.4.4", 443, "ok.test", True)]  # pinned first IP, SNI = host
        assert t.ip == "8.8.4.4"

    async def test_unverified_fallback_reads_cert_and_reports_reason(self):
        der, _ = certs.make_cert("bank.test", ["bank.test"], now=NOW)
        modes = []

        async def connector(ip, port, name, verify, timeout):
            modes.append(verify)
            if verify:
                err = ssl.SSLCertVerificationError(1, "self-signed certificate")
                err.verify_message = "self-signed certificate"
                raise err
            return der
        t = await tls_mod.fetch_tls("bank.test", ips=["8.8.4.4"], connector=connector,
                                    now=NOW)
        assert modes == [True, False]
        assert t.ok and not t.verified and t.verify_error == "self-signed certificate"
        assert t.self_signed

    @pytest.mark.parametrize("exc,expect", [
        (asyncio.TimeoutError(), "timeout"),
        (ConnectionRefusedError(), "connect: ConnectionRefusedError"),
        (ssl.SSLError("handshake"), "tls: SSLError"),
        (RuntimeError("x"), "unexpected: RuntimeError"),
    ])
    async def test_failures_become_error_field(self, exc, expect):
        async def connector(*a):
            raise exc
        t = await tls_mod.fetch_tls("x.test", ips=["8.8.4.4"], connector=connector)
        assert t.error == expect and not t.ok

    async def test_real_handshake_against_local_self_signed_server(self, tmp_path):
        der, key_pem = certs.make_cert("localhost", ["localhost"], now=dt.datetime.now(
            dt.timezone.utc))
        (tmp_path / "c.pem").write_bytes(certs.der_to_pem(der))
        (tmp_path / "k.pem").write_bytes(key_pem)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")

        async def handle(reader, writer):
            writer.close()
        server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=sctx)
        port = server.sockets[0].getsockname()[1]
        try:
            t = await tls_mod.fetch_tls("localhost", port=port, ips=["127.0.0.1"],
                                        allow_private=True, allowed_ports=frozenset({port}),
                                        timeout=5.0)
        finally:
            server.close()
            await server.wait_closed()
        assert t.ok, t.error
        assert t.self_signed and not t.verified and t.verify_error
        assert t.covers_host is True and t.cert_sha256 is not None


# =========================================================================== ASN
class TestASN:
    def test_reverse_names(self):
        assert asn_mod._reverse_name("8.8.4.4") == "4.4.8.8.origin.asn.cymru.com"
        v6 = asn_mod._reverse_name("2001:4860:4860::8888")
        assert v6.endswith(".origin6.asn.cymru.com") and v6.startswith("8.8.8.8.0.0.0.0")
        assert asn_mod._reverse_name("nope") is None

    def test_classify(self):
        assert asn_mod.classify_asn(13335, "CLOUDFLARENET, US")[:2] == (True, "Cloudflare")
        h, p, abuse, res, note = asn_mod.classify_asn(44477, "STARK-INDUSTRIES, GB")
        assert abuse and h and "abuse" in note
        h, p, abuse, res, note = asn_mod.classify_asn(64500, "Example Broadband Ltd, XX")
        assert res and not h and not abuse
        h, p, abuse, res, _ = asn_mod.classify_asn(64501, "Acme Cloud Hosting GmbH, DE")
        assert h and not res
        assert asn_mod.classify_asn(64502, None) == (False, None, False, False, None)

    async def test_lookup_maps_origin_and_name(self):
        rr = make_rr({
            ("4.4.8.8.origin.asn.cymru.com", "TXT"):
                RRSet(('"15169 | 8.8.4.0/24 | US | arin | 2023-12-28"',), 60),
            ("as15169.asn.cymru.com", "TXT"):
                RRSet(('"15169 | US | arin | 2000-03-30 | GOOGLE, US"',), 60),
        })
        a = await asn_mod.lookup_asn("8.8.4.4", rr_resolver=rr)
        assert a.asn == 15169 and a.prefix == "8.8.4.0/24" and a.country == "US"
        assert a.org == "GOOGLE, US" and a.is_hosting and a.hosting_provider == "Google"
        assert a.label == "AS15169 GOOGLE, US"

    async def test_multi_asn_origin_takes_first_and_caches(self):
        calls = {"n": 0}

        async def rr(host, rdtype, timeout):
            calls["n"] += 1
            if host.endswith("origin.asn.cymru.com"):
                return RRSet(('"64500 64501 | 198.51.100.0/24 | NL | ripencc | 2020-01-01"',))
            return RRSet(('"64500 | NL | ripencc | 2010-01-01 | EXAMPLE-NET Telecom, NL"',))
        a = await asn_mod.lookup_asn("1.1.1.1", rr_resolver=rr)
        assert a.asn == 64500 and a.is_residential_like
        n = calls["n"]
        b = await asn_mod.lookup_asn("1.1.1.1", rr_resolver=rr)
        assert b.asn == 64500 and calls["n"] == n  # disk-cached

    async def test_non_public_ip_is_never_queried(self):
        async def rr(*a):  # pragma: no cover - must not be reached
            raise AssertionError("queried DNS for a private address")
        for ip in ("10.1.2.3", "127.0.0.1", "169.254.169.254", "garbage", ""):
            assert await asn_mod.lookup_asn(ip, rr_resolver=rr) is None

    async def test_lookup_failures_return_none(self):
        async def rr(host, rdtype, timeout):
            raise dns.exception.Timeout()
        assert await asn_mod.lookup_asn("1.1.1.1", rr_resolver=rr) is None
        assert await asn_mod.lookup_asn("1.0.0.1", rr_resolver=make_rr({})) is None

    async def test_name_lookup_failure_still_maps_asn(self):
        async def rr(host, rdtype, timeout):
            if host.endswith("origin.asn.cymru.com"):
                return RRSet(('"64510 | 198.51.100.0/24 | US | arin | 2020-01-01"',))
            raise dns.exception.Timeout()
        a = await asn_mod.lookup_asn("9.9.9.9", rr_resolver=rr)
        assert a.asn == 64510 and a.org is None
