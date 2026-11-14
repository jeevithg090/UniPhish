"""Offline tests for the outbound verdict sinks (no real network, no real endpoints)."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import io
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from uniphish.core.net import FetchResult
from uniphish.core.types import (
    Action,
    ArtifactKind,
    BrandMatch,
    Indicator,
    IndicatorType,
    Level,
    Signal,
    Verdict,
)
from uniphish.integrations import sinks as sinks_mod
from uniphish.integrations.sinks import (
    ElasticSink,
    FileSink,
    SinkError,
    SlackSink,
    SplunkHECSink,
    StdoutSink,
    StoreSink,
    WebhookSink,
    coerce_level,
    fan_out,
    slack_payload,
)
from uniphish.store import Store

PUBLIC_IP = "93.184.216.34"  # example.com's documentation-grade public address
TARGET = "https://login.paypa1-secure.test/signin?next=%2Fhome"


def make_verdict(
    level: Level = Level.MALICIOUS,
    score: int = 96,
    *,
    target: str = TARGET,
    brand: bool = True,
    summary: str | None = None,
    vid: str | None = None,
) -> Verdict:
    action = {
        Level.MALICIOUS: Action.BLOCK,
        Level.SUSPICIOUS: Action.WARN,
        Level.BENIGN: Action.ALLOW,
    }[level]
    kwargs = {} if vid is None else {"id": vid}
    return Verdict(
        kind=ArtifactKind.URL,
        target=target,
        artifact_id="a" * 24,
        risk=score / 100,
        score=score,
        logit=3.2,
        level=level,
        action=action,
        confidence=0.9,
        summary=summary
        if summary is not None
        else f"Looks like a PayPal phish at {target} reported by victim@example.com",
        signals=[
            Signal(
                id="url.homoglyph",
                title="Domain imitates PayPal with a digit look-alike",
                detail=f"Host in {target}",
                weight=4.0,
                category="url",
                evidence={"url": target, "host": "login.paypa1-secure.test"},
                mitre=["T1566.002"],
            )
        ],
        indicators=[
            Indicator(type=IndicatorType.URL, value=target, role="landing", malicious=True),
            Indicator(type=IndicatorType.DOMAIN, value="login.paypa1-secure.test", malicious=True),
        ],
        brand=BrandMatch(
            brand="paypal",
            name="PayPal",
            technique="homoglyph",
            confidence=0.9,
            legit_domains=["paypal.com"],
        )
        if brand
        else None,
        techniques=["homoglyph"],
        **kwargs,
    )


async def _public_resolver(host: str, rdtype: str, timeout: float) -> list[str]:
    return [PUBLIC_IP] if rdtype == "A" else []


def _private_resolver(ip: str):
    async def resolver(host: str, rdtype: str, timeout: float) -> list[str]:
        return [ip] if rdtype == "A" else []

    return resolver


class Recorder:
    """A mock HTTP endpoint (httpx.MockTransport) recording every request it receives."""

    def __init__(self, *responses: httpx.Response) -> None:
        self.requests: list[httpx.Request] = []
        self._responses = list(responses) or [httpx.Response(200, json={"ok": True})]
        self.transport = httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        idx = min(len(self.requests) - 1, len(self._responses) - 1)
        return self._responses[idx]

    @property
    def last(self) -> httpx.Request:
        return self.requests[-1]


class MemorySink:
    def __init__(
        self,
        name: str,
        min_level: Level = Level.BENIGN,
        *,
        fail: Exception | None = None,
        delay: float = 0.0,
    ) -> None:
        self.name, self.min_level = name, min_level
        self.received: list[Verdict] = []
        self._fail, self._delay = fail, delay

    async def send(self, verdict: Verdict) -> None:
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._fail:
            raise self._fail
        self.received.append(verdict)


# --------------------------------------------------------------------------- #
# Levels and fan-out
# --------------------------------------------------------------------------- #
def test_coerce_level_accepts_names_and_rejects_junk():
    assert coerce_level("Malicious") is Level.MALICIOUS
    assert coerce_level(Level.BENIGN) is Level.BENIGN
    with pytest.raises(ValueError, match="unknown level"):
        coerce_level("severe")


async def test_fan_out_respects_min_level():
    benign = make_verdict(Level.BENIGN, 5)
    suspicious = make_verdict(Level.SUSPICIOUS, 60)
    malicious = make_verdict(Level.MALICIOUS, 99)
    any_sink = MemorySink("any", Level.BENIGN)
    warn_sink = MemorySink("warn", Level.SUSPICIOUS)
    block_sink = MemorySink("block", Level.MALICIOUS)
    sinks = [any_sink, warn_sink, block_sink]

    r_benign = await fan_out(benign, sinks)
    r_susp = await fan_out(suspicious, sinks)
    r_mal = await fan_out(malicious, sinks)

    assert [r.status for r in r_benign] == ["sent", "skipped", "skipped"]
    assert [r.status for r in r_susp] == ["sent", "sent", "skipped"]
    assert [r.status for r in r_mal] == ["sent", "sent", "sent"]
    assert [v.level for v in any_sink.received] == [Level.BENIGN, Level.SUSPICIOUS, Level.MALICIOUS]
    assert len(block_sink.received) == 1


async def test_fan_out_isolates_failures_and_timeouts(caplog):
    good = MemorySink("good")
    boom = MemorySink("boom", fail=RuntimeError("kaput"))
    slow = MemorySink("slow", delay=5.0)
    with caplog.at_level("WARNING", logger="uniphish.integrations"):
        results = await fan_out(make_verdict(), [boom, good, slow], timeout=0.05)
    assert [r.sink for r in results] == ["boom", "good", "slow"]
    assert [r.status for r in results] == ["failed", "sent", "failed"]
    assert "kaput" in (results[0].error or "")
    assert "timeout" in (results[2].error or "")
    assert not results[0].ok and results[1].ok
    assert len(good.received) == 1
    assert "boom" in caplog.text


async def test_fan_out_with_no_sinks_and_custom_sink_without_min_level():
    assert await fan_out(make_verdict(), []) == []

    class Bare:
        name = "bare"

        def __init__(self) -> None:
            self.n = 0

        async def send(self, verdict: Verdict) -> None:
            self.n += 1

    bare = Bare()
    res = await fan_out(make_verdict(Level.BENIGN, 1), [bare])
    assert res[0].status == "sent" and bare.n == 1


async def test_fan_out_scrubs_secrets_from_failure_reason():
    class Leaky(sinks_mod.BaseSink):
        async def send(self, verdict: Verdict) -> None:
            raise RuntimeError("upstream said: bad token s3cr3t-token-value")

    sink = Leaky(secrets=["s3cr3t-token-value"], name="leaky")
    (res,) = await fan_out(make_verdict(), [sink])
    assert res.status == "failed"
    assert "s3cr3t-token-value" not in (res.error or "")
    assert "***" in (res.error or "")


# --------------------------------------------------------------------------- #
# WebhookSink
# --------------------------------------------------------------------------- #
async def test_webhook_posts_defanged_verdict_json_with_signature():
    rec = Recorder()
    sink = WebhookSink(
        "https://hooks.example.test/in",
        secret="topsecret-hmac-key",
        transport=rec.transport,
        resolver=_public_resolver,
        retries=0,
    )
    verdict = make_verdict()
    await sink.send(verdict)

    req = rec.last
    assert req.method == "POST"
    assert req.headers["content-type"] == "application/json"
    assert req.headers["host"] == "hooks.example.test"
    assert req.headers["x-uniphish-event"] == "verdict"
    body = req.content
    assert int(req.headers["content-length"]) == len(body)
    digest = hmac.new(b"topsecret-hmac-key", body, hashlib.sha256).hexdigest()
    assert req.headers["x-uniphish-signature"] == f"sha256={digest}"

    data = json.loads(body)
    assert data["id"] == verdict.id and data["level"] == "malicious"
    assert data["kind"] == "url" and data["engine_version"] == verdict.engine_version
    assert data["signals"][0]["id"] == "url.homoglyph"
    assert data["signals"][0]["mitre"] == ["T1566.002"]
    text = body.decode()
    assert "https://" not in text and "http://" not in text
    assert data["target"].startswith("hxxps://login[.]paypa1-secure[.]test")
    assert "victim[@]example[.]test" not in text  # example.com address -> example[.]com
    assert "victim[@]example[.]com" in data["summary"]
    assert data["signals"][0]["evidence"]["host"] == "login[.]paypa1-secure[.]test"


async def test_webhook_defang_can_be_disabled_for_machine_consumers():
    rec = Recorder()
    sink = WebhookSink(
        "https://hooks.example.test/in",
        defang=False,
        retries=0,
        transport=rec.transport,
        resolver=_public_resolver,
    )
    await sink.send(make_verdict())
    assert json.loads(rec.last.content)["target"] == TARGET


async def test_webhook_blocks_private_and_metadata_destinations():
    rec = Recorder()
    cases = [
        ("https://127.0.0.1/hook", _public_resolver),
        ("https://169.254.169.254/latest/meta-data", _public_resolver),
        ("https://[::1]/hook", _public_resolver),
        ("https://10.0.0.7/hook", _public_resolver),
        ("https://internal.example.test/hook", _private_resolver("10.1.2.3")),  # DNS -> RFC1918
        ("https://rebind.example.test/hook", _private_resolver("169.254.169.254")),
    ]
    for url, resolver in cases:
        sink = WebhookSink(url, transport=rec.transport, resolver=resolver, retries=3, backoff_s=0)
        with pytest.raises(SinkError, match="blocked"):
            await sink.send(make_verdict())
    assert rec.requests == []  # nothing ever reached the transport


async def test_webhook_blocks_non_allowed_port_and_never_follows_redirects():
    rec = Recorder()
    sink = WebhookSink(
        "https://hooks.example.test:22/in", transport=rec.transport, resolver=_public_resolver
    )
    with pytest.raises(SinkError, match="port"):
        await sink.send(make_verdict())

    redirect = Recorder(httpx.Response(302, headers={"location": "https://127.0.0.1/steal"}))
    sink = WebhookSink(
        "https://hooks.example.test/in",
        transport=redirect.transport,
        resolver=_public_resolver,
        retries=0,
    )
    with pytest.raises(SinkError, match="HTTP 302"):
        await sink.send(make_verdict())
    assert len(redirect.requests) == 1


async def test_webhook_uses_safe_fetch_without_private_or_redirects(monkeypatch):
    calls: list[tuple[str, dict]] = []

    async def fake_safe_fetch(url, **kwargs):
        calls.append((url, kwargs))
        return FetchResult(
            url=url,
            final_url=url,
            status=204,
            headers={},
            body=b"",
            truncated=False,
            chain=[],
            ip=None,
            elapsed_ms=1.0,
            error=None,
            blocked_reason=None,
            content_type=None,
            charset=None,
        )

    monkeypatch.setattr(sinks_mod, "safe_fetch", fake_safe_fetch)
    sink = WebhookSink("https://hooks.example.test/in")
    await sink.send(make_verdict())
    ((url, kwargs),) = calls
    assert url == "https://hooks.example.test/in"
    assert kwargs["method"] == "POST"
    assert kwargs["allow_private"] is False
    assert kwargs["follow_redirects"] is False
    assert kwargs["headers"]["content-type"] == "application/json"

    async def blocked(url, **kwargs):
        return FetchResult(
            url=url,
            final_url=url,
            status=0,
            headers={},
            body=b"",
            truncated=False,
            chain=[],
            ip=None,
            elapsed_ms=0.0,
            error=None,
            blocked_reason="non-public address: 127.0.0.1",
            content_type=None,
            charset=None,
        )

    monkeypatch.setattr(sinks_mod, "safe_fetch", blocked)
    with pytest.raises(SinkError, match="non-public address"):
        await WebhookSink("https://hooks.example.test/in").send(make_verdict())


async def test_webhook_retries_transient_failures_but_not_client_errors():
    rec = Recorder(httpx.Response(503), httpx.Response(200))
    sink = WebhookSink(
        "https://hooks.example.test/in",
        transport=rec.transport,
        resolver=_public_resolver,
        retries=2,
        backoff_s=0,
    )
    await sink.send(make_verdict())
    assert len(rec.requests) == 2
    assert rec.requests[0].content == rec.requests[1].content  # same body re-sent

    rec = Recorder(httpx.Response(400, text="nope"))
    sink = WebhookSink(
        "https://hooks.example.test/in",
        transport=rec.transport,
        resolver=_public_resolver,
        retries=3,
        backoff_s=0,
    )
    with pytest.raises(SinkError, match="HTTP 400"):
        await sink.send(make_verdict())
    assert len(rec.requests) == 1

    rec = Recorder(httpx.Response(500))
    sink = WebhookSink(
        "https://hooks.example.test/in",
        transport=rec.transport,
        resolver=_public_resolver,
        retries=1,
        backoff_s=0,
    )
    with pytest.raises(SinkError, match="HTTP 500"):
        await sink.send(make_verdict())
    assert len(rec.requests) == 2


def test_http_sinks_validate_urls():
    with pytest.raises(ValueError, match="http"):
        WebhookSink("http://hooks.example.test/in")
    WebhookSink("http://hooks.example.test/in", allow_insecure_http=True)
    with pytest.raises(ValueError, match="credentials"):
        WebhookSink("https://user:pw@hooks.example.test/in")
    with pytest.raises(ValueError, match="absolute"):
        WebhookSink("ftp://hooks.example.test/in")
    with pytest.raises(ValueError, match="absolute"):
        WebhookSink("/relative/path")
    with pytest.raises(ValueError):
        WebhookSink("https://hooks.example.test/in", min_level="nonsense")


async def test_webhook_error_and_repr_do_not_leak_secrets():
    secret_url = "https://hooks.example.test/services/T000/B000/XXXXSECRETXXXX"
    rec = Recorder(httpx.Response(500))
    sink = WebhookSink(
        secret_url,
        headers={"authorization": "Bearer tok-abcdef123456"},
        secret="hmac-key-123456",
        transport=rec.transport,
        resolver=_public_resolver,
        retries=0,
    )
    with pytest.raises(SinkError) as exc:
        await sink.send(make_verdict())
    shown = f"{exc.value} {sink!r} {sink.scrub(secret_url + ' tok-abcdef123456 hmac-key-123456')}"
    for needle in ("XXXXSECRETXXXX", "tok-abcdef123456", "hmac-key-123456"):
        assert needle not in shown


async def test_webhook_drops_children_when_payload_too_large():
    child = make_verdict(Level.SUSPICIOUS, 60, target="https://a.example.test/x")
    parent = make_verdict()
    parent.children = [child] * 20
    rec = Recorder()
    sink = WebhookSink(
        "https://hooks.example.test/in",
        transport=rec.transport,
        resolver=_public_resolver,
        max_payload_bytes=2_000,
        retries=0,
    )
    await sink.send(parent)
    data = json.loads(rec.last.content)
    assert data["children"] == [] and data["children_omitted"] == 20


async def test_real_wrapper_delivers_body_over_loopback():
    """End to end through the real (unmocked) transport against a local test server."""
    seen: dict[str, object] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            n = int(self.headers.get("content-length", "0"))
            seen["body"] = self.rfile.read(n)
            seen["headers"] = dict(self.headers)
            self.send_response(200)
            self.send_header("content-length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        sink = WebhookSink(
            f"http://127.0.0.1:{port}/hook",
            allow_insecure_http=True,
            allow_private=True,
            allowed_ports={port},
            retries=0,
            timeout=5,
        )
        verdict = make_verdict()
        await sink.send(verdict)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert json.loads(seen["body"])["id"] == verdict.id  # type: ignore[arg-type]
    wire = {k.lower(): v for k, v in seen["headers"].items()}  # type: ignore[attr-defined]
    assert wire["content-type"] == "application/json"
    assert int(wire["content-length"]) == len(seen["body"])  # type: ignore[arg-type]

    # ...and the same sink without the private opt-in must be refused, no connection made.
    strict = WebhookSink(
        "http://127.0.0.1:9/hook", allow_insecure_http=True, allowed_ports={9}, retries=0
    )
    with pytest.raises(SinkError, match="blocked"):
        await strict.send(make_verdict())


# --------------------------------------------------------------------------- #
# Slack
# --------------------------------------------------------------------------- #
def test_slack_payload_shape_and_defanging():
    verdict = make_verdict(
        summary="Click <!channel> to verify @here at https://evil.test/a?b=1&c=2"
    )
    payload = slack_payload(verdict)
    assert set(payload) == {"text", "blocks"}
    blocks = payload["blocks"]
    assert blocks[0]["type"] == "header"
    assert blocks[0]["text"] == {"type": "plain_text", "text": "UniPhish: MALICIOUS (96/100)"}
    section = blocks[1]["text"]["text"]
    assert "hxxps://login[.]paypa1-secure[.]test" in section
    assert "<!channel>" not in section and "‹!channel›" in section
    assert "[@]here" in section and "&amp;" in section
    field_text = " ".join(f["text"] for f in blocks[2]["fields"])
    assert "PayPal" in field_text and "block" in field_text and "homoglyph" in field_text
    signals = next(
        b
        for b in blocks
        if b["type"] == "section" and "Top signals" in b.get("text", {}).get("text", "")
    )
    assert "+4.0" in signals["text"]["text"]
    assert blocks[-1]["type"] == "context" and verdict.id in blocks[-1]["elements"][0]["text"]
    blob = json.dumps(payload)
    assert "http://" not in blob and "https://" not in blob
    assert len(payload["text"]) <= 3000


def test_slack_payload_handles_benign_and_missing_brand():
    payload = slack_payload(make_verdict(Level.BENIGN, 3, brand=False, summary=""))
    assert ":white_check_mark:" in payload["text"]
    assert "No summary." in payload["blocks"][1]["text"]["text"]
    assert all("Impersonates" not in f["text"] for f in payload["blocks"][2]["fields"])


async def test_slack_sink_posts_and_hides_webhook_url():
    rec = Recorder(httpx.Response(200, text="ok"))
    url = "https://hooks.example.test/services/T1/B2/SLACKSECRETPATH"
    sink = SlackSink(url, transport=rec.transport, resolver=_public_resolver, retries=0)
    await sink.send(make_verdict())
    assert rec.last.method == "POST"
    assert str(rec.last.headers["host"]) == "hooks.example.test"
    body = json.loads(rec.last.content)
    assert body["blocks"][0]["type"] == "header"
    assert "SLACKSECRETPATH" not in repr(sink)
    assert sink.min_level is Level.SUSPICIOUS

    failing = SlackSink(
        url, transport=Recorder(httpx.Response(403)).transport, resolver=_public_resolver, retries=0
    )
    with pytest.raises(SinkError) as exc:
        await failing.send(make_verdict())
    assert "SLACKSECRETPATH" not in str(exc.value)


# --------------------------------------------------------------------------- #
# Splunk HEC and Elastic
# --------------------------------------------------------------------------- #
async def test_splunk_hec_sends_ecs_event_with_token_header():
    rec = Recorder(httpx.Response(200, json={"text": "Success", "code": 0}))
    sink = SplunkHECSink(
        "https://splunk.example.test:8088",
        "hec-token-0123456789",
        index="security",
        host="uniphish-1",
        transport=rec.transport,
        resolver=_public_resolver,
        retries=0,
    )
    verdict = make_verdict()
    await sink.send(verdict)
    req = rec.last
    assert req.method == "POST"
    assert req.url.path == "/services/collector/event"
    assert req.headers["authorization"] == "Splunk hec-token-0123456789"
    assert req.headers["host"] == "splunk.example.test:8088"
    event = json.loads(req.content)
    assert event["sourcetype"] == "uniphish:verdict" and event["index"] == "security"
    assert event["host"] == "uniphish-1"
    assert event["time"] == pytest.approx(verdict.created_at.timestamp(), abs=0.001)
    doc = event["event"]
    assert doc["event"]["kind"] == "alert" and doc["event"]["id"] == verdict.id
    assert doc["ecs"]["version"] == "8.11.0"
    assert doc["uniphish"]["level"] == "malicious"
    assert "https://" not in doc["message"]  # free text defanged...
    assert "https://" not in doc["event"]["reason"]
    assert doc["threat"]["technique"]["id"] == ["T1566"] or "T1566" in str(doc["threat"])


async def test_splunk_hec_application_error_and_secret_scrubbing():
    rec = Recorder(httpx.Response(200, json={"text": "Invalid token", "code": 4}))
    sink = SplunkHECSink(
        "https://splunk.example.test:8088/services/collector/event",
        "hec-token-0123456789",
        transport=rec.transport,
        resolver=_public_resolver,
        retries=0,
    )
    with pytest.raises(SinkError, match="code 4") as exc:
        await sink.send(make_verdict())
    assert "hec-token-0123456789" not in str(exc.value) + repr(sink)
    with pytest.raises(ValueError):
        SplunkHECSink("https://splunk.example.test", "")


async def test_splunk_default_port_is_allowed_but_unlisted_ports_are_not():
    rec = Recorder()
    ok = SplunkHECSink(
        "https://splunk.example.test:8088",
        "tok-123456",
        retries=0,
        transport=rec.transport,
        resolver=_public_resolver,
    )
    await ok.send(make_verdict())
    bad = SplunkHECSink(
        "https://splunk.example.test:9999",
        "tok-123456",
        retries=0,
        transport=rec.transport,
        resolver=_public_resolver,
    )
    with pytest.raises(SinkError, match="port"):
        await bad.send(make_verdict())
    assert len(rec.requests) == 1


async def test_elastic_sink_creates_document_idempotently():
    rec = Recorder(
        httpx.Response(201, json={"result": "created"}),
        httpx.Response(409, json={"error": "version_conflict_engine_exception"}),
        httpx.Response(401, json={"error": "security_exception"}),
    )
    sink = ElasticSink(
        "https://es.example.test:9200/",
        "uniphish-verdicts",
        "ES-API-KEY-abcdef",
        transport=rec.transport,
        resolver=_public_resolver,
        retries=0,
    )
    verdict = make_verdict(vid="deadbeef" * 4)
    await sink.send(verdict)
    req = rec.last
    assert req.method == "PUT"
    assert req.url.path == f"/uniphish-verdicts/_create/{verdict.id}"
    assert req.headers["authorization"] == "ApiKey ES-API-KEY-abcdef"
    assert json.loads(req.content)["event"]["id"] == verdict.id

    await sink.send(verdict)  # 409: already indexed -> success
    with pytest.raises(SinkError, match="HTTP 401") as exc:
        await sink.send(verdict)
    assert "ES-API-KEY-abcdef" not in str(exc.value) + repr(sink)


@pytest.mark.parametrize("index", ["", "Upper", "_hidden", "a/b", "a b", "a,b", "a*", ".x", "a#b"])
def test_elastic_rejects_bad_index_names(index):
    with pytest.raises(ValueError, match="index"):
        ElasticSink("https://es.example.test:9200", index, "key-123456")
    with pytest.raises(ValueError, match="API key"):
        ElasticSink("https://es.example.test:9200", "ok-index", "")


# --------------------------------------------------------------------------- #
# Local sinks
# --------------------------------------------------------------------------- #
async def test_store_sink_persists_full_verdict():
    with Store(":memory:") as store:
        sink = StoreSink(store, source="unit")
        verdict = make_verdict()
        await sink.send(verdict)
        got = store.get_verdict(verdict.id)
        assert got is not None and got.target == TARGET  # lossless, not defanged
        assert store.get_verdict_row(verdict.id)["level"] == "malicious"
        assert sink.min_level is Level.BENIGN


async def test_file_sink_appends_defanged_jsonl_with_private_permissions(tmp_path):
    path = tmp_path / "out" / "verdicts.jsonl"
    sink = FileSink(path)
    v1, v2 = make_verdict(), make_verdict(Level.SUSPICIOUS, 60)
    await asyncio.gather(sink.send(v1), sink.send(v2))
    await sink.send(make_verdict(Level.BENIGN, 2))
    lines = path.read_text().splitlines()
    assert len(lines) == 3
    rows = [json.loads(line) for line in lines]
    assert {r["id"] for r in rows[:2]} == {v1.id, v2.id}
    assert "https://" not in path.read_text()
    assert rows[0]["target"].startswith("hxxps://")
    if os.name == "posix":
        assert (path.stat().st_mode & 0o777) == 0o600

    raw = FileSink(tmp_path / "raw.jsonl", defang=False)
    await raw.send(v1)
    assert json.loads((tmp_path / "raw.jsonl").read_text())["target"] == TARGET


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="needs O_NOFOLLOW")
async def test_file_sink_refuses_symlinked_target(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    link = tmp_path / "log.jsonl"
    link.symlink_to(victim)
    sink = FileSink(link)
    (res,) = await fan_out(make_verdict(), [sink])
    assert res.status == "failed"
    assert victim.read_text() == "keep me"


async def test_stdout_sink_writes_defanged_line():
    buf = io.StringIO()
    sink = StdoutSink(buf)
    await sink.send(make_verdict())
    out = buf.getvalue()
    assert out.startswith("[MALICIOUS  96] url hxxps://login[.]paypa1-secure[.]test")
    assert "brand=PayPal" in out and out.count("\n") == 1
    assert "https://" not in out

    jbuf = io.StringIO()
    await StdoutSink(jbuf, as_json=True).send(make_verdict())
    assert json.loads(jbuf.getvalue())["level"] == "malicious"


async def test_stdout_sink_defaults_to_sys_stdout(capsys):
    await StdoutSink().send(make_verdict(Level.BENIGN, 1, brand=False, summary="fine"))
    assert "[BENIGN" in capsys.readouterr().out


@settings(max_examples=60, deadline=None)
@given(st.text(max_size=300))
def test_defang_tree_never_raises_and_leaves_no_live_links(text):
    tree = {
        "id": "keep.this.id",
        "summary": f"see http://{text}.test/x or https://a.b.c/",
        "evidence": {"url": "https://x.example.test/p"},
        "list": [text, {"detail": text}],
    }
    out = sinks_mod._defang_tree(tree)
    assert out["id"] == "keep.this.id"
    blob = json.dumps(out)
    assert "http://" not in blob and "https://" not in blob
