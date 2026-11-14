"""Tests for the UniPhish HTTP API (FastAPI).

Everything runs in-process against the ASGI app — no sockets, no network (the engine's
online analyzers are off by default). Each test builds its own app bound to an isolated
settings object (own SQLite file under the per-test data dir), so state never leaks
between tests. The SSE test drives the app with an async httpx client so a scan and the
live stream can run concurrently on one event loop.
"""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from uniphish.core.config import Settings
from uniphish.server import security
from uniphish.server.app import create_app

# A tiny, synthetic, inert phishing email using reserved/example domains only.
SAMPLE_EML = (
    b'From: "PayPal Security" <alert@secure-paypal.example>\r\n'
    b"To: victim@example.com\r\n"
    b"Subject: Your account is limited - verify now\r\n"
    b"Reply-To: harvest@evil.test\r\n"
    b"\r\n"
    b"Urgent: confirm your identity at http://paypal-verify.evil.test/login or lose access.\r\n"
)

SAMPLE_HTML = (
    "<html><title>Sign in to Microsoft</title><body>"
    "<form action='http://harvest.evil.test/collect' method='post'>"
    "<input type='password' name='pass'></form></body></html>"
)


def make_settings(tmp_path: Path, **overrides) -> Settings:
    data = tmp_path / "data"
    return Settings(data_dir=data, db_path=data / "uniphish.db", **overrides)


@pytest.fixture
def client(tmp_path):
    app = create_app(make_settings(tmp_path))
    with TestClient(app) as c:
        yield c


# --------------------------------------------------------------------------- #
# meta / health
# --------------------------------------------------------------------------- #
def test_health(client):
    r = client.get("/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["auth"] == "disabled"
    assert "url" in body["analyzers"]
    # Security headers are present on every response.
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" in r.headers
    assert r.headers["x-uniphish-auth"] == "disabled"


def test_version_and_catalog(client):
    assert client.get("/v1/meta/version").json()["name"] == "uniphish"
    cat = client.get("/v1/meta/analyzers").json()
    assert cat["analyzers"] and isinstance(cat["signals"], dict)
    # The URL analyzer declares brand signals in the catalog.
    assert any(sid.startswith("brand.") for sid in cat["signals"])


# --------------------------------------------------------------------------- #
# scan happy paths
# --------------------------------------------------------------------------- #
def test_scan_url(client):
    r = client.post("/v1/scan/url", json={"url": "http://paypal-login.evil.test/signin"})
    assert r.status_code == 200
    v = r.json()
    assert v["kind"] == "url"
    assert 0 <= v["score"] <= 100
    assert v["level"] in {"benign", "suspicious", "malicious"}
    assert isinstance(v["signals"], list)


def test_scan_text(client):
    r = client.post(
        "/v1/scan/text", json={"text": "Your parcel is held. Pay the fee: http://dhl-fee.evil.test"}
    )
    assert r.status_code == 200
    assert r.json()["kind"] == "text"


def test_scan_email(client):
    r = client.post("/v1/scan/email", json={"email": base64.b64encode(SAMPLE_EML).decode()})
    assert r.status_code == 200
    assert r.json()["kind"] == "email"


def test_scan_email_raw(client):
    r = client.post("/v1/scan/email", json={"raw": SAMPLE_EML.decode()})
    assert r.status_code == 200
    assert r.json()["kind"] == "email"


def test_scan_page(client):
    r = client.post(
        "/v1/scan/page", json={"html": SAMPLE_HTML, "url": "http://micr0soft-login.evil.test/"}
    )
    assert r.status_code == 200
    assert r.json()["kind"] == "page"


def test_scan_file_multipart(client):
    r = client.post(
        "/v1/scan/file",
        files={"file": ("invoice.pdf.exe", b"MZ\x90\x00 inert sample", "application/octet-stream")},
    )
    assert r.status_code == 200
    assert r.json()["kind"] == "file"


def test_scan_autodetect(client):
    r = client.post("/v1/scan", json={"text": "verify at http://evil.test now"})
    assert r.status_code == 200 and r.json()["kind"] == "text"
    r2 = client.post("/v1/scan", json={"url": "http://example.com"})
    assert r2.status_code == 200 and r2.json()["kind"] == "url"


def test_scan_empty_rejected(client):
    r = client.post("/v1/scan", json={})
    assert r.status_code == 422


def test_scan_bad_base64(client):
    r = client.post("/v1/scan", json={"input_type": "email", "email": "!!!not base64!!!"})
    assert r.status_code == 400


def test_scan_url_too_large(client):
    huge = "http://a.test/" + "x" * 9000
    r = client.post("/v1/scan/url", json={"url": huge})
    assert r.status_code == 413


# --------------------------------------------------------------------------- #
# batch
# --------------------------------------------------------------------------- #
def test_scan_batch(client):
    items = [{"url": "http://a.test"}, {"text": "hello"}, {"url": ""}]
    r = client.post("/v1/scan/batch", json={"items": items})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 3
    oks = [x["ok"] for x in body["results"]]
    assert oks == [True, True, False]  # the empty url fails in isolation


def test_scan_batch_cap(client):
    r = client.post("/v1/scan/batch", json={"items": [{"url": "http://a.test"}] * 51})
    assert r.status_code == 422  # over the 50-item cap


# --------------------------------------------------------------------------- #
# explain
# --------------------------------------------------------------------------- #
def test_explain(client):
    r = client.post("/v1/explain", json={"url": "http://paypa1-secure.evil.test/login"})
    assert r.status_code == 200
    body = r.json()
    assert "report" in body
    assert body["report"]["narrative"]  # template narrative works offline
    assert body["report"]["triage"]["source"] in {"ai", "template"}
    assert body["report"]["ai_available"] is False


# --------------------------------------------------------------------------- #
# stored verdicts / stats / indicators
# --------------------------------------------------------------------------- #
def test_verdicts_and_stats(client):
    vid = client.post("/v1/scan/url", json={"url": "http://paypal-login.evil.test/x"}).json()["id"]
    assert client.get(f"/v1/verdicts/{vid}").json()["id"] == vid
    assert client.get("/v1/verdicts/does-not-exist").status_code == 404
    listing = client.get("/v1/verdicts").json()
    assert listing["count"] >= 1
    stats = client.get("/v1/stats").json()
    assert stats["verdicts"] >= 1 and "by_level" in stats


def test_no_persist_option(client):
    client.post("/v1/scan/url", json={"url": "http://a.test", "options": {"persist": False}})
    assert client.get("/v1/stats").json()["verdicts"] == 0


def test_indicators(client):
    client.post("/v1/scan/url", json={"url": "http://paypal-login.evil.test/x"})
    r = client.get("/v1/indicators")
    assert r.status_code == 200 and "indicators" in r.json()


# --------------------------------------------------------------------------- #
# exports
# --------------------------------------------------------------------------- #
def test_export_by_verdict_id(client):
    vid = client.post("/v1/scan/url", json={"url": "http://paypal-login.evil.test/signin"}).json()[
        "id"
    ]
    stix = client.post("/v1/export/stix", json={"verdict_id": vid})
    assert stix.status_code == 200
    assert stix.json()["type"] == "bundle"
    ecs = client.post("/v1/export/ecs", json={"verdict_id": vid})
    assert ecs.status_code == 200 and "event" in ecs.json()


def test_export_inline_formats(client):
    payload = {"url": "http://paypal-login.evil.test/signin"}
    for fmt in ("stix", "misp", "ecs"):
        assert client.post(f"/v1/export/{fmt}", json=payload).status_code == 200
    sigma = client.post("/v1/export/sigma", json=payload)
    assert sigma.status_code == 200
    assert "application/yaml" in sigma.headers["content-type"]
    assert "title" in sigma.text


def test_export_unknown_format(client):
    r = client.post("/v1/export/notaformat", json={"url": "http://a.test"})
    assert r.status_code == 404


def test_export_missing_verdict(client):
    r = client.post("/v1/export/stix", json={"verdict_id": "nope"})
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# TAXII 2.1
# --------------------------------------------------------------------------- #
def test_taxii_discovery(client):
    disc = client.get("/taxii2/")
    assert disc.status_code == 200
    assert "taxii+json" in disc.headers["content-type"]
    assert disc.json()["api_roots"]
    cols = client.get("/taxii2/api/collections/").json()["collections"]
    assert cols[0]["id"] == "phishing-iocs"
    objs = client.get("/taxii2/api/collections/phishing-iocs/objects/")
    assert objs.status_code == 200 and "objects" in objs.json()
    assert client.get("/taxii2/api/collections/wrong/objects/").status_code == 404


# --------------------------------------------------------------------------- #
# legacy shims
# --------------------------------------------------------------------------- #
def test_legacy_scan_and_stix(client):
    r = client.post("/scan", json={"url": "http://paypal-login.evil.test/x"})
    assert r.status_code == 200 and "level" in r.json()
    s = client.post("/stix", json={"url": "http://paypal-login.evil.test/x"})
    assert s.status_code == 200 and s.json()["type"] == "bundle"


# --------------------------------------------------------------------------- #
# auth
# --------------------------------------------------------------------------- #
def test_auth_required_when_keys_set(tmp_path):
    app = create_app(make_settings(tmp_path, api_keys=["s3cret-key"]))
    with TestClient(app) as c:
        health = c.get("/v1/health")
        assert health.status_code == 200  # meta stays open
        assert health.json()["auth"] == "enabled"
        assert "x-uniphish-auth" not in health.headers  # the note is for dev mode only
        assert c.post("/v1/scan/url", json={"url": "http://a.test"}).status_code == 401
        bad = c.post("/v1/scan/url", json={"url": "http://a.test"}, headers={"x-api-key": "wrong"})
        assert bad.status_code == 401
        ok = c.post(
            "/v1/scan/url", json={"url": "http://a.test"}, headers={"x-api-key": "s3cret-key"}
        )
        assert ok.status_code == 200
        ok2 = c.post(
            "/v1/scan/url",
            json={"url": "http://a.test"},
            headers={"authorization": "Bearer s3cret-key"},
        )
        assert ok2.status_code == 200


def test_auth_covers_taxii_and_legacy_routes(tmp_path):
    """TAXII (serves the IOC store) and the legacy shims must not bypass API-key auth."""
    app = create_app(make_settings(tmp_path, api_keys=["s3cret-key"]))
    with TestClient(app) as c:
        assert c.get("/taxii2/").status_code == 401
        assert c.post("/scan", json={"url": "http://a.test"}).status_code == 401
        assert c.post("/stix", json={"url": "http://a.test"}).status_code == 401
        hdr = {"x-api-key": "s3cret-key"}
        assert c.get("/taxii2/", headers=hdr).status_code == 200
        assert c.post("/scan", json={"url": "http://a.test"}, headers=hdr).status_code == 200


# --------------------------------------------------------------------------- #
# rate limiting
# --------------------------------------------------------------------------- #
def test_rate_limit_trips(tmp_path):
    app = create_app(make_settings(tmp_path, rate_limit_per_minute=3))
    with TestClient(app) as c:
        codes = [c.get("/v1/health").status_code for _ in range(6)]
    assert 200 in codes and 429 in codes
    assert codes.index(429) >= 3  # first 3 pass, then the bucket empties


def test_rate_limit_not_bypassed_by_rotating_invalid_keys(tmp_path):
    """A fresh junk key per request must not mint a fresh bucket (falls back to the IP)."""
    app = create_app(make_settings(tmp_path, rate_limit_per_minute=3, api_keys=["real-key"]))
    with TestClient(app) as c:
        codes = [
            c.get("/v1/health", headers={"x-api-key": f"junk-{i}"}).status_code for i in range(6)
        ]
    assert 429 in codes


def test_rate_limit_valid_key_gets_own_bucket(tmp_path):
    app = create_app(make_settings(tmp_path, rate_limit_per_minute=2, api_keys=["real-key"]))
    with TestClient(app) as c:
        assert [c.get("/v1/health").status_code for _ in range(3)][-1] == 429
        # the authenticated caller is metered separately from the anonymous IP bucket
        assert c.get("/v1/health", headers={"x-api-key": "real-key"}).status_code == 200


def test_rate_limiter_memory_is_bounded():
    now = [0.0]
    rl = security.RateLimiter(60, max_identities=50, clock=lambda: now[0])
    for i in range(500):
        assert rl.allow(f"ip:10.0.{i // 256}.{i % 256}")
    assert len(rl) <= 50
    # an identity that is still draining its bucket keeps being limited after eviction runs
    hot = security.RateLimiter(2, max_identities=4, clock=lambda: now[0])
    assert hot.allow("hot") and hot.allow("hot") and not hot.allow("hot")


# --------------------------------------------------------------------------- #
# request size cap
# --------------------------------------------------------------------------- #
def test_request_size_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(security, "MAX_REQUEST_BYTES", 40)
    app = create_app(make_settings(tmp_path))
    with TestClient(app) as c:
        r = c.post("/v1/scan/url", json={"url": "http://example.com/a-fairly-long-url-path"})
    assert r.status_code == 413


def test_request_size_cap_applies_to_chunked_body(tmp_path, monkeypatch):
    """No Content-Length (chunked transfer): the streamed byte count is still capped."""
    monkeypatch.setattr(security, "MAX_REQUEST_BYTES", 40)
    app = create_app(make_settings(tmp_path))
    payload = b'{"url": "http://example.com/a-fairly-long-url-path-that-is-over-the-cap"}'

    def chunks():
        for i in range(0, len(payload), 8):
            yield payload[i : i + 8]

    with TestClient(app) as c:
        r = c.post("/v1/scan/url", content=chunks(), headers={"content-type": "application/json"})
    assert r.status_code == 413
    assert r.json()["detail"] == "Request body too large."


def test_small_chunked_body_still_accepted(tmp_path):
    app = create_app(make_settings(tmp_path))
    payload = b'{"url": "http://example.com/"}'
    with TestClient(app) as c:
        r = c.post(
            "/v1/scan/url",
            content=iter([payload[:10], payload[10:]]),
            headers={"content-type": "application/json"},
        )
    assert r.status_code == 200


# --------------------------------------------------------------------------- #
# SSE live stream
# --------------------------------------------------------------------------- #
def test_stream_endpoint_registered(client):
    """The stream route exists and is wired as text/event-stream (preamble only)."""
    with client.stream("GET", "/v1/stream") as resp:
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        lines = []
        for line in resp.iter_lines():
            lines.append(line)
            if line == "":  # end of the preamble event
                break
        assert lines[0] == "retry: 3000"
        assert any("connected" in ln for ln in lines)


@pytest.mark.asyncio
async def test_stream_emits_verdict_event(tmp_path):
    """A scan publishes a verdict event that the SSE generator yields to subscribers.

    Drives the real ``_event_source`` generator against the process-wide event bus and a
    real engine scan — ASGITransport buffers streaming bodies, so this exercises the
    actual SSE machinery deterministically instead.
    """
    from uniphish.core import events
    from uniphish.core.types import Artifact
    from uniphish.server.routes.stream import _event_source

    class _FakeRequest:
        async def is_disconnected(self) -> bool:
            return False

    gen = _event_source(_FakeRequest())
    preamble = await gen.__anext__()
    assert "connected" in preamble

    # Advance the generator so it subscribes and then awaits the next bus event.
    before = events.bus.subscriber_count
    nxt = asyncio.create_task(gen.__anext__())
    for _ in range(200):
        if events.bus.subscriber_count > before:
            break
        await asyncio.sleep(0.01)
    assert events.bus.subscriber_count > before

    app = create_app(make_settings(tmp_path))
    async with app.router.lifespan_context(app):
        await app.state.engine.analyze(Artifact.from_url("http://evil.test/login"))

    chunk = await asyncio.wait_for(nxt, timeout=5.0)
    assert chunk.startswith("event: verdict")
    assert "evil.test" in chunk
    await gen.aclose()
