"""Offline tests for the CT hunter: parsing, transport (fake websocket), pipeline, store."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

import pytest

from uniphish.core import events
from uniphish.hunt import ct as ctmod
from uniphish.hunt.ct import (
    CTHunter,
    clean_domain,
    parse_record,
    stream_certstream,
)
from uniphish.store import Store

LOOKALIKES = {
    "paypa1.test": "paypal",  # digit typo
    "xn--pypal-4ve.test": "paypal",  # IDN homoglyph
    "secure-paypal-login.test": "paypal",  # combosquat
    "apple-id-verify.test": "apple",
    "micr0soft-support.test": "microsoft",
}
BENIGN = ["my-garden-shop.test", "kitchen-recipes.test", "blog.example.org", "mail.paypal.com"]


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


@pytest.fixture
def hunter(store):
    return CTHunter(store=store, threshold=75)


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Example.COM.", "example.com"),
        ("*.login.Example.com", "login.example.com"),
        ("  a.b.test ", "a.b.test"),
        ("pаypal.test", "xn--pypal-4ve.test"),  # Cyrillic а
        ("localhost", None),
        ("1.2.3.4", None),
        ("a@b.com", None),
        ("http://x.com", None),
        ("a b.com", None),
        ("-a.com", None),
        ("a" * 64 + ".com", None),
        ("", None),
        (None, None),
        ("a." + "b" * 250 + ".com", None),
        ("[::1]", None),
        ("x.123", None),
        (42, None),
    ],
)
def test_clean_domain(raw, expected):
    assert clean_domain(raw) == expected


def test_parse_certstream_message():
    msg = {
        "message_type": "certificate_update",
        "data": {
            "seen": 1.7e9,
            "source": {"name": "Argon"},
            "leaf_cert": {
                "all_domains": ["*.paypa1.test", "paypa1.test", "bad domain", "x"],
                "issuer": {"O": "Test CA"},
                "not_before": 1700000000,
                "fingerprint": "AA:BB",
            },
        },
    }
    out = parse_record(msg)
    assert [d for d, _ in out] == ["paypa1.test", "paypa1.test"]
    meta = out[0][1]
    assert meta["issuer"] == "Test CA" and meta["log"] == "Argon" and meta["source"] == "certstream"


def test_parse_ignores_heartbeat_and_garbage():
    assert parse_record({"message_type": "heartbeat"}) == []
    assert parse_record({"message_type": "certificate_update", "data": "x"}) == []
    assert parse_record(123) == [] and parse_record(None) == [] and parse_record([]) == []


def test_parse_flat_shapes_and_san_cap():
    assert [d for d, _ in parse_record("A.example.test")] == ["a.example.test"]
    assert [d for d, _ in parse_record({"domain": "a.test", "issuer": "X"})] == ["a.test"]
    many = {"domains": [f"h{i}.test" for i in range(500)]}
    assert len(parse_record(many, max_sans=10)) == 10


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #
class FakeWS:
    def __init__(self, msgs, then=None):
        self.msgs, self.then = list(msgs), then

    def __aiter__(self):
        return self._gen()

    async def _gen(self):
        for m in self.msgs:
            yield m
        if self.then == "hang":
            await asyncio.sleep(3600)
        elif isinstance(self.then, Exception):
            raise self.then


def _cert(*domains):
    return json.dumps(
        {
            "message_type": "certificate_update",
            "data": {"leaf_cert": {"all_domains": list(domains)}},
        }
    )


def _connector(script):
    """script: list of FakeWS or Exception, one per connection attempt."""
    calls = []

    @asynccontextmanager
    async def connect(url, **kw):
        calls.append((url, kw))
        item = script[min(len(calls), len(script)) - 1]
        if isinstance(item, Exception):
            raise item
        yield item

    connect.calls = calls
    return connect


async def _nosleep(_):
    return None


def test_stream_reconnects_after_failures_and_closure():
    conn = _connector(
        [
            ConnectionError("boom"),
            FakeWS([_cert("a.test"), "not json", b'{"message_type":"heartbeat"}']),
            FakeWS([_cert("b.test", "c.test")]),
        ]
    )
    got: list[str] = []
    n = asyncio.run(
        stream_certstream(
            lambda d, m: got.append(d),
            connect=conn,
            max_certs=3,
            sleep=_nosleep,
            backoff_base_s=0.0,
        )
    )
    assert n == 3 and got == ["a.test", "b.test", "c.test"]
    assert len(conn.calls) == 3
    assert conn.calls[0][1]["max_size"] == 1 << 20  # bounded frames


def test_stream_gives_up_after_max_reconnects():
    conn = _connector([OSError("down")])
    n = asyncio.run(
        stream_certstream(lambda d, m: None, connect=conn, max_reconnects=2, sleep=_nosleep)
    )
    assert n == 0 and len(conn.calls) == 3


def test_stream_idle_timeout_triggers_reconnect_and_stop_event():
    async def main():
        stop = asyncio.Event()
        conn = _connector([FakeWS([], then="hang"), FakeWS([_cert("z.test")])])
        got = []

        async def cb(d, m):
            got.append(d)
            stop.set()

        n = await stream_certstream(
            cb, connect=conn, stop=stop, idle_timeout_s=0.05, sleep=_nosleep
        )
        return n, got, len(conn.calls)

    assert asyncio.run(main()) == (1, ["z.test"], 2)


def test_stream_stop_while_blocked_on_socket():
    async def main():
        stop = asyncio.Event()
        conn = _connector([FakeWS([], then="hang")])
        asyncio.get_running_loop().call_later(0.05, stop.set)
        return await asyncio.wait_for(
            stream_certstream(lambda d, m: None, connect=conn, stop=stop), 5
        )

    assert asyncio.run(main()) == 0


def test_stream_rejects_insecure_and_bad_source():
    with pytest.raises(ValueError):
        asyncio.run(stream_certstream(lambda d, m: None, url="ws://evil.example/"))
    with pytest.raises(ValueError):
        asyncio.run(stream_certstream(lambda d, m: None, url="http://x/"))
    with pytest.raises(ValueError):
        asyncio.run(stream_certstream(lambda d, m: None, source="carrier-pigeon"))


def test_sample_replay_file(tmp_path):
    f = tmp_path / "s.jsonl"
    f.write_text(
        '{"domain": "paypa1.test", "issuer": "T"}\n\n"x.example.test"\n'
        'garbage{\n{"domains": ["a.test", "*.b.test"]}\nplain.test\n'
    )
    got = []
    n = asyncio.run(stream_certstream(lambda d, m: got.append((d, m)), source="sample", path=f))
    assert [d for d, _ in got] == [
        "paypa1.test",
        "x.example.test",
        "a.test",
        "b.test",
        "plain.test",
    ][:n]
    assert got[0][1]["source"] == "sample" and got[0][1]["issuer"] == "T"


def test_sample_replay_builtin_limit():
    got = []
    asyncio.run(stream_certstream(lambda d, m: got.append(d), source="sample", max_certs=3))
    assert got == list(ctmod.SAMPLE_DOMAINS[:3])


# --------------------------------------------------------------------------- #
# pipeline
# --------------------------------------------------------------------------- #
def test_only_lookalikes_are_recorded(hunter, store):
    hits = hunter.hunt_once(list(LOOKALIKES) + BENIGN)
    assert {h.domain: h.brand for h in hits} == LOOKALIKES
    rows = store.recent_hunt_events()
    assert {r["domain"]: r["brand"] for r in rows} == LOOKALIKES
    for r in rows:
        assert r["source"] == "sample" and r["score"] >= 40 and r["techniques"]
        assert r["stix"]["type"] == "bundle"
    st = hunter.stats
    assert st.seen == 9 and st.recorded == 5 and st.official_skipped == 1
    assert st.scored == 8 and st.by_brand["paypal"] == 3


def test_stix_objects_stored_for_taxii(hunter, store):
    hunter.hunt_once(["paypa1.test"])
    objs = store.stix_objects(synthesize=False, limit=100)
    types = {o["type"] for o in objs}
    assert {"indicator", "domain-name", "attack-pattern"} <= types
    ind = next(o for o in objs if o["type"] == "indicator")
    assert "paypa1.test" in ind["pattern"]
    ev = store.recent_hunt_events()[0]
    assert any(o["id"] == ind["id"] for o in ev["stix"]["objects"])


def test_fresh_cert_raises_recorded_score(store):
    base = CTHunter(store=store, threshold=99, brand_floor=40)
    fresh = base.process("paypall.test", fresh=True)
    stale = CTHunter(store=Store(":memory:"), threshold=99).process("paypall.test", fresh=False)
    assert fresh and stale and fresh.score > stale.score
    sig = [s for s in fresh.verdict.signals if s.id == ctmod.FRESH_SIGNAL_ID]
    assert len(sig) == 1 and sig[0].contribution > 0
    assert not [s for s in stale.verdict.signals if s.id == ctmod.FRESH_SIGNAL_ID]
    assert "T1583.001" in {m.id for m in fresh.verdict.mitre}


def test_freshness_from_cert_timestamp(store):
    import time

    h = CTHunter(store=store)
    now = time.time()
    assert h._is_fresh({"not_before": now - 60}, None)
    assert not h._is_fresh({"not_before": now - 30 * 86400}, None)
    assert h._is_fresh({"source": "certstream"}, None)
    assert not h._is_fresh({"source": "sample"}, None)
    assert not h._is_fresh({"fresh": False, "not_before": now}, None)


def test_watch_brands_filter(store):
    h = CTHunter(store=store, watch_brands=["PayPal"])
    hits = h.hunt_once(list(LOOKALIKES))
    assert {x.brand for x in hits} == {"paypal"} and len(hits) == 3
    assert h.stats.recorded == 3 and h.stats.flagged == 3
    assert store.recent_hunt_events(brand="apple") == []
    # by display name and unknown brand tokens are tolerated
    h2 = CTHunter(store=Store(":memory:"), watch_brands=["Apple", "no-such-brand"])
    assert [x.brand for x in h2.hunt_once(list(LOOKALIKES))] == ["apple"]
    assert CTHunter(store=store, watch_brands=[]).watch is None


def test_high_score_non_brand_domain_respects_threshold(store):
    h = CTHunter(store=store, threshold=10, brand_floor=100)
    hit = h.process("kitchen-recipes.test", fresh=True)  # 12 >= 10, no brand
    assert hit and hit.brand is None and hit.reason == "score"
    assert CTHunter(store=Store(":memory:"), threshold=90).process("blog.example.org") is None


def test_dedup_and_invalid(hunter, store):
    assert hunter.process("paypa1.test")
    assert hunter.process("PAYPA1.test.") is None  # same host, normalised
    assert hunter.process("*.paypa1.test") is None
    assert hunter.process("not a domain") is None
    assert len(store.recent_hunt_events()) == 1
    assert hunter.stats.duplicates == 2 and hunter.stats.invalid == 1


def test_same_registrable_domain_alerted_once(hunter, store):
    assert hunter.process("paypa1.test")
    assert hunter.process("login.paypa1.test") is None
    assert hunter.stats.duplicate_alerts == 1
    assert len(store.recent_hunt_events()) == 1


def test_bus_event_published(hunter):
    async def main():
        got = []

        async def sub():
            async for ev in events.bus.subscribe():
                got.append(ev)
                if ev["type"] == "hunt":
                    return

        t = asyncio.create_task(sub())
        await asyncio.sleep(0)
        hit = await hunter.aprocess("paypa1.test", {"source": "sample"})
        await asyncio.wait_for(t, 2)
        return hit, got

    hit, got = asyncio.run(main())
    assert hit is not None
    hunt = [e for e in got if e["type"] == "hunt"]
    assert len(hunt) == 1
    d = hunt[0]["data"]
    assert d["domain"] == "paypa1.test" and d["brand"] == "paypal" and d["id"] == hit.event_id
    assert d["stix_id"].startswith("indicator--")


def test_no_bus_event_for_benign(hunter):
    async def main():
        got = []

        async def sub():
            async for ev in events.bus.subscribe():
                got.append(ev)

        t = asyncio.create_task(sub())
        await asyncio.sleep(0)
        await hunter.aprocess("my-garden-shop.test", {})
        await asyncio.sleep(0.05)
        t.cancel()
        return got

    assert not [e for e in asyncio.run(main()) if e["type"] == "hunt"]


def test_run_sample_end_to_end(store):
    h = CTHunter(store=store, workers=2, queue_size=2)  # tiny queue: back-pressure, no loss
    stats = asyncio.run(h.run("sample"))
    assert stats.recorded >= 5 and stats.errors == 0 and stats.dropped_queue_full == 0
    brands = {r["brand"] for r in store.recent_hunt_events()}
    assert {"paypal", "microsoft", "apple"} <= brands
    assert stats.duplicates >= 1  # paypa1.test repeats in the sample
    assert stats.to_dict()["by_brand"]["paypal"] >= 1
    json.dumps(stats.to_dict())


def test_run_certstream_fake_ws_max_domains(store):
    conn = _connector(
        [
            FakeWS(
                [
                    _cert("paypa1.test", "my-garden-shop.test"),
                    _cert("apple-id-verify.test"),
                    _cert("late.test"),
                ]
            )
        ]
    )
    h = CTHunter(store=store, workers=1)
    stats = asyncio.run(h.run("certstream", connect=conn, max_domains=3))
    assert stats.seen == 3 and stats.recorded == 2
    assert all(r["source"] == "certstream" for r in store.recent_hunt_events())


def test_run_live_drops_when_queue_full(store):
    conn = _connector([FakeWS([_cert(*[f"p{i}.test" for i in range(50)])])])
    h = CTHunter(store=store, workers=1, queue_size=1)
    stats = asyncio.run(h.run("certstream", connect=conn, max_certs=50))
    assert stats.dropped_queue_full > 0 and stats.seen + stats.dropped_queue_full == 50


def test_rate_cap_drops(store):
    conn = _connector([FakeWS([_cert(*[f"q{i}.test" for i in range(30)])])])
    h = CTHunter(store=store, workers=1, max_rate=1.0)
    stats = asyncio.run(h.run("certstream", connect=conn, max_certs=30))
    assert stats.dropped_rate_limit >= 25


def test_run_duration_stops_idle_stream(store):
    conn = _connector([FakeWS([], then="hang")])
    h = CTHunter(store=store)
    stats = asyncio.run(asyncio.wait_for(h.run("certstream", connect=conn, duration_s=0.1), 5))
    assert stats.seen == 0


def test_engine_failure_is_isolated(store):
    h = CTHunter(store=store)

    async def boom(*a, **k):
        raise RuntimeError("engine down")

    h.engine.analyze = boom  # type: ignore[method-assign]
    assert asyncio.run(h.aprocess("paypa1.test")) is None
    assert h.stats.errors == 1


def test_never_fetches_or_persists_verdicts(hunter, store, monkeypatch):
    """Issuance-time only: no network (conftest blocks it) and no verdict rows saved."""
    hunter.hunt_once(["paypa1.test"])
    assert store.stats()["verdicts"] == 0
    assert hunter.engine.hooks == []
    assert hunter._options.online is False and hunter._options.fetch_pages is False


def test_default_store_used_when_none(tmp_path):
    from uniphish.store import get_store, reset_store

    reset_store()
    try:
        h = CTHunter()
        h.process("paypa1.test")
        assert len(get_store().recent_hunt_events()) == 1
    finally:
        reset_store()
