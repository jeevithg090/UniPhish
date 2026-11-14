"""Tests for uniphish.store.db (offline, temp-file SQLite)."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

from uniphish.core.types import (
    Action,
    ArtifactKind,
    BrandMatch,
    Indicator,
    IndicatorType,
    Level,
    Verdict,
)
from uniphish.store import SCHEMA_VERSION, Store, get_store, norm_value, reset_store


def make_verdict(
    target="http://login.evil.test/a",
    score=90,
    level=Level.MALICIOUS,
    kind=ArtifactKind.URL,
    indicators=(),
    brand=None,
    created_at=None,
    children=(),
) -> Verdict:
    kw = {}
    if created_at is not None:
        kw["created_at"] = created_at
    return Verdict(
        kind=kind,
        target=target,
        artifact_id="a" * 24,
        risk=score / 100,
        score=score,
        logit=1.0,
        level=level,
        action=Action.BLOCK,
        confidence=0.9,
        summary="test",
        indicators=list(indicators),
        brand=brand,
        children=list(children),
        **kw,
    )


def dom(value, mal=True):
    return Indicator(type=IndicatorType.DOMAIN, value=value, malicious=mal)


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "t.db")
    yield s
    s.close()


# ---- migrations ---------------------------------------------------------- #
def test_migrations_idempotent(tmp_path):
    p = tmp_path / "m.db"
    s1 = Store(p)
    assert s1.schema_version == SCHEMA_VERSION
    s1.set_reputation("domain", "a.test", "deny")
    s1.close()
    s2 = Store(p)
    assert s2.schema_version == SCHEMA_VERSION
    assert s2.lookup_reputation("domain", "a.test") is not None
    s2.close()


def test_newer_schema_rejected(tmp_path):
    p = tmp_path / "n.db"
    Store(p).close()
    c = sqlite3.connect(p)
    c.execute(f"PRAGMA user_version={SCHEMA_VERSION + 5}")
    c.close()
    with pytest.raises(RuntimeError):
        Store(p)


def test_upgrade_from_v1(tmp_path):
    from uniphish.store import db as dbmod

    p = tmp_path / "v1.db"
    c = sqlite3.connect(p, isolation_level=None)
    for stmt in dbmod._MIGRATIONS[0]:
        c.execute(stmt)
    c.execute("PRAGMA user_version=1")
    c.close()
    s = Store(p)
    assert s.schema_version == SCHEMA_VERSION
    assert s.stix_objects(synthesize=False) == []
    s.close()


def test_default_path_uses_settings(tmp_path):
    reset_store()
    s = get_store()
    assert s is get_store()
    assert s.path.startswith(str(tmp_path))
    reset_store()


def test_closed_store_raises(tmp_path):
    s = Store(tmp_path / "c.db")
    s.close()
    s.close()
    with pytest.raises(RuntimeError):
        s.stats()


# ---- verdicts ------------------------------------------------------------ #
def test_save_get_roundtrip(store):
    brand = BrandMatch(brand="paypal", name="PayPal", technique="homoglyph", confidence=0.9)
    v = make_verdict(indicators=[dom("login.evil.test")], brand=brand)
    assert store.save_verdict(v, source="api") == v.id
    got = store.get_verdict(v.id)
    assert got is not None
    assert got.model_dump() == v.model_dump()
    row = store.get_verdict_row(v.id)
    assert row["brand"] == "paypal" and row["source"] == "api" and row["level"] == "malicious"
    assert store.get_verdict("missing") is None


def test_resave_same_id_does_not_recount(store):
    v = make_verdict(indicators=[dom("x.test")])
    store.save_verdict(v)
    store.save_verdict(v)
    assert store.search_indicator("domain", "x.test")[0]["count"] == 1
    assert store.stats()["verdicts"] == 1


def test_indicator_upsert_counts_and_last_seen(store):
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    t1 = t0 + timedelta(days=2)
    store.save_verdict(make_verdict(indicators=[dom("Evil.Test.", mal=False)], created_at=t0))
    store.save_verdict(make_verdict(indicators=[dom("evil.test")], created_at=t1))
    rows = store.search_indicator("domain", "EVIL.test")
    assert len(rows) == 1
    r = rows[0]
    assert r["count"] == 2
    assert r["first_seen"].startswith("2026-01-01")
    assert r["last_seen"].startswith("2026-01-03")
    assert r["malicious"] == 1  # sticky
    assert store.search_indicator("domain", "other.test") == []


def test_child_indicators_saved(store):
    child = make_verdict(target="http://c.test/", indicators=[dom("child.test")])
    parent = make_verdict(indicators=[dom("parent.test")], children=[child])
    store.save_verdict(parent)
    assert store.search_indicator("domain", "child.test")
    assert store.search_indicator("domain", "parent.test")


def test_recent_filters(store):
    base = datetime(2026, 3, 1, tzinfo=timezone.utc)
    store.save_verdict(make_verdict("http://a.test/", 95, Level.MALICIOUS, created_at=base))
    store.save_verdict(
        make_verdict("http://b.test/", 60, Level.SUSPICIOUS, created_at=base + timedelta(minutes=1))
    )
    store.save_verdict(
        make_verdict(
            "hello", 5, Level.BENIGN, ArtifactKind.TEXT, created_at=base + timedelta(minutes=2)
        )
    )
    allv = store.recent_verdicts()
    assert [r["score"] for r in allv] == [5, 60, 95]  # newest first
    assert [r["score"] for r in store.recent_verdicts(min_score=60)] == [60, 95]
    assert [r["kind"] for r in store.recent_verdicts(kind="text")] == ["text"]
    assert [r["kind"] for r in store.recent_verdicts(kind=ArtifactKind.URL)] == ["url", "url"]
    assert [r["score"] for r in store.recent_verdicts(level="suspicious")] == [60]
    assert len(store.recent_verdicts(limit=1)) == 1
    assert len(store.recent_verdicts(limit=0)) == 1  # clamped
    assert "json" not in allv[0]


def test_find_verdicts_normalised_url(store):
    store.save_verdict(make_verdict("HTTP://Evil.TEST/a#frag"))
    assert len(store.find_verdicts("url", "http://evil.test/a")) == 1


def test_sql_injection_is_inert(store):
    nasty = "x'; DROP TABLE verdicts; --"
    store.save_verdict(make_verdict(nasty, indicators=[dom(nasty)]))
    store.set_reputation("domain", nasty, "deny")
    assert store.recent_verdicts(kind=nasty) == []
    assert store.stats()["verdicts"] == 1
    assert store.lookup_reputation("domain", nasty) is not None


def test_stats_and_timeline(store):
    now = datetime.now(timezone.utc)
    store.save_verdict(make_verdict(score=100, created_at=now))
    store.save_verdict(make_verdict("http://b.test/", 55, Level.SUSPICIOUS, created_at=now))
    store.save_verdict(
        make_verdict("http://c.test/", 3, Level.BENIGN, created_at=now - timedelta(hours=3))
    )
    store.save_verdict(
        make_verdict("http://old.test/", 3, Level.BENIGN, created_at=now - timedelta(days=10))
    )
    s = store.stats()
    assert s["verdicts"] == 4
    assert s["by_level"] == {"malicious": 1, "suspicious": 1, "benign": 2}
    assert s["by_kind"] == {"url": 4}
    assert s["score_histogram"][9] == 1 and s["score_histogram"][5] == 1
    assert s["score_histogram"][0] == 2 and sum(s["score_histogram"]) == 4
    tl = store.timeline(6)
    assert len(tl) == 6
    assert sum(b["total"] for b in tl) == 3
    assert tl[-1]["malicious"] == 1 and tl[-1]["suspicious"] == 1
    assert sum(b["benign"] for b in tl) == 1


# ---- reputation ---------------------------------------------------------- #
def test_reputation_set_lookup_update(store):
    store.set_reputation("domain", "Good.Example.COM.", "allow", 2.5, "official", "seed")
    r = store.lookup_reputation("domain", "good.example.com")
    assert r["verdict"] == "allow" and r["weight"] == 2.5 and r["expires_at"] is None
    store.set_reputation(IndicatorType.DOMAIN, "good.example.com", "deny", 4, "hijacked")
    assert store.lookup_reputation("domain", "good.example.com")["verdict"] == "deny"
    assert store.reputation_counts() == {"allow": 0, "deny": 1, "unknown": 0}
    assert store.lookup_reputation("domain", "nope.test") is None
    assert store.delete_reputation("domain", "good.example.com") is True
    assert store.delete_reputation("domain", "good.example.com") is False


def test_reputation_validation(store):
    with pytest.raises(ValueError):
        store.set_reputation("domain", "a.test", "maybe")
    with pytest.raises(ValueError):
        store.set_reputation("domain", "  ", "deny")


def test_reputation_expiry(store):
    store.set_reputation("domain", "short.test", "deny", ttl=-1)  # already expired
    store.set_reputation("domain", "long.test", "deny", ttl=3600)
    store.set_reputation("domain", "td.test", "allow", ttl=timedelta(minutes=5))
    assert store.lookup_reputation("domain", "short.test") is None
    assert store.lookup_reputation("domain", "long.test") is not None
    assert store.reputation_counts() == {"allow": 1, "deny": 1, "unknown": 0}
    assert {r["value"] for r in store.list_reputation()} == {"long.test", "td.test"}
    assert [r["value"] for r in store.list_reputation(verdict="allow")] == ["td.test"]
    assert store.purge_expired() == 1
    assert store.purge_expired() == 0


def test_bulk_set_atomic(store):
    n = store.bulk_set(
        [
            {"type": "domain", "value": "a.test", "verdict": "deny", "weight": 3},
            ("domain", "b.test", "allow", 1.0, "r", "feed", 60),
            ("ipv4", "1.2.3.4", "unknown"),
        ]
    )
    assert n == 3
    assert store.lookup_reputation("domain", "b.test")["expires_at"] is not None
    assert store.lookup_reputation("ipv4", "1.2.3.4")["weight"] == 0.0
    with pytest.raises(ValueError):
        store.bulk_set([("domain", "c.test", "deny"), ("domain", "d.test", "bogus")])
    assert store.lookup_reputation("domain", "c.test") is None
    assert store.bulk_set([]) == 0


# ---- hunt events --------------------------------------------------------- #
def test_hunt_events(store):
    base = datetime(2026, 5, 1, tzinfo=timezone.utc)
    store.add_hunt_event(
        "ct",
        "Paypa1-login.test.",
        80,
        "PayPal",
        ["homoglyph", "combosquat"],
        {"type": "indicator"},
        ts=base,
    )
    store.add_hunt_event("ct", "other.test", 20, None, ts=base + timedelta(seconds=1))
    store.add_hunt_event("ct", "bank.test", 999, "paypal", ts=base + timedelta(seconds=2))
    ev = store.recent_hunt_events()
    assert [e["domain"] for e in ev] == ["bank.test", "other.test", "paypa1-login.test"]
    assert ev[0]["score"] == 100  # clamped
    assert ev[2]["techniques"] == ["homoglyph", "combosquat"]
    assert ev[2]["stix"] == {"type": "indicator"} and ev[1]["stix"] is None
    assert len(store.recent_hunt_events(min_score=50)) == 2
    assert {e["domain"] for e in store.recent_hunt_events(brand="PAYPAL")} == {
        "bank.test",
        "paypa1-login.test",
    }
    assert len(store.recent_hunt_events(limit=1)) == 1


# ---- stix ---------------------------------------------------------------- #
def test_stix_synthesised_and_explicit(store):
    store.save_verdict(make_verdict(indicators=[dom("bad.test"), dom("fine.test", mal=False)]))
    objs = store.stix_objects()
    assert len(objs) == 1
    o = objs[0]
    assert o["type"] == "indicator" and o["spec_version"] == "2.1"
    assert o["pattern"] == "[domain-name:value = 'bad.test']"
    assert store.stix_objects()[0]["id"] == o["id"]  # deterministic
    sid = "identity--11111111-1111-4111-8111-111111111111"
    assert store.add_stix_object({"type": "identity", "id": sid, "name": "x"})
    assert {x["type"] for x in store.stix_objects()} == {"indicator", "identity"}
    assert [x["type"] for x in store.stix_objects(synthesize=False)] == ["identity"]
    future = datetime.now(timezone.utc) + timedelta(days=1)
    assert store.stix_objects(added_after=future) == []
    assert len(store.stix_objects(added_after="2000-01-01T00:00:00Z", limit=1)) == 1
    with pytest.raises(ValueError):
        store.add_stix_object({"type": "identity", "id": "bad"})


def test_stix_pattern_escaping(store):
    store.save_verdict(
        make_verdict(
            indicators=[
                Indicator(type=IndicatorType.URL, value="http://x.test/it's", malicious=True)
            ]
        )
    )
    assert store.stix_objects()[0]["pattern"] == "[url:value = 'http://x.test/it\\'s']"


# ---- normalisation ------------------------------------------------------- #
def test_norm_value():
    assert norm_value("domain", "Example.COM.") == "example.com"
    assert norm_value("domain", "bücher.test") == "xn--bcher-kva.test"
    assert norm_value("url", "HTTP://User@Ex.com:8080/P?q=1#f") == "http://User@ex.com:8080/P?q=1"
    assert norm_value("url", "http://[::1]:80/x") == "http://[::1]:80/x"
    assert norm_value("sha256", "ABC") == "abc"
    assert norm_value("ipv6", "2001:0DB8:0:0:0:0:0:1") == "2001:db8::1"
    assert norm_value("phone", "+1 (555) 010-0000") == "+15550100000"
    assert norm_value("asn", "AS123") == "123"
    assert norm_value("url", "http://[bad") == "http://[bad"


# ---- concurrency --------------------------------------------------------- #
def test_concurrent_writes_threads(tmp_path):
    s = Store(tmp_path / "c.db")
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        try:
            for j in range(15):
                s.save_verdict(
                    make_verdict(f"http://h{i}-{j}.test/", indicators=[dom("shared.test")])
                )
                s.set_reputation("domain", f"r{i}-{j}.test", "deny")
        except BaseException as e:
            errors.append(e)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors
    assert s.stats()["verdicts"] == 120
    assert s.search_indicator("domain", "shared.test")[0]["count"] == 120
    assert s.reputation_counts()["deny"] == 120
    s.close()


def test_concurrent_writes_two_connections(tmp_path):
    p = tmp_path / "shared.db"
    a, b = Store(p), Store(p)
    errors: list[BaseException] = []

    def worker(s: Store, tag: str) -> None:
        try:
            for j in range(25):
                s.save_verdict(
                    make_verdict(f"http://{tag}{j}.test/", indicators=[dom("shared.test")])
                )
        except BaseException as e:
            errors.append(e)

    ts = [
        threading.Thread(target=worker, args=(a, "a")),
        threading.Thread(target=worker, args=(b, "b")),
    ]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors
    assert a.stats()["verdicts"] == 50
    assert b.search_indicator("domain", "shared.test")[0]["count"] == 50
    assert sqlite3.connect(p).execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    a.close()
    b.close()


def test_memory_store():
    with Store(":memory:") as s:
        s.save_verdict(make_verdict())
        assert s.stats()["verdicts"] == 1
