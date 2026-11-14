"""Tests for the caching primitives (:mod:`uniphish.core.cache`).

Covers the three tools: the in-process :class:`TTLCache` (LRU + expiry + thread
safety), the :func:`async_cached` decorator (single-flight de-duplication + TTL), and
the persistent :class:`DiskCache` (round-trip, expiry, bound, persistence). A manual
clock is injected where time must be deterministic.
"""

from __future__ import annotations

import asyncio
import threading

import pytest

from uniphish.core.cache import DiskCache, TTLCache, async_cached


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


# --------------------------------------------------------------------------- TTLCache
def test_ttlcache_set_get_contains():
    c = TTLCache(maxsize=10, ttl=100)
    c.set("k", 42)
    assert c.get("k") == 42
    assert "k" in c
    assert c.get("missing") is None
    assert c.get("missing", "d") == "d"
    assert len(c) == 1


def test_ttlcache_expiry():
    clock = Clock()
    c = TTLCache(maxsize=10, ttl=10, timer=clock)
    c.set("k", 1)
    clock.advance(9)
    assert c.get("k") == 1
    clock.advance(2)  # now 11 > ttl 10
    assert c.get("k") is None
    assert "k" not in c
    assert len(c) == 0


def test_ttlcache_lru_eviction():
    c = TTLCache(maxsize=2, ttl=100, timer=Clock())
    c.set("a", 1)
    c.set("b", 2)
    assert c.get("a") == 1  # touch 'a' so 'b' is now least-recently-used
    c.set("c", 3)
    assert c.get("b") is None  # evicted
    assert c.get("a") == 1 and c.get("c") == 3


def test_ttlcache_update_moves_to_end():
    c = TTLCache(maxsize=2, ttl=100, timer=Clock())
    c.set("a", 1)
    c.set("b", 2)
    c.set("a", 10)  # refresh 'a'
    c.set("c", 3)  # should evict 'b'
    assert c.get("a") == 10 and c.get("c") == 3 and c.get("b") is None


def test_ttlcache_no_ttl_is_pure_lru():
    c = TTLCache(maxsize=10, ttl=0, timer=Clock())
    c.set("k", 1)
    assert c.get("k") == 1 and len(c) == 1


def test_ttlcache_get_or_set_and_pop():
    c = TTLCache(maxsize=10, ttl=100)
    calls = {"n": 0}

    def factory():
        calls["n"] += 1
        return "v"

    assert c.get_or_set("k", factory) == "v"
    assert c.get_or_set("k", factory) == "v"
    assert calls["n"] == 1  # factory ran once
    assert c.pop("k") == "v"
    assert c.pop("k", "default") == "default"


def test_ttlcache_len_excludes_expired():
    clock = Clock()
    c = TTLCache(maxsize=10, ttl=5, timer=clock)
    c.set("a", 1)
    c.set("b", 2)
    assert len(c) == 2
    clock.advance(6)
    assert len(c) == 0


def test_ttlcache_thread_safe_under_contention():
    c = TTLCache(maxsize=256, ttl=100)
    errors: list[Exception] = []

    def worker(base: int) -> None:
        try:
            for i in range(2000):
                c.set((base, i % 50), i)
                c.get((base, i % 50))
        except Exception as exc:  # pragma: no cover - would indicate a race
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(b,)) for b in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(c) <= 256  # maxsize honoured


# ------------------------------------------------------------------------ async_cached
async def test_async_cached_single_flight():
    calls = {"n": 0}
    gate = asyncio.Event()

    @async_cached(ttl=100, maxsize=10)
    async def fetch(x: int) -> int:
        calls["n"] += 1
        await gate.wait()
        return x * 2

    tasks = [asyncio.create_task(fetch(5)) for _ in range(6)]
    await asyncio.sleep(0.01)  # let them all reach the gate and coalesce
    gate.set()
    results = await asyncio.gather(*tasks)
    assert results == [10] * 6
    assert calls["n"] == 1  # the herd collapsed to one call


async def test_async_cached_returns_cached_value():
    calls = {"n": 0}

    @async_cached(ttl=100, maxsize=10)
    async def fetch(x: int) -> int:
        calls["n"] += 1
        return x + 1

    assert await fetch(1) == 2
    assert await fetch(1) == 2
    assert calls["n"] == 1
    assert await fetch(2) == 3
    assert calls["n"] == 2


async def test_async_cached_distinct_keys_not_shared():
    @async_cached(ttl=100)
    async def fetch(x: int) -> int:
        return x

    a, b = await asyncio.gather(fetch(1), fetch(2))
    assert a == 1 and b == 2


async def test_async_cached_custom_key():
    calls = {"n": 0}

    @async_cached(ttl=100, key=lambda host, port=80: host)
    async def lookup(host: str, port: int = 80) -> str:
        calls["n"] += 1
        return f"{host}:{port}"

    assert await lookup("a.test", 80) == "a.test:80"
    assert await lookup("a.test", 443) == "a.test:80"  # same key -> cached
    assert calls["n"] == 1


async def test_async_cached_ttl_expiry():
    calls = {"n": 0}

    @async_cached(ttl=0.05, maxsize=10)
    async def fetch(x: int) -> int:
        calls["n"] += 1
        return x

    await fetch(1)
    await fetch(1)
    assert calls["n"] == 1
    await asyncio.sleep(0.08)
    await fetch(1)
    assert calls["n"] == 2


async def test_async_cached_error_not_cached_and_shared():
    calls = {"n": 0}

    @async_cached(ttl=100)
    async def boom() -> int:
        calls["n"] += 1
        await asyncio.sleep(0.01)
        raise ValueError("fail")

    results = await asyncio.gather(boom(), boom(), boom(), return_exceptions=True)
    assert all(isinstance(e, ValueError) for e in results)
    assert calls["n"] == 1  # concurrent callers shared the single failing flight
    with pytest.raises(ValueError):
        await boom()  # error was not cached -> runs again
    assert calls["n"] == 2


async def test_async_cached_exposes_cache_clear():
    calls = {"n": 0}

    @async_cached(ttl=100)
    async def fetch(x: int) -> int:
        calls["n"] += 1
        return x

    await fetch(1)
    fetch.cache_clear()
    await fetch(1)
    assert calls["n"] == 2


# --------------------------------------------------------------------------- DiskCache
def test_diskcache_roundtrip_json(tmp_path):
    d = DiskCache("dns", ttl=100, data_dir=tmp_path)
    assert d.set("a.test", {"A": ["1.2.3.4"], "ttl": 300}) is True
    assert d.get("a.test") == {"A": ["1.2.3.4"], "ttl": 300}
    assert d.get("missing") is None
    assert "a.test" in d and len(d) == 1


def test_diskcache_overwrite(tmp_path):
    d = DiskCache("ns", ttl=100, data_dir=tmp_path)
    d.set("k", 1)
    d.set("k", 2)
    assert d.get("k") == 2 and len(d) == 1


def test_diskcache_delete_and_clear(tmp_path):
    d = DiskCache("ns", ttl=100, data_dir=tmp_path)
    d.set("a", 1)
    d.set("b", 2)
    d.delete("a")
    assert d.get("a") is None and d.get("b") == 2
    d.clear()
    assert len(d) == 0


def test_diskcache_expiry(tmp_path):
    d = DiskCache("ns", ttl=0.05, data_dir=tmp_path)
    d.set("k", "v")
    assert d.get("k") == "v"
    import time

    time.sleep(0.08)
    assert d.get("k") is None
    assert "k" not in d


def test_diskcache_persists_across_instances(tmp_path):
    DiskCache("ns", ttl=100, data_dir=tmp_path).set("k", {"x": 1})
    # A fresh handle to the same file (a second process would be identical) sees it.
    assert DiskCache("ns", ttl=100, data_dir=tmp_path).get("k") == {"x": 1}


def test_diskcache_size_bound_evicts(tmp_path):
    d = DiskCache("ns", ttl=1000, data_dir=tmp_path, max_entries=3)
    for i in range(6):
        d.set(f"k{i}", i)
    assert len(d) == 3


def test_diskcache_rejects_oversized_value(tmp_path):
    d = DiskCache("ns", ttl=100, data_dir=tmp_path, max_value_bytes=16)
    assert d.set("k", "x" * 100) is False
    assert d.get("k") is None


def test_diskcache_rejects_unserialisable_value(tmp_path):
    d = DiskCache("ns", ttl=100, data_dir=tmp_path)
    assert d.set("k", object()) is False


def test_diskcache_get_or_set(tmp_path):
    d = DiskCache("ns", ttl=100, data_dir=tmp_path)
    calls = {"n": 0}

    def factory():
        calls["n"] += 1
        return {"v": 1}

    assert d.get_or_set("k", factory) == {"v": 1}
    assert d.get_or_set("k", factory) == {"v": 1}
    assert calls["n"] == 1


def test_diskcache_namespace_sanitised(tmp_path):
    d = DiskCache("weird/../name space!", ttl=100, data_dir=tmp_path)
    d.set("k", 1)
    assert d.get("k") == 1
    assert d.path.parent == tmp_path  # no path traversal out of the cache dir


def test_diskcache_uses_settings_data_dir_by_default():
    # With no explicit data_dir the file lands under the (test-isolated) settings dir.
    from uniphish.core.config import get_settings

    d = DiskCache("defaults", ttl=100)
    d.set("k", 1)
    assert d.get("k") == 1
    assert get_settings().data_dir in d.path.parents


def test_diskcache_concurrent_writes_same_file(tmp_path):
    # Thread-level stand-in for multiprocess access: shared file, concurrent writers.
    errors: list[Exception] = []

    def worker(base: int) -> None:
        d = DiskCache("shared", ttl=1000, data_dir=tmp_path)
        try:
            for i in range(50):
                d.set(f"{base}-{i}", {"i": i})
                d.get(f"{base}-{i}")
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(b,)) for b in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert DiskCache("shared", ttl=1000, data_dir=tmp_path).get("0-0") == {"i": 0}
