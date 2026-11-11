"""Caching primitives shared across the platform.

Three complementary tools, each for a distinct need:

* :class:`TTLCache` — a thread-safe in-process LRU cache with per-entry expiry, for
  hot, cheap-to-store values (parsed assets, compiled rules, small lookups).
* :func:`async_cached` — a decorator for ``async def`` functions that both caches
  results *and* collapses concurrent identical calls into one (single-flight), so a
  burst of look-ups for the same host does one DNS query, not N.
* :class:`DiskCache` — a tiny SQLite key/value store under ``settings.data_dir`` for
  values that should survive the process (DNS answers, RDAP/WHOIS, feed responses).
  It is JSON-only, size-bounded and safe to share between threads and processes.

None of these ever touch the network; they are pure caching mechanisms.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import json
import logging
import random
import re
import sqlite3
import threading
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Hashable
from pathlib import Path
from typing import Any, TypeVar

from uniphish.core.config import get_settings

log = logging.getLogger("uniphish.cache")

__all__ = ["DiskCache", "TTLCache", "async_cached"]

_MISSING = object()
T = TypeVar("T")


# --------------------------------------------------------------------------- TTLCache
class TTLCache:
    """Thread-safe least-recently-used cache with a per-entry time-to-live.

    ``ttl`` is in seconds; ``ttl <= 0`` disables expiry (pure LRU). ``maxsize`` bounds
    the number of live entries (``<= 0`` means unbounded). Expired and evicted entries
    are dropped lazily on access and eagerly on insertion. The ``timer`` is injectable
    so tests can advance time deterministically.
    """

    __slots__ = ("_data", "_lock", "_maxsize", "_timer", "_ttl")

    def __init__(
        self,
        maxsize: int = 1024,
        ttl: float = 300.0,
        *,
        timer: Callable[[], float] = time.monotonic,
    ) -> None:
        self._data: OrderedDict[Hashable, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()
        self._maxsize = maxsize
        self._ttl = ttl
        self._timer = timer

    def _expired(self, expires_at: float) -> bool:
        return self._ttl > 0 and expires_at <= self._timer()

    def get(self, key: Hashable, default: Any = None) -> Any:
        with self._lock:
            entry = self._data.get(key, _MISSING)
            if entry is _MISSING:
                return default
            expires_at, value = entry  # type: ignore[misc]
            if self._expired(expires_at):
                del self._data[key]
                return default
            self._data.move_to_end(key)
            return value

    def set(self, key: Hashable, value: Any) -> None:
        with self._lock:
            expires_at = self._timer() + self._ttl if self._ttl > 0 else float("inf")
            self._data[key] = (expires_at, value)
            self._data.move_to_end(key)
            if self._maxsize > 0:
                while len(self._data) > self._maxsize:
                    self._data.popitem(last=False)

    def get_or_set(self, key: Hashable, factory: Callable[[], T]) -> T:
        """Return the cached value, or compute it with ``factory`` and store it."""
        found = self.get(key, _MISSING)
        if found is not _MISSING:
            return found
        value = factory()
        self.set(key, value)
        return value

    def pop(self, key: Hashable, default: Any = None) -> Any:
        with self._lock:
            entry = self._data.pop(key, _MISSING)
            if entry is _MISSING:
                return default
            expires_at, value = entry  # type: ignore[misc]
            return default if self._expired(expires_at) else value

    def __contains__(self, key: Hashable) -> bool:
        return self.get(key, _MISSING) is not _MISSING

    def __len__(self) -> int:
        with self._lock:
            now = self._timer()
            if self._ttl <= 0:
                return len(self._data)
            return sum(1 for expires_at, _ in self._data.values() if expires_at > now)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


# ------------------------------------------------------------------------ async_cached
def _default_key(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    return f"{args!r}|{sorted(kwargs.items())!r}"


def async_cached(
    ttl: float = 300.0,
    maxsize: int = 1024,
    *,
    key: Callable[..., Hashable] | None = None,
) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    """Cache an ``async`` function's results and de-duplicate concurrent calls.

    Concurrent calls that map to the same key share a single in-flight coroutine
    (single-flight), so the wrapped function runs once even under a thundering herd;
    both success and failure are shared with every waiter. Results are stored in a
    :class:`TTLCache`. The wrapper exposes ``.cache`` and ``.cache_clear()``.
    """

    def decorator(fn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        cache = TTLCache(maxsize=maxsize, ttl=ttl)
        key_fn = key or (lambda *a, **k: _default_key(a, k))
        inflight: dict[Hashable, asyncio.Future] = {}

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            cache_key = key_fn(*args, **kwargs)
            cached = cache.get(cache_key, _MISSING)
            if cached is not _MISSING:
                return cached

            loop = asyncio.get_running_loop()
            pending = inflight.get(cache_key)
            # Reuse an in-flight call only if it belongs to this event loop.
            if pending is not None and not pending.done() and pending.get_loop() is loop:
                return await pending

            future: asyncio.Future = loop.create_future()
            inflight[cache_key] = future
            # No await happened between the check above and here, so this assignment is
            # atomic w.r.t. other coroutines on this loop: exactly one runner is created.
            try:
                result = await fn(*args, **kwargs)
            except BaseException as exc:
                inflight.pop(cache_key, None)
                if not future.done():
                    future.set_exception(exc)
                raise
            else:
                cache.set(cache_key, result)
                inflight.pop(cache_key, None)
                if not future.done():
                    future.set_result(result)
                return result

        wrapper.cache = cache  # type: ignore[attr-defined]
        wrapper.cache_clear = cache.clear  # type: ignore[attr-defined]
        return wrapper

    return decorator


# --------------------------------------------------------------------------- DiskCache
_NAMESPACE_RE = re.compile(r"[^A-Za-z0-9_.-]")


class DiskCache:
    """A tiny persistent JSON key/value store backed by SQLite.

    One SQLite file per ``namespace`` lives under ``settings.data_dir/cache``. Values
    must be JSON-serialisable. Entries expire after ``ttl`` seconds (``ttl <= 0``
    disables expiry). The store is bounded to ``max_entries`` rows (oldest-expiring
    evicted first) and rejects values larger than ``max_value_bytes``. SQLite's own
    locking (WAL + a busy timeout) makes it safe to share between threads and separate
    processes; a fresh connection is opened per operation.
    """

    def __init__(
        self,
        namespace: str,
        ttl: float = 86_400.0,
        *,
        data_dir: Path | None = None,
        max_entries: int = 50_000,
        max_value_bytes: int = 1_000_000,
    ) -> None:
        safe = _NAMESPACE_RE.sub("_", namespace) or "default"
        base = data_dir if data_dir is not None else get_settings().data_dir / "cache"
        base.mkdir(parents=True, exist_ok=True)
        self.path = base / f"{safe}.sqlite"
        self.ttl = ttl
        self.max_entries = max_entries
        self.max_value_bytes = max_value_bytes
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        # busy_timeout is per-connection and must be set on every one: it makes a
        # concurrent writer wait rather than fail with "database is locked". WAL mode
        # is persisted in the database header by _init_db, so it is NOT re-set here —
        # re-running `PRAGMA journal_mode=WAL` on every operation is itself a
        # write-lock contention point under concurrent access.
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    @contextlib.contextmanager
    def _session(self):
        """Yield a connection inside a transaction and ALWAYS close it afterwards.

        Leaving connections for the GC to close (the previous behaviour) let them
        linger holding WAL locks under concurrent access, which starved writers and
        caused contended writes to be dropped. Closing promptly keeps lock hold-times
        short so ``busy_timeout`` can do its job.
        """
        conn = self._connect()
        try:
            with conn:  # commit on success, rollback on exception
                yield conn
        finally:
            conn.close()

    def _write(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        """Run a write ``fn(conn)`` inside a ``BEGIN IMMEDIATE`` transaction, retrying on
        lock contention, so a contended write waits and succeeds rather than being dropped.

        ``BEGIN IMMEDIATE`` takes the write lock at the *start* of the transaction, so
        ``busy_timeout`` reliably governs how long the writer waits. A deferred (default)
        transaction acquires the write lock lazily and, when two connections each hold a
        read lock and both try to upgrade, SQLite raises ``SQLITE_BUSY`` immediately —
        bypassing ``busy_timeout`` — which is how a write could be dropped under
        concurrency despite the timeout. The jittered backoff is a backstop that also
        breaks up thundering-herd re-collisions."""
        last: sqlite3.OperationalError | None = None
        for attempt in range(8):
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                result = fn(conn)
                conn.execute("COMMIT")
                return result
            except sqlite3.OperationalError as exc:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                if "lock" not in str(exc).lower():
                    raise
                last = exc
                time.sleep(0.05 * (attempt + 1) + random.uniform(0.0, 0.03))
            except BaseException:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()
        raise last if last else sqlite3.OperationalError("write failed")

    def _init_db(self) -> None:
        """Set WAL mode and create the schema, retrying on lock contention.

        Flipping the journal mode to WAL needs a brief exclusive lock on a fresh
        database, and ``busy_timeout`` does not govern that change — so when several
        connections open the same new file at once, all but one raise "database is
        locked". Retrying rides that out; once any connection has set WAL the pragma is a
        cheap no-op, and ``CREATE ... IF NOT EXISTS`` is idempotent."""
        last: sqlite3.OperationalError | None = None
        for attempt in range(8):
            conn = self._connect()
            try:
                mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()
                if not mode or str(mode[0]).lower() != "wal":
                    # Another connection holds the header lock; back off and retry.
                    raise sqlite3.OperationalError("database is locked")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS kv ("
                    "  key TEXT PRIMARY KEY,"
                    "  value TEXT NOT NULL,"
                    "  expires_at REAL NOT NULL"
                    ")"
                )
                conn.execute("CREATE INDEX IF NOT EXISTS kv_expires ON kv(expires_at)")
                return
            except sqlite3.OperationalError as exc:
                if "lock" not in str(exc).lower():
                    raise
                last = exc
                time.sleep(0.05 * (attempt + 1) + random.uniform(0.0, 0.03))
            finally:
                conn.close()
        raise last if last else sqlite3.OperationalError("init failed")

    def get(self, key: str, default: Any = None) -> Any:
        now = time.time()
        try:
            with self._session() as conn:
                row = conn.execute(
                    "SELECT value, expires_at FROM kv WHERE key = ?", (key,)
                ).fetchone()
                if row is None:
                    return default
                value_json, expires_at = row
                if self.ttl > 0 and expires_at <= now:
                    conn.execute("DELETE FROM kv WHERE key = ?", (key,))
                    return default
        except sqlite3.Error as exc:
            log.warning("DiskCache[%s].get failed: %r", self.path.name, exc)
            return default
        try:
            return json.loads(value_json)
        except (json.JSONDecodeError, TypeError):
            return default

    def set(self, key: str, value: Any) -> bool:
        """Store ``value`` (JSON). Returns ``False`` if it was too large or unserialisable."""
        try:
            encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            log.warning("DiskCache[%s].set unserialisable value: %r", self.path.name, exc)
            return False
        if len(encoded.encode("utf-8")) > self.max_value_bytes:
            log.warning("DiskCache[%s].set value exceeds %d bytes",
                        self.path.name, self.max_value_bytes)
            return False
        expires_at = (time.time() + self.ttl) if self.ttl > 0 else float("inf")

        def _do(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO kv(key, value, expires_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                "expires_at = excluded.expires_at",
                (key, encoded, expires_at),
            )
            self._enforce_bound(conn)

        try:
            self._write(_do)
        except sqlite3.Error as exc:
            log.warning("DiskCache[%s].set failed: %r", self.path.name, exc)
            return False
        return True

    def _enforce_bound(self, conn: sqlite3.Connection) -> None:
        if self.max_entries <= 0:
            return
        now = time.time()
        if self.ttl > 0:
            conn.execute("DELETE FROM kv WHERE expires_at <= ?", (now,))
        count = conn.execute("SELECT COUNT(*) FROM kv").fetchone()[0]
        if count > self.max_entries:
            conn.execute(
                "DELETE FROM kv WHERE key IN ("
                "  SELECT key FROM kv ORDER BY expires_at ASC LIMIT ?"
                ")",
                (count - self.max_entries,),
            )

    def get_or_set(self, key: str, factory: Callable[[], Any]) -> Any:
        """Return the cached value, or compute it with ``factory``, store and return it."""
        found = self.get(key, _MISSING)
        if found is not _MISSING:
            return found
        value = factory()
        self.set(key, value)
        return value

    def delete(self, key: str) -> None:
        try:
            self._write(lambda conn: conn.execute("DELETE FROM kv WHERE key = ?", (key,)))
        except sqlite3.Error as exc:
            log.warning("DiskCache[%s].delete failed: %r", self.path.name, exc)

    def clear(self) -> None:
        try:
            self._write(lambda conn: conn.execute("DELETE FROM kv"))
        except sqlite3.Error as exc:
            log.warning("DiskCache[%s].clear failed: %r", self.path.name, exc)

    def __contains__(self, key: str) -> bool:
        return self.get(key, _MISSING) is not _MISSING

    def __len__(self) -> int:
        now = time.time()
        try:
            with self._session() as conn:
                if self.ttl > 0:
                    row = conn.execute(
                        "SELECT COUNT(*) FROM kv WHERE expires_at > ?", (now,)
                    ).fetchone()
                else:
                    row = conn.execute("SELECT COUNT(*) FROM kv").fetchone()
                return int(row[0])
        except sqlite3.Error as exc:
            log.warning("DiskCache[%s].__len__ failed: %r", self.path.name, exc)
            return 0
