"""SQLite persistence for verdicts, IOCs, allow/deny reputation and the hunt feed.

Why this module exists: the API, dashboard, TAXII feed and reputation analyzer all
need one durable, dependency-free source of truth. SQLite (stdlib) in WAL mode gives
crash-safe storage, concurrent readers and a single file to back up.

Design notes
------------
* **Thread safety**: one connection per :class:`Store`, guarded by a re-entrant lock;
  every multi-statement write runs in an explicit ``BEGIN IMMEDIATE`` transaction.
  Several processes may share the same file (WAL + ``busy_timeout``).
* **Migrations**: ``PRAGMA user_version`` tracks the schema; :data:`_MIGRATIONS` are
  applied in order, each inside a transaction, and re-opening is a no-op.
* **Parameterised queries only**: no value is ever interpolated into SQL.
* **Timestamps** are UTC ISO-8601 strings with a fixed width
  (``2026-01-02T03:04:05.000000Z``) so they sort and compare lexicographically.
* **Normalisation**: lookups go through :func:`norm_value` so ``Example.COM.`` and
  ``example.com`` are the same domain, URL fragments are dropped, hashes are lowercase.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import random
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from uniphish.core.types import Verdict

log = logging.getLogger("uniphish.store")

REPUTATION_VERDICTS = frozenset({"allow", "deny", "unknown"})
MAX_LIMIT = 10_000
_MAX_VALUE_CHARS = 8_192
_TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"
_STIX_NS = uuid.UUID("5d1f6a2e-7a0b-4c53-9a53-1d5b8c0f2e11")

# --------------------------------------------------------------------------- #
# Schema + migrations
# --------------------------------------------------------------------------- #
_MIGRATIONS: list[list[str]] = [
    # v1: initial schema
    [
        """CREATE TABLE verdicts (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            kind TEXT NOT NULL,
            target TEXT NOT NULL,
            target_norm TEXT NOT NULL,
            score INTEGER NOT NULL,
            level TEXT NOT NULL,
            brand TEXT,
            summary TEXT NOT NULL DEFAULT '',
            json TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'engine'
        )""",
        "CREATE INDEX idx_verdicts_created ON verdicts(created_at)",
        "CREATE INDEX idx_verdicts_target ON verdicts(kind, target_norm)",
        "CREATE INDEX idx_verdicts_score ON verdicts(score)",
        """CREATE TABLE indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            value_norm TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 1,
            malicious INTEGER NOT NULL DEFAULT 0,
            verdict_id TEXT,
            source TEXT NOT NULL DEFAULT 'engine',
            UNIQUE(type, value_norm)
        )""",
        "CREATE INDEX idx_indicators_last_seen ON indicators(last_seen)",
        """CREATE TABLE reputation (
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            verdict TEXT NOT NULL CHECK (verdict IN ('allow','deny','unknown')),
            weight REAL NOT NULL DEFAULT 0,
            reason TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT 'manual',
            added_at TEXT NOT NULL,
            expires_at TEXT,
            UNIQUE(type, value)
        )""",
        """CREATE TABLE hunt_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            source TEXT NOT NULL,
            domain TEXT NOT NULL,
            score INTEGER NOT NULL DEFAULT 0,
            brand TEXT,
            techniques TEXT NOT NULL DEFAULT '[]',
            stix_json TEXT
        )""",
        "CREATE INDEX idx_hunt_ts ON hunt_events(ts)",
        "CREATE INDEX idx_hunt_score ON hunt_events(score)",
    ],
    # v2: explicit STIX object table backing the TAXII feed
    [
        """CREATE TABLE stix_objects (
            stix_id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            added_at TEXT NOT NULL,
            json TEXT NOT NULL
        )""",
        "CREATE INDEX idx_stix_added ON stix_objects(added_at)",
    ],
]
SCHEMA_VERSION = len(_MIGRATIONS)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | str | float | int | None = None) -> str:
    """Format *dt* (datetime, epoch seconds, ISO string or None=now) as fixed-width UTC."""
    if dt is None:
        dt = _utcnow()
    elif isinstance(dt, (int, float)):
        dt = datetime.fromtimestamp(float(dt), timezone.utc)
    elif isinstance(dt, str):
        dt = datetime.fromisoformat(dt.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(_TS_FMT)


def _clamp_limit(limit: int) -> int:
    return max(1, min(int(limit), MAX_LIMIT))


def norm_value(type_: str, value: str) -> str:
    """Normalise an observable for lookup/dedup (case, trailing dots, IDNA, fragments)."""
    v = (value or "").strip()[:_MAX_VALUE_CHARS]
    t = (type_ or "").strip().lower()
    if t == "url":
        try:
            parts = urlsplit(v)
            host = (parts.hostname or "").lower().rstrip(".")
            netloc = host
            if ":" in host:
                netloc = f"[{host}]"
            if parts.port:
                netloc += f":{parts.port}"
            if parts.username:
                netloc = f"{parts.username}@{netloc}"
            return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, ""))
        except ValueError:
            return v.split("#", 1)[0]
    if t == "domain":
        d = v.lower().rstrip(".")
        try:
            d.encode("ascii")
        except UnicodeEncodeError:
            with suppress(UnicodeError):
                d = d.encode("idna").decode("ascii")
        return d
    if t in {"ipv4", "ipv6"}:
        try:
            return str(ipaddress.ip_address(v.strip("[]")))
        except ValueError:
            return v.lower()
    if t in {"sha256", "sha1", "md5", "cert_sha256", "email"}:
        return v.lower()
    if t == "phone":
        return "".join(ch for ch in v if ch.isdigit() or ch == "+")
    if t == "asn":
        return v.upper().removeprefix("AS")
    if t == "crypto_wallet":
        return v  # many wallet formats are case-sensitive
    return v.lower()


def _type_str(t: Any) -> str:
    return str(getattr(t, "value", t)).lower()


def _target_norm(kind: str, target: str) -> str:
    if kind == "url":
        return norm_value("url", target)
    return (target or "").strip()[:_MAX_VALUE_CHARS].lower()


def _row(r: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(r) if r is not None else None


# --------------------------------------------------------------------------- #
# Store
# --------------------------------------------------------------------------- #
class Store:
    """Thread-safe SQLite store. ``Store()`` uses ``settings.db_path``.

    Pass ``":memory:"`` for an ephemeral database. Use as a context manager or call
    :meth:`close` when done.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        if path is None:
            from uniphish.core.config import get_settings

            settings = get_settings()
            settings.ensure_dirs()
            path = settings.db_path
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = sqlite3.connect(
            self.path, timeout=30.0, isolation_level=None, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout=30000")
        if self.path != ":memory:":
            # Flipping the journal mode to WAL needs a brief exclusive lock that
            # busy_timeout does not cover, so when several processes open the same new
            # file at once all but one raise "database is locked". Retry until WAL is set
            # (afterwards the pragma is a cheap no-op).
            for attempt in range(8):
                try:
                    mode = self._conn.execute("PRAGMA journal_mode=WAL").fetchone()
                    if mode and str(mode[0]).lower() == "wal":
                        break
                except sqlite3.OperationalError as exc:
                    if "lock" not in str(exc).lower():
                        raise
                time.sleep(0.05 * (attempt + 1) + random.uniform(0.0, 0.03))
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    # ---- lifecycle ------------------------------------------------------- #
    def close(self) -> None:
        """Close the connection (idempotent)."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def schema_version(self) -> int:
        with self._lock:
            return int(self._db().execute("PRAGMA user_version").fetchone()[0])

    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Store is closed")
        return self._conn

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        """Serialised write transaction (BEGIN IMMEDIATE ... COMMIT / ROLLBACK)."""
        with self._lock:
            db = self._db()
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
            except BaseException:
                db.execute("ROLLBACK")
                raise
            else:
                db.execute("COMMIT")

    def _migrate(self) -> None:
        with self._lock:
            current = self.schema_version
            if current > SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema v{current} is newer than supported v{SCHEMA_VERSION}")
            for version in range(current, SCHEMA_VERSION):
                with self._tx() as db:
                    # Re-check inside the write lock: another process may have migrated.
                    if int(db.execute("PRAGMA user_version").fetchone()[0]) > version:
                        continue
                    for stmt in _MIGRATIONS[version]:
                        db.execute(stmt)
                    db.execute(f"PRAGMA user_version={version + 1}")  # int, not user input
                log.info("store migrated to schema v%d", version + 1)

    # ---- verdicts -------------------------------------------------------- #
    def save_verdict(self, verdict: Verdict, *, source: str = "engine") -> str:
        """Persist *verdict* (full JSON) and upsert its indicators. Returns the verdict id.

        Re-saving an existing id replaces the row but does not re-count its indicators.
        """
        kind = _type_str(verdict.kind)
        level = _type_str(verdict.level)
        created = _iso(verdict.created_at)
        brand = verdict.brand.brand if verdict.brand else None
        payload = verdict.model_dump_json()
        with self._tx() as db:
            existed = db.execute("SELECT 1 FROM verdicts WHERE id=?", (verdict.id,)).fetchone()
            db.execute(
                "INSERT OR REPLACE INTO verdicts(id, created_at, kind, target, target_norm,"
                " score, level, brand, summary, json, source) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (verdict.id, created, kind, verdict.target, _target_norm(kind, verdict.target),
                 int(verdict.score), level, brand, verdict.summary, payload, source),
            )
            if not existed:
                for ind in verdict.all_indicators():
                    self._upsert_indicator(
                        db, _type_str(ind.type), ind.value, bool(ind.malicious),
                        verdict.id, source, created)
        return verdict.id

    @staticmethod
    def _upsert_indicator(db: sqlite3.Connection, type_: str, value: str, malicious: bool,
                          verdict_id: str | None, source: str, ts: str) -> None:
        value = value[:_MAX_VALUE_CHARS]
        db.execute(
            "INSERT INTO indicators(type, value, value_norm, first_seen, last_seen, count,"
            " malicious, verdict_id, source) VALUES (?,?,?,?,?,1,?,?,?)"
            " ON CONFLICT(type, value_norm) DO UPDATE SET"
            "  count = count + 1,"
            "  last_seen = MAX(last_seen, excluded.last_seen),"
            "  first_seen = MIN(first_seen, excluded.first_seen),"
            "  malicious = MAX(malicious, excluded.malicious),"
            "  verdict_id = excluded.verdict_id,"
            "  source = excluded.source",
            (type_, value, norm_value(type_, value), ts, ts, int(malicious), verdict_id, source),
        )

    def get_verdict(self, verdict_id: str) -> Verdict | None:
        """Return the full :class:`Verdict` for *verdict_id*, or ``None``."""
        with self._lock:
            r = self._db().execute("SELECT json FROM verdicts WHERE id=?",
                                   (verdict_id,)).fetchone()
        return Verdict.model_validate_json(r["json"]) if r else None

    def get_verdict_row(self, verdict_id: str) -> dict[str, Any] | None:
        """Return the verdict's metadata row (no JSON blob), or ``None``."""
        with self._lock:
            r = self._db().execute(
                "SELECT id, created_at, kind, target, target_norm, score, level, brand,"
                " summary, source FROM verdicts WHERE id=?", (verdict_id,)).fetchone()
        return _row(r)

    def recent_verdicts(self, limit: int = 50, min_score: int = 0, kind: str | None = None,
                        level: str | None = None) -> list[dict[str, Any]]:
        """Newest-first verdict rows (metadata only; use :meth:`get_verdict` for the full one)."""
        sql = ("SELECT id, created_at, kind, target, score, level, brand, summary, source"
               " FROM verdicts WHERE score >= ?")
        args: list[Any] = [int(min_score)]
        if kind is not None:
            sql += " AND kind = ?"
            args.append(_type_str(kind))
        if level is not None:
            sql += " AND level = ?"
            args.append(_type_str(level))
        sql += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
        args.append(_clamp_limit(limit))
        with self._lock:
            return [dict(r) for r in self._db().execute(sql, args).fetchall()]

    def find_verdicts(self, kind: str, target: str, limit: int = 20) -> list[dict[str, Any]]:
        """Previous verdict rows for a normalised target, newest first."""
        with self._lock:
            rows = self._db().execute(
                "SELECT id, created_at, kind, target, score, level, brand, summary, source"
                " FROM verdicts WHERE kind=? AND target_norm=?"
                " ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (_type_str(kind), _target_norm(_type_str(kind), target), _clamp_limit(limit)),
            ).fetchall()
        return [dict(r) for r in rows]

    # ---- indicators ------------------------------------------------------ #
    def search_indicator(self, type: str, value: str) -> list[dict[str, Any]]:
        """Indicator rows matching the normalised (type, value)."""
        t = _type_str(type)
        with self._lock:
            rows = self._db().execute(
                "SELECT * FROM indicators WHERE type=? AND value_norm=?",
                (t, norm_value(t, value))).fetchall()
        return [dict(r) for r in rows]

    def recent_indicators(self, limit: int = 100, malicious_only: bool = False,
                          type: str | None = None) -> list[dict[str, Any]]:
        """Most recently seen indicators."""
        sql = "SELECT * FROM indicators WHERE 1=1"
        args: list[Any] = []
        if malicious_only:
            sql += " AND malicious = 1"
        if type is not None:
            sql += " AND type = ?"
            args.append(_type_str(type))
        sql += " ORDER BY last_seen DESC, id DESC LIMIT ?"
        args.append(_clamp_limit(limit))
        with self._lock:
            return [dict(r) for r in self._db().execute(sql, args).fetchall()]

    # ---- stats ----------------------------------------------------------- #
    def stats(self) -> dict[str, Any]:
        """Counts by level/kind, a 10-bucket score histogram and table sizes."""
        with self._lock:
            db = self._db()
            total = db.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
            by_level = {r[0]: r[1] for r in db.execute(
                "SELECT level, COUNT(*) FROM verdicts GROUP BY level")}
            by_kind = {r[0]: r[1] for r in db.execute(
                "SELECT kind, COUNT(*) FROM verdicts GROUP BY kind")}
            hist = [0] * 10
            for bucket, n in db.execute(
                    "SELECT MIN(score / 10, 9), COUNT(*) FROM verdicts GROUP BY 1"):
                hist[int(bucket)] = n
            return {
                "verdicts": total,
                "by_level": by_level,
                "by_kind": by_kind,
                "score_histogram": hist,  # bucket i = scores [10*i, 10*i+9]; last includes 100
                "indicators": db.execute("SELECT COUNT(*) FROM indicators").fetchone()[0],
                "malicious_indicators": db.execute(
                    "SELECT COUNT(*) FROM indicators WHERE malicious=1").fetchone()[0],
                "reputation": self.reputation_counts(),
                "hunt_events": db.execute("SELECT COUNT(*) FROM hunt_events").fetchone()[0],
                "stix_objects": db.execute("SELECT COUNT(*) FROM stix_objects").fetchone()[0],
                "schema_version": self.schema_version,
            }

    def timeline(self, hours: int = 24) -> list[dict[str, Any]]:
        """Hourly verdict counts for the last *hours* hours (oldest first, zero-filled)."""
        hours = max(1, min(int(hours), 24 * 90))
        now = _utcnow().replace(minute=0, second=0, microsecond=0)
        start = now - timedelta(hours=hours - 1)
        with self._lock:
            rows = self._db().execute(
                "SELECT substr(created_at,1,13) AS h, level, COUNT(*) AS n FROM verdicts"
                " WHERE created_at >= ? GROUP BY h, level", (_iso(start),)).fetchall()
        buckets: dict[str, dict[str, Any]] = {}
        for i in range(hours):
            h = (start + timedelta(hours=i)).strftime("%Y-%m-%dT%H")
            buckets[h] = {"hour": h + ":00:00Z", "total": 0, "benign": 0,
                          "suspicious": 0, "malicious": 0}
        for r in rows:
            b = buckets.get(r["h"])
            if b is None:
                continue
            b["total"] += r["n"]
            if r["level"] in b:
                b[r["level"]] += r["n"]
        return list(buckets.values())

    # ---- reputation ------------------------------------------------------ #
    @staticmethod
    def _rep_params(type_: Any, value: str, verdict: str, weight: float, reason: str,
                    source: str, ttl: float | timedelta | None, now: datetime) -> tuple[Any, ...]:
        verdict = (verdict or "").lower()
        if verdict not in REPUTATION_VERDICTS:
            raise ValueError(f"reputation verdict must be one of {sorted(REPUTATION_VERDICTS)}")
        t = _type_str(type_)
        if not (value or "").strip():
            raise ValueError("empty reputation value")
        expires = None
        if ttl is not None:
            delta = ttl if isinstance(ttl, timedelta) else timedelta(seconds=float(ttl))
            expires = _iso(now + delta)
        return (t, norm_value(t, value), verdict, float(weight), reason or "", source or "manual",
                _iso(now), expires)

    _REP_SQL = (
        "INSERT INTO reputation(type, value, verdict, weight, reason, source, added_at,"
        " expires_at) VALUES (?,?,?,?,?,?,?,?)"
        " ON CONFLICT(type, value) DO UPDATE SET verdict=excluded.verdict,"
        " weight=excluded.weight, reason=excluded.reason, source=excluded.source,"
        " added_at=excluded.added_at, expires_at=excluded.expires_at")

    def set_reputation(self, type: str, value: str, verdict: str, weight: float = 0.0,
                       reason: str = "", source: str = "manual",
                       ttl: float | timedelta | None = None) -> None:
        """Upsert an allow/deny/unknown entry. *ttl* is seconds or a timedelta (None = forever)."""
        params = self._rep_params(type, value, verdict, weight, reason, source, ttl, _utcnow())
        with self._tx() as db:
            db.execute(self._REP_SQL, params)

    def bulk_set(self, rows: Iterable[Mapping[str, Any] | Sequence[Any]]) -> int:
        """Upsert many reputation entries atomically. Returns the number written.

        Each row is a mapping with keys ``type, value, verdict`` (optional ``weight, reason,
        source, ttl``) or a sequence
        ``(type, value, verdict[, weight[, reason[, source[, ttl]]]])``.
        Any invalid row aborts the whole batch.
        """
        now = _utcnow()
        prepared: list[tuple[Any, ...]] = []
        for r in rows:
            if isinstance(r, Mapping):
                prepared.append(self._rep_params(
                    r["type"], r["value"], r["verdict"], r.get("weight", 0.0),
                    r.get("reason", ""), r.get("source", "bulk"), r.get("ttl"), now))
            else:
                a = list(r) + [None] * (7 - len(r))
                prepared.append(self._rep_params(
                    a[0], a[1], a[2], a[3] if a[3] is not None else 0.0, a[4] or "",
                    a[5] or "bulk", a[6], now))
        if not prepared:
            return 0
        with self._tx() as db:
            db.executemany(self._REP_SQL, prepared)
        return len(prepared)

    def lookup_reputation(self, type: str, value: str) -> dict[str, Any] | None:
        """Return the live (non-expired) reputation row, or ``None``."""
        t = _type_str(type)
        with self._lock:
            r = self._db().execute(
                "SELECT * FROM reputation WHERE type=? AND value=?"
                " AND (expires_at IS NULL OR expires_at > ?)",
                (t, norm_value(t, value), _iso())).fetchone()
        return _row(r)

    def delete_reputation(self, type: str, value: str) -> bool:
        """Remove an entry. Returns True if something was deleted."""
        t = _type_str(type)
        with self._tx() as db:
            cur = db.execute("DELETE FROM reputation WHERE type=? AND value=?",
                             (t, norm_value(t, value)))
        return cur.rowcount > 0

    def list_reputation(self, verdict: str | None = None, limit: int = 100
                        ) -> list[dict[str, Any]]:
        """Live reputation entries, newest first, optionally filtered by verdict."""
        sql = "SELECT * FROM reputation WHERE (expires_at IS NULL OR expires_at > ?)"
        args: list[Any] = [_iso()]
        if verdict is not None:
            sql += " AND verdict = ?"
            args.append(verdict.lower())
        sql += " ORDER BY added_at DESC, rowid DESC LIMIT ?"
        args.append(_clamp_limit(limit))
        with self._lock:
            return [dict(r) for r in self._db().execute(sql, args).fetchall()]

    def purge_expired(self) -> int:
        """Delete expired reputation rows. Returns how many were removed."""
        with self._tx() as db:
            cur = db.execute("DELETE FROM reputation WHERE expires_at IS NOT NULL"
                             " AND expires_at <= ?", (_iso(),))
        return cur.rowcount

    def reputation_counts(self) -> dict[str, int]:
        """Live entry counts per verdict (always has allow/deny/unknown keys)."""
        out = dict.fromkeys(sorted(REPUTATION_VERDICTS), 0)
        with self._lock:
            for r in self._db().execute(
                    "SELECT verdict, COUNT(*) FROM reputation"
                    " WHERE (expires_at IS NULL OR expires_at > ?) GROUP BY verdict",
                    (_iso(),)):
                out[r[0]] = r[1]
        return out

    # ---- hunt events ----------------------------------------------------- #
    def add_hunt_event(self, source: str, domain: str, score: int = 0, brand: str | None = None,
                       techniques: Iterable[str] = (), stix: Mapping[str, Any] | None = None,
                       ts: datetime | str | float | None = None) -> int:
        """Record a CT/brand-watch hit. Returns the event id."""
        with self._tx() as db:
            cur = db.execute(
                "INSERT INTO hunt_events(ts, source, domain, score, brand, techniques, stix_json)"
                " VALUES (?,?,?,?,?,?,?)",
                (_iso(ts), source, norm_value("domain", domain), max(0, min(int(score), 100)),
                 brand, json.dumps(list(techniques)),
                 json.dumps(stix, default=str) if stix is not None else None))
            return int(cur.lastrowid or 0)

    def recent_hunt_events(self, limit: int = 100, min_score: int = 0, brand: str | None = None
                           ) -> list[dict[str, Any]]:
        """Newest-first hunt events with ``techniques`` as a list and ``stix`` parsed."""
        sql = "SELECT * FROM hunt_events WHERE score >= ?"
        args: list[Any] = [int(min_score)]
        if brand:
            sql += " AND lower(brand) = ?"
            args.append(brand.lower())
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        args.append(_clamp_limit(limit))
        with self._lock:
            rows = self._db().execute(sql, args).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            d["techniques"] = _loads(d.pop("techniques"), [])
            stix_json = d.pop("stix_json")
            d["stix"] = _loads(stix_json, None) if stix_json else None
            out.append(d)
        return out

    # ---- STIX / TAXII ---------------------------------------------------- #
    def add_stix_object(self, obj: Mapping[str, Any]) -> bool:
        """Store a STIX 2.1 object (needs ``id`` and ``type``). Returns True if new/updated."""
        stix_id, stix_type = obj.get("id"), obj.get("type")
        if not isinstance(stix_id, str) or not isinstance(stix_type, str) \
                or not stix_id.startswith(f"{stix_type}--"):
            raise ValueError("STIX object needs matching 'type' and 'id' (type--uuid)")
        with self._tx() as db:
            cur = db.execute(
                "INSERT OR REPLACE INTO stix_objects(stix_id, type, added_at, json)"
                " VALUES (?,?,?,?)", (stix_id, stix_type, _iso(), json.dumps(obj, default=str)))
        return cur.rowcount > 0

    def stix_objects(self, limit: int = 100, added_after: datetime | str | float | None = None,
                     synthesize: bool = True) -> list[dict[str, Any]]:
        """STIX objects for the TAXII feed, oldest-first by ``added_at`` (stable paging).

        Explicit objects come from the ``stix_objects`` table. With *synthesize*, malicious
        indicators (domain/url/ip/hash/email) are also rendered as STIX 2.1 ``indicator``
        objects with deterministic ids (uuid5 of type+value), so no extra bookkeeping is
        needed. Results are merged by ``added_at`` and cut to *limit*.
        """
        limit = _clamp_limit(limit)
        after = _iso(added_after) if added_after is not None else ""
        with self._lock:
            db = self._db()
            rows = db.execute(
                "SELECT json, added_at FROM stix_objects WHERE added_at > ?"
                " ORDER BY added_at, stix_id LIMIT ?", (after, limit)).fetchall()
            items: list[tuple[str, dict[str, Any]]] = [
                (r["added_at"], _loads(r["json"], {})) for r in rows]
            if synthesize:
                for r in db.execute(
                        "SELECT type, value, first_seen, last_seen FROM indicators"
                        " WHERE malicious=1 AND last_seen > ? ORDER BY last_seen, id LIMIT ?",
                        (after, limit)):
                    obj = _indicator_to_stix(r["type"], r["value"], r["first_seen"],
                                             r["last_seen"])
                    if obj is not None:
                        items.append((r["last_seen"], obj))
        items.sort(key=lambda p: p[0])
        return [o for _, o in items[:limit]]


_STIX_PATTERNS = {
    "domain": "domain-name:value", "url": "url:value", "ipv4": "ipv4-addr:value",
    "ipv6": "ipv6-addr:value", "email": "email-addr:value",
    "sha256": "file:hashes.'SHA-256'", "sha1": "file:hashes.'SHA-1'", "md5": "file:hashes.MD5",
}


def _indicator_to_stix(type_: str, value: str, first: str, last: str) -> dict[str, Any] | None:
    prop = _STIX_PATTERNS.get(type_)
    if prop is None:
        return None
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid5(_STIX_NS, f'{type_}:{norm_value(type_, value)}')}",
        "created": first,
        "modified": last,
        "name": f"{type_}: {value[:120]}",
        "pattern": f"[{prop} = '{escaped}']",
        "pattern_type": "stix",
        "valid_from": first,
        "indicator_types": ["malicious-activity"],
        "labels": ["phishing"],
    }


def _loads(text: str | None, default: Any) -> Any:
    try:
        return json.loads(text) if text else default
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------- #
# Process-wide default store
# --------------------------------------------------------------------------- #
_default: Store | None = None
_default_lock = threading.Lock()


def get_store() -> Store:
    """Lazily open the shared :class:`Store` at ``settings.db_path``."""
    global _default
    with _default_lock:
        if _default is None:
            _default = Store()
        return _default


def reset_store() -> None:
    """Close and forget the shared store (tests change the data dir)."""
    global _default
    with _default_lock:
        if _default is not None:
            _default.close()
        _default = None
