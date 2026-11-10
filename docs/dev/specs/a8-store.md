# Spec: persistence layer
OWN: uniphish/store/__init__.py, uniphish/store/db.py, tests/store/test_db.py.

PURPOSE: durable storage for verdicts, IOCs, an allow/deny list, and the CT/hunt feed,
backing the API, dashboard, TAXII feed and reputation analyzer. SQLite (stdlib sqlite3),
WAL mode, thread-safe, migration-versioned, in settings.db_path.

db.py: class Store(path=None):
- schema with PRAGMA user_version migrations: verdicts(id, created_at, kind, target,
  target_norm (normalised for lookup), score, level, brand, summary, json (full Verdict
  JSON), source), indicators(id, type, value, value_norm, first_seen, last_seen, count,
  malicious, verdict_id, source), reputation(type, value, verdict [allow/deny/unknown],
  weight, reason, source, added_at, expires_at) UNIQUE(type,value), hunt_events(id, ts,
  source, domain, score, brand, techniques, stix_json).
- save_verdict(verdict) (also upserts its indicators with first/last-seen + count),
  get_verdict(id), recent_verdicts(limit, min_score=0, kind=None, level=None),
  search_indicator(type, value) -> rows, stats() -> counts/histogram, timeline(hours).
- reputation: set_reputation(type, value, verdict, weight, reason, source, ttl=None),
  lookup_reputation(type, value) -> row|None (honour expiry), bulk_set, counts.
- hunt_events: add_hunt_event(...), recent_hunt_events(limit, min_score, brand).
- taxii: stix_objects(limit, added_after) reading from a stix objects table or
  synthesising from indicators (coordinate a simple objects table).
- JSON helpers; parameterised queries only (no string interpolation); connection-per-
  thread or a lock; safe concurrent writes (WAL + busy_timeout).

TESTS: migrations idempotent; save/get round-trip; indicator upsert increments count +
updates last_seen; reputation expiry; recent filters; concurrent writes don't corrupt.
