"""Certificate Transparency threat hunter: catch phishing domains at issuance time.

Why this module exists: every publicly trusted TLS certificate is published to CT logs
within seconds of issuance, which is typically *before* the phishing site goes live and
long before any blocklist knows the domain. Streaming that firehose through UniPhish's
fast URL/brand analysis turns "a certificate was just issued for paypa1-login.example"
into an alert, a STIX 2.1 indicator in the TAXII feed and a live dashboard event.

Two halves:

* :func:`stream_certstream` - a robust, bounded transport. It speaks the
  certstream-compatible websocket protocol (``wss://...``), reconnects with jittered
  exponential backoff, and can instead replay a JSONL file (``source="sample"``) for
  offline demos and tests.
* :class:`CTHunter` - the scoring/recording pipeline. For each new domain it builds
  ``https://{domain}/``, runs a *fast* subset of the engine (the URL analyzer only; no
  network, no page fetch, no DNS), applies an "issued just now" context weight to brand
  look-alikes and, when the domain is flagged, writes a hunt event, a STIX bundle, the
  STIX objects (TAXII feed) and a ``hunt`` event on :mod:`uniphish.core.events`.

Safety properties: sites are **never fetched** (issuance-time detection only); every
domain from the wire is treated as hostile input (strict syntax validation, SAN and
message size caps); the pipeline is volume-bounded (de-duplication, bounded queue,
optional rate cap, ``max_domains``) so a firehose cannot exhaust memory.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import random
import threading
import time
from collections import Counter, OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from uniphish.core import events, mitre, scoring
from uniphish.core.analyzer import AnalysisOptions
from uniphish.core.engine import Engine
from uniphish.core.types import Artifact, Indicator, IndicatorType, Signal, Verdict
from uniphish.url.brandkb import BrandKB, get_kb, normalize_host
from uniphish.url.brands import split_host
from uniphish.url.parse import parse_url

log = logging.getLogger("uniphish.hunt")

CERTSTREAM_URL = "wss://certstream.calidog.io/"
MAX_SANS_PER_CERT = 100
MAX_RECORD_CHARS = 1_000_000
MAX_DOMAIN_CHARS = 253
FRESH_WINDOW_S = 48 * 3600
FRESH_SIGNAL_ID = "ct.fresh_cert_lookalike"
FRESH_WEIGHT = 1.5
FAST_ANALYZERS = frozenset({"url"})

#: Synthetic, inert replay data for ``source="sample"`` (reserved TLDs only).
SAMPLE_DOMAINS: tuple[str, ...] = (
    "paypa1.test", "xn--pypal-4ve.test", "secure-paypal-login.test",
    "paypal.verify-account.example", "micr0soft-support.test", "xn--ggle-55da.test",
    "amaz0n-orders.test", "apple-id-verify.test", "bank-of-amerca.test",
    "my-garden-shop.test", "kitchen-recipes.test", "blog.example.org", "mail.paypal.com",
    "*.docs.example", "paypa1.test",
)

CertCallback = Callable[[str, dict[str, Any]], Awaitable[None] | None]
Connector = Callable[..., Any]


# --------------------------------------------------------------------------- #
# Domain + record parsing (hostile input)
# --------------------------------------------------------------------------- #
_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")


def clean_domain(raw: Any) -> str | None:
    """Normalise a CT SAN to a lowercase ASCII hostname, or ``None`` if unusable.

    Strips wildcard prefixes (``*.``), trailing dots and whitespace, IDNA-encodes
    Unicode names, and rejects IP literals, emails, URLs, single-label names and
    anything violating hostname syntax (label 1-63 chars, total <= 253).
    """
    if not isinstance(raw, str) or not raw or len(raw) > 1024:
        return None
    h = raw.strip().lower()
    while h.startswith("*."):
        h = h[2:]
    h = normalize_host(h)
    if not h or len(h) > MAX_DOMAIN_CHARS or not h.isascii() or ":" in h:
        return None
    labels = h.split(".")
    if len(labels) < 2:
        return None
    for lab in labels:
        if not 1 <= len(lab) <= 63 or lab[0] == "-" or lab[-1] == "-" \
                or not _LABEL_CHARS.issuperset(lab):
            return None
    tld = labels[-1]
    if tld.isdigit() or not any(c.isalpha() for c in tld):   # IPv4 literal / numeric TLD
        return None
    return h


def _meta_scalar(v: Any) -> Any:
    if isinstance(v, (str, int, float, bool)) and not (isinstance(v, str) and len(v) > 256):
        return v
    return None


def parse_record(obj: Any, *, source: str = "certstream",
                 max_sans: int = MAX_SANS_PER_CERT) -> list[tuple[str, dict[str, Any]]]:
    """Extract ``(domain, cert_meta)`` pairs from one firehose / JSONL record.

    Accepted shapes: a certstream ``certificate_update`` message, a bare string
    domain, or a flat dict with ``domain`` / ``domains`` / ``all_domains``. Other
    certstream message types (heartbeats) yield nothing. Never raises.
    """
    meta: dict[str, Any] = {"source": source}
    names: Any = None
    try:
        if isinstance(obj, str):
            names = [obj]
        elif isinstance(obj, Mapping):
            mt = obj.get("message_type")
            if mt is not None:
                if mt != "certificate_update" or not isinstance(obj.get("data"), Mapping):
                    return []
                data = obj["data"]
                leaf = data.get("leaf_cert") if isinstance(data.get("leaf_cert"), Mapping) else {}
                names = leaf.get("all_domains")
                issuer = leaf.get("issuer") if isinstance(leaf.get("issuer"), Mapping) else {}
                src = data.get("source") if isinstance(data.get("source"), Mapping) else {}
                meta.update({
                    "seen": _meta_scalar(data.get("seen")),
                    "not_before": _meta_scalar(leaf.get("not_before")),
                    "fingerprint": _meta_scalar(leaf.get("fingerprint")),
                    "issuer": _meta_scalar(issuer.get("O") or issuer.get("CN")),
                    "log": _meta_scalar(src.get("name")),
                })
            else:
                names = obj.get("all_domains") or obj.get("domains") or obj.get("domain") \
                    or obj.get("host")
                for k, v in obj.items():
                    if k not in {"all_domains", "domains", "domain", "host"} \
                            and _meta_scalar(v) is not None:
                        meta[str(k)[:64]] = v
                meta["source"] = source
            if isinstance(names, str):
                names = [names]
        if not isinstance(names, (list, tuple)):
            return []
    except Exception:   # pragma: no cover - defensive; inputs are plain JSON
        return []
    meta = {k: v for k, v in meta.items() if v is not None}
    meta["san_count"] = len(names)
    return [(d, dict(meta)) for d in
            (clean_domain(n) for n in names[:max(1, max_sans)]) if d]


def _epoch(value: Any) -> float | None:
    """Best-effort conversion of a cert timestamp (epoch seconds or ISO-8601) to epoch."""
    try:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return float(value) / (1000.0 if value > 1e11 else 1.0)
        if isinstance(value, str) and value:
            if value.replace(".", "", 1).isdigit():
                return _epoch(float(value))
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    except (ValueError, OverflowError, OSError):
        return None
    return None


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #
class _Stopped(Exception):
    """Internal: stop event fired while waiting on the socket."""


def _validate_url(url: str, allow_insecure: bool) -> None:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme == "wss" and host:
        return
    if parts.scheme == "ws" and host and (allow_insecure or host in {"localhost", "127.0.0.1",
                                                                       "::1"}):
        return
    raise ValueError(f"unsupported CT firehose URL {url!r}: use wss:// (ws:// only for "
                     "loopback or with allow_insecure=True)")


def _default_connector() -> Connector:
    try:
        import websockets
    except ImportError as e:   # pragma: no cover - extra not installed
        raise RuntimeError("the 'websockets' package is required for the live CT firehose "
                           "(pip install websockets)") from e
    return websockets.connect


async def _call(on_cert: CertCallback, domain: str, meta: dict[str, Any]) -> None:
    r = on_cert(domain, meta)
    if inspect.isawaitable(r):
        await r


async def _replay(on_cert: CertCallback, path: Path | None, stop: asyncio.Event,
                  limit: int | None, max_sans: int) -> int:
    """Replay a JSONL file (or the bundled sample) through ``on_cert``."""
    def _lines() -> Iterable[str]:
        if path is None:
            return [json.dumps({"domain": d}) for d in SAMPLE_DOMAINS]
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [ln for _, ln in zip(range(1_000_000), fh, strict=False)]   # bounded read

    lines = await asyncio.to_thread(lambda: list(_lines()))
    n = 0
    for i, line in enumerate(lines):
        if stop.is_set() or (limit is not None and n >= limit):
            break
        line = line.strip()
        if not line or len(line) > MAX_RECORD_CHARS:
            continue
        try:
            obj: Any = json.loads(line) if line[0] in '{["' else line
        except ValueError:
            continue
        for dom, meta in parse_record(obj, source="sample", max_sans=max_sans):
            await _call(on_cert, dom, meta)
            n += 1
        if i % 256 == 255:
            await asyncio.sleep(0)
    return n


async def stream_certstream(on_cert: CertCallback, *, source: str = "certstream",
                            url: str = CERTSTREAM_URL, path: str | Path | None = None,
                            stop: asyncio.Event | None = None, max_certs: int | None = None,
                            connect: Connector | None = None, allow_insecure: bool = False,
                            max_sans: int = MAX_SANS_PER_CERT, idle_timeout_s: float = 120.0,
                            backoff_base_s: float = 1.0, backoff_max_s: float = 60.0,
                            max_reconnects: int | None = None,
                            sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> int:
    """Feed ``on_cert(domain, cert_meta)`` for every domain from a CT firehose.

    ``source="certstream"`` connects to ``url`` (certstream-compatible websocket) and
    reconnects forever with jittered exponential backoff (reset once a message
    arrives) until ``stop`` is set or ``max_reconnects`` consecutive failures occur.
    ``source="sample"`` replays ``path`` (JSONL) - or the bundled synthetic list when
    ``path`` is None - once, offline. ``on_cert`` may be sync or async; exceptions it
    raises propagate. Returns the number of domains delivered.
    """
    stop = stop or asyncio.Event()
    if source == "sample":
        return await _replay(on_cert, Path(path) if path else None, stop, max_certs, max_sans)
    if source != "certstream":
        raise ValueError(f"unknown CT source {source!r} (use 'certstream' or 'sample')")
    _validate_url(url, allow_insecure)
    connector = connect or _default_connector()
    delivered = 0
    attempt = 0
    stop_task = asyncio.ensure_future(stop.wait())
    try:
        while not stop.is_set() and (max_certs is None or delivered < max_certs):
            got_any = False
            try:
                async with connector(url, ping_interval=20, ping_timeout=20, max_size=1 << 20,
                                     open_timeout=15, close_timeout=5) as ws:
                    it = ws.__aiter__()
                    while max_certs is None or delivered < max_certs:
                        nxt = asyncio.ensure_future(it.__anext__())
                        done, _ = await asyncio.wait({nxt, stop_task}, timeout=idle_timeout_s,
                                                     return_when=asyncio.FIRST_COMPLETED)
                        if nxt not in done:
                            nxt.cancel()
                            if stop_task in done:
                                raise _Stopped
                            raise ConnectionError(f"no CT message for {idle_timeout_s:.0f}s")
                        try:
                            msg = nxt.result()
                        except StopAsyncIteration:
                            break
                        got_any = True
                        attempt = 0
                        if isinstance(msg, (bytes, bytearray)):
                            msg = bytes(msg).decode("utf-8", "replace")
                        if not isinstance(msg, str) or len(msg) > MAX_RECORD_CHARS:
                            continue
                        try:
                            obj = json.loads(msg)
                        except ValueError:
                            continue
                        for dom, meta in parse_record(obj, source="certstream",
                                                      max_sans=max_sans):
                            await _call(on_cert, dom, meta)
                            delivered += 1
            except _Stopped:
                break
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("CT firehose error: %s: %s", type(e).__name__, e)
            if stop.is_set() or (max_certs is not None and delivered >= max_certs):
                break
            if not got_any:
                attempt += 1
            if max_reconnects is not None and attempt > max_reconnects:
                log.error("CT firehose: giving up after %d failed connection attempts", attempt)
                break
            delay = min(backoff_max_s, backoff_base_s * (2 ** max(0, attempt - 1)))
            delay *= random.uniform(0.5, 1.0)
            log.info("CT firehose reconnecting in %.1fs", delay)
            sleeper = asyncio.ensure_future(sleep(delay))
            await asyncio.wait({sleeper, stop_task}, return_when=asyncio.FIRST_COMPLETED)
            sleeper.cancel()
    finally:
        stop_task.cancel()
    return delivered


# --------------------------------------------------------------------------- #
# Hunter
# --------------------------------------------------------------------------- #
class _BoundedSet:
    """Insertion-ordered set evicting the oldest entry beyond ``maxsize``."""

    def __init__(self, maxsize: int) -> None:
        self._d: OrderedDict[str, None] = OrderedDict()
        self._max = max(1, maxsize)

    def add(self, key: str) -> bool:
        """Add ``key``; return False if it was already present."""
        if key in self._d:
            self._d.move_to_end(key)
            return False
        self._d[key] = None
        if len(self._d) > self._max:
            self._d.popitem(last=False)
        return True

    def __contains__(self, key: str) -> bool:
        return key in self._d

    def __len__(self) -> int:
        return len(self._d)


@dataclass
class HuntStats:
    """Per-run counters. ``to_dict()`` is JSON-safe."""

    seen: int = 0
    invalid: int = 0
    duplicates: int = 0
    official_skipped: int = 0
    scored: int = 0
    errors: int = 0
    flagged: int = 0
    recorded: int = 0
    duplicate_alerts: int = 0
    dropped_queue_full: int = 0
    dropped_rate_limit: int = 0
    by_brand: Counter[str] = field(default_factory=Counter)
    started_at: float = field(default_factory=time.monotonic)

    @property
    def elapsed_s(self) -> float:
        return round(time.monotonic() - self.started_at, 3)

    def to_dict(self) -> dict[str, Any]:
        d = {k: getattr(self, k) for k in (
            "seen", "invalid", "duplicates", "official_skipped", "scored", "errors", "flagged",
            "recorded", "duplicate_alerts", "dropped_queue_full", "dropped_rate_limit")}
        d["by_brand"] = dict(self.by_brand.most_common())
        d["elapsed_s"] = self.elapsed_s
        return d


@dataclass
class HuntHit:
    """A flagged domain, as recorded."""

    domain: str
    score: int
    level: str
    brand: str | None
    brand_name: str | None
    technique: str | None
    techniques: list[str]
    reason: str
    fresh: bool
    event_id: int
    stix_id: str | None
    source: str
    verdict: Verdict = field(repr=False)

    def to_event(self) -> dict[str, Any]:
        return {"id": self.event_id, "domain": self.domain, "score": self.score,
                "level": self.level, "brand": self.brand, "brand_name": self.brand_name,
                "technique": self.technique, "techniques": self.techniques[:6],
                "reason": self.reason, "fresh": self.fresh, "source": self.source,
                "stix_id": self.stix_id, "summary": self.verdict.summary}


_WARMED = False
_WARM_LOCK = threading.Lock()


class CTHunter:
    """Score newly issued domains and record the look-alikes.

    Args:
        engine: engine to borrow analyzers (and settings) from; ``None`` builds the
            default. Only fast, offline analyzers are run, in a private hook-free copy,
            so verdict-persistence hooks never see CT noise.
        store: :class:`~uniphish.store.Store` (``None`` -> the shared store).
        threshold: score (0-100) at which a domain is flagged regardless of brand.
        watch_brands: brand ids / names / aliases. When given, *only* domains that
            impersonate one of them are recorded; otherwise any brand look-alike counts.
        brand_floor: minimum score for a brand look-alike to be flagged below
            ``threshold`` (suppresses weak typo coincidences).
        fresh_weight: log-odds added when a just-issued cert accompanies a look-alike.
        queue_size / workers / max_rate / max_seen: volume bounds for :meth:`run`.
    """

    def __init__(self, engine: Engine | None = None, store: Any = None, *,
                 threshold: int = 75, watch_brands: Iterable[str] | None = None,
                 brand_floor: int = 40, fresh_weight: float = FRESH_WEIGHT,
                 fresh_window_s: float = FRESH_WINDOW_S, queue_size: int = 10_000,
                 workers: int = 4, max_rate: float | None = None, max_seen: int = 200_000,
                 publish: bool = True, kb: BrandKB | None = None,
                 warm: bool = True) -> None:
        self.engine = self._fast_engine(engine)
        if store is None:
            from uniphish.store import get_store
            store = get_store()
        self.store = store
        self.kb = kb or get_kb()
        self.threshold = int(threshold)
        self.brand_floor = int(brand_floor)
        self.fresh_weight = float(fresh_weight)
        self.fresh_window_s = float(fresh_window_s)
        self.queue_size = max(1, queue_size)
        self.workers = max(1, workers)
        self.max_rate = max_rate
        self.publish = publish
        self.watch = self._resolve_watch(watch_brands)
        self.stats = HuntStats()
        self._seen = _BoundedSet(max_seen)
        self._alerted = _BoundedSet(max_seen)
        self._lock = threading.Lock()
        self._tokens = float(max_rate or 0)
        self._tick = time.monotonic()
        names = frozenset(a.name for a in self.engine.analyzers)
        self._options = AnalysisOptions(online=False, fetch_pages=False, detonate=False,
                                        explain=False, ai_report=False, max_depth=0,
                                        max_children=0, timeout_s=5.0, analyzer_timeout_s=3.0,
                                        enable=names, persist=False)
        if warm:
            self.warm_up()

    def warm_up(self) -> None:
        """Load lazy assets (YAML knowledge bases, model weights) once, outside any timeout.

        The first analysis of a process can take several seconds while data files are
        parsed; without this the per-analyzer timeout would silently drop the URL
        analyzer's evidence for the first domains of a stream.
        """
        global _WARMED
        with _WARM_LOCK:
            if _WARMED:
                return
            try:
                opts = AnalysisOptions(online=False, fetch_pages=False, detonate=False,
                                       explain=False, ai_report=False, max_depth=0,
                                       max_children=0, timeout_s=120.0,
                                       analyzer_timeout_s=120.0, enable=self._options.enable,
                                       persist=False)
                self.engine.analyze_sync(self._artifact("paypa1-login.example.test"), opts)
                _WARMED = True
            except Exception:  # pragma: no cover - warm-up is best effort
                log.exception("CT hunter warm-up failed")

    # ---- setup ---------------------------------------------------------- #
    @staticmethod
    def _fast_engine(engine: Engine | None) -> Engine:
        base = engine or Engine()
        fast = [a for a in base.analyzers if a.name in FAST_ANALYZERS and not a.requires_online]
        if not fast:   # custom engine without a 'url' analyzer: any offline, static analyzer
            fast = [a for a in base.analyzers
                    if not a.requires_online and not a.requires_detonation and a.stage == 0]
        return Engine(base.settings, analyzers=fast, hooks=[])

    def _resolve_watch(self, brands: Iterable[str] | None) -> frozenset[str] | None:
        if brands is None:
            return None
        wanted = {b.strip().casefold() for b in brands if isinstance(b, str) and b.strip()}
        if not wanted:
            return None
        ids: set[str] = set()
        for b in self.kb.all():
            if wanted & {b.id.casefold(), b.name.casefold(), *(a.casefold() for a in b.aliases)}:
                ids.add(b.id.casefold())
        for unknown in wanted - {x for b in self.kb.all()
                                 for x in (b.id.casefold(), b.name.casefold(),
                                           *(a.casefold() for a in b.aliases))}:
            log.warning("watch_brands: %r is not in the brand knowledge base", unknown)
            ids.add(unknown)
        return frozenset(ids)

    # ---- admission ------------------------------------------------------ #
    def _admit(self, domain: Any) -> str | None:
        with self._lock:
            self.stats.seen += 1
            host = clean_domain(domain)
            if host is None:
                self.stats.invalid += 1
                return None
            if not self._seen.add(host):
                self.stats.duplicates += 1
                return None
            if self.kb.official_brand_for_host(host) is not None:
                self.stats.official_skipped += 1
                return None
            return host

    def _rate_ok(self) -> bool:
        if not self.max_rate:
            return True
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self.max_rate, self._tokens + (now - self._tick) * self.max_rate)
            self._tick = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            self.stats.dropped_rate_limit += 1
            return False

    # ---- scoring -------------------------------------------------------- #
    def _is_fresh(self, meta: Mapping[str, Any], default: bool | None) -> bool:
        if isinstance(meta.get("fresh"), bool):
            return bool(meta["fresh"])
        ts = _epoch(meta.get("not_before"))
        if ts is not None:
            return 0 <= time.time() - ts <= self.fresh_window_s
        if default is not None:
            return default
        return meta.get("source") == "certstream"

    @staticmethod
    def _artifact(host: str) -> Artifact:
        return Artifact.from_url(f"https://{host}/", origin="ct")

    def _brand_ok(self, verdict: Verdict) -> bool:
        b = verdict.brand
        return bool(b and not b.official and b.technique != "official")

    def _decide(self, verdict: Verdict) -> str | None:
        """Return the flag reason, or None when the domain is to be ignored."""
        looks_alike = self._brand_ok(verdict)
        if self.watch is not None:
            b = verdict.brand
            watched = bool(looks_alike and b and (b.brand.casefold() in self.watch
                                                  or b.name.casefold() in self.watch))
            return "watched_brand" if watched and verdict.score >= self.brand_floor else None
        if verdict.score >= self.threshold:
            return "score"
        if looks_alike and verdict.score >= self.brand_floor:
            return "brand_lookalike"
        return None

    def _apply_fresh(self, verdict: Verdict, fresh: bool) -> None:
        """Add the 'issued just now' weight to a brand look-alike and re-fuse in place."""
        if not (fresh and self.fresh_weight and self._brand_ok(verdict)):
            return
        b = verdict.brand
        assert b is not None
        verdict.signals.append(Signal(
            id=FRESH_SIGNAL_ID, title="Certificate issued moments ago for a brand look-alike",
            detail=f"A TLS certificate was just issued for a domain imitating {b.name} "
                   f"({b.technique}); phishing sites are usually staged right after issuance.",
            weight=self.fresh_weight, confidence=max(0.5, min(1.0, b.confidence)),
            category="infra", analyzer="ct", mitre=["T1583.001"],
            evidence={"brand": b.brand, "technique": b.technique, "fresh_cert": True}))
        fused = scoring.fuse(verdict.signals, self.engine.settings)
        for k, v in fused.items():
            setattr(verdict, k, v)
        verdict.signals.sort(key=lambda s: abs(s.contribution or 0.0), reverse=True)
        verdict.mitre = mitre.resolve_many({m.id for m in verdict.mitre} | {"T1583.001"})
        verdict.summary = scoring.summarize(verdict)

    def _finish(self, host: str, verdict: Verdict, meta: Mapping[str, Any],
                fresh_default: bool | None) -> HuntHit | None:
        with self._lock:
            self.stats.scored += 1
        fresh = self._is_fresh(meta, fresh_default)
        self._apply_fresh(verdict, fresh)
        reason = self._decide(verdict)
        if reason is None:
            return None
        from uniphish.export.stix import to_stix_bundle

        with self._lock:
            self.stats.flagged += 1
            registrable = _registrable(verdict, host)
            if not self._alerted.add(registrable):
                self.stats.duplicate_alerts += 1
                return None
        for ind in verdict.indicators:
            if ind.type is IndicatorType.DOMAIN:
                ind.malicious = True
        if not any(i.type is IndicatorType.DOMAIN for i in verdict.indicators):
            verdict.indicators.append(Indicator(type=IndicatorType.DOMAIN, value=host,
                                                role="host", malicious=True))
        verdict.meta["ct"] = {"fresh": fresh, "reason": reason, "domain": host,
                              **{k: v for k, v in meta.items() if k != "source"}}
        bundle = to_stix_bundle(verdict, include_benign=True)
        stix_id = next((o["id"] for o in bundle["objects"] if o.get("type") == "indicator"),
                       None)
        source = str(meta.get("source") or "ct")
        b = verdict.brand if self._brand_ok(verdict) else None
        event_id = self.store.add_hunt_event(
            source, host, verdict.score, b.brand if b else None, verdict.techniques, bundle)
        for obj in bundle["objects"]:
            self.store.add_stix_object(obj)
        hit = HuntHit(domain=host, score=verdict.score, level=verdict.level.value,
                      brand=b.brand if b else None, brand_name=b.name if b else None,
                      technique=b.technique if b else None, techniques=list(verdict.techniques),
                      reason=reason, fresh=fresh, event_id=event_id, stix_id=stix_id,
                      source=source, verdict=verdict)
        with self._lock:
            self.stats.recorded += 1
            if hit.brand:
                self.stats.by_brand[hit.brand] += 1
        if self.publish:
            events.publish("hunt", hit.to_event())
        log.info("CT hit %s score=%d brand=%s reason=%s", host, hit.score, hit.brand, reason)
        return hit

    # ---- public API ------------------------------------------------------ #
    def process(self, domain: str, meta: Mapping[str, Any] | None = None, *,
                fresh: bool | None = None) -> HuntHit | None:
        """Score one domain synchronously; return the recorded hit or ``None``.

        ``fresh`` overrides whether the certificate counts as just issued (default:
        from ``meta['not_before']``, else True for live certstream records).
        """
        host = self._admit(domain)
        if host is None:
            return None
        try:
            verdict = self.engine.analyze_sync(self._artifact(host), self._options)
        except Exception:
            log.exception("CT scoring failed for %s", host)
            with self._lock:
                self.stats.errors += 1
            return None
        return self._finish(host, verdict, meta or {}, fresh)

    async def aprocess(self, domain: str, meta: Mapping[str, Any] | None = None, *,
                       fresh: bool | None = None) -> HuntHit | None:
        """Async twin of :meth:`process` (used by :meth:`run`)."""
        host = self._admit(domain)
        if host is None:
            return None
        try:
            verdict = await self.engine.analyze(self._artifact(host), self._options)
        except Exception:
            log.exception("CT scoring failed for %s", host)
            with self._lock:
                self.stats.errors += 1
            return None
        return self._finish(host, verdict, meta or {}, fresh)

    def hunt_once(self, domains: Iterable[str], *, meta: Mapping[str, Any] | None = None,
                  fresh: bool | None = True) -> list[HuntHit]:
        """Process a batch of newly issued domains (tests / CLI); return the hits."""
        base = {"source": "sample", **(meta or {})}
        hits = []
        for d in domains:
            hit = self.process(d, base, fresh=fresh)
            if hit is not None:
                hits.append(hit)
        return hits

    async def run(self, source: str = "certstream", *, url: str = CERTSTREAM_URL,
                  path: str | Path | None = None, max_domains: int | None = None,
                  duration_s: float | None = None, stop: asyncio.Event | None = None,
                  connect: Connector | None = None, **stream_kwargs: Any) -> HuntStats:
        """Main loop: stream -> bounded queue -> worker pool -> :meth:`aprocess`.

        Live mode drops (and counts) domains when the queue is full or ``max_rate`` is
        exceeded; sample replay applies back-pressure instead so nothing is lost.
        Stops on ``stop``, after ``max_domains`` admitted domains, after ``duration_s``,
        or when a sample replay ends. Returns the cumulative :class:`HuntStats`.
        """
        stop = stop or asyncio.Event()
        queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue(self.queue_size)
        live = source == "certstream"
        admitted = 0

        async def on_cert(domain: str, meta: dict[str, Any]) -> None:
            nonlocal admitted
            if max_domains is not None and admitted >= max_domains:
                stop.set()
                return
            if live and not self._rate_ok():
                return
            if live:
                try:
                    queue.put_nowait((domain, meta))
                except asyncio.QueueFull:
                    self.stats.dropped_queue_full += 1
                    return
            else:
                await queue.put((domain, meta))
            admitted += 1
            if max_domains is not None and admitted >= max_domains:
                stop.set()

        async def worker() -> None:
            while True:
                domain, meta = await queue.get()
                try:
                    await self.aprocess(domain, meta)
                except Exception:   # pragma: no cover - aprocess already isolates faults
                    log.exception("CT worker error")
                finally:
                    queue.task_done()

        tasks = [asyncio.create_task(worker()) for _ in range(self.workers)]
        timer = asyncio.get_running_loop().call_later(duration_s, stop.set) \
            if duration_s else None
        try:
            await stream_certstream(on_cert, source=source, url=url, path=path, stop=stop,
                                    connect=connect, **stream_kwargs)
            await queue.join()
        finally:
            if timer:
                timer.cancel()
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        return self.stats


def _registrable(verdict: Verdict, host: str) -> str:
    """Registrable domain for alert de-duplication (handles unknown TLDs like ``.test``)."""
    try:
        parts = split_host(parse_url(f"https://{host}/"))
        if parts.sld and parts.suffix:
            return f"{parts.sld}.{parts.suffix}".lower()
    except Exception:   # pragma: no cover - parse_url never raises on a validated host
        log.debug("registrable-domain split failed for %s", host)
    return host


async def iter_domains(source: str = "sample", *, path: str | Path | None = None,
                       limit: int | None = None) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Async-iterate replayed ``(domain, meta)`` pairs (convenience for tools/tests)."""
    out: list[tuple[str, dict[str, Any]]] = []
    await stream_certstream(lambda d, m: out.append((d, m)), source=source, path=path,
                            max_certs=limit)
    for item in out:
        yield item


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for ``uniphish hunt`` / ``python -m uniphish.hunt.ct``.

    Offline by default (``--source sample`` replays a bundled demo set); ``--source
    certstream`` streams the live Certificate Transparency firehose (needs ``online``).
    """
    import argparse

    from uniphish.core.engine import default_engine

    ap = argparse.ArgumentParser(prog="uniphish hunt",
                                 description="Hunt newly-issued phishing domains via "
                                             "Certificate Transparency.")
    ap.add_argument("--source", default="sample",
                    help="'sample' (offline demo), 'certstream' (live), or a JSONL file path")
    ap.add_argument("--threshold", type=int, default=60, help="min risk score to alert (0-100)")
    ap.add_argument("--brands", default="", help="comma-separated brand ids to watch (optional)")
    ap.add_argument("--max-domains", type=int, default=None, help="stop after N domains")
    ap.add_argument("--duration", type=float, default=None, help="stop after N seconds (live)")
    ap.add_argument("domains", nargs="*", help="score these domains directly and exit")
    args = ap.parse_args(argv)

    watch = tuple(b.strip() for b in args.brands.split(",") if b.strip()) or None
    hunter = CTHunter(default_engine(), threshold=args.threshold, watch_brands=watch)

    if args.domains:
        hits = hunter.hunt_once(args.domains)
    elif args.source in ("sample",) or Path(args.source).exists():
        path = None if args.source == "sample" else args.source
        domains = list(SAMPLE_DOMAINS) if path is None else None
        if domains is not None:
            hits = hunter.hunt_once(domains)
        else:
            hits = asyncio.run(_run_collect(hunter, args.source, path, args.max_domains))
    else:
        hits = asyncio.run(_run_collect(hunter, args.source, None, args.max_domains,
                                        duration_s=args.duration))

    for h in hits:
        brand = f" impersonates {h.brand}" if getattr(h, "brand", None) else ""
        tech = ",".join(getattr(h, "techniques", []) or []) or "-"
        print(f"[{getattr(h, 'score', '?'):>3}] {getattr(h, 'domain', '?'):40s}{brand}  ({tech})")
    print(f"\n{len(hits)} alert(s) from source={args.source!r} at threshold {args.threshold}.")
    return 0


async def _run_collect(hunter: CTHunter, source: str, path: str | None,
                       max_domains: int | None, *, duration_s: float | None = None
                       ) -> list[HuntHit]:
    hits: list[HuntHit] = []
    async for domain, meta in iter_domains(source, path=path, limit=max_domains):
        hit = hunter.process(domain, meta)
        if hit is not None:
            hits.append(hit)
    return hits


__all__ = ["CERTSTREAM_URL", "SAMPLE_DOMAINS", "CTHunter", "HuntHit", "HuntStats",
           "clean_domain", "iter_domains", "main", "parse_record", "stream_certstream"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
