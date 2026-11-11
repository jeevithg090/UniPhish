"""Threat-feed ingestion: pull public phishing blocklists into the local reputation DB.

Why this exists
---------------
The :class:`~uniphish.analyzers.reputation.ReputationAnalyzer` consults the local
reputation table (``Store.lookup_reputation``) *offline*. This module is the supply
chain for that table: pluggable importers download well-known **open** feeds, parse
them into :class:`FeedEntry` rows and write them with ``Store.bulk_set`` as
``verdict='deny'`` entries carrying a source tag (``feed:<name>``) and a TTL, so a
stale listing expires by itself. After one online ``update_all`` the platform flags
known-bad indicators with no network at all.

Importers
---------
=====================  ==========================================  ===============================
name                   source                                       licence / terms (read them!)
=====================  ==========================================  ===============================
``openphish``          OpenPhish community feed (plain URL list)    free for non-commercial use;
                                                                    do not poll more than a few
                                                                    times per day
``urlhaus``            abuse.ch URLhaus online-URL CSV / text       CC0; abuse.ch may require a
                                                                    free ``Auth-Key``
                                                                    (``URLHAUS_AUTH_KEY``)
``phishtank``          PhishTank ``online-valid.csv`` (verified)    free with an app key
                                                                    (``PHISHTANK_APP_KEY``);
                                                                    attribution required
``blocklist``          generic one-host-per-line / hosts-file       whatever the list's licence
                       domain list (e.g. Phishing.Database)         says; default preset is MIT
``taxii``              any TAXII 2.1 collection of STIX indicators  set by the server operator
=====================  ==========================================  ===============================

Safety design (feeds are *untrusted input*)
-------------------------------------------
* Every byte goes through :func:`uniphish.core.net.safe_fetch` (SSRF-guarded, streamed
  under a hard size cap). A truncated line feed drops its partial last line; a
  truncated JSON/TAXII page is an error, never half-parsed.
* Entries are validated (scheme, host syntax, length, public IPs only) and capped at
  ``max_entries`` per feed.
* A poisoned or careless feed must not be able to deny the internet: **domain** entries
  that equal a top-ranked site or a "living-off-trusted-sites" platform (``github.io``,
  ``pages.dev`` ...) are skipped (those are only ever denied as full *URLs*), and an
  operator **allow** row is never overwritten.
* Per-feed error isolation: one failing feed never aborts the others. Secrets embedded
  in a feed URL (the PhishTank app key) are redacted from errors and logs.
* Nothing runs unless ``online`` is true; successful runs are rate-limited per feed with
  a :class:`~uniphish.core.cache.DiskCache` marker (``force=True`` overrides).

Run ``python -m uniphish.intel.feeds --online`` (or call :func:`update_all`) to import.
"""

from __future__ import annotations

import asyncio
import base64
import csv
import io
import ipaddress
import logging
import os
import re
import sys
import time
from collections.abc import Iterable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from uniphish.core.cache import DiskCache
from uniphish.core.config import get_settings
from uniphish.core.net import Resolver, is_public_ip, safe_fetch

log = logging.getLogger("uniphish.intel.feeds")

__all__ = [
    "BlocklistFeed",
    "Feed",
    "FeedEntry",
    "FeedError",
    "FeedResult",
    "OpenPhishFeed",
    "PhishTankFeed",
    "TaxiiFeed",
    "UpdateSummary",
    "UrlhausFeed",
    "aupdate_all",
    "default_feeds",
    "parse_stix_pattern",
    "parse_stix_objects",
    "store_entries",
    "update_all",
]

MAX_URL_CHARS = 2048
MAX_DOMAIN_CHARS = 253
DEFAULT_MAX_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_ENTRIES = 250_000
BATCH_SIZE = 5_000
TOP_SITE_PROTECT_RANK = 5_000  # domains at or above this Tranco rank are never denied
_DAY = 86_400.0
_MAX_PATTERN_CHARS = 20_000
_TAXII_MAX_PAGES = 50
_TAXII_PAGE_BYTES = 8 * 1024 * 1024


class FeedError(Exception):
    """A feed could not be fetched or parsed (isolated per feed by the orchestrator)."""


@dataclass(frozen=True, slots=True)
class FeedEntry:
    """One indicator from a feed. ``type`` uses the store's observable names
    (``url``, ``domain``, ``ipv4``, ``ipv6``, ``sha256``)."""

    type: str
    value: str
    source: str
    first_seen: str | None = None
    reason: str = ""


# --------------------------------------------------------------------------- #
# Validation helpers (pure)
# --------------------------------------------------------------------------- #
_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_CTRL_RE = re.compile(r"[\x00-\x20\x7f]")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_HOSTS_SINKS = frozenset(
    {
        "0.0.0.0",  # noqa: S104 (hosts-file sink address, not a bind)
        "127.0.0.1",
        "::1",
        "::",
        "0",
        "255.255.255.255",
    }
)
_IGNORED_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
    }
)


def clean_url(raw: str | None) -> str | None:
    """Return a canonical-enough http(s) URL, or ``None`` if the string is not one."""
    if not raw:
        return None
    u = raw.strip().strip('"').strip()
    if not u or len(u) > MAX_URL_CHARS or _CTRL_RE.search(u):
        return None
    try:
        parts = urlsplit(u)
        host = parts.hostname
        parts.port  # noqa: B018  (raises ValueError on a bad port)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    if _ip_type(host) is not None:
        return u if is_public_ip(host) else None
    return u if clean_domain(host) else None


def _ip_type(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None
    return "ipv6" if ip.version == 6 else "ipv4"


def clean_domain(raw: str | None) -> str | None:
    """Validate and lower-case a hostname; Unicode names are converted to IDNA (A-label).

    Returns ``None`` for IPs, single labels, bad syntax or reserved/local names.
    """
    if not raw:
        return None
    d = raw.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    if not d or len(d) > MAX_DOMAIN_CHARS * 2 or _CTRL_RE.search(d):
        return None
    try:
        d.encode("ascii")
    except UnicodeEncodeError:
        try:
            d = d.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if len(d) > MAX_DOMAIN_CHARS or d in _IGNORED_HOSTS or _ip_type(d) is not None:
        return None
    labels = d.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(x) for x in labels):
        return None
    if labels[-1].isdigit():
        return None
    return d


def _data_lines(text: str) -> Iterator[str]:
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            yield s


def _drop_partial_line(text: str) -> str:
    """For a size-capped download, discard the possibly cut-off final line."""
    cut = text.rfind("\n")
    return text[:cut] if cut >= 0 else ""


def _host_entry(host: str, source: str, first_seen: str | None, reason: str) -> FeedEntry | None:
    t = _ip_type(host)
    if t is not None:
        if not is_public_ip(host):
            return None
        return FeedEntry(t, str(ipaddress.ip_address(host.strip("[]"))), source, first_seen, reason)
    d = clean_domain(host)
    return FeedEntry("domain", d, source, first_seen, reason) if d else None


# --------------------------------------------------------------------------- #
# Feed base class
# --------------------------------------------------------------------------- #
class Feed:
    """Base importer. Subclasses implement :meth:`parse`; :meth:`fetch` downloads + parses.

    ``transport`` / ``resolver`` are test injection points forwarded to ``safe_fetch``.
    """

    name = "feed"
    title = "Feed"
    default_url: str | None = None
    entry_type = "url"
    licence = ""
    weight = 6.0  # log-odds hint stored on the deny row (analyzer clamps 0.5..8)
    ttl_s = 3 * _DAY  # how long a listing is trusted without being re-seen
    min_interval_s = 3600.0  # do not re-download more often than this
    line_based = True  # truncated body -> drop partial last line (else: error)

    def __init__(
        self,
        url: str | None = None,
        *,
        name: str | None = None,
        headers: dict[str, str] | None = None,
        ttl_s: float | None = None,
        weight: float | None = None,
        min_interval_s: float | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        timeout: float = 60.0,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        self.url = url or self.default_url
        if name:
            self.name = name
        self.headers = dict(headers or {})
        if ttl_s is not None:
            self.ttl_s = float(ttl_s)
        if weight is not None:
            self.weight = float(weight)
        if min_interval_s is not None:
            self.min_interval_s = float(min_interval_s)
        self.max_bytes = int(max_bytes)
        self.max_entries = int(max_entries)
        self.timeout = float(timeout)
        self.transport = transport
        self.resolver = resolver
        self.last_truncated = False

    # -- secrets ----------------------------------------------------------- #
    def secrets(self) -> tuple[str, ...]:
        """Strings (API keys inside URLs/headers) that must never appear in output."""
        vals = [
            v
            for k, v in self.headers.items()
            if k.lower() in {"authorization", "auth-key", "x-api-key", "api-key"}
        ]
        return tuple(s for s in vals if s)

    def redact(self, text: str) -> str:
        for s in self.secrets():
            text = text.replace(s, "***")
        return text

    @property
    def display_url(self) -> str:
        return self.redact(self.url or "")

    # -- pure parsing ------------------------------------------------------ #
    def parse(self, text: str) -> list[FeedEntry]:  # pragma: no cover - abstract
        raise NotImplementedError

    # -- network ----------------------------------------------------------- #
    def _request_headers(self) -> dict[str, str]:
        return {"accept": "text/plain, text/csv, */*;q=0.5", **self.headers}

    async def _download(
        self, url: str, headers: dict[str, str], max_bytes: int | None = None
    ) -> Any:
        cap = max_bytes or self.max_bytes
        res = await safe_fetch(
            url,
            headers=headers,
            max_bytes=cap,
            max_decompressed_bytes=cap,
            timeout=self.timeout,
            max_redirects=3,
            transport=self.transport,
            resolver=self.resolver,
        )
        if res.blocked_reason:
            raise FeedError(f"blocked: {res.blocked_reason}")
        if res.error:
            raise FeedError(res.error)
        if not 200 <= res.status < 300:
            raise FeedError(f"http {res.status}")
        return res

    async def fetch(self) -> list[FeedEntry]:
        """Download, parse and cap the feed. Raises :class:`FeedError` on any failure."""
        if not self.url:
            raise FeedError("no url configured")
        res = await self._download(self.url, self._request_headers())
        self.last_truncated = bool(res.truncated)
        text = res.text()
        if res.truncated:
            if not self.line_based:
                raise FeedError(f"response exceeded {self.max_bytes} bytes")
            text = _drop_partial_line(text)
        try:
            entries = self.parse(text)
        except FeedError:
            raise
        except Exception as exc:  # parsers must not crash the run
            raise FeedError(f"parse error: {type(exc).__name__}") from exc
        if len(entries) > self.max_entries:
            self.last_truncated = True
            entries = entries[: self.max_entries]
        return entries


# --------------------------------------------------------------------------- #
# Concrete importers
# --------------------------------------------------------------------------- #
class OpenPhishFeed(Feed):
    """OpenPhish community feed: one phishing URL per line."""

    name = "openphish"
    title = "OpenPhish community feed"
    default_url = "https://openphish.com/feed.txt"
    licence = "free for non-commercial use (openphish.com/terms)"
    min_interval_s = 6 * 3600.0

    def parse(self, text: str) -> list[FeedEntry]:
        out: list[FeedEntry] = []
        seen: set[str] = set()
        for line in _data_lines(text):
            u = clean_url(line)
            if u and u not in seen:
                seen.add(u)
                out.append(FeedEntry("url", u, self.name, None, "listed by OpenPhish"))
        return out


class UrlhausFeed(Feed):
    """abuse.ch URLhaus malware-distribution URLs (CSV or one-URL-per-line text).

    Many URLhaus URLs are phishing-adjacent malware droppers; weight is slightly lower
    than a verified phishing feed.
    """

    name = "urlhaus"
    title = "abuse.ch URLhaus"
    default_url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    licence = "CC0 (urlhaus.abuse.ch/api); abuse.ch may require a free Auth-Key"
    weight = 5.0
    min_interval_s = 3600.0

    def __init__(self, url: str | None = None, *, auth_key: str | None = None, **kw: Any) -> None:
        super().__init__(url, **kw)
        if auth_key:
            self.headers.setdefault("Auth-Key", auth_key)

    def parse(self, text: str) -> list[FeedEntry]:
        out: list[FeedEntry] = []
        seen: set[str] = set()
        for line in _data_lines(text):
            first_seen = threat = None
            url_raw = line
            if line.startswith('"') or line.count(",") >= 2:
                try:
                    row = next(csv.reader([line]))
                except (csv.Error, StopIteration):
                    continue
                if len(row) < 3:
                    continue
                url_raw = row[2]
                first_seen = _norm_ts(row[1])
                if len(row) > 3 and row[3].strip().lower() == "offline":
                    continue
                if len(row) > 5:
                    threat = row[5].strip()
            u = clean_url(url_raw)
            if u and u not in seen:
                seen.add(u)
                reason = "listed by URLhaus" + (f" ({threat})" if threat else "")
                out.append(FeedEntry("url", u, self.name, first_seen, reason))
        return out


class PhishTankFeed(Feed):
    """PhishTank ``online-valid.csv`` (verified, still online phishing URLs)."""

    name = "phishtank"
    title = "PhishTank verified phishes"
    default_url = "https://data.phishtank.com/data/online-valid.csv"
    licence = "free with an app key; attribution to PhishTank required"
    min_interval_s = 6 * 3600.0
    line_based = True

    def __init__(self, url: str | None = None, *, app_key: str | None = None, **kw: Any) -> None:
        if url is None and app_key:
            url = f"https://data.phishtank.com/data/{quote(app_key, safe='')}/online-valid.csv"
        super().__init__(url, **kw)
        self._app_key = app_key

    def secrets(self) -> tuple[str, ...]:
        extra = (self._app_key, quote(self._app_key, safe="")) if self._app_key else ()
        return super().secrets() + tuple(x for x in extra if x)

    def parse(self, text: str) -> list[FeedEntry]:
        rows = csv.DictReader(io.StringIO(text))
        if not rows.fieldnames or "url" not in rows.fieldnames:
            raise FeedError("unexpected PhishTank format (no 'url' column)")
        out: list[FeedEntry] = []
        seen: set[str] = set()
        for row in rows:
            if (row.get("verified") or "yes").strip().lower() != "yes":
                continue
            if (row.get("online") or "yes").strip().lower() != "yes":
                continue
            u = clean_url(row.get("url"))
            if not u or u in seen:
                continue
            seen.add(u)
            target = (row.get("target") or "").strip()
            reason = "verified by PhishTank" + (
                f" (target: {target[:60]})" if target and target.lower() != "other" else ""
            )
            out.append(FeedEntry("url", u, self.name, _norm_ts(row.get("submission_time")), reason))
        return out


class BlocklistFeed(Feed):
    """Generic domain blocklist: one host per line, hosts-file (``0.0.0.0 host``) or
    adblock (``||host^``) syntax. Public IPs are imported as ``ipv4``/``ipv6`` entries.

    The default preset is the Phishing.Database active-domains list (MIT licence); it is
    the project's published location and is not verified by the offline test-suite.
    """

    name = "blocklist"
    title = "Domain blocklist"
    default_url = (
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/"
        "master/phishing-domains-ACTIVE.txt"
    )
    entry_type = "domain"
    licence = "depends on the list (default preset: MIT)"
    weight = 5.0
    ttl_s = 7 * _DAY
    min_interval_s = 12 * 3600.0

    def parse(self, text: str) -> list[FeedEntry]:
        out: list[FeedEntry] = []
        seen: set[str] = set()
        for line in _data_lines(text):
            tok = self._host_token(line)
            if tok is None:
                continue
            e = _host_entry(tok, self.name, None, f"listed in {self.title}")
            if e and (e.type, e.value) not in seen:
                seen.add((e.type, e.value))
                out.append(e)
        return out

    @staticmethod
    def _host_token(line: str) -> str | None:
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("!", "[")):
            return None
        if line.startswith("||"):
            line = line[2:].split("^", 1)[0].split("/", 1)[0]
            return line or None
        parts = line.split()
        if len(parts) >= 2 and parts[0] in _HOSTS_SINKS:
            return parts[1]
        if len(parts) == 1:
            tok = parts[0]
            if "://" in tok:  # a URL slipped into a domain list: use its host
                try:
                    return urlsplit(tok).hostname
                except ValueError:
                    return None
            return tok
        return None


# --------------------------------------------------------------------------- #
# STIX / TAXII
# --------------------------------------------------------------------------- #
_STIX_TERM_RE = re.compile(
    r"(?P<obj>url|domain-name|ipv4-addr|ipv6-addr|file):(?P<prop>[A-Za-z0-9_.'\"-]{1,40})"
    r"\s*(?P<op>=|IN)\s*"
    r"(?P<val>'(?:[^'\\]|\\.){0,2048}'|\([^()]{0,8192}\))"
)
_STIX_STR_RE = re.compile(r"'((?:[^'\\]|\\.){0,2048})'")
_STIX_UNSUPPORTED_RE = re.compile(r"\b(?:AND|NOT|FOLLOWEDBY|START|STOP|WITHIN|REPEATS)\b")
_HASH_PROP_RE = re.compile(r"^hashes\.(?:'|\")?(?:SHA-?256)(?:'|\")?$", re.IGNORECASE)


def _stix_unescape(s: str) -> str:
    return re.sub(r"\\(.)", r"\1", s)


def parse_stix_pattern(pattern: str) -> list[tuple[str, str]]:
    """Extract ``(type, value)`` observables from a simple STIX 2.1 indicator pattern.

    Handles ``url:value``, ``domain-name:value``, ``ipv4-addr:value``,
    ``ipv6-addr:value`` and ``file:hashes.'SHA-256'`` joined by ``OR`` / ``IN (...)``.
    Anything involving ``AND``, ``NOT`` or temporal operators is skipped entirely (it
    does not describe a single standalone indicator), as is any unrecognised property.
    """
    if not isinstance(pattern, str) or len(pattern) > _MAX_PATTERN_CHARS:
        return []
    outside = _STIX_STR_RE.sub("''", pattern)
    if _STIX_UNSUPPORTED_RE.search(outside):
        return []
    found: list[tuple[str, str]] = []
    for m in _STIX_TERM_RE.finditer(pattern):
        obj, prop, val = m.group("obj"), m.group("prop"), m.group("val")
        t: str | None
        if obj == "url" and prop == "value":
            t = "url"
        elif obj == "domain-name" and prop == "value":
            t = "domain"
        elif obj == "ipv4-addr" and prop == "value":
            t = "ipv4"
        elif obj == "ipv6-addr" and prop == "value":
            t = "ipv6"
        elif obj == "file" and _HASH_PROP_RE.match(prop):
            t = "sha256"
        else:
            continue
        vals = _STIX_STR_RE.findall(val)
        for v in vals:
            found.append((t, _stix_unescape(v)))
    return found


def _parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _norm_ts(value: Any) -> str | None:
    dt = _parse_dt(value if isinstance(value, str) else None)
    if dt is None and isinstance(value, str):
        try:
            dt = datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def _validate_typed(t: str, v: str) -> str | None:
    if t == "url":
        return clean_url(v)
    if t == "domain":
        return clean_domain(v)
    if t in ("ipv4", "ipv6"):
        if "/" in v:
            try:
                net = ipaddress.ip_network(v, strict=False)
            except ValueError:
                return None
            if net.num_addresses != 1:  # a CIDR range is not a single host indicator
                return None
            v = str(net.network_address)
        return v if _ip_type(v) == t and is_public_ip(v) else None
    if t == "sha256":
        h = v.strip().lower()
        return h if len(h) == 64 and _HEX_RE.match(h) else None
    return None


def parse_stix_objects(
    objects: Iterable[Any], source: str, *, now: datetime | None = None
) -> list[FeedEntry]:
    """Turn STIX 2.x objects (from a bundle or a TAXII envelope) into feed entries.

    Only ``indicator`` objects with the ``stix`` pattern type are used; revoked and
    expired (``valid_until`` in the past) indicators are dropped.
    """
    now = now or datetime.now(timezone.utc)
    out: list[FeedEntry] = []
    seen: set[tuple[str, str]] = set()
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        if obj.get("revoked") is True:
            continue
        if str(obj.get("pattern_type", "stix")).lower() != "stix":
            continue
        until = _parse_dt(obj.get("valid_until"))
        if until is not None and until <= now:
            continue
        first_seen = _norm_ts(obj.get("valid_from") or obj.get("created"))
        name = str(obj.get("name") or "").strip()[:80]
        reason = "TAXII indicator" + (f": {name}" if name else "")
        for t, raw in parse_stix_pattern(str(obj.get("pattern") or "")):
            v = _validate_typed(t, raw)
            if v and (t, v) not in seen:
                seen.add((t, v))
                out.append(FeedEntry(t, v, source, first_seen, reason))
    return out


class TaxiiFeed(Feed):
    """Pull ``indicator`` objects from a TAXII 2.1 collection into the reputation DB.

    ``api_root`` is the API-root URL (e.g. ``https://taxii.example.test/api1``). Auth is
    optional: ``token`` (Bearer) or ``username``/``password`` (Basic), or any raw
    ``headers``. Pagination follows the envelope's ``more`` / ``next`` (max 50 pages).
    """

    name = "taxii"
    title = "TAXII 2.1 collection"
    entry_type = "mixed"
    licence = "set by the server operator"
    weight = 5.0
    ttl_s = 14 * _DAY
    min_interval_s = 3600.0
    line_based = False

    def __init__(
        self,
        api_root: str,
        collection_id: str,
        *,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        added_after: str | None = None,
        page_size: int = 500,
        name: str | None = None,
        **kw: Any,
    ) -> None:
        root = api_root.rstrip("/")
        host = urlsplit(root).hostname or "taxii"
        super().__init__(root, name=name or f"taxii:{host}", **kw)
        if not re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", collection_id or ""):
            raise ValueError("invalid TAXII collection id")
        self.collection_id = collection_id
        self.title = f"TAXII collection {collection_id[:12]} @ {host}"
        self.added_after = added_after
        self.page_size = max(1, min(int(page_size), 1000))
        if token:
            self.headers.setdefault("Authorization", f"Bearer {token}")
        elif username is not None and password is not None:
            raw = base64.b64encode(f"{username}:{password}".encode()).decode()
            self.headers.setdefault("Authorization", f"Basic {raw}")
        self._extra_secrets = tuple(x for x in (token, password) if x)

    def secrets(self) -> tuple[str, ...]:
        auth = self.headers.get("Authorization", "")
        tail = auth.split(" ", 1)[-1] if auth else ""
        return super().secrets() + self._extra_secrets + ((tail,) if tail else ())

    def parse(self, text: str) -> list[FeedEntry]:
        """Parse one TAXII envelope **or** a plain STIX bundle (JSON text)."""
        import json

        try:
            doc = json.loads(text)
        except ValueError as exc:
            raise FeedError("invalid JSON from TAXII server") from exc
        if not isinstance(doc, dict):
            raise FeedError("unexpected TAXII payload")
        return parse_stix_objects(doc.get("objects") or [], self.name)

    def _page_url(self, cursor: str | None) -> str:
        q = ["match[type]=indicator", f"limit={self.page_size}"]
        if self.added_after:
            q.append("added_after=" + quote(self.added_after, safe=""))
        if cursor:
            q.append("next=" + quote(cursor, safe=""))
        return f"{self.url}/collections/{quote(self.collection_id, safe='')}/objects/?" + "&".join(
            q
        )

    async def fetch(self) -> list[FeedEntry]:
        import json

        headers = {"accept": "application/taxii+json;version=2.1", **self.headers}
        entries: list[FeedEntry] = []
        seen: set[tuple[str, str]] = set()
        cursor: str | None = None
        self.last_truncated = False
        for _ in range(_TAXII_MAX_PAGES):
            res = await self._download(self._page_url(cursor), headers, _TAXII_PAGE_BYTES)
            if res.truncated:
                raise FeedError("TAXII page exceeded the size cap")
            try:
                doc = json.loads(res.text())
            except ValueError as exc:
                raise FeedError("invalid JSON from TAXII server") from exc
            if not isinstance(doc, dict):
                raise FeedError("unexpected TAXII payload")
            for e in parse_stix_objects(doc.get("objects") or [], self.name):
                if (e.type, e.value) not in seen:
                    seen.add((e.type, e.value))
                    entries.append(e)
            if len(entries) >= self.max_entries:
                self.last_truncated = True
                return entries[: self.max_entries]
            nxt = doc.get("next")
            if not (doc.get("more") and isinstance(nxt, str) and nxt):
                return entries
            cursor = nxt
        self.last_truncated = True  # page budget exhausted
        return entries


# --------------------------------------------------------------------------- #
# Writing to the store
# --------------------------------------------------------------------------- #
def _is_protected_domain(domain: str) -> bool:
    """True for domains that must never be denied wholesale (top sites, LOTS platforms)."""
    from uniphish.assets.lists import lots_match, top_rank

    if lots_match(domain) is not None:
        return True
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        rank = top_rank(".".join(labels[i:]))
        if rank is not None and rank <= TOP_SITE_PROTECT_RANK:
            return True
    return False


def store_entries(store: Any, feed: Feed, entries: Sequence[FeedEntry]) -> tuple[int, int]:
    """Write ``entries`` as deny-reputation rows. Returns ``(written, skipped)``.

    Skips protected domains and anything an operator has explicitly allow-listed.
    """
    source = f"feed:{feed.name}"
    batch: list[dict[str, Any]] = []
    written = skipped = 0

    def flush() -> None:
        nonlocal written
        if batch:
            written += store.bulk_set(batch)
            batch.clear()

    for e in entries:
        if e.type == "domain" and _is_protected_domain(e.value):
            skipped += 1
            continue
        try:
            row = store.lookup_reputation(e.type, e.value)
        except Exception:
            row = None
        if row and row.get("verdict") == "allow":
            skipped += 1
            continue
        reason = e.reason or f"listed by {feed.title}"
        if e.first_seen:
            reason = f"{reason}; first seen {e.first_seen}"
        batch.append(
            {
                "type": e.type,
                "value": e.value,
                "verdict": "deny",
                "weight": feed.weight,
                "reason": reason[:300],
                "source": source,
                "ttl": feed.ttl_s,
            }
        )
        if len(batch) >= BATCH_SIZE:
            flush()
    flush()
    return written, skipped


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class FeedResult:
    """Outcome for one feed. ``status`` is ``ok``, ``skipped`` or ``error``."""

    feed: str
    status: str
    fetched: int = 0
    written: int = 0
    skipped: int = 0
    truncated: bool = False
    error: str | None = None
    reason: str | None = None
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self.__slots__}


@dataclass(slots=True)
class UpdateSummary:
    """Aggregate result of :func:`update_all`."""

    online: bool
    results: list[FeedResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when no feed errored (skipped feeds are not failures)."""
        return all(r.status != "error" for r in self.results)

    @property
    def written(self) -> int:
        return sum(r.written for r in self.results)

    @property
    def errors(self) -> dict[str, str]:
        return {r.feed: r.error or "" for r in self.results if r.status == "error"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "online": self.online,
            "ok": self.ok,
            "written": self.written,
            "feeds": [r.to_dict() for r in self.results],
        }

    def render(self) -> str:
        lines = [
            f"feed update ({'online' if self.online else 'offline'}): "
            f"{self.written} indicators written"
        ]
        for r in self.results:
            tail = r.error or r.reason or ""
            lines.append(
                f"  {r.feed:<16} {r.status:<8} fetched={r.fetched} written={r.written} "
                f"skipped={r.skipped}{' truncated' if r.truncated else ''}"
                f"{'  ' + tail if tail else ''}"
            )
        return "\n".join(lines)


def default_feeds() -> list[Feed]:
    """The standard open-feed set. Keys are read from the environment when present."""
    feeds: list[Feed] = [OpenPhishFeed(), UrlhausFeed(auth_key=os.environ.get("URLHAUS_AUTH_KEY"))]
    key = os.environ.get("PHISHTANK_APP_KEY")
    if key:  # without a key PhishTank rate-limits hard; opt in explicitly
        feeds.append(PhishTankFeed(app_key=key))
    feeds.append(
        BlocklistFeed(
            name="phishing-database",
            url=BlocklistFeed.default_url,
        )
    )
    return feeds


async def _run_one(feed: Feed, store: Any, force: bool) -> FeedResult:
    t0 = time.monotonic()
    cache = DiskCache(
        f"feeds-{re.sub(r'[^A-Za-z0-9_.-]', '_', feed.name)[:60]}",
        ttl=max(feed.min_interval_s, 1.0),
    )
    if not force:
        last = cache.get("last")
        if isinstance(last, dict):
            age = max(0, int(time.time() - float(last.get("at", 0))))
            return FeedResult(feed.name, "skipped", reason=f"fresh (updated {age}s ago)")
    try:
        entries = await feed.fetch()
        written, skipped = await asyncio.to_thread(store_entries, store, feed, entries)
    except Exception as exc:
        msg = feed.redact(str(exc) or type(exc).__name__)
        log.warning("feed %s failed: %s", feed.name, msg)
        return FeedResult(
            feed.name, "error", error=msg[:300], elapsed_ms=(time.monotonic() - t0) * 1000
        )
    cache.set("last", {"at": time.time(), "fetched": len(entries), "written": written})
    return FeedResult(
        feed.name,
        "ok",
        fetched=len(entries),
        written=written,
        skipped=skipped,
        truncated=feed.last_truncated,
        elapsed_ms=(time.monotonic() - t0) * 1000,
    )


async def aupdate_all(
    online: bool | None = None,
    *,
    feeds: Sequence[Feed] | None = None,
    store: Any = None,
    force: bool = False,
    concurrency: int = 3,
) -> UpdateSummary:
    """Import every feed concurrently with per-feed error isolation.

    Offline (``online`` false; ``None`` means ``Settings.online``) nothing is fetched and
    every feed reports ``skipped``.
    """
    if online is None:
        online = get_settings().online
    chosen = list(feeds) if feeds is not None else default_feeds()
    if not online:
        return UpdateSummary(
            False, [FeedResult(f.name, "skipped", reason="offline") for f in chosen]
        )
    if store is None:
        from uniphish.store import get_store

        store = get_store()
    sem = asyncio.Semaphore(max(1, concurrency))

    async def guarded(f: Feed) -> FeedResult:
        async with sem:
            try:
                return await _run_one(f, store, force)
            except Exception as exc:  # last-resort isolation (e.g. cache errors)
                return FeedResult(
                    f.name, "error", error=f.redact(f"{type(exc).__name__}: {exc}")[:300]
                )

    return UpdateSummary(True, list(await asyncio.gather(*(guarded(f) for f in chosen))))


def update_all(online: bool | None = None, **kwargs: Any) -> UpdateSummary:
    """Synchronous wrapper around :func:`aupdate_all` (safe inside a running event loop)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(aupdate_all(online, **kwargs))
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(aupdate_all(online, **kwargs))).result()


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m uniphish.intel.feeds [--online] [--force]``; exit 1 if any feed failed."""
    args = list(sys.argv[1:] if argv is None else argv)
    summary = update_all(online=True if "--online" in args else None, force="--force" in args)
    sys.stdout.write(summary.render() + "\n")
    return 0 if summary.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
