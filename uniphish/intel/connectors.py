"""Thin typed clients for optional enrichment APIs (VirusTotal, urlscan.io, Safe Browsing).

Why this exists
---------------
The reputation and infra analyzers can enrich a verdict with third-party opinions when
the operator has supplied API keys. These clients give them (and scripts) one tested,
typed, SSRF-safe place to do that, instead of ad-hoc ``httpx`` calls.

Contract (all three clients)
----------------------------
* **Optional.** Without a key every method returns a result with ``status == "no_key"``
  and performs no network I/O. Keys default to the ``Settings`` values
  (``VT_API_KEY``, ``URLSCAN_API_KEY``, ``GSB_API_KEY``); pass ``api_key=`` to override.
* **Never raises.** Bad input, HTTP failures, malformed JSON and rate limits are
  reported in ``status`` (``ok`` | ``not_found`` | ``no_key`` | ``rate_limited`` |
  ``error`` | ``invalid_input``) and ``error``. API keys travel in headers only and
  are never placed in URLs, results or logs.
* **SSRF-safe and bounded.** All traffic goes through :func:`uniphish.core.net.safe_fetch`
  (no redirects followed, 2 MB response cap). Successful and not-found answers are cached
  in-process (15 min); errors are never cached.
* **Online gating is the caller's job.** Analyzers call these only when ``ctx.online``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from uniphish.core.cache import TTLCache
from uniphish.core.config import get_settings
from uniphish.core.net import Resolver, safe_fetch

log = logging.getLogger("uniphish.intel.connectors")

__all__ = [
    "ConnectorResult",
    "GoogleSafeBrowsingClient",
    "SafeBrowsingResult",
    "UrlscanClient",
    "UrlscanHit",
    "UrlscanResult",
    "UrlscanSearch",
    "VirusTotalClient",
    "VTReport",
]

STATUSES = ("ok", "not_found", "no_key", "rate_limited", "error", "invalid_input")
MAX_RESPONSE_BYTES = 2_000_000
CACHE_TTL_S = 900.0
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
_MAX_URL = 8192


@dataclass(frozen=True, slots=True, kw_only=True)
class ConnectorResult:
    """Common envelope: ``ok`` means the service answered with usable data."""

    status: str
    error: str | None = None
    retry_after: float | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def available(self) -> bool:
        """False when no lookup could be attempted (no key / bad input)."""
        return self.status not in ("no_key", "invalid_input")


# --------------------------------------------------------------------------- #
# Shared transport
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class _Reply:
    status: str  # ok | not_found | rate_limited | error
    data: Any = None
    error: str | None = None
    retry_after: float | None = None


class _Base:
    """Key handling, cached JSON GET and error mapping shared by the clients."""

    service = "service"
    _key_attr = ""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: Resolver | None = None,
        cache_ttl: float = CACHE_TTL_S,
    ) -> None:
        self._api_key = (
            api_key if api_key is not None else getattr(get_settings(), self._key_attr, None)
        ) or None
        self.timeout = timeout
        self._transport = transport
        self._resolver = resolver
        self._cache: TTLCache = TTLCache(maxsize=1024, ttl=cache_ttl)

    @property
    def has_key(self) -> bool:
        return bool(self._api_key)

    def _no_key(self) -> str:
        return f"no {self.service} API key configured"

    async def _get(
        self, url: str, headers: dict[str, str], *, cache_key: Any = None, allow_404: bool = True
    ) -> _Reply:
        if cache_key is not None:
            hit = self._cache.get(cache_key)
            if hit is not None:
                return hit
        try:
            res = await safe_fetch(
                url,
                headers={"accept": "application/json", **headers},
                max_bytes=MAX_RESPONSE_BYTES,
                timeout=self.timeout,
                follow_redirects=False,
                transport=self._transport,
                resolver=self._resolver,
            )
        except Exception as exc:  # safe_fetch never raises; belt and braces
            return _Reply("error", error=type(exc).__name__)
        if res.blocked_reason:
            return _Reply("error", error=f"blocked: {res.blocked_reason}")
        if res.error:
            return _Reply("error", error=res.error)
        if res.status == 404 and allow_404:
            reply = _Reply("not_found")
        elif res.status == 429:
            return _Reply(
                "rate_limited", error="rate limited", retry_after=_retry_after(res.headers)
            )
        elif res.status in (401, 403):
            return _Reply("error", error=f"http {res.status} (check the {self.service} API key)")
        elif not 200 <= res.status < 300:
            return _Reply("error", error=f"http {res.status}")
        elif res.truncated:
            return _Reply("error", error="response too large")
        else:
            try:
                reply = _Reply("ok", data=json.loads(res.text()))
            except ValueError:
                return _Reply("error", error="malformed JSON response")
        if cache_key is not None:
            self._cache.set(cache_key, reply)
        return reply


def _retry_after(headers: dict[str, str]) -> float | None:
    try:
        return max(0.0, float(headers.get("retry-after", "")))
    except ValueError:
        return None


def _iso_epoch(value: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _fail(cls: type, reply: _Reply, **extra: Any) -> Any:
    return cls(status=reply.status, error=reply.error, retry_after=reply.retry_after, **extra)


# --------------------------------------------------------------------------- #
# VirusTotal (API v3)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True, kw_only=True)
class VTReport(ConnectorResult):
    """Parsed VirusTotal analysis summary for a URL, domain or file."""

    kind: str = ""  # url | domain | file
    indicator: str = ""
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int | None = None
    last_analysis: str | None = None
    categories: tuple[str, ...] = ()
    threat_label: str | None = None  # files: suggested_threat_label
    file_type: str | None = None
    permalink: str | None = None

    @property
    def engines(self) -> int:
        return self.malicious + self.suspicious + self.harmless + self.undetected

    def is_malicious(self, min_engines: int = 2) -> bool:
        return self.ok and self.malicious >= max(1, min_engines)


class VirusTotalClient(_Base):
    """VirusTotal v3 lookups: :meth:`lookup_url`, :meth:`lookup_domain`, :meth:`lookup_file`.

    These are read-only lookups of existing analyses; nothing is ever submitted.
    """

    service = "VirusTotal"
    _key_attr = "virustotal_api_key"
    base = "https://www.virustotal.com/api/v3"

    async def lookup_url(self, url: str) -> VTReport:
        u = (url or "").strip()
        try:
            parts = urlsplit(u)
            ok = parts.scheme.lower() in ("http", "https") and bool(parts.hostname)
        except ValueError:
            ok = False
        if not ok or len(u) > _MAX_URL:
            return VTReport(
                status="invalid_input", error="not an http(s) URL", kind="url", indicator=u[:200]
            )
        ident = base64.urlsafe_b64encode(u.encode("utf-8", "ignore")).decode().rstrip("=")
        gui = hashlib.sha256(u.encode("utf-8", "ignore")).hexdigest()
        return await self._lookup(
            "url", u, f"urls/{ident}", f"https://www.virustotal.com/gui/url/{gui}"
        )

    async def lookup_domain(self, domain: str) -> VTReport:
        d = (domain or "").strip().lower().rstrip(".")
        try:
            d = d.encode("idna").decode("ascii") if not d.isascii() else d
        except UnicodeError:
            d = ""
        if not d or len(d) > 253 or not _DOMAIN_RE.match(d):
            return VTReport(
                status="invalid_input",
                error="not a domain name",
                kind="domain",
                indicator=(domain or "")[:200],
            )
        return await self._lookup(
            "domain", d, f"domains/{d}", f"https://www.virustotal.com/gui/domain/{d}"
        )

    async def lookup_file(self, file_hash: str) -> VTReport:
        h = (file_hash or "").strip().lower()
        if len(h) not in _HASH_LENGTHS or not re.fullmatch(r"[0-9a-f]+", h):
            return VTReport(
                status="invalid_input",
                error="expected an MD5, SHA-1 or SHA-256 hex digest",
                kind="file",
                indicator=(file_hash or "")[:80],
            )
        return await self._lookup(
            "file", h, f"files/{h}", f"https://www.virustotal.com/gui/file/{h}"
        )

    async def _lookup(self, kind: str, indicator: str, path: str, permalink: str) -> VTReport:
        if not self.has_key:
            return VTReport(status="no_key", error=self._no_key(), kind=kind, indicator=indicator)
        reply = await self._get(
            f"{self.base}/{path}", {"x-apikey": self._api_key or ""}, cache_key=("vt", path)
        )
        if reply.status != "ok":
            return _fail(
                VTReport,
                reply,
                kind=kind,
                indicator=indicator,
                permalink=permalink if reply.status == "not_found" else None,
            )
        try:
            attrs = reply.data["data"]["attributes"]
            stats = attrs["last_analysis_stats"]
            if not isinstance(attrs, dict) or not isinstance(stats, dict):
                raise TypeError
        except (KeyError, TypeError):
            return VTReport(
                status="error",
                error="unexpected VirusTotal response shape",
                kind=kind,
                indicator=indicator,
            )
        cats = attrs.get("categories")
        cat_values = sorted({str(v)[:40] for v in cats.values()}) if isinstance(cats, dict) else []
        rep = attrs.get("reputation")
        classification = attrs.get("popular_threat_classification")
        label = (
            classification.get("suggested_threat_label")
            if isinstance(classification, dict)
            else None
        )
        ftype = attrs.get("type_description") if kind == "file" else None
        return VTReport(
            status="ok",
            kind=kind,
            indicator=indicator,
            malicious=_int(stats.get("malicious")),
            suspicious=_int(stats.get("suspicious")),
            harmless=_int(stats.get("harmless")),
            undetected=_int(stats.get("undetected")),
            reputation=int(rep)
            if isinstance(rep, (int, float)) and not isinstance(rep, bool)
            else None,
            last_analysis=_iso_epoch(attrs.get("last_analysis_date")),
            categories=tuple(cat_values[:10]),
            threat_label=str(label)[:80] if label else None,
            file_type=str(ftype)[:60] if ftype else None,
            permalink=permalink,
        )


# --------------------------------------------------------------------------- #
# urlscan.io
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class UrlscanHit:
    """One row of a urlscan.io search."""

    scan_id: str
    url: str
    domain: str
    ip: str | None
    country: str | None
    asn: str | None
    time: str | None
    report_url: str


@dataclass(frozen=True, slots=True, kw_only=True)
class UrlscanSearch(ConnectorResult):
    """Result of :meth:`UrlscanClient.search`."""

    query: str = ""
    total: int = 0
    hits: tuple[UrlscanHit, ...] = field(default_factory=tuple)
    has_more: bool = False


@dataclass(frozen=True, slots=True, kw_only=True)
class UrlscanResult(ConnectorResult):
    """Verdict summary of one finished scan (:meth:`UrlscanClient.result`)."""

    scan_id: str = ""
    url: str = ""
    domain: str = ""
    ip: str | None = None
    country: str | None = None
    asn: str | None = None
    server: str | None = None
    score: int = 0
    malicious: bool = False
    categories: tuple[str, ...] = ()
    brands: tuple[str, ...] = ()
    time: str | None = None
    report_url: str = ""
    screenshot_url: str = ""


class UrlscanClient(_Base):
    """urlscan.io search and result lookups (read-only; never submits a scan)."""

    service = "urlscan.io"
    _key_attr = "urlscan_api_key"
    base = "https://urlscan.io"

    async def search(self, query: str, *, size: int = 10) -> UrlscanSearch:
        q = (query or "").strip()
        if not q or len(q) > 1000:
            return UrlscanSearch(
                status="invalid_input", error="empty or oversized query", query=q[:200]
            )
        if not self.has_key:
            return UrlscanSearch(status="no_key", error=self._no_key(), query=q)
        size = max(1, min(int(size), 100))
        reply = await self._get(
            f"{self.base}/api/v1/search/?size={size}&q={quote(q, safe='')}",
            {"API-Key": self._api_key or ""},
            cache_key=("us-search", q, size),
            allow_404=False,
        )
        if reply.status != "ok":
            return _fail(UrlscanSearch, reply, query=q)
        data = reply.data
        rows = data.get("results") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            return UrlscanSearch(status="error", error="unexpected urlscan response shape", query=q)
        hits: list[UrlscanHit] = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            sid = str(r.get("_id") or "")
            if not _UUID_RE.match(sid):
                continue
            page = r.get("page") if isinstance(r.get("page"), dict) else {}
            task = r.get("task") if isinstance(r.get("task"), dict) else {}
            hits.append(
                UrlscanHit(
                    scan_id=sid,
                    url=str(page.get("url") or task.get("url") or "")[:2048],
                    domain=str(page.get("domain") or "")[:253],
                    ip=_opt(page.get("ip")),
                    country=_opt(page.get("country")),
                    asn=_opt(page.get("asn")),
                    time=_opt(task.get("time")),
                    report_url=f"{self.base}/result/{sid}/",
                )
            )
        return UrlscanSearch(
            status="ok",
            query=q,
            hits=tuple(hits),
            total=_int(data.get("total")) or len(hits),
            has_more=bool(data.get("has_more")),
        )

    async def search_domain(self, domain: str, *, size: int = 10) -> UrlscanSearch:
        d = (domain or "").strip().lower().rstrip(".")
        if not d or not _DOMAIN_RE.match(d):
            return UrlscanSearch(status="invalid_input", error="not a domain name", query=d[:200])
        return await self.search(f'page.domain:"{d}"', size=size)

    async def result(self, scan_id: str) -> UrlscanResult:
        sid = (scan_id or "").strip()
        if not _UUID_RE.match(sid):
            return UrlscanResult(
                status="invalid_input", error="scan id must be a UUID", scan_id=sid[:60]
            )
        if not self.has_key:
            return UrlscanResult(status="no_key", error=self._no_key(), scan_id=sid)
        reply = await self._get(
            f"{self.base}/api/v1/result/{sid}/",
            {"API-Key": self._api_key or ""},
            cache_key=("us-result", sid),
        )
        if reply.status != "ok":
            return _fail(UrlscanResult, reply, scan_id=sid)
        d = reply.data
        if not isinstance(d, dict):
            return UrlscanResult(
                status="error", error="unexpected urlscan response shape", scan_id=sid
            )
        page = d.get("page") if isinstance(d.get("page"), dict) else {}
        task = d.get("task") if isinstance(d.get("task"), dict) else {}
        verdicts = d.get("verdicts") if isinstance(d.get("verdicts"), dict) else {}
        overall = verdicts.get("overall") if isinstance(verdicts.get("overall"), dict) else {}
        cats = overall.get("categories")
        brands = overall.get("brands")
        names: list[str] = []
        for b in brands if isinstance(brands, list) else []:
            n = b.get("name") if isinstance(b, dict) else b
            if isinstance(n, str) and n:
                names.append(n[:60])
        return UrlscanResult(
            status="ok",
            scan_id=sid,
            url=str(page.get("url") or task.get("url") or "")[:2048],
            domain=str(page.get("domain") or "")[:253],
            ip=_opt(page.get("ip")),
            country=_opt(page.get("country")),
            asn=_opt(page.get("asn")),
            server=_opt(page.get("server")),
            score=_int(overall.get("score")),
            malicious=bool(overall.get("malicious")),
            categories=tuple(str(c)[:40] for c in cats[:10]) if isinstance(cats, list) else (),
            brands=tuple(dict.fromkeys(names))[:10],
            time=_opt(task.get("time")),
            report_url=f"{self.base}/result/{sid}/",
            screenshot_url=f"https://urlscan.io/screenshots/{sid}.png",
        )


def _opt(value: Any) -> str | None:
    return str(value)[:200] if value not in (None, "") else None


# --------------------------------------------------------------------------- #
# Google Safe Browsing (v5 URL search; key sent in a header)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True, kw_only=True)
class SafeBrowsingResult(ConnectorResult):
    """Safe Browsing verdict: ``threats`` empty means the URL is not currently listed."""

    url: str = ""
    threats: tuple[str, ...] = ()

    @property
    def is_unsafe(self) -> bool:
        return self.ok and bool(self.threats)


class GoogleSafeBrowsingClient(_Base):
    """Google Safe Browsing URL lookup (``urls:search``)."""

    service = "Google Safe Browsing"
    _key_attr = "safebrowsing_api_key"
    base = "https://safebrowsing.googleapis.com/v5/urls:search"

    async def lookup(self, url: str) -> SafeBrowsingResult:
        u = (url or "").strip()
        try:
            parts = urlsplit(u)
            ok = parts.scheme.lower() in ("http", "https") and bool(parts.hostname)
        except ValueError:
            ok = False
        if not ok or len(u) > 2048:
            return SafeBrowsingResult(
                status="invalid_input", error="not an http(s) URL", url=u[:200]
            )
        if not self.has_key:
            return SafeBrowsingResult(status="no_key", error=self._no_key(), url=u)
        reply = await self._get(
            f"{self.base}?urls={quote(u, safe='')}",
            {"x-goog-api-key": self._api_key or ""},
            cache_key=("gsb", u),
            allow_404=False,
        )
        if reply.status != "ok":
            return _fail(SafeBrowsingResult, reply, url=u)
        data = reply.data
        if not isinstance(data, dict):
            return SafeBrowsingResult(
                status="error", error="unexpected Safe Browsing response shape", url=u
            )
        threats: set[str] = set()
        for t in data.get("threats") or []:
            if not isinstance(t, dict):
                continue
            raw = t.get("threatTypes") or t.get("threatType") or []
            for x in [raw] if isinstance(raw, str) else raw if isinstance(raw, list) else []:
                if isinstance(x, str) and x:
                    threats.add(x[:60])
        return SafeBrowsingResult(status="ok", url=u, threats=tuple(sorted(threats)))
