"""Reputation analyzer: local allow/deny DB, top-site legitimacy, optional threat feeds.

Why this exists
---------------
Most of UniPhish judges *form* (how a URL or message is built). Reputation is the
orthogonal question of *history*: has an operator or a feed already told us this
observable is bad, or is it a very popular, long-established site? Both are cheap,
high-value evidence, and both are easy to get wrong in ways attackers exploit, so the
guard rails matter as much as the weights:

* **Local reputation DB** (:meth:`uniphish.store.Store.lookup_reputation`): an operator
  deny entry is strong positive evidence (``rep.local_denylist``); an allow entry is
  negative evidence (``rep.local_allowlist``). Deny always wins over allow. For e-mail,
  an allow entry is honoured only when the sender passed an aligned DMARC check,
  because the ``From`` header is trivially forged.
* **Top-site legitimacy** (``rep.top_site``): a registrable domain in the shipped
  Tranco top-100k earns negative evidence scaled by rank, but never for
  living-off-trusted-sites hosts (``github.io``, ``pages.dev``, ...), brand user-content
  hosts, URL shorteners, dynamic-DNS, open-redirect abuse, ``user@host`` tricks, or when
  an earlier analyzer already saw impersonation or other strong evidence. Popularity is
  not safety: a top-ranked platform that hosts anyone's content must not launder a
  phishing page.
* **Novelty** (``rep.never_seen``): a tiny contextual bump for a registrable domain the
  local store has never recorded (only once the store has enough history for that to
  mean anything).
* **Optional feeds** (Google Safe Browsing, VirusTotal, urlscan.io): only when the
  request is online *and* the corresponding API key is configured. They go through
  :func:`uniphish.core.net.safe_fetch`, are cached, never raise, never block the
  verdict, and are skipped for hosts that are not public (internal or reserved names
  are never sent to third parties).

Weights follow the build contract scale; every signal is in category ``reputation``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import quote

import httpx

from uniphish.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult, register
from uniphish.core.cache import async_cached
from uniphish.core.net import is_public_ip, safe_fetch
from uniphish.core.types import (
    Artifact,
    ArtifactKind,
    Indicator,
    IndicatorType,
    Signal,
)
from uniphish.url.parse import ParsedURL, parse_url

log = logging.getLogger("uniphish.analyzers.reputation")

CATEGORY = "reputation"

#: Default weights when a local reputation row carries ``weight == 0``.
DEFAULT_DENY_WEIGHT = 6.0
DEFAULT_ALLOW_WEIGHT = -3.0
#: Clamp for operator-supplied weights (absolute value).
MAX_DENY_WEIGHT = 8.0
MIN_ALLOW_MAGNITUDE = 0.5
MAX_ALLOW_MAGNITUDE = 6.0
#: Novelty weight (contextual only).
NOVELTY_WEIGHT = 0.3
#: Earlier-stage evidence at or above this weight suppresses the top-site credit.
STRONG_EVIDENCE_WEIGHT = 4.0

_RESERVED_SUFFIXES = (".test", ".example", ".invalid", ".localhost", ".local", ".internal",
                      ".lan", ".home.arpa", ".onion", ".corp", ".intranet")
_HOST_SAFE_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

_FEED_TTL = 3600.0
_FEED_MAX_BYTES = 5_000_000


def top_site_weight(rank: int) -> float:
    """Legitimacy weight for a Tranco *rank* (top-1k -3, top-10k -2, top-100k -1)."""
    if rank <= 1_000:
        return -3.0
    if rank <= 10_000:
        return -2.0
    return -1.0


# --------------------------------------------------------------------------- #
# Optional feeds (module level so they can be cached and single-flighted)
# --------------------------------------------------------------------------- #
class FeedError(Exception):
    """A feed lookup failed operationally (never cached, never surfaced as a signal)."""


@dataclass(frozen=True)
class FeedHit:
    """Normalised result of one feed lookup (``malicious_weight`` 0 = nothing found)."""

    feed: str
    weight: float
    detail: str
    evidence: dict[str, Any]


def _json_body(res: Any) -> Any:
    try:
        return json.loads(res.text())
    except (ValueError, TypeError) as exc:
        raise FeedError("bad json") from exc


async def _get_json(url: str, headers: dict[str, str], timeout: float,
                    transport: httpx.AsyncBaseTransport | None,
                    *, allow_404: bool = False) -> Any | None:
    res = await safe_fetch(url, headers=headers, max_bytes=_FEED_MAX_BYTES, timeout=timeout,
                           follow_redirects=False, transport=transport)
    if allow_404 and res.status == 404 and not res.blocked_reason:
        return None
    if not res.ok or res.truncated:
        raise FeedError(res.blocked_reason or res.error or f"http {res.status}")
    return _json_body(res)


_GSB_WEIGHTS = {
    "SOCIAL_ENGINEERING": 6.0, "MALWARE": 6.0, "THREAT_TYPE_UNSPECIFIED": 4.0,
    "UNWANTED_SOFTWARE": 3.0, "POTENTIALLY_HARMFUL_APPLICATION": 4.0,
}


@async_cached(ttl=_FEED_TTL, maxsize=2048, key=lambda url, *_: url)
async def _safebrowsing(url: str, api_key: str, timeout: float,
                        transport: httpx.AsyncBaseTransport | None) -> FeedHit | None:
    data = await _get_json(
        "https://safebrowsing.googleapis.com/v5/urls:search?urls=" + quote(url, safe=""),
        {"x-goog-api-key": api_key, "accept": "application/json"}, timeout, transport)
    threats = data.get("threats") if isinstance(data, dict) else None
    if not isinstance(threats, list) or not threats:
        return None
    types: list[str] = []
    for t in threats:
        if not isinstance(t, dict):
            continue
        raw = t.get("threatTypes") or t.get("threatType") or []
        types.extend(str(x) for x in ([raw] if isinstance(raw, str) else raw))
    if not types:
        return None
    weight = max(_GSB_WEIGHTS.get(t, 4.0) for t in types)
    uniq = sorted(set(types))
    return FeedHit("safebrowsing", weight,
                   "Google Safe Browsing lists this URL as " + ", ".join(uniq).lower() + ".",
                   {"threat_types": uniq})


def _vt_weight(malicious: int, suspicious: int) -> float:
    if malicious >= 5:
        return 6.0
    if malicious >= 2:
        return 3.5
    if malicious == 1:
        return 1.5
    return 0.8 if suspicious >= 3 else 0.0


@async_cached(ttl=_FEED_TTL, maxsize=2048, key=lambda kind, value, *_: (kind, value))
async def _virustotal(kind: str, value: str, api_key: str, timeout: float,
                      transport: httpx.AsyncBaseTransport | None) -> FeedHit | None:
    path = "ip_addresses" if kind == "ip" else "domains"
    data = await _get_json(f"https://www.virustotal.com/api/v3/{path}/{quote(value, safe='')}",
                           {"x-apikey": api_key, "accept": "application/json"}, timeout,
                           transport, allow_404=True)
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
    weight = _vt_weight(mal, sus)
    if weight <= 0:
        return None
    return FeedHit("virustotal", weight,
                   f"{mal} VirusTotal engine(s) flag {value} as malicious and {sus} as suspicious.",
                   {"malicious": mal, "suspicious": sus})


@async_cached(ttl=_FEED_TTL, maxsize=2048, key=lambda host, *_: host)
async def _urlscan(host: str, api_key: str, timeout: float,
                   transport: httpx.AsyncBaseTransport | None) -> FeedHit | None:
    headers = {"API-Key": api_key, "accept": "application/json"}
    q = quote(f'page.domain:"{host}"', safe="")
    found = await _get_json(f"https://urlscan.io/api/v1/search/?size=1&q={q}", headers,
                            timeout, transport)
    results = found.get("results") if isinstance(found, dict) else None
    if not isinstance(results, list) or not results or not isinstance(results[0], dict):
        return None
    scan_id = str(results[0].get("_id") or "")
    if not _UUID_RE.match(scan_id):
        return None
    detail = await _get_json(f"https://urlscan.io/api/v1/result/{scan_id}/", headers, timeout,
                             transport)
    try:
        overall = detail["verdicts"]["overall"]
        malicious, score = bool(overall.get("malicious")), int(overall.get("score") or 0)
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
    weight = 5.0 if malicious else (2.5 if score >= 50 else 0.0)
    if weight <= 0:
        return None
    return FeedHit("urlscan", weight,
                   f"urlscan.io's most recent scan of {host} was judged "
                   f"{'malicious' if malicious else 'suspicious'} (score {score}).",
                   {"scan_id": scan_id, "score": score, "malicious": malicious})


_FEED_META = {
    "safebrowsing": ("rep.safebrowsing", "Google Safe Browsing lists this URL as unsafe"),
    "virustotal": ("rep.virustotal", "VirusTotal engines flag this domain"),
    "urlscan": ("rep.urlscan", "urlscan.io judged this host malicious"),
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _registrable(p: ParsedURL) -> str:
    """Registrable domain (ASCII). For TLDs absent from the PSL (``.test``, ``.example``)
    fall back to the last two labels so reserved/lab domains still group sensibly."""
    if p.is_ip or not p.host_ascii:
        return ""
    if p.suffix:
        return p.registrable_ascii
    labels = p.host_ascii.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else p.host_ascii


def _is_reserved(host: str) -> bool:
    return "." not in host or host.endswith(_RESERVED_SUFFIXES)


def _publicly_checkable(p: ParsedURL) -> bool:
    """True when sending this host to a third-party feed would not leak private names."""
    if not p.valid or p.scheme not in ("http", "https"):
        return False
    if p.is_ip:
        return p.ip is not None and is_public_ip(p.ip)
    return bool(_registrable(p)) and not _is_reserved(p.host_ascii) \
        and _HOST_SAFE_RE.match(p.host_ascii) is not None


def _ancestors(p: ParsedURL) -> list[str]:
    """Host and its parents down to (not above) the registrable domain."""
    host = p.host_ascii
    reg = _registrable(p) or host
    out = [host]
    while host != reg and "." in host:
        host = host.split(".", 1)[1]
        out.append(host)
        if len(out) > 12:
            break
    return out


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def _impersonation_seen(ctx: AnalysisContext) -> bool:
    """True when an earlier analyzer flagged impersonation or other strong evidence."""
    brand = ctx.brand()
    if brand is not None and not brand.official and brand.confidence >= 0.3:
        return True
    for res in ctx.results.values():
        for s in res.signals:
            if s.weight <= 0:
                continue
            if s.category in ("brand", "unicode") or s.id.startswith(("brand.", "unicode.")) \
                    or ".brand." in s.id:
                return True
            if s.weight >= STRONG_EVIDENCE_WEIGHT:
                return True
    return False


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #
@register
class ReputationAnalyzer(Analyzer):
    """Local allow/deny, top-site legitimacy, novelty and optional external feeds."""

    name = "reputation"
    kinds = frozenset({ArtifactKind.URL, ArtifactKind.EMAIL})
    stage = 10
    requires_online = False   # offline core always runs; feeds are gated on ctx.online + keys
    blocking = True
    description = ("Local IOC allow/deny DB, Tranco top-site legitimacy (never for LOTS hosts), "
                   "domain novelty, and optional Safe Browsing / VirusTotal / urlscan.io lookups")
    signals = {
        "rep.local_denylist": "Observable is on the local deny list",
        "rep.local_allowlist": "Observable is on the local allow list",
        "rep.top_site": "Domain is a long-established, highly ranked site",
        "rep.never_seen": "Domain has never been seen before by this installation",
        "rep.safebrowsing": "Google Safe Browsing lists this URL as unsafe",
        "rep.virustotal": "VirusTotal engines flag this domain",
        "rep.urlscan": "urlscan.io judged this host malicious",
    }

    #: Verdicts the store must hold before "never seen" carries any meaning.
    novelty_min_history: ClassVar[int] = 25

    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport

    # ---- store access ---------------------------------------------------- #
    @staticmethod
    def _store() -> Any:
        from uniphish.store import get_store
        return get_store()

    def _lookup(self, type_: str, value: str) -> dict[str, Any] | None:
        try:
            return self._store().lookup_reputation(type_, value)
        except Exception:   # a broken DB must never break analysis
            log.warning("reputation lookup failed", exc_info=True)
            return None

    # ---- signal builders ------------------------------------------------- #
    @staticmethod
    def _local_signal(row: dict[str, Any], type_: str, value: str, role: str) -> Signal:
        raw = abs(float(row.get("weight") or 0.0))
        reason = str(row.get("reason") or "").strip()
        source = str(row.get("source") or "manual")
        evidence = {"type": type_, "value": value, "source": source, "reason": reason,
                    "expires_at": row.get("expires_at")}
        suffix = f" Reason: {reason}." if reason else ""
        if row.get("verdict") == "deny":
            w = _clamp(raw or DEFAULT_DENY_WEIGHT, 0.5, MAX_DENY_WEIGHT)
            return Signal(
                id="rep.local_denylist", category=CATEGORY, weight=w, evidence=evidence,
                title=f"{type_.capitalize()} is on the local deny list",
                detail=f"{value} is on this installation's deny list (source: {source}).{suffix}",
                mitre=["T1566.002"] if type_ in ("url", "domain") else [], tags=[role])
        w = -_clamp(raw or -DEFAULT_ALLOW_WEIGHT, MIN_ALLOW_MAGNITUDE, MAX_ALLOW_MAGNITUDE)
        return Signal(
            id="rep.local_allowlist", category=CATEGORY, weight=w, evidence=evidence,
            title=f"{type_.capitalize()} is on the local allow list",
            detail=f"{value} is on this installation's allow list (source: {source}).{suffix}",
            tags=[role])

    @staticmethod
    def _indicator_type(type_: str) -> IndicatorType:
        return {"url": IndicatorType.URL, "domain": IndicatorType.DOMAIN,
                "email": IndicatorType.EMAIL, "ipv4": IndicatorType.IPV4,
                "ipv6": IndicatorType.IPV6}[type_]

    def _apply_rows(self, rows: list[tuple[str, str, dict[str, Any]]], role: str,
                    result: AnalyzerResult, *, allow_ok: bool = True) -> tuple[bool, bool]:
        """Turn matched rows into at most one deny and one allow signal; deny wins."""
        deny = [r for r in rows if r[2].get("verdict") == "deny"]
        allow = [r for r in rows if r[2].get("verdict") == "allow"]
        if deny:
            # Strongest (then most specific = first) deny entry carries the signal.
            t, v, row = max(deny, key=lambda r: abs(float(r[2].get("weight") or 0.0)))
            result.signals.append(self._local_signal(row, t, v, role))
            for t, v, row in deny:
                result.indicators.append(Indicator(
                    type=self._indicator_type(t), value=v, role=role, malicious=True,
                    context=str(row.get("reason") or "local deny list") or None))
            return True, False
        if allow and allow_ok:
            t, v, row = allow[0]
            result.signals.append(self._local_signal(row, t, v, role))
            return False, True
        return False, False

    # ---- offline analysis ------------------------------------------------ #
    def analyze_sync(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        result = AnalyzerResult()
        try:
            if artifact.kind is ArtifactKind.URL:
                self._analyze_url(artifact, ctx, result)
            elif artifact.kind is ArtifactKind.EMAIL:
                self._analyze_email(artifact, ctx, result)
        except Exception:
            log.warning("reputation analysis failed", exc_info=True)
        return result

    def _analyze_url(self, artifact: Artifact, ctx: AnalysisContext,
                     result: AnalyzerResult) -> None:
        p = parse_url(artifact.url or "")
        if not p.valid or not p.host:
            return
        rows: list[tuple[str, str, dict[str, Any]]] = []
        lookups: list[tuple[str, str]] = [("url", p.url)]
        if p.is_ip and p.ip is not None:
            lookups.append(("ipv6" if p.ip.version == 6 else "ipv4", str(p.ip)))
        else:
            lookups.extend(("domain", h) for h in _ancestors(p))
        for t, v in dict.fromkeys(lookups):
            row = self._lookup(t, v)
            if row:
                rows.append((t, v, row))
        denied, allowed = self._apply_rows(rows, "landing", result)

        top = False
        if not denied and not allowed:
            top = self._top_site(p, ctx, result)
        if not denied and not allowed and not top:
            self._novelty(p, result)
        if _registrable(p) and not p.is_ip:
            result.indicators.append(Indicator(type=IndicatorType.DOMAIN, value=_registrable(p),
                                               role="landing"))

    def _top_site(self, p: ParsedURL, ctx: AnalysisContext, result: AnalyzerResult) -> bool:
        from uniphish.assets.lists import (
            is_dyndns,
            is_shortener,
            lots_match,
            open_redirect_match,
            top_rank,
        )
        from uniphish.url.brandkb import get_kb

        if p.is_ip or p.scheme not in ("http", "https") or p.has_userinfo:
            return False
        reg = _registrable(p)
        rank = top_rank(reg) if reg else None
        if rank is None:
            return False
        host = p.host_ascii
        if (lots_match(host, p.path) or lots_match(reg, p.path)
                or get_kb().is_user_content_host(host) is not None
                or is_shortener(host) or is_dyndns(host)
                or open_redirect_match(host, p.path, p.query) is not None):
            return False
        if _impersonation_seen(ctx):
            return False
        weight = top_site_weight(rank)
        result.signals.append(Signal(
            id="rep.top_site", category=CATEGORY, weight=weight,
            title=f"{reg} is a top-ranked, long-established site",
            detail=(f"{reg} ranks #{rank:,} among the most visited sites and is not a "
                    "free-hosting platform, so a lookalike attack is unlikely on this exact "
                    "domain."),
            evidence={"registrable": reg, "rank": rank}, confidence=0.9))
        return True

    def _novelty(self, p: ParsedURL, result: AnalyzerResult) -> None:
        reg = _registrable(p)
        if p.is_ip or not reg:
            return
        try:
            store = self._store()
            need = self.novelty_min_history
            if len(store.recent_verdicts(limit=need)) < need:
                return
            if store.search_indicator("domain", reg) or store.find_verdicts("url", p.url, limit=1):
                return
        except Exception:
            log.warning("novelty lookup failed", exc_info=True)
            return
        result.signals.append(Signal(
            id="rep.never_seen", category=CATEGORY, weight=NOVELTY_WEIGHT,
            title="Domain never seen before by this installation",
            detail=f"{reg} has not appeared in any earlier analysis on this system. This is "
                   "only weak context: most new domains are harmless.",
            evidence={"registrable": reg}, confidence=0.6))

    def _analyze_email(self, artifact: Artifact, ctx: AnalysisContext,
                       result: AnalyzerResult) -> None:
        from uniphish.mail import MEMO_KEY, analyze_auth, parse_email

        parsed = ctx.memo(MEMO_KEY, lambda: parse_email(artifact.content or b""))
        auth = analyze_auth(parsed)
        sender = parsed.from_
        lookups: list[tuple[str, str]] = []
        if sender and sender.addr:
            lookups.append(("email", sender.addr))
            lookups.append(("domain", sender.domain))
        # reply_to is a list[Address]; return_path is a raw address string.
        for addr in parsed.reply_to:
            if addr and addr.domain:
                lookups.append(("domain", addr.domain))
        if parsed.return_path and "@" in parsed.return_path:
            rp_domain = parsed.return_path.rsplit("@", 1)[-1].strip("<> ").lower()
            if rp_domain:
                lookups.append(("domain", rp_domain))
        ip = auth.spf.client_ip
        if ip and is_public_ip(ip):
            lookups.append(("ipv6" if ":" in ip else "ipv4", ip))
        rows: list[tuple[str, str, dict[str, Any]]] = []
        for t, v in dict.fromkeys(lookups):
            row = self._lookup(t, v)
            if row:
                rows.append((t, v, row))
        # An allow entry is only trusted when the sender actually authenticated (From is
        # trivially forged); deny entries always apply.
        if not auth.dmarc_aligned:
            if any(r[2].get("verdict") == "allow" for r in rows):
                result.meta["reputation_allow_ignored"] = "sender not DMARC-authenticated"
            rows = [r for r in rows if r[2].get("verdict") != "allow"]
        self._apply_rows(rows, "sender", result)

    # ---- online feeds ---------------------------------------------------- #
    async def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        result = await asyncio.to_thread(self.analyze_sync, artifact, ctx)
        if artifact.kind is ArtifactKind.URL and ctx.online:
            try:
                await self._feeds(artifact, ctx, result)
            except Exception:   # feeds are best-effort by contract
                log.warning("reputation feeds failed", exc_info=True)
        return result

    async def _feeds(self, artifact: Artifact, ctx: AnalysisContext,
                     result: AnalyzerResult) -> None:
        s = ctx.settings
        if not (s.safebrowsing_api_key or s.virustotal_api_key or s.urlscan_api_key):
            return
        p = parse_url(artifact.url or "")
        if not _publicly_checkable(p):
            return
        clean = p.url   # normalised: no userinfo, no fragment -> nothing private leaves
        t, tr = s.http_timeout_s, self._transport
        jobs: list[Any] = []
        if s.safebrowsing_api_key:
            jobs.append(_safebrowsing(clean, s.safebrowsing_api_key, t, tr))
        if s.virustotal_api_key:
            kind, value = ("ip", str(p.ip)) if p.is_ip else ("domain", _registrable(p))
            jobs.append(_virustotal(kind, value, s.virustotal_api_key, t, tr))
        if s.urlscan_api_key and not p.is_ip:
            jobs.append(_urlscan(p.host_ascii, s.urlscan_api_key, t, tr))
        for out in await asyncio.gather(*jobs, return_exceptions=True):
            if isinstance(out, BaseException):
                log.debug("reputation feed unavailable: %s", type(out).__name__)
                continue
            if out is None:
                continue
            sid, title = _FEED_META[out.feed]
            result.signals.append(Signal(
                id=sid, title=title, detail=out.detail, weight=out.weight, category=CATEGORY,
                evidence={"feed": out.feed, **out.evidence}, mitre=["T1566.002"],
                confidence=0.9))
            if out.weight >= 3.0:
                result.indicators.append(Indicator(
                    type=IndicatorType.IPV6 if (p.is_ip and p.ip and p.ip.version == 6)
                    else IndicatorType.IPV4 if p.is_ip else IndicatorType.DOMAIN,
                    value=str(p.ip) if p.is_ip else _registrable(p), role="landing",
                    malicious=True, context=f"flagged by {out.feed}"))
