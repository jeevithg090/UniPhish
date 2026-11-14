"""Outbound verdict sinks: where UniPhish sends what it finds.

A *sink* receives a finished :class:`~uniphish.core.types.Verdict` and forwards it to the
place a SOC actually looks: a webhook, a Slack channel, Splunk HEC, Elasticsearch, the
local store, a JSONL file or the terminal.  :func:`fan_out` delivers one verdict to many
sinks concurrently, honours each sink's ``min_level`` and isolates failures so one broken
destination never blocks the others (or the analysis pipeline).

Security properties (this module talks to operator-configured URLs while handling
attacker-controlled text, so both directions matter):

* **SSRF-guarded.** Every HTTP sink sends through :func:`uniphish.core.net.safe_fetch`,
  which resolves and validates every hop and pins the connection to the validated IP. A
  sink URL that points at loopback, link-local, RFC 1918 space or cloud metadata is refused
  (``blocked``), and redirects are never followed. On-prem SIEMs on private addresses must
  be opted in explicitly per sink with ``allow_private=True``.
* **TLS required by default.** Webhook secrets, Splunk tokens and Elastic API keys travel in
  headers, so plain ``http://`` URLs are rejected unless ``allow_insecure_http=True``.
  Credentials embedded in the URL (``user:pass@host``) are refused outright.
* **Defanged output.** Verdict text is attacker-influenced (subjects, URLs, signal details).
  Human-facing sinks (Slack, stdout) and the JSON sinks (webhook, file) defang it by default:
  ``hxxps://login[.]example[.]test``. SIEM sinks keep the structured IOC fields of the ECS
  document machine-actionable (that is their purpose) but defang its free-text fields.
* **No secret leakage.** Tokens, API keys, HMAC secrets and secret-bearing webhook URLs are
  never logged, never put in ``repr()`` and are scrubbed from every error message.

``min_level`` filtering is applied by :func:`fan_out`; calling ``sink.send`` directly always
sends.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import sys
import threading
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TextIO, runtime_checkable
from urllib.parse import quote, urlsplit

import httpx

from uniphish.ai.prompts import defang
from uniphish.core.net import DEFAULT_ALLOWED_PORTS, Resolver, safe_fetch
from uniphish.core.types import Level, Verdict

log = logging.getLogger("uniphish.integrations")

__all__ = [
    "BaseSink",
    "ElasticSink",
    "FileSink",
    "Sink",
    "SinkError",
    "SinkResult",
    "SlackSink",
    "SplunkHECSink",
    "StdoutSink",
    "StoreSink",
    "WebhookSink",
    "coerce_level",
    "fan_out",
    "slack_payload",
]

LEVEL_RANK: dict[Level, int] = {Level.BENIGN: 0, Level.SUSPICIOUS: 1, Level.MALICIOUS: 2}
_DEFANG_LIMIT = 4_000
_MAX_RESPONSE_BYTES = 64_000
_DEFAULT_TIMEOUT_S = 10.0
_RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
# Keys whose string values are identifiers/enums, never free text: leave them untouched
# (outside evidence/meta/context subtrees, which are defanged in full).
_RAW_KEYS = frozenset(
    {
        "id",
        "artifact_id",
        "parent_id",
        "engine_version",
        "created_at",
        "kind",
        "level",
        "action",
        "severity",
        "category",
        "analyzer",
        "status",
        "type",
        "role",
        "framework",
        "tactic",
        "technique",
        "techniques",
        "mitre",
        "tags",
        "origin",
        "url",
    }
)
_FREE_TREES = frozenset({"evidence", "meta", "context"})


class SinkError(RuntimeError):
    """A sink failed to deliver (message is already scrubbed of secrets)."""


def coerce_level(value: Level | str) -> Level:
    """Accept a :class:`Level` or its (case-insensitive) name."""
    if isinstance(value, Level):
        return value
    try:
        return Level(str(value).strip().lower())
    except ValueError:
        raise ValueError(
            f"unknown level {value!r}; expected one of {', '.join(lv.value for lv in Level)}"
        ) from None


@runtime_checkable
class Sink(Protocol):
    """Anything that can receive a verdict."""

    name: str
    min_level: Level

    async def send(self, verdict: Verdict) -> None:
        """Deliver ``verdict``; raise on failure (:func:`fan_out` isolates it)."""


@dataclass(frozen=True)
class SinkResult:
    """Outcome of delivering one verdict to one sink."""

    sink: str
    status: str  # "sent" | "skipped" | "failed"
    error: str | None = None
    elapsed_ms: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status != "failed"


# --------------------------------------------------------------------------- #
# Defanging helpers
# --------------------------------------------------------------------------- #
def _defang_tree(obj: Any, *, free: bool = False, key: str | None = None) -> Any:
    """Defang every free-text string in a JSON-like tree, preserving identifiers."""
    if isinstance(obj, str):
        if not free and key in _RAW_KEYS:
            return obj
        return defang(obj, _DEFANG_LIMIT)
    if isinstance(obj, Mapping):
        return {
            k: _defang_tree(v, free=free or k in _FREE_TREES, key=str(k)) for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [_defang_tree(v, free=free, key=key) for v in obj]
    return obj


def verdict_json(verdict: Verdict, *, defanged: bool = True) -> dict[str, Any]:
    """The verdict as a JSON-safe dict, defanged unless ``defanged`` is False."""
    data = verdict.model_dump(mode="json")
    return _defang_tree(data) if defanged else data


def _mrkdwn(text: str, limit: int = 300) -> str:
    """Defang and escape text for Slack ``mrkdwn`` (no links, mentions or markup)."""
    s = defang(text, limit)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_payload(verdict: Verdict) -> dict[str, Any]:
    """Build the Slack Block Kit message for ``verdict`` (all text defanged/escaped)."""
    emoji = {
        Level.MALICIOUS: ":rotating_light:",
        Level.SUSPICIOUS: ":warning:",
        Level.BENIGN: ":white_check_mark:",
    }[verdict.level]
    title = f"UniPhish: {verdict.level.value.upper()} ({verdict.score}/100)"
    target = _mrkdwn(verdict.target, 200)
    summary = _mrkdwn(verdict.summary, 600) if verdict.summary else "No summary."
    fields = [
        {"type": "mrkdwn", "text": f"*Kind*\n{verdict.kind.value}"},
        {"type": "mrkdwn", "text": f"*Action*\n{verdict.action.value}"},
    ]
    if verdict.brand is not None and not verdict.brand.official:
        fields.append(
            {"type": "mrkdwn", "text": f"*Impersonates*\n{_mrkdwn(verdict.brand.name, 80)}"}
        )
    if verdict.techniques:
        fields.append(
            {
                "type": "mrkdwn",
                "text": "*Techniques*\n"
                + ", ".join(_mrkdwn(t, 40) for t in verdict.techniques[:5]),
            }
        )
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": title[:150]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"`{target}`\n{summary}"[:2900]}},
        {"type": "section", "fields": fields[:10]},
    ]
    sigs = verdict.top_signals(5)
    if sigs:
        lines = []
        for s in sigs:
            weight = s.contribution if s.contribution is not None else s.weight
            lines.append(f"- {_mrkdwn(s.title, 90)} ({weight:+.1f})")
        text = ("*Top signals*\n" + "\n".join(lines))[:2900]
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text}})
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"verdict `{verdict.id}` | engine {verdict.engine_version}",
                }
            ],
        }
    )
    return {"text": f"{emoji} {title} - {target}"[:3000], "blocks": blocks}


def _ecs_doc(verdict: Verdict) -> dict[str, Any]:
    """ECS document with free-text fields defanged (structured IOC fields stay raw)."""
    from uniphish.export.ecs import to_ecs

    doc = to_ecs(verdict, allow_benign=True)
    for path in (("message",), ("event", "reason"), ("rule", "description")):
        node: Any = doc
        for part in path[:-1]:
            node = node.get(part) if isinstance(node, dict) else None
        if isinstance(node, dict) and isinstance(node.get(path[-1]), str):
            node[path[-1]] = defang(node[path[-1]], _DEFANG_LIMIT)
    return doc


# --------------------------------------------------------------------------- #
# Base classes
# --------------------------------------------------------------------------- #
class BaseSink:
    """Common behaviour: name, ``min_level`` gate, secret scrubbing, safe ``repr``."""

    default_min_level: Level = Level.SUSPICIOUS

    def __init__(
        self,
        *,
        min_level: Level | str | None = None,
        name: str | None = None,
        secrets: Iterable[str | None] = (),
    ) -> None:
        self.min_level: Level = (
            coerce_level(min_level) if min_level is not None else self.default_min_level
        )
        self.name: str = name or type(self).__name__
        self._secrets: tuple[str, ...] = tuple(
            sorted({s for s in secrets if s and len(s) >= 4}, key=len, reverse=True)
        )

    def accepts(self, verdict: Verdict) -> bool:
        """True if ``verdict`` is at or above this sink's ``min_level``."""
        return LEVEL_RANK[verdict.level] >= LEVEL_RANK[self.min_level]

    def scrub(self, text: object) -> str:
        """Remove configured secrets from ``text`` (used for every error/log message)."""
        out = str(text)
        for secret in self._secrets:
            out = out.replace(secret, "***")
        return out

    async def send(self, verdict: Verdict) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def _describe(self) -> str:
        return ""

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._describe()}min_level={self.min_level.value})"


def _header_secrets(headers: Mapping[str, str]) -> list[str]:
    """Header values plus their credential part (``Bearer abc`` -> ``abc``)."""
    out: list[str] = []
    for value in headers.values():
        out.append(value)
        if value.split():
            out.append(value.split()[-1])
    return out


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc.rsplit('@', 1)[-1]}"


class _BodyTransport(httpx.AsyncBaseTransport):
    """Attach a request body to the bodyless request :func:`safe_fetch` builds.

    ``safe_fetch`` performs all SSRF validation and IP pinning but only issues bodyless
    requests; this thin wrapper (its documented ``transport`` injection point) adds the
    payload just before the bytes go out, so the guard stays in one place. The wrapped
    transport receives the already-pinned URL, ``Host`` header and SNI extension.
    """

    def __init__(self, body: bytes, inner: httpx.AsyncBaseTransport | None) -> None:
        self._body = body
        self._inner = inner if inner is not None else httpx.AsyncHTTPTransport(verify=True)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        headers = [
            (k, v)
            for k, v in request.headers.multi_items()
            if k.lower() not in ("content-length", "transfer-encoding")
        ]
        framed = httpx.Request(
            request.method,
            request.url,
            headers=headers,
            content=self._body,
            extensions=request.extensions,
        )
        return await self._inner.handle_async_request(framed)

    async def aclose(self) -> None:
        await self._inner.aclose()


class _HttpSink(BaseSink):
    """Shared SSRF-guarded HTTP delivery with bounded retries."""

    def __init__(
        self,
        url: str,
        *,
        min_level: Level | str | None = None,
        name: str | None = None,
        headers: Mapping[str, str] | None = None,
        secrets: Iterable[str | None] = (),
        timeout: float = _DEFAULT_TIMEOUT_S,
        retries: int = 2,
        backoff_s: float = 0.5,
        allow_private: bool = False,
        allow_insecure_http: bool = False,
        allowed_ports: Iterable[int] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        extra_headers = dict(headers or {})
        parts = urlsplit(url)
        super().__init__(
            min_level=min_level,
            name=name,
            secrets=[
                url,
                parts.path.strip("/") if len(parts.path) > 8 else None,
                parts.query,
                *secrets,
                *_header_secrets(extra_headers),
            ],
        )
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise ValueError("sink url must be an absolute http(s) URL")
        if parts.username or parts.password:
            raise ValueError("credentials in the sink URL are not allowed; use headers")
        if parts.scheme == "http" and not allow_insecure_http:
            raise ValueError(
                "plain http:// sink URLs are refused (secrets would travel in "
                "clear text); use https or pass allow_insecure_http=True"
            )
        self.url = url
        self._origin = _origin_of(url)
        self._headers = extra_headers
        self._timeout = float(timeout)
        self._retries = max(0, int(retries))
        self._backoff_s = max(0.0, float(backoff_s))
        self._allow_private = bool(allow_private)
        self._allowed_ports = (
            frozenset(allowed_ports) if allowed_ports is not None else DEFAULT_ALLOWED_PORTS
        )
        self._transport = transport
        self._resolver = resolver

    def _describe(self) -> str:
        return f"{self._origin}/..., "

    async def _post(
        self,
        body: bytes,
        *,
        url: str | None = None,
        method: str = "POST",
        extra_headers: Mapping[str, str] | None = None,
        ok_statuses: frozenset[int] = frozenset(),
    ) -> bytes:
        """Send ``body`` and return the response body; raise :class:`SinkError` on failure."""
        target = url or self.url
        headers = {"content-type": "application/json", **self._headers, **(extra_headers or {})}
        last = "unknown error"
        for attempt in range(self._retries + 1):
            result = await safe_fetch(
                target,
                method=method,
                headers=headers,
                max_bytes=_MAX_RESPONSE_BYTES,
                timeout=self._timeout,
                follow_redirects=False,
                allowed_ports=self._allowed_ports,
                allow_private=self._allow_private,
                transport=_BodyTransport(body, self._transport),
                resolver=self._resolver,
            )
            if result.blocked_reason:  # security refusal: never retried
                raise SinkError(
                    f"{self.name}: destination blocked: {self.scrub(result.blocked_reason)}"
                )
            if result.error is None and (
                200 <= result.status < 300 or result.status in ok_statuses
            ):
                return result.body
            retryable = result.error is not None or result.status in _RETRY_STATUSES
            last = self.scrub(result.error) if result.error is not None else f"HTTP {result.status}"
            if not retryable or attempt >= self._retries:
                break
            await asyncio.sleep(self._backoff_s * (2**attempt))
        raise SinkError(f"{self.name}: delivery to {self._origin} failed: {last}")


# --------------------------------------------------------------------------- #
# Network sinks
# --------------------------------------------------------------------------- #
class WebhookSink(_HttpSink):
    """POST the verdict as JSON to a webhook (SSRF-guarded via ``safe_fetch``).

    Args:
        url: destination (https unless ``allow_insecure_http``).
        min_level: minimum verdict level to deliver (default ``suspicious``).
        secret: optional HMAC key; adds ``X-UniPhish-Signature: sha256=<hex>`` over the body.
        headers: extra request headers (e.g. ``Authorization``); values are scrubbed from errors.
        defang: defang free-text and URLs in the JSON (default True). Set False only for
            trusted machine consumers that need raw IOCs.
        max_payload_bytes: oversized payloads drop child verdicts (``children_omitted``).
    """

    def __init__(
        self,
        url: str,
        *,
        min_level: Level | str | None = None,
        secret: str | None = None,
        defang: bool = True,
        max_payload_bytes: int = 2_000_000,
        **kwargs: Any,
    ) -> None:
        super().__init__(url, min_level=min_level, secrets=[secret], **kwargs)
        self._secret = secret.encode() if secret else None
        self._defang = defang
        self._max_payload = int(max_payload_bytes)

    def _body(self, verdict: Verdict) -> bytes:
        data = verdict_json(verdict, defanged=self._defang)
        raw = json.dumps(data, ensure_ascii=True, separators=(",", ":")).encode()
        if len(raw) > self._max_payload and data.get("children"):
            data["children_omitted"] = len(data["children"])
            data["children"] = []
            raw = json.dumps(data, ensure_ascii=True, separators=(",", ":")).encode()
        return raw

    async def send(self, verdict: Verdict) -> None:
        body = self._body(verdict)
        extra = {"x-uniphish-event": "verdict"}
        if self._secret:
            digest = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
            extra["x-uniphish-signature"] = f"sha256={digest}"
        await self._post(body, extra_headers=extra)


class SlackSink(_HttpSink):
    """Post a formatted, defanged message to a Slack (or compatible) incoming webhook.

    The webhook URL *is* the credential, so it is never logged or shown in ``repr``.
    """

    def __init__(
        self, webhook_url: str, *, min_level: Level | str | None = None, **kwargs: Any
    ) -> None:
        super().__init__(webhook_url, min_level=min_level, **kwargs)

    def _describe(self) -> str:
        return f"{self._origin}/<redacted>, "

    async def send(self, verdict: Verdict) -> None:
        body = json.dumps(slack_payload(verdict), ensure_ascii=True).encode()
        await self._post(body)


class SplunkHECSink(_HttpSink):
    """Send ECS documents to a Splunk HTTP Event Collector.

    ``url`` may be the base URL (``https://splunk.example:8088``); the standard
    ``/services/collector/event`` path is appended when none is given. HEC's default port
    8088 is allowed automatically.
    """

    def __init__(
        self,
        url: str,
        token: str,
        *,
        index: str | None = None,
        sourcetype: str = "uniphish:verdict",
        source: str = "uniphish",
        host: str | None = None,
        min_level: Level | str | None = None,
        allowed_ports: Iterable[int] | None = None,
        **kwargs: Any,
    ) -> None:
        if not token:
            raise ValueError("a Splunk HEC token is required")
        parts = urlsplit(url)
        if parts.path in ("", "/"):
            url = f"{parts.scheme}://{parts.netloc}/services/collector/event"
        ports = (
            frozenset(allowed_ports)
            if allowed_ports is not None
            else DEFAULT_ALLOWED_PORTS | {8088}
        )
        super().__init__(
            url,
            min_level=min_level,
            secrets=[token],
            headers={"authorization": f"Splunk {token}"},
            allowed_ports=ports,
            **kwargs,
        )
        self._index, self._sourcetype, self._source, self._host = index, sourcetype, source, host

    async def send(self, verdict: Verdict) -> None:
        event: dict[str, Any] = {
            "time": round(verdict.created_at.timestamp(), 3),
            "source": self._source,
            "sourcetype": self._sourcetype,
            "event": _ecs_doc(verdict),
        }
        if self._index:
            event["index"] = self._index
        if self._host:
            event["host"] = self._host
        raw = await self._post(json.dumps(event, ensure_ascii=True).encode())
        try:  # HEC answers 200 with {"code": 0} on success, {"code": N} on app errors
            code = json.loads(raw.decode("utf-8", "replace")).get("code", 0)
        except (ValueError, AttributeError):
            return
        if code not in (0, None):
            raise SinkError(f"{self.name}: Splunk HEC rejected the event (code {code})")


_BAD_INDEX_CHARS = frozenset('/\\*?"<>|, #:')


class ElasticSink(_HttpSink):
    """Index ECS documents into Elasticsearch (or an ECS-compatible data stream).

    Uses ``PUT /<index>/_create/<verdict-id>`` so redelivery is idempotent (HTTP 409 for
    an already-indexed verdict counts as success) and data streams work. Auth is an API
    key sent as ``Authorization: ApiKey <key>``. Elasticsearch's default port 9200 is
    allowed automatically.
    """

    def __init__(
        self,
        url: str,
        index: str,
        api_key: str,
        *,
        min_level: Level | str | None = None,
        allowed_ports: Iterable[int] | None = None,
        **kwargs: Any,
    ) -> None:
        if not api_key:
            raise ValueError("an Elasticsearch API key is required")
        if (
            not index
            or index[0] in "-_+."
            or index != index.lower()
            or any(c in _BAD_INDEX_CHARS for c in index)
        ):
            raise ValueError(f"invalid Elasticsearch index name {index!r}")
        ports = (
            frozenset(allowed_ports)
            if allowed_ports is not None
            else DEFAULT_ALLOWED_PORTS | {9200}
        )
        super().__init__(
            url,
            min_level=min_level,
            secrets=[api_key],
            headers={"authorization": f"ApiKey {api_key}"},
            allowed_ports=ports,
            **kwargs,
        )
        self._index = index

    async def send(self, verdict: Verdict) -> None:
        base = self.url.rstrip("/")
        target = f"{base}/{quote(self._index, safe='')}/_create/{quote(verdict.id, safe='')}"
        body = json.dumps(_ecs_doc(verdict), ensure_ascii=True).encode()
        await self._post(body, url=target, method="PUT", ok_statuses=frozenset({409}))


# --------------------------------------------------------------------------- #
# Local sinks
# --------------------------------------------------------------------------- #
class StoreSink(BaseSink):
    """Persist the verdict (full, lossless JSON) in a :class:`uniphish.store.Store`."""

    default_min_level = Level.BENIGN

    def __init__(
        self, store: Any, *, source: str = "sink", min_level: Level | str | None = None
    ) -> None:
        super().__init__(min_level=min_level)
        self._store = store
        self._source = source

    async def send(self, verdict: Verdict) -> None:
        await asyncio.to_thread(self._store.save_verdict, verdict, source=self._source)


class FileSink(BaseSink):
    """Append one JSON line per verdict to ``path`` (created ``0600``, symlinks refused).

    Defanged by default (the file is for humans and log shippers); use
    :class:`StoreSink` for a lossless copy.
    """

    default_min_level = Level.BENIGN

    def __init__(
        self, path: str | Path, *, min_level: Level | str | None = None, defang: bool = True
    ) -> None:
        super().__init__(min_level=min_level)
        self.path = Path(path)
        self._defang = defang
        self._lock = threading.Lock()

    def _describe(self) -> str:
        return f"{self.path.name!r}, "

    def _append(self, line: bytes) -> None:
        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, flags, 0o600)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)

    async def send(self, verdict: Verdict) -> None:
        data = verdict_json(verdict, defanged=self._defang)
        line = json.dumps(data, ensure_ascii=True, separators=(",", ":")) + "\n"
        await asyncio.to_thread(self._append, line.encode())


class StdoutSink(BaseSink):
    """Write a one-line, defanged summary per verdict to a stream (default ``sys.stdout``)."""

    default_min_level = Level.BENIGN

    def __init__(
        self,
        stream: TextIO | None = None,
        *,
        min_level: Level | str | None = None,
        as_json: bool = False,
    ) -> None:
        super().__init__(min_level=min_level)
        self._stream = stream
        self._as_json = as_json

    async def send(self, verdict: Verdict) -> None:
        if self._as_json:
            line = json.dumps(verdict_json(verdict), ensure_ascii=True, separators=(",", ":"))
        else:
            brand = (
                f" brand={_inline(verdict.brand.name)}"
                if verdict.brand and not verdict.brand.official
                else ""
            )
            line = (
                f"[{verdict.level.value.upper()} {verdict.score:>3}] {verdict.kind.value} "
                f"{_inline(verdict.target)}{brand} :: {_inline(verdict.summary)}"
            )
        stream = self._stream if self._stream is not None else sys.stdout
        stream.write(line + "\n")
        stream.flush()


def _inline(text: str, limit: int = 200) -> str:
    return " ".join(defang(text, limit).split())


# --------------------------------------------------------------------------- #
# Fan-out
# --------------------------------------------------------------------------- #
def _sink_name(sink: Any) -> str:
    return str(getattr(sink, "name", None) or type(sink).__name__)


async def _deliver(verdict: Verdict, sink: Any, timeout: float | None) -> SinkResult:
    name = _sink_name(sink)
    min_level = getattr(sink, "min_level", Level.BENIGN)
    try:
        if LEVEL_RANK[coerce_level(min_level)] > LEVEL_RANK[verdict.level]:
            return SinkResult(name, "skipped")
    except ValueError:
        log.warning("sink %s has an invalid min_level; delivering anyway", name)
    scrub = getattr(sink, "scrub", None)
    start = time.monotonic()
    try:
        await asyncio.wait_for(sink.send(verdict), timeout)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # isolate every sink failure
        reason = (
            f"timeout after {timeout}s"
            if isinstance(exc, asyncio.TimeoutError)
            else f"{type(exc).__name__}: {exc}"
        )
        reason = scrub(reason) if callable(scrub) else reason
        log.warning("sink %s failed for verdict %s: %s", name, verdict.id, reason)
        return SinkResult(name, "failed", reason, round((time.monotonic() - start) * 1000, 2))
    return SinkResult(name, "sent", None, round((time.monotonic() - start) * 1000, 2))


async def fan_out(
    verdict: Verdict, sinks: Sequence[Sink] | Iterable[Sink], *, timeout: float | None = 30.0
) -> list[SinkResult]:
    """Deliver ``verdict`` to every sink concurrently; never raises for a sink failure.

    Sinks whose ``min_level`` is above the verdict's level are ``skipped``. Results come
    back in the order the sinks were given.
    """
    return list(await asyncio.gather(*(_deliver(verdict, s, timeout) for s in sinks)))
