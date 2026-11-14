"""API security: authentication, rate limiting, size caps and response hardening.

Why this module exists: the API is internet-facing and consumes attacker-controlled
input (URLs, emails, pages, files) all day. Everything that keeps the surface safe lives
here so it is reviewable in one place:

* **API-key auth** (:func:`verify_api_key`) — constant-time key comparison; when no keys
  are configured the API runs open (developer mode) and advertises that with an
  ``X-UniPhish-Auth: disabled`` header so it is never mistaken for a hardened deployment.
* **Rate limiting** (:class:`RateLimiter`) — an in-memory token bucket keyed by a *valid*
  API key or else the client IP, sized from ``settings.rate_limit_per_minute``. Unknown or
  forged keys never earn their own bucket, so rotating junk keys cannot dodge the limit.
* **Request size cap + security headers** (:class:`ServerMiddleware`) — a pure-ASGI
  middleware (streaming-safe, unlike ``BaseHTTPMiddleware``) that rejects oversized bodies
  by ``Content-Length`` *and* by counting the bytes actually received (so a chunked body
  without a length cannot slip past), and stamps a strict CSP and the usual hardening
  headers onto every response, including the SSE stream.
* **Option gating** (:func:`resolve_options`) — maps caller options onto
  :class:`~uniphish.core.analyzer.AnalysisOptions`, refusing to let a request push the
  server onto the network unless the operator enabled it, and clamping recursion/timeout
  budgets.

The module treats every value from the request as data: nothing is interpolated into a
response unescaped, and comparisons that gate access use :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
from typing import TYPE_CHECKING

from fastapi import HTTPException, Request, status
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from uniphish.core.analyzer import AnalysisOptions

if TYPE_CHECKING:  # pragma: no cover
    from uniphish.server.schemas import OptionsModel

log = logging.getLogger("uniphish.server.security")

# Largest request body accepted (declared or streamed). A base64-encoded 25 MB email/file
# inflates to ~34 MB, so the cap leaves headroom. Module-level so tests can tighten it.
MAX_REQUEST_BYTES = 40_000_000

# Caller option clamps (defence against resource exhaustion via the options bag).
MAX_TIMEOUT_S = 120.0
MAX_ANALYZER_TIMEOUT_S = 60.0
MAX_DEPTH = 4
MAX_CHILDREN = 50

_CSP = (
    "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; "
    "img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
    "connect-src 'self'; font-src 'self'; form-action 'self'"
)
SECURITY_HEADERS: dict[str, str] = {
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "cross-origin-opener-policy": "same-origin",
    "permissions-policy": "geolocation=(), microphone=(), camera=()",
    "content-security-policy": _CSP,
}

# Paths exempt from rate limiting / auth noise (health is polled by load balancers).
_RATE_EXEMPT_PREFIXES = ("/docs", "/redoc", "/openapi.json", "/favicon", "/assets")


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #
def extract_key(request: Request) -> str | None:
    """Return the presented API key from ``X-API-Key`` or a ``Bearer`` token, else None."""
    key = request.headers.get("x-api-key")
    if key:
        return key.strip()
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip() or None
    return None


def key_is_valid(presented: str | None, accepted: list[str]) -> bool:
    """Constant-time membership test of *presented* against *accepted* keys."""
    if not presented:
        return False
    ok = False
    pb = presented.encode("utf-8", "ignore")
    for candidate in accepted:
        # compare_digest against every candidate so timing does not leak which matched.
        if hmac.compare_digest(pb, candidate.encode("utf-8", "ignore")):
            ok = True
    return ok


def verify_api_key(request: Request) -> None:
    """FastAPI dependency: enforce API-key auth when keys are configured.

    With no configured keys the API is open (developer mode) and this is a no-op; the
    ``X-UniPhish-Auth: disabled`` response header (added by :class:`ServerMiddleware`)
    makes that explicit to clients.
    """
    settings = request.app.state.settings
    accepted = list(settings.api_keys or [])
    if not accepted:
        return
    if not key_is_valid(extract_key(request), accepted):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #
class RateLimiter:
    """Thread-safe token-bucket limiter (per identity). ``per_minute <= 0`` disables it.

    The bucket table is bounded: once it holds ``max_identities`` entries, buckets that
    have fully refilled (idle identities) are dropped, and if that is not enough the
    oldest entries are evicted. An attacker spraying source addresses therefore costs a
    bounded amount of memory.
    """

    def __init__(self, per_minute: int, *, max_identities: int = 10_000,
                 clock=time.monotonic) -> None:
        self.per_minute = int(per_minute)
        self.capacity = float(max(1, per_minute))
        self.refill_per_s = self.capacity / 60.0
        self.max_identities = max(1, int(max_identities))
        self._clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.per_minute > 0

    def __len__(self) -> int:
        return len(self._buckets)

    def allow(self, identity: str) -> bool:
        """Consume one token for *identity*; return False when the bucket is empty."""
        if not self.enabled:
            return True
        now = self._clock()
        with self._lock:
            if identity not in self._buckets and len(self._buckets) >= self.max_identities:
                self._evict(now)
            tokens, last = self._buckets.get(identity, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill_per_s)
            if tokens < 1.0:
                self._buckets[identity] = (tokens, now)
                return False
            self._buckets[identity] = (tokens - 1.0, now)
            return True

    def _evict(self, now: float) -> None:
        """Drop refilled buckets; then, if still full, the least recently seen ones."""
        full_after = (self.capacity - 1.0) / self.refill_per_s if self.refill_per_s else 0.0
        idle = [k for k, (_t, last) in self._buckets.items() if now - last >= full_after]
        for k in idle:
            del self._buckets[k]
        overflow = len(self._buckets) - self.max_identities + 1
        if overflow > 0:
            # Still full of active identities: evict the least recently seen.
            stalest = sorted(self._buckets.items(), key=lambda kv: kv[1][1])[:overflow]
            for k, _ in stalest:
                del self._buckets[k]


def _identity(request: Request, accepted: list[str] | None = None) -> str:
    """Rate-limit identity: a *valid* API key, else the client IP.

    An invalid or unknown key falls back to the IP so that sending a fresh random key on
    every request cannot mint a fresh token bucket.
    """
    key = extract_key(request)
    if key and accepted and key_is_valid(key, accepted):
        return "key:" + hashlib.sha256(key.encode("utf-8", "ignore")).hexdigest()[:32]
    client = request.client
    return "ip:" + (client.host if client else "unknown")


class _BodyTooLarge(HTTPException):
    """Raised from the wrapped ``receive`` when a streamed body exceeds the cap.

    An :class:`HTTPException` so FastAPI's body parsing re-raises it untouched and the
    normal exception handler renders a 413 (instead of a generic 400 parse error).
    """

    def __init__(self) -> None:
        super().__init__(status_code=413, detail="Request body too large.")


# --------------------------------------------------------------------------- #
# ASGI middleware: size cap + security headers + rate limiting
# --------------------------------------------------------------------------- #
class ServerMiddleware:
    """Pure-ASGI hardening middleware.

    Pure ASGI (not ``BaseHTTPMiddleware``) so it never buffers streaming responses — the
    ``/v1/stream`` SSE endpoint keeps flushing in real time.
    """

    def __init__(self, app: ASGIApp, *, settings, limiter: RateLimiter) -> None:
        self.app = app
        self.settings = settings
        self.limiter = limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        path = scope.get("path", "")

        # 1) Request size cap (by declared Content-Length). Read the module global at call
        #    time so tests can tighten MAX_REQUEST_BYTES.
        cl = headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > MAX_REQUEST_BYTES:
            await self._send_json(send, 413,
                                  {"detail": "Request body too large."})
            return

        # 2) Rate limiting (skip static/docs assets).
        if self.limiter.enabled and not path.startswith(_RATE_EXEMPT_PREFIXES):
            request = Request(scope, receive)
            if not self.limiter.allow(_identity(request, list(self.settings.api_keys or []))):
                await self._send_json(
                    send, status.HTTP_429_TOO_MANY_REQUESTS,
                    {"detail": "Rate limit exceeded."},
                    extra={"retry-after": "1"})
                return

        auth_disabled = not self.settings.api_keys
        limit = MAX_REQUEST_BYTES
        received = 0
        response_started = False

        async def receive_wrapper() -> Message:
            # 3) Streamed size cap: Content-Length is optional (chunked uploads), so count
            #    the bytes that actually arrive and stop reading once over the cap.
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge
            return message

        async def send_wrapper(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                mh = MutableHeaders(raw=message.setdefault("headers", []))
                for name, value in SECURITY_HEADERS.items():
                    if name not in mh:
                        mh[name] = value
                if auth_disabled:
                    mh["x-uniphish-auth"] = "disabled"
            await send(message)

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except _BodyTooLarge:
            if response_started:  # pragma: no cover - nothing sane left to send
                raise
            await self._send_json(send, 413, {"detail": "Request body too large."})

    async def _send_json(self, send: Send, code: int, payload: dict[str, str],
                         extra: dict[str, str] | None = None) -> None:
        body = json.dumps(payload).encode()
        raw = [(b"content-type", b"application/json"),
               (b"content-length", str(len(body)).encode())]
        for name, value in SECURITY_HEADERS.items():
            raw.append((name.encode(), value.encode()))
        if not self.settings.api_keys:
            raw.append((b"x-uniphish-auth", b"disabled"))
        for name, value in (extra or {}).items():
            raw.append((name.encode(), value.encode()))
        await send({"type": "http.response.start", "status": code, "headers": raw})
        await send({"type": "http.response.body", "body": body})


# --------------------------------------------------------------------------- #
# Option gating
# --------------------------------------------------------------------------- #
def resolve_options(options: OptionsModel | None, settings) -> AnalysisOptions:
    """Map caller options onto :class:`AnalysisOptions`, gated by server policy.

    Policy:

    * Network analysis (``online``) is refused unless the operator enabled it with
      ``settings.online``. A request may still *disable* online.
    * ``fetch_pages`` and ``detonate`` require effective online; otherwise they are forced
      off (defence-in-depth — the engine also skips those analyzers offline).
    * Recursion depth, child fan-out and time budgets are clamped to sane maxima.
    """
    raw = options.to_dict() if options is not None else {}
    opts = AnalysisOptions.from_dict(raw)

    if not settings.online:
        opts.online = False
    online_effective = opts.is_online(settings)
    if not online_effective:
        opts.fetch_pages = False
        opts.detonate = False

    opts.max_depth = max(0, min(int(opts.max_depth), MAX_DEPTH))
    opts.max_children = max(0, min(int(opts.max_children), MAX_CHILDREN))
    opts.timeout_s = max(0.5, min(float(opts.timeout_s), MAX_TIMEOUT_S))
    opts.analyzer_timeout_s = max(0.1, min(float(opts.analyzer_timeout_s), MAX_ANALYZER_TIMEOUT_S))
    return opts


__all__ = [
    "MAX_REQUEST_BYTES",
    "RateLimiter",
    "SECURITY_HEADERS",
    "ServerMiddleware",
    "extract_key",
    "key_is_valid",
    "resolve_options",
    "verify_api_key",
]
