"""Configuration and per-chat rate limiting for the UniPhish Telegram bot.

Why: the bot is a public-facing surface that runs a CPU-bound engine, so it needs an
abuse guard and explicit, environment-driven knobs. Both are Telegram-free and
unit-testable. State is in memory only; nothing about a chat is persisted.
"""

from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field

from uniphish.core.config import get_settings


def _env_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, default)))
    except ValueError:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "on"}


def _env_ids(name: str) -> frozenset[int]:
    out: set[int] = set()
    for part in os.environ.get(name, "").split(","):
        part = part.strip()
        if part.lstrip("-").isdigit():
            out.add(int(part))
    return frozenset(out)


@dataclass(frozen=True)
class BotConfig:
    """Bot settings (``UNIPHISH_BOT_*`` environment variables).

    ``token`` comes from ``Settings.telegram_bot_token`` (``TELEGRAM_BOT_TOKEN``) and is
    never logged or included in ``repr``.
    """

    token: str | None = field(default=None, repr=False)
    online: bool = False  # UNIPHISH_BOT_ONLINE: DNS/RDAP/TLS enrichment
    fetch_pages: bool = False  # UNIPHISH_BOT_FETCH: fetch linked pages (needs online)
    ai_note: bool = False  # UNIPHISH_BOT_AI: add an AI analyst note if available
    rate_limit: int = 10  # UNIPHISH_BOT_RATE: scans per window per chat
    rate_window_s: float = 60.0  # UNIPHISH_BOT_RATE_WINDOW
    max_file_bytes: int = 5_000_000  # UNIPHISH_BOT_MAX_FILE_BYTES
    max_concurrent_scans: int = 4  # UNIPHISH_BOT_CONCURRENCY
    allowed_chats: frozenset[int] = frozenset()  # UNIPHISH_BOT_ALLOWED_CHATS (empty = all)

    @classmethod
    def from_env(cls) -> BotConfig:
        return cls(
            token=get_settings().telegram_bot_token,
            online=_env_bool("UNIPHISH_BOT_ONLINE"),
            fetch_pages=_env_bool("UNIPHISH_BOT_FETCH"),
            ai_note=_env_bool("UNIPHISH_BOT_AI"),
            rate_limit=_env_int("UNIPHISH_BOT_RATE", 10),
            rate_window_s=float(_env_int("UNIPHISH_BOT_RATE_WINDOW", 60)) or 60.0,
            max_file_bytes=_env_int("UNIPHISH_BOT_MAX_FILE_BYTES", 5_000_000) or 5_000_000,
            max_concurrent_scans=_env_int("UNIPHISH_BOT_CONCURRENCY", 4) or 1,
            allowed_chats=_env_ids("UNIPHISH_BOT_ALLOWED_CHATS"),
        )

    def permits(self, chat_id: int) -> bool:
        """True if the chat may use the bot (empty allow-list means everyone)."""
        return not self.allowed_chats or chat_id in self.allowed_chats


@dataclass(frozen=True)
class RateDecision:
    """Result of :meth:`RateLimiter.check`."""

    allowed: bool
    retry_after: float = 0.0
    notify: bool = False  # True only for the first denial in a window (avoid reply spam)


class RateLimiter:
    """Thread-safe sliding-window limiter keyed by chat id.

    ``max_events <= 0`` disables limiting. The number of tracked chats is bounded
    (least-recently-seen eviction) so an attacker rotating chat ids cannot grow memory.
    """

    def __init__(
        self,
        max_events: int = 10,
        window_s: float = 60.0,
        *,
        max_chats: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_events = max_events
        self.window_s = window_s
        self.max_chats = max(1, max_chats)
        self._clock = clock
        self._hits: OrderedDict[int, deque[float]] = OrderedDict()
        self._warned: dict[int, float] = {}
        self._lock = threading.Lock()

    def check(self, chat_id: int) -> RateDecision:
        """Record one event for ``chat_id`` and say whether it is allowed."""
        if self.max_events <= 0:
            return RateDecision(True)
        now = self._clock()
        with self._lock:
            q = self._hits.get(chat_id)
            if q is None:
                q = self._hits[chat_id] = deque()
                while len(self._hits) > self.max_chats:
                    old, _ = self._hits.popitem(last=False)
                    self._warned.pop(old, None)
            else:
                self._hits.move_to_end(chat_id)
            while q and now - q[0] >= self.window_s:
                q.popleft()
            if len(q) < self.max_events:
                q.append(now)
                self._warned.pop(chat_id, None)
                return RateDecision(True)
            retry = max(0.0, self.window_s - (now - q[0]))
            notify = chat_id not in self._warned
            self._warned[chat_id] = now
            return RateDecision(False, retry_after=retry, notify=notify)

    def __len__(self) -> int:
        return len(self._hits)
