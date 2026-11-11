"""In-process async pub/sub used for live dashboards (SSE) and integrations.

Publishers (engine, CT hunter, AgentGuard, brandwatch) call :func:`publish`; the API's
``/v1/stream`` endpoint subscribes. Slow subscribers never block publishers: each has a
bounded queue and the oldest events are dropped when it is full.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any


class EventBus:
    def __init__(self, queue_size: int = 256) -> None:
        self._subs: set[asyncio.Queue[dict[str, Any]]] = set()
        self._queue_size = queue_size

    @property
    def subscriber_count(self) -> int:
        return len(self._subs)

    def publish(self, type_: str, data: Any) -> None:
        """Fan an event out to every subscriber (non-blocking, drop-oldest)."""
        if not self._subs:
            return
        event = {"type": type_, "ts": datetime.now(timezone.utc).isoformat(), "data": data}
        for q in list(self._subs):
            if q.full():
                with contextlib.suppress(asyncio.QueueEmpty):
                    q.get_nowait()
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(event)

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(self._queue_size)
        self._subs.add(q)
        try:
            while True:
                yield await q.get()
        finally:
            self._subs.discard(q)


bus = EventBus()


def publish(type_: str, data: Any) -> None:
    bus.publish(type_, data)
