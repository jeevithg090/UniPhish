"""Server-Sent Events: a live feed of verdicts and hunt alerts.

Subscribes to the in-process :data:`uniphish.core.events.bus`; the engine publishes a
``verdict`` event after every top-level scan and the hunting subsystems publish their
alerts there too. The response is a long-lived ``text/event-stream`` with periodic
heartbeat comments so proxies keep it open, and it tears down as soon as the client
disconnects.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from uniphish.core import events

log = logging.getLogger("uniphish.server.stream")

router = APIRouter(tags=["stream"])

_HEARTBEAT_S = 15.0


def _format(event: dict) -> str:
    etype = str(event.get("type", "message"))
    data = json.dumps(event.get("data"), default=str)
    ts = event.get("ts", "")
    return f"event: {etype}\nid: {ts}\ndata: {data}\n\n"


async def _event_source(request: Request) -> AsyncIterator[str]:
    subscription = events.bus.subscribe()
    # Flush headers immediately and tell the client the retry interval.
    yield "retry: 3000\n: connected\n\n"
    try:
        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(subscription.__anext__(), timeout=_HEARTBEAT_S)
            except asyncio.TimeoutError:
                yield ": ping\n\n"
                continue
            yield _format(event)
    except asyncio.CancelledError:  # client went away / server shutdown
        raise
    finally:
        await subscription.aclose()


@router.get("/stream")
async def stream(request: Request) -> StreamingResponse:
    """Live SSE feed of verdicts and hunt alerts."""
    return StreamingResponse(
        _event_source(request),
        media_type="text/event-stream",
        headers={"cache-control": "no-cache", "x-accel-buffering": "no",
                 "connection": "keep-alive"},
    )
