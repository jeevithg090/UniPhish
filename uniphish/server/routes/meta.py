"""Metadata endpoints: health, version and the detection-signal catalog.

These are unauthenticated on purpose — a load balancer must be able to poll ``/v1/health``
and a dashboard must be able to render the signal catalog before a key is entered. They
expose no secrets and no caller input.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Request

from uniphish import __version__
from uniphish.core.analyzer import signal_catalog
from uniphish.core.types import ENGINE_VERSION
from uniphish.store import SCHEMA_VERSION

router = APIRouter(tags=["meta"])


@router.get("/health")
def health(request: Request) -> dict[str, Any]:
    """Liveness probe plus a snapshot of how the engine is configured."""
    settings = request.app.state.settings
    engine = getattr(request.app.state, "engine", None)
    return {
        "status": "ok",
        "version": __version__,
        "engine_version": ENGINE_VERSION,
        "online": bool(settings.online),
        "auth": "disabled" if not settings.api_keys else "enabled",
        "analyzers": engine.analyzer_names() if engine is not None else [],
        "time": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/meta/version")
def version() -> dict[str, Any]:
    """Component and schema versions (for compatibility checks)."""
    return {
        "name": "uniphish",
        "version": __version__,
        "engine_version": ENGINE_VERSION,
        "schema_version": SCHEMA_VERSION,
    }


@router.get("/meta/analyzers")
def analyzers(request: Request) -> dict[str, Any]:
    """The detection catalog: every registered analyzer and the signals it can emit."""
    engine = getattr(request.app.state, "engine", None)
    out: list[dict[str, Any]] = []
    if engine is not None:
        for a in engine.analyzers:
            out.append(
                {
                    "name": a.name,
                    "description": a.description,
                    "stage": a.stage,
                    "kinds": sorted(k.value for k in a.kinds),
                    "requires_online": a.requires_online,
                    "requires_detonation": a.requires_detonation,
                    "signals": dict(a.signals),
                }
            )
    return {"analyzers": out, "signals": signal_catalog()}
