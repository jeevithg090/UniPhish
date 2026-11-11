"""FastAPI application factory for the UniPhish HTTP API.

``create_app(settings=None)`` wires the engine, the persistence store, the live event
bus, the security middleware and every route group into one app. A module-level
``app = create_app()`` is the ASGI entry point for ``uvicorn uniphish.server.app:app``.

Lifespan
--------
On startup the app builds its own :class:`~uniphish.core.engine.Engine` and
:class:`~uniphish.store.Store` (so test apps are fully isolated), registers a verdict →
store persistence hook that honours ``options.persist``, and prepares the optional AI
analyst. On shutdown it closes any store it opened.

Nothing here trusts request input; hardening lives in :mod:`uniphish.server.security`.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from uniphish import __version__
from uniphish.ai import AIAnalyst
from uniphish.core.analyzer import AnalysisOptions
from uniphish.core.config import Settings, get_settings
from uniphish.core.engine import Engine
from uniphish.core.types import Artifact, ArtifactTooLarge, Verdict
from uniphish.server.routes import intel, meta, scan, stream, taxii
from uniphish.server.security import RateLimiter, ServerMiddleware, verify_api_key
from uniphish.store import Store

log = logging.getLogger("uniphish.server")

_STATIC_DIR = Path(__file__).resolve().parent / "static"


class _LegacyScan(BaseModel):
    """Body of the legacy ``/scan`` and ``/stix`` compatibility shims."""

    url: str


def _make_persist_hook(store: Store):
    """Engine hook: persist each top-level verdict unless the request opted out."""

    def hook(verdict: Verdict, artifact: Artifact, opts: AnalysisOptions) -> None:
        if getattr(opts, "persist", True):
            try:
                store.save_verdict(verdict, source="api")
            except Exception:  # persistence must never break a scan response
                log.exception("verdict persistence failed for %s", verdict.id)

    return hook


def create_app(settings: Settings | None = None, *, engine: Engine | None = None,
               store: Store | None = None) -> FastAPI:
    """Build the FastAPI app. ``engine``/``store`` may be injected (tests); otherwise the
    app owns freshly-built ones bound to *settings*."""
    settings = settings or get_settings()
    limiter = RateLimiter(settings.rate_limit_per_minute)
    _owns_store = store is None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        _store = store or Store(settings.db_path)
        _engine = engine or Engine(settings=settings)
        _engine.add_hook(_make_persist_hook(_store))
        app.state.store = _store
        app.state.engine = _engine
        app.state.ai = AIAnalyst(settings)
        log.info("uniphish API ready (analyzers=%d, online=%s, auth=%s)",
                 len(_engine.analyzers), settings.online, bool(settings.api_keys))
        try:
            yield
        finally:
            if _owns_store:
                _store.close()

    app = FastAPI(
        title="UniPhish API",
        version=__version__,
        description="Explainable, AI-native anti-phishing detection engine.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.limiter = limiter

    # Hardening is innermost; CORS outermost so preflight and CORS headers wrap everything.
    app.add_middleware(ServerMiddleware, settings=settings, limiter=limiter)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins or []),
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["authorization", "content-type", "x-api-key"],
        allow_credentials=False,
        max_age=600,
    )

    _auth = [Depends(verify_api_key)]
    app.include_router(meta.router, prefix="/v1")
    app.include_router(scan.router, prefix="/v1", dependencies=_auth)
    app.include_router(intel.router, prefix="/v1", dependencies=_auth)
    app.include_router(stream.router, prefix="/v1", dependencies=_auth)
    app.include_router(taxii.router, dependencies=_auth)  # root-mounted /taxii2/*

    _register_errors(app)
    _register_legacy(app, _auth)
    _mount_static(app)
    return app


# --------------------------------------------------------------------------- #
# Error handling (never reflect raw input back unescaped)
# --------------------------------------------------------------------------- #
def _register_errors(app: FastAPI) -> None:
    @app.exception_handler(ArtifactTooLarge)
    async def _too_large(_request: Request, exc: ArtifactTooLarge) -> JSONResponse:
        return JSONResponse(status_code=413, content={"detail": str(exc)})


# --------------------------------------------------------------------------- #
# Legacy compatibility shims (thin wrappers on the v1 engine)
# --------------------------------------------------------------------------- #
def _register_legacy(app: FastAPI, auth: list[Any]) -> None:
    @app.post("/scan", include_in_schema=False, dependencies=auth)
    async def legacy_scan(body: _LegacyScan, request: Request) -> dict[str, Any]:
        verdict = await request.app.state.engine.analyze(
            Artifact.from_url(body.url), AnalysisOptions())
        return {"url": body.url, "score": verdict.score, "risk": verdict.risk,
                "level": verdict.level.value, "action": verdict.action.value,
                "summary": verdict.summary}

    @app.post("/stix", include_in_schema=False, dependencies=auth)
    async def legacy_stix(body: _LegacyScan, request: Request) -> Any:
        from uniphish.export.stix import to_stix_bundle

        verdict = await request.app.state.engine.analyze(
            Artifact.from_url(body.url), AnalysisOptions())
        return JSONResponse(to_stix_bundle(verdict))


# --------------------------------------------------------------------------- #
# Static dashboard (mounted last so API routes always win; tolerate absence)
# --------------------------------------------------------------------------- #
def _mount_static(app: FastAPI) -> None:
    if _STATIC_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(_STATIC_DIR), html=True), name="static")
    else:
        @app.get("/", include_in_schema=False)
        def root() -> dict[str, Any]:
            return {"name": "uniphish", "version": __version__,
                    "docs": "/docs", "api": "/v1/health"}


app = create_app()
