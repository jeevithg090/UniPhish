"""Intelligence endpoints: stored verdicts, statistics, indicator lookups and exports.

These read the durable :class:`~uniphish.store.Store` the engine persists into, and turn a
verdict (stored or freshly scanned) into detection-as-code: STIX 2.1, MISP, Sigma,
Suricata, YARA and Elastic ECS. Export generators are imported lazily so a missing
optional exporter never breaks the rest of the API.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse

from uniphish.server.routes import artifact_from_scan, get_engine, get_store
from uniphish.server.schemas import ExportRequest
from uniphish.server.security import resolve_options

log = logging.getLogger("uniphish.server.intel")

router = APIRouter(tags=["intel"])

_TEXT_FORMATS = {"sigma", "suricata", "yara"}
_JSON_FORMATS = {"stix", "misp", "ecs"}


# --------------------------------------------------------------------------- #
# Stored verdicts
# --------------------------------------------------------------------------- #
@router.get("/verdicts")
def recent_verdicts(store=Depends(get_store),
                    limit: int = Query(50, ge=1, le=500),
                    min_score: int = Query(0, ge=0, le=100),
                    kind: str | None = Query(None),
                    level: str | None = Query(None)) -> dict[str, Any]:
    """Newest-first verdict metadata rows (full verdicts via ``/v1/verdicts/{id}``)."""
    rows = store.recent_verdicts(limit=limit, min_score=min_score, kind=kind, level=level)
    return {"count": len(rows), "verdicts": rows}


@router.get("/verdicts/{verdict_id}")
def get_verdict(verdict_id: str, store=Depends(get_store)) -> dict[str, Any]:
    verdict = store.get_verdict(verdict_id)
    if verdict is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Verdict not found.")
    return verdict.model_dump(mode="json")


@router.get("/stats")
def stats(store=Depends(get_store)) -> dict[str, Any]:
    """Aggregate counts, score histogram and store sizes for the dashboard."""
    return store.stats()


@router.get("/indicators")
def indicators(store=Depends(get_store),
               type: str | None = Query(None, description="Indicator type, e.g. 'domain'."),
               value: str | None = Query(None, description="Exact value to look up."),
               limit: int = Query(100, ge=1, le=1000),
               malicious_only: bool = Query(False)) -> dict[str, Any]:
    """Look up an IOC by (type, value), or list the most recently seen indicators."""
    if type and value:
        rows = store.search_indicator(type, value)
    else:
        rows = store.recent_indicators(limit=limit, malicious_only=malicious_only, type=type)
    return {"count": len(rows), "indicators": rows}


# --------------------------------------------------------------------------- #
# Exports
# --------------------------------------------------------------------------- #
@router.post("/export/{fmt}")
async def export(fmt: str, req: ExportRequest, request: Request,
                 engine=Depends(get_engine), store=Depends(get_store)):
    """Export a verdict (by ``verdict_id`` or ad-hoc scan) as detection-as-code."""
    fmt = fmt.lower()
    if fmt not in _TEXT_FORMATS and fmt not in _JSON_FORMATS:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            detail=f"Unknown export format '{fmt}'.")
    verdict = await _resolve_verdict(req, engine, store, request)
    try:
        return _render_export(fmt, verdict, allow_benign=req.allow_benign)
    except _NoIndicators as exc:
        raise HTTPException(422,
                            detail=f"Nothing to export for '{fmt}': {exc}") from exc


async def _resolve_verdict(req: ExportRequest, engine, store, request):
    if req.verdict_id:
        verdict = store.get_verdict(req.verdict_id)
        if verdict is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Verdict not found.")
        return verdict
    artifact = artifact_from_scan(req)
    opts = resolve_options(req.options, request.app.state.settings)
    return await engine.analyze(artifact, opts)


class _NoIndicators(Exception):
    """Internal: raised when an exporter has no IOCs to emit."""


def _render_export(fmt: str, verdict, *, allow_benign: bool):
    from uniphish.export.sigma import NoIndicatorsError

    try:
        if fmt == "stix":
            from uniphish.export.stix import to_stix_bundle
            return JSONResponse(to_stix_bundle(verdict, include_benign=allow_benign))
        if fmt == "misp":
            from uniphish.export.misp import to_misp_event
            return JSONResponse(to_misp_event(verdict, include_benign=allow_benign))
        if fmt == "ecs":
            from uniphish.export.ecs import to_ecs
            return JSONResponse(to_ecs(verdict, allow_benign=allow_benign))
        if fmt == "sigma":
            from uniphish.export.sigma import to_sigma_yaml
            text = to_sigma_yaml(verdict, allow_benign=allow_benign)
            if not text.strip():
                raise _NoIndicators("no rule generated")
            return PlainTextResponse(text, media_type="application/yaml")
        if fmt == "suricata":
            from uniphish.export.suricata import to_suricata_rules
            rules = to_suricata_rules(verdict, allow_benign=allow_benign)
            if not rules:
                raise _NoIndicators("no deployable rules")
            return PlainTextResponse("\n".join(rules) + "\n", media_type="text/plain")
        if fmt == "yara":
            from uniphish.export.yara import to_yara
            return PlainTextResponse(to_yara(verdict, allow_benign=allow_benign),
                                     media_type="text/plain")
    except NoIndicatorsError as exc:
        raise _NoIndicators(str(exc)) from exc
    except IndexError as exc:  # some exporters index [0] into an empty rule list
        raise _NoIndicators("no indicators") from exc
    raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Unknown export format '{fmt}'.")
