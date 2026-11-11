"""Scan endpoints: the core of the API.

``POST /v1/scan`` takes a single polymorphic body (url / text / email / html / file) and
returns an explainable :class:`~uniphish.core.types.Verdict`. Typed convenience routes
(``/v1/scan/url`` …), a bounded concurrent ``/v1/scan/batch`` and ``/v1/explain`` (which
adds an AI/template analyst narrative) are thin wrappers over the same machinery.

Every option bag is passed through :func:`uniphish.server.security.resolve_options`, so no
request can push the server onto the network or exhaust it with unbounded recursion.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status

from uniphish.core.types import ArtifactTooLarge
from uniphish.server.routes import artifact_from_scan, build_artifact, get_engine, run_scan
from uniphish.server.schemas import (
    BatchRequest,
    EmailRequest,
    OptionsModel,
    PageRequest,
    ScanRequest,
    TextRequest,
    UrlRequest,
)
from uniphish.server.security import MAX_REQUEST_BYTES, resolve_options

log = logging.getLogger("uniphish.server.scan")

router = APIRouter(tags=["scan"])

_BATCH_CONCURRENCY = 8


@router.post("/scan")
async def scan(req: ScanRequest, request: Request,
               engine=Depends(get_engine)) -> dict[str, Any]:
    """Analyse a single input; ``input_type`` is auto-detected when omitted."""
    artifact = artifact_from_scan(req)
    opts = resolve_options(req.options, request.app.state.settings)
    return await run_scan(engine, artifact, opts)


@router.post("/scan/url")
async def scan_url(req: UrlRequest, request: Request,
                   engine=Depends(get_engine)) -> dict[str, Any]:
    artifact = build_artifact(input_type="url", url=req.url)
    opts = resolve_options(req.options, request.app.state.settings)
    return await run_scan(engine, artifact, opts)


@router.post("/scan/text")
async def scan_text(req: TextRequest, request: Request,
                    engine=Depends(get_engine)) -> dict[str, Any]:
    artifact = build_artifact(input_type="text", text=req.text)
    opts = resolve_options(req.options, request.app.state.settings)
    return await run_scan(engine, artifact, opts)


@router.post("/scan/email")
async def scan_email(req: EmailRequest, request: Request,
                     engine=Depends(get_engine)) -> dict[str, Any]:
    if req.email is not None:
        artifact = build_artifact(input_type="email", email=req.email)
    elif req.raw is not None:
        artifact = build_artifact(input_type="email",
                                  email=_to_b64(req.raw))
    else:
        raise HTTPException(422,
                            detail="Provide base64 'email' or UTF-8 'raw'.")
    opts = resolve_options(req.options, request.app.state.settings)
    return await run_scan(engine, artifact, opts)


@router.post("/scan/page")
async def scan_page(req: PageRequest, request: Request,
                    engine=Depends(get_engine)) -> dict[str, Any]:
    artifact = build_artifact(input_type="html", html=req.html, url=req.url)
    opts = resolve_options(req.options, request.app.state.settings)
    return await run_scan(engine, artifact, opts)


@router.post("/scan/file")
async def scan_file(request: Request, file: UploadFile = File(...),
                    options: str | None = Form(default=None),
                    engine=Depends(get_engine)) -> dict[str, Any]:
    """Multipart file upload. ``options`` is an optional JSON string form field."""
    data = await _read_upload(file)
    try:
        from uniphish.core.types import Artifact
        artifact = Artifact.from_file(data, filename=file.filename)
    except ArtifactTooLarge as exc:
        raise HTTPException(413, detail=str(exc)) from exc
    opts = resolve_options(_parse_form_options(options), request.app.state.settings)
    return await run_scan(engine, artifact, opts)


@router.post("/scan/batch")
async def scan_batch(req: BatchRequest, request: Request,
                     engine=Depends(get_engine)) -> dict[str, Any]:
    """Analyse up to 50 inputs concurrently (bounded). One bad item never fails the batch."""
    settings = request.app.state.settings
    sem = asyncio.Semaphore(_BATCH_CONCURRENCY)

    async def _one(index: int, item: ScanRequest) -> dict[str, Any]:
        async with sem:
            try:
                artifact = artifact_from_scan(item)
                opts = resolve_options(item.options or req.options, settings)
                verdict = await run_scan(engine, artifact, opts)
                return {"index": index, "ok": True, "verdict": verdict}
            except HTTPException as exc:
                return {"index": index, "ok": False, "error": str(exc.detail)}
            except Exception as exc:  # fault isolation per item
                log.exception("batch item %d failed", index)
                return {"index": index, "ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]}

    results = await asyncio.gather(*(_one(i, it) for i, it in enumerate(req.items)))
    return {"count": len(results), "results": results}


@router.post("/explain")
async def explain(req: ScanRequest, request: Request,
                  engine=Depends(get_engine)) -> dict[str, Any]:
    """Scan with explanations forced on, then attach an analyst narrative + triage.

    The narrative/triage come from :class:`uniphish.ai.AIAnalyst`, which uses an LLM when a
    key is configured and otherwise falls back to a deterministic template — so this
    endpoint is useful (and offline-safe) with or without AI configured.
    """
    artifact = artifact_from_scan(req)
    options = req.options or OptionsModel()
    options = options.model_copy(update={"explain": True, "ai_report": True})
    opts = resolve_options(options, request.app.state.settings)
    verdict = await engine.analyze(artifact, opts)

    analyst = request.app.state.ai
    report: dict[str, Any] = {"source": "unavailable"}
    try:
        narrative = await analyst.narrative(verdict)
        triage = await analyst.triage(verdict)
        report = {"narrative": narrative, "triage": triage,
                  "ai_available": bool(analyst.available)}
    except Exception:  # analyst methods are defensive, but never let this break /explain
        log.exception("analyst report failed")
    out = verdict.model_dump(mode="json")
    out["report"] = report
    return out


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _to_b64(raw: str) -> str:
    import base64
    return base64.b64encode(raw.encode("utf-8", "replace")).decode("ascii")


def _parse_form_options(options: str | None) -> OptionsModel | None:
    if not options:
        return None
    try:
        return OptionsModel.model_validate_json(options)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            detail="'options' form field is not valid JSON options.") from exc


async def _read_upload(file: UploadFile) -> bytes:
    """Read an upload with a hard byte cap (defence against unbounded multipart bodies)."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1_048_576)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_REQUEST_BYTES:
            raise HTTPException(413,
                                detail="Uploaded file too large.")
        chunks.append(chunk)
    return b"".join(chunks)
