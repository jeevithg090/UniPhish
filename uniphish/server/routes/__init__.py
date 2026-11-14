"""Shared helpers for the API route modules.

Building an :class:`~uniphish.core.types.Artifact` from an untrusted request body is the
one piece of logic every scan-shaped endpoint needs, so it lives here together with the
small FastAPI dependencies that hand routes the engine, store and settings off
``app.state``. Size limits are enforced by the ``Artifact.from_*`` constructors; this
layer only decodes transport (base64), picks the artifact kind and turns the library's
``ValueError``/``ArtifactTooLarge`` into clean HTTP status codes.
"""

from __future__ import annotations

import base64
import binascii
from typing import TYPE_CHECKING, Any

from fastapi import HTTPException, Request, status

from uniphish.core.types import Artifact, ArtifactTooLarge

if TYPE_CHECKING:  # pragma: no cover
    from uniphish.core.analyzer import AnalysisOptions
    from uniphish.core.config import Settings
    from uniphish.core.engine import Engine
    from uniphish.server.schemas import ExportRequest, ScanRequest
    from uniphish.store import Store


# --------------------------------------------------------------------------- #
# app.state accessors (FastAPI dependencies)
# --------------------------------------------------------------------------- #
def get_engine(request: Request) -> Engine:
    return request.app.state.engine


def get_store(request: Request) -> Store:
    return request.app.state.store


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


# --------------------------------------------------------------------------- #
# Artifact construction from an untrusted payload
# --------------------------------------------------------------------------- #
def _b64(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail=f"Field '{field}' is not valid base64."
        ) from exc


def _detect_type(
    url: str | None, text: str | None, email: str | None, html: str | None, file: str | None
) -> str | None:
    """Infer the input kind from whichever payload is present (file > email > html > url > text)."""
    if file is not None:
        return "file"
    if email is not None:
        return "email"
    if html is not None:
        return "html"
    if url is not None:
        return "url"
    if text is not None:
        return "text"
    return None


def build_artifact(
    *,
    input_type: str | None,
    url: str | None = None,
    text: str | None = None,
    email: str | None = None,
    html: str | None = None,
    file: str | None = None,
    filename: str | None = None,
) -> Artifact:
    """Build an :class:`Artifact` from request fields, or raise an HTTP error.

    ``input_type`` may be omitted; it is then auto-detected. 413 is returned for inputs
    that exceed the engine's hard size limits, 400 for malformed base64 or empty inputs,
    422 when no usable payload is present.
    """
    kind = (input_type or _detect_type(url, text, email, html, file) or "").lower()
    if kind == "page":
        kind = "html"
    try:
        if kind == "url":
            if not url:
                raise HTTPException(422, detail="input_type 'url' requires a non-empty 'url'.")
            return Artifact.from_url(url)
        if kind == "text":
            if not text:
                raise HTTPException(422, detail="input_type 'text' requires a non-empty 'text'.")
            return Artifact.from_text(text)
        if kind == "email":
            if email is None:
                raise HTTPException(422, detail="input_type 'email' requires base64 'email'.")
            return Artifact.from_email(_b64(email, "email"))
        if kind == "html":
            if not html:
                raise HTTPException(422, detail="input_type 'html' requires non-empty 'html'.")
            return Artifact.from_page(html, url=url)
        if kind == "file":
            if file is None:
                raise HTTPException(422, detail="input_type 'file' requires base64 'file'.")
            return Artifact.from_file(_b64(file, "file"), filename=filename)
    except ArtifactTooLarge as exc:
        raise HTTPException(413, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    raise HTTPException(422, detail="No scannable input provided (url/text/email/html/file).")


def artifact_from_scan(req: ScanRequest | ExportRequest) -> Artifact:
    """Build an artifact from a :class:`ScanRequest`/:class:`ExportRequest`-shaped body."""
    return build_artifact(
        input_type=req.input_type,
        url=req.url,
        text=req.text,
        email=req.email,
        html=req.html,
        file=req.file,
        filename=req.filename,
    )


async def run_scan(engine: Engine, artifact: Artifact, opts: AnalysisOptions) -> dict[str, Any]:
    """Analyse *artifact* and return its verdict as a JSON-safe dict."""
    verdict = await engine.analyze(artifact, opts)
    return verdict.model_dump(mode="json")


__all__ = [
    "artifact_from_scan",
    "build_artifact",
    "get_engine",
    "get_settings",
    "get_store",
    "run_scan",
]
