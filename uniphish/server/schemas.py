"""Request/response schemas for the UniPhish HTTP API.

These pydantic v2 models define the *wire* contract of the API. They are deliberately
permissive on input (every scan field is optional so one ``/v1/scan`` body can carry a
URL, text, an email, a page or a file) and strict on structure. Keeping the schemas in
one module lets the OpenAPI docs, the routes and the tests share a single source of
truth.

Nothing here trusts the caller: byte payloads arrive base64-encoded and are size-capped
by :mod:`uniphish.core.types` the moment an :class:`~uniphish.core.types.Artifact` is
built, and option values are clamped by :func:`uniphish.server.security.resolve_options`
before they ever reach the engine.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

InputType = Literal["url", "text", "email", "html", "page", "file"]


class OptionsModel(BaseModel):
    """Caller-supplied analysis switches (a safe subset of ``AnalysisOptions``).

    All fields are optional; unset fields fall back to the engine/server defaults.
    Network-touching switches (``online``, ``fetch_pages``, ``detonate``) are only
    honoured when the server's own policy allows them — see
    :func:`uniphish.server.security.resolve_options`.
    """

    model_config = ConfigDict(extra="ignore")

    online: bool | None = None
    fetch_pages: bool | None = None
    detonate: bool | None = None
    explain: bool | None = None
    ai_report: bool | None = None
    max_depth: int | None = Field(default=None, ge=0, le=4)
    max_children: int | None = Field(default=None, ge=0, le=50)
    timeout_s: float | None = Field(default=None, gt=0, le=120)
    analyzer_timeout_s: float | None = Field(default=None, gt=0, le=60)
    enable: list[str] | None = None
    disable: list[str] | None = None
    persist: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Only the explicitly-set fields (so ``None`` never clobbers a default)."""
        return self.model_dump(exclude_none=True)


class ScanRequest(BaseModel):
    """A single scan request. Provide exactly one payload; ``input_type`` is optional
    and auto-detected from whichever payload is present."""

    model_config = ConfigDict(extra="forbid")

    input_type: InputType | None = None
    url: str | None = None
    text: str | None = None
    email: str | None = Field(default=None, description="Base64-encoded RFC 5322 message.")
    html: str | None = None
    file: str | None = Field(default=None, description="Base64-encoded file bytes.")
    filename: str | None = None
    options: OptionsModel | None = None


class UrlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1)
    options: OptionsModel | None = None


class TextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1)
    options: OptionsModel | None = None


class EmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str | None = Field(default=None, description="Base64-encoded raw .eml.")
    raw: str | None = Field(default=None, description="Raw .eml as UTF-8 text (alternative).")
    options: OptionsModel | None = None


class PageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    html: str = Field(min_length=1)
    url: str | None = None
    options: OptionsModel | None = None


class BatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[ScanRequest] = Field(min_length=1, max_length=50)
    options: OptionsModel | None = Field(
        default=None, description="Defaults applied to every item lacking its own options.")


class ExportRequest(BaseModel):
    """Export an already-stored verdict (``verdict_id``) or an ad-hoc scan of an input."""

    model_config = ConfigDict(extra="forbid")

    verdict_id: str | None = None
    input_type: InputType | None = None
    url: str | None = None
    text: str | None = None
    email: str | None = None
    html: str | None = None
    file: str | None = None
    filename: str | None = None
    allow_benign: bool = False
    options: OptionsModel | None = None


class BatchItemResult(BaseModel):
    index: int
    ok: bool
    verdict: dict[str, Any] | None = None
    error: str | None = None


__all__ = [
    "BatchItemResult",
    "BatchRequest",
    "EmailRequest",
    "ExportRequest",
    "InputType",
    "OptionsModel",
    "PageRequest",
    "ScanRequest",
    "TextRequest",
    "UrlRequest",
]
