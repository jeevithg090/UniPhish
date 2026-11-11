"""AgentGuard MCP server — UniPhish detection exposed over the Model Context Protocol.

This is the AI-native face of UniPhish: a Model Context Protocol (MCP) server an agent
host connects to over stdio, giving any MCP-capable agent a set of tools to *check
before it acts* — scan a URL, message, email, file or page, quarantine fetched content,
vet a proposed tool call, and export a verdict as STIX for a SOC.

Design principles baked into every tool:

* **Content is data, never instructions.** The server runs detectors over the submitted
  content and returns evidence; it never follows, renders or executes anything inside
  it, and matched strings are defanged in the output so a downstream UI can't auto-link
  them.
* **Offline by default.** Tools run the engine with ``online=False``. A tool may request
  network enrichment only when the operator has opted the whole server in via
  ``UNIPHISH_MCP_ONLINE=1`` *and* the call passes ``online=True``; otherwise the request
  is silently kept offline.
* **Bounded and total.** Every handler validates and size-limits its input and returns a
  compact structured result (verdict summary, action, top reasons, defanged IOCs). The
  handlers are plain coroutines, callable and testable directly without a transport.

Run it as a stdio MCP server::

    python -m uniphish.agent.mcp_server

(or wire a ``uniphish-mcp`` console script to :func:`main`). The ``mcp`` package is an
optional dependency (``uniphish[mcp]``); importing this module never requires it —
:func:`build_server` imports it lazily and raises a clear message if it is missing.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import re
from typing import Any

from uniphish import __version__
from uniphish.agent.guard import AgentGuard, _defang_indicator, _defang_text
from uniphish.core.analyzer import AnalysisOptions
from uniphish.core.types import (
    MAX_EMAIL_BYTES,
    MAX_FILE_BYTES,
    MAX_PAGE_BYTES,
    MAX_TEXT_CHARS,
    MAX_URL_CHARS,
    Artifact,
    ArtifactKind,
    Verdict,
)

log = logging.getLogger("uniphish.agent.mcp")

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

SERVER_NAME = "uniphish-agentguard"
INSTRUCTIONS = (
    "UniPhish AgentGuard: scan URLs, text, emails, files and web pages for phishing and "
    "prompt injection before an AI agent acts on them, quarantine untrusted content, vet "
    "proposed tool calls, and export verdicts as STIX. All submitted content is treated "
    "strictly as DATA and is never followed or executed; indicators are defanged. "
    "Analysis is offline by default."
)

#: Tools exposed by the server, in registration order.
TOOL_NAMES = ("scan_url", "scan_text", "scan_email", "scan_file", "check_content",
              "check_tool_call", "export_stix")

_guard: AgentGuard | None = None


def get_guard() -> AgentGuard:
    """Return the process-wide :class:`AgentGuard` (lazily built, offline policy)."""
    global _guard
    if _guard is None:
        _guard = AgentGuard()
    return _guard


def set_guard(guard: AgentGuard | None) -> None:
    """Override (or reset, with ``None``) the guard the handlers use. For tests/config."""
    global _guard
    _guard = guard


def _online(requested: bool) -> bool:
    """Network is enabled only if the operator opted the server in *and* the call asks."""
    flag = os.environ.get("UNIPHISH_MCP_ONLINE", "").strip().lower()
    return bool(requested) and flag in {"1", "true", "yes", "on"}


def _options(online: bool) -> AnalysisOptions:
    return AnalysisOptions.from_dict({"online": _online(online)})


# --------------------------------------------------------------------------- #
# Verdict -> compact, defanged payload
# --------------------------------------------------------------------------- #
def _defang_target(verdict: Verdict) -> str:
    if verdict.kind in (ArtifactKind.URL, ArtifactKind.PAGE):
        return _defang_text(verdict.target)
    return _CTRL.sub("", verdict.target)[:200]


def verdict_payload(verdict: Verdict, *, max_reasons: int = 8) -> dict[str, Any]:
    """Compact, JSON-safe, defanged summary of a verdict (the shape every tool returns)."""
    reasons = [{
        "id": s.id, "title": _defang_text(s.title), "detail": _defang_text(s.detail),
        "weight": s.weight, "contribution": s.contribution, "category": s.category,
        "severity": s.severity.value if s.severity else None,
    } for s in verdict.top_signals(max_reasons)]
    brand = None
    if verdict.brand is not None:
        brand = {"id": verdict.brand.brand, "name": verdict.brand.name,
                 "technique": verdict.brand.technique,
                 "confidence": round(verdict.brand.confidence, 3),
                 "official": verdict.brand.official}
    children = [{
        "kind": c.kind.value, "level": c.level.value, "score": c.score,
        "action": c.action.value, "origin": c.origin,
        "target": _defang_target(c), "summary": _defang_text(c.summary),
    } for c in verdict.children]
    return {
        "target": _defang_target(verdict),
        "kind": verdict.kind.value,
        "level": verdict.level.value,
        "action": verdict.action.value,
        "score": verdict.score,
        "risk": verdict.risk,
        "confidence": verdict.confidence,
        "summary": _defang_text(verdict.summary),
        "brand": brand,
        "techniques": list(verdict.techniques),
        "mitre": [{"id": m.id, "name": m.name, "tactic": m.tactic,
                   "framework": m.framework} for m in verdict.mitre],
        "reasons": reasons,
        "indicators": [_defang_indicator(i) for i in verdict.all_indicators()],
        "children": children,
        "analyzers": [{"name": a.name, "status": a.status, "signals": a.signals}
                      for a in verdict.analyzers],
        "engine_version": verdict.engine_version,
    }


# --------------------------------------------------------------------------- #
# Internal scan helpers (shared by the scan_* tools and export_stix)
# --------------------------------------------------------------------------- #
def _require_str(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if not value.strip():
        raise ValueError(f"{field} must not be empty")
    if len(value) > limit:
        raise ValueError(f"{field} exceeds the {limit}-character limit")
    return value


def _decode_base64(value: Any, field: str, limit: int) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty base64 string")
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field} is not valid base64: {exc}") from None
    if len(data) > limit:
        raise ValueError(f"{field} decodes to more than {limit} bytes")
    return data


async def _scan(kind: str, target: Any, *, online: bool = False,
                filename: str | None = None) -> Verdict:
    """Run the engine over one artifact described by ``kind`` + ``target`` (offline)."""
    engine = get_guard().engine
    opts = _options(online)
    kind = (kind or "").lower()
    if kind == "url":
        artifact = Artifact.from_url(_require_str(target, "url", MAX_URL_CHARS))
    elif kind == "text":
        artifact = Artifact.from_text(_require_str(target, "text", MAX_TEXT_CHARS))
    elif kind == "email":
        raw = _require_str(target, "raw", MAX_EMAIL_BYTES).encode("utf-8", "replace")
        artifact = Artifact.from_email(raw)
    elif kind == "page":
        artifact = Artifact.from_page(_require_str(target, "html", MAX_PAGE_BYTES), filename)
    else:
        raise ValueError(f"unsupported kind {kind!r}")
    return await engine.analyze(artifact, opts)


# --------------------------------------------------------------------------- #
# MCP tool handlers (plain coroutines — call directly in tests)
# --------------------------------------------------------------------------- #
async def scan_url(url: str, online: bool = False) -> dict[str, Any]:
    """Analyse a URL for phishing (homoglyph/IDN, brand impersonation, abused hosting).

    Args:
        url: the URL to analyse.
        online: request DNS/RDAP/TLS/feed enrichment (ignored unless the server operator
            enabled networking with UNIPHISH_MCP_ONLINE=1).

    Returns a compact verdict summary with the action, top reasons and defanged IOCs.
    """
    verdict = await _scan("url", url, online=online)
    return verdict_payload(verdict)


async def scan_text(text: str, online: bool = False) -> dict[str, Any]:
    """Analyse a free-text message (SMS, chat, LLM context) for phishing, social
    engineering and prompt injection; URLs inside it are analysed as children."""
    verdict = await _scan("text", text, online=online)
    return verdict_payload(verdict)


async def scan_email(raw: str, online: bool = False) -> dict[str, Any]:
    """Analyse a raw RFC 5322 email (.eml as a UTF-8 string): auth (SPF/DKIM/DMARC),
    sender spoofing, and the risk of its links and attachments."""
    verdict = await _scan("email", raw, online=online)
    return verdict_payload(verdict)


async def scan_file(filename: str, content_base64: str, online: bool = False) -> dict[str, Any]:
    """Analyse a file / attachment / image supplied as base64 (QR codes are decoded and
    their URLs followed as children).

    Args:
        filename: the file's name (used for extension / double-extension checks).
        content_base64: the file bytes, base64-encoded.
    """
    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("filename must be a non-empty string")
    data = _decode_base64(content_base64, "content_base64", MAX_FILE_BYTES)
    engine = get_guard().engine
    artifact = Artifact.from_file(data, filename)
    verdict = await engine.analyze(artifact, _options(online))
    return verdict_payload(verdict)


async def check_content(content: str, kind: str = "text",
                        source: str | None = None) -> dict[str, Any]:
    """Guard tool output / fetched web content before the agent consumes it.

    Detects prompt injection (including hidden/indirect and obfuscated payloads) plus
    phishing, and returns an ``allow`` decision together with a ``sanitized`` quarantined
    view of the content (offending spans stripped, fenced as untrusted DATA).

    Args:
        content: the text or HTML to scan.
        kind: ``"text"`` or ``"page"`` (HTML).
        source: the URL the content came from, if known (improves page analysis).
    """
    if not isinstance(content, str):
        raise ValueError("content must be a string")
    if len(content) > MAX_PAGE_BYTES:
        raise ValueError(f"content exceeds the {MAX_PAGE_BYTES}-byte limit")
    kind = (kind or "text").lower()
    if kind not in ("text", "page"):
        raise ValueError("kind must be 'text' or 'page'")
    decision = await get_guard().check_content(content, kind=kind, source=source)
    return decision.to_dict()


async def check_tool_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Vet a proposed tool call's arguments for exfiltration / tool-abuse before it runs.

    Args:
        name: the tool being called.
        arguments: the proposed arguments (inspected for URLs, file paths and shell-ish
            strings that exfiltrate data or abuse a tool).
    """
    if not isinstance(name, str):
        raise ValueError("name must be a string")
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, (dict, list, str)):
        raise ValueError("arguments must be an object, array or string")
    decision = await get_guard().check_tool_call(name, arguments)
    return decision.to_dict()


async def export_stix(kind: str, target: str, online: bool = False,
                      validate: bool = False) -> dict[str, Any]:
    """Scan ``target`` and export the verdict as a STIX 2.1 bundle (shareable CTI).

    Args:
        kind: ``"url"``, ``"text"``, ``"email"`` or ``"page"``.
        target: the artifact to scan (a URL, message, raw email, or HTML page).
        online: request network enrichment (subject to the server's network policy).
        validate: validate the bundle with the ``stix2`` library when installed.
    """
    from uniphish.export.stix import to_stix_bundle

    kind = (kind or "").lower()
    if kind not in ("url", "text", "email", "page"):
        raise ValueError("kind must be one of: url, text, email, page")
    verdict = await _scan(kind, target, online=online)
    bundle = to_stix_bundle(verdict, validate=bool(validate))
    return {"verdict": verdict_payload(verdict), "stix": bundle}


# --------------------------------------------------------------------------- #
# Server assembly
# --------------------------------------------------------------------------- #
_HANDLERS = (scan_url, scan_text, scan_email, scan_file, check_content,
             check_tool_call, export_stix)


def build_server() -> Any:
    """Build the MCP server with every tool registered.

    Imports the optional ``mcp`` package lazily and raises a clear :class:`RuntimeError`
    when it is not installed, so importing this module stays free of the dependency.
    """
    try:
        from mcp.server.mcpserver import MCPServer as _Server  # mcp >= 2
    except ImportError:
        try:
            from mcp.server.fastmcp import FastMCP as _Server  # mcp 1.x
        except ImportError as exc:
            raise RuntimeError(
                "The 'mcp' package is required to run the AgentGuard MCP server. "
                "Install it with:  uv pip install --python .venv/bin/python 'mcp>=1.2'  "
                "(or install the extra:  pip install 'uniphish[mcp]')."
            ) from exc

    server = _Server(name=SERVER_NAME, instructions=INSTRUCTIONS, version=__version__)
    for handler in _HANDLERS:
        server.tool()(handler)
    return server


def main(argv: list[str] | None = None) -> None:
    """Console entry point: run the AgentGuard MCP server over stdio."""
    logging.basicConfig(level=logging.WARNING)
    server = build_server()
    server.run()


if __name__ == "__main__":  # pragma: no cover - module execution path
    main()
