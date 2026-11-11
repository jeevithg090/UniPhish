"""Optional LLM analyst: SOC narrative and structured second-opinion triage.

Why: explainable verdicts are great for machines; analysts want a ticket-ready paragraph
and a quick second opinion. This layer is strictly optional and never raises: with no
API key, no ``anthropic`` SDK, a timeout, a rate limit or any API error, it returns a
deterministic template built from the :class:`~uniphish.core.types.Verdict` instead.
Only a compact defanged digest is sent to the model (see :mod:`uniphish.ai.prompts`).
"""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import re
from typing import Any

from uniphish.ai.prompts import (
    TRIAGE_TOOL,
    build_narrative_prompt,
    build_triage_prompt,
    defang,
)
from uniphish.core.config import Settings, get_settings
from uniphish.core.types import Level, Verdict

log = logging.getLogger("uniphish.ai")

_ACTIONS = {"allow", "warn", "block"}
_LEVELS = {"benign", "suspicious", "malicious"}
_MD_LINK_RE = re.compile(r"\[([^\]]{0,200})\]\((?:https?|hxxps?)://[^)\s]{0,500}\)", re.IGNORECASE)
_URL_RE = re.compile(r"\b(?:https?)://", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>\n]{0,200}>")


def _sanitize_output(text: str, limit: int = 2000) -> str:
    """Make model output safe to paste into a ticket: no live links, no HTML."""
    s = _MD_LINK_RE.sub(lambda m: m.group(1), text)
    s = _TAG_RE.sub("", s)
    s = _URL_RE.sub(
        lambda m: "hxxps://" if m.group(0).lower().startswith("https") else "hxxp://", s)
    return s.strip()[:limit]


class AIAnalyst:
    """LLM-backed analyst with a deterministic fallback.

    Args:
        settings: defaults to :func:`uniphish.core.config.get_settings`.
        client: optional pre-built async Anthropic-compatible client (used by tests).
        timeout_s: per-request timeout.
        max_concurrency: cap on simultaneous API calls (rate-limit friendly).
    """

    def __init__(self, settings: Settings | None = None, *, client: Any = None,
                 timeout_s: float = 20.0, max_concurrency: int = 4) -> None:
        self.settings = settings or get_settings()
        self.timeout_s = timeout_s
        self._client = client
        self._sem: asyncio.Semaphore | None = None
        self._max_concurrency = max(1, max_concurrency)

    @property
    def available(self) -> bool:
        """True when an LLM call is possible (injected client, or key and SDK present)."""
        if self._client is not None:
            return True
        return bool(self.settings.anthropic_api_key) and \
            importlib.util.find_spec("anthropic") is not None

    # ------------------------------------------------------------------ #
    def _get_client(self) -> Any:
        if self._client is None:
            import anthropic  # local import: optional dependency

            self._client = anthropic.AsyncAnthropic(
                api_key=self.settings.anthropic_api_key, timeout=self.timeout_s, max_retries=2)
        return self._client

    def _semaphore(self) -> asyncio.Semaphore:
        if self._sem is None:
            self._sem = asyncio.Semaphore(self._max_concurrency)
        return self._sem

    async def _create(self, **kwargs: Any) -> Any:
        async with self._semaphore():
            return await asyncio.wait_for(
                self._get_client().messages.create(model=self.settings.ai_model, **kwargs),
                timeout=self.timeout_s + 5)

    # ------------------------------------------------------------------ #
    async def narrative(self, verdict: Verdict) -> str:
        """3-5 sentence SOC explanation of ``verdict``; template fallback, never raises."""
        if self.available:
            try:
                system, user = build_narrative_prompt(verdict)
                resp = await self._create(
                    max_tokens=400, temperature=0.2, system=system,
                    messages=[{"role": "user", "content": user}])
                text = "".join(getattr(b, "text", "") for b in resp.content
                               if getattr(b, "type", "text") == "text").strip()
                if text:
                    return _sanitize_output(text)
            except Exception as exc:
                log.warning("AI narrative failed (%s); using template", type(exc).__name__)
        return template_narrative(verdict)

    async def triage(self, verdict: Verdict) -> dict[str, Any]:
        """Structured second opinion; template fallback, never raises.

        Returns keys: assessment, confidence, recommended_action, notable_signals,
        rationale, source ("ai" or "template").
        """
        if self.available:
            try:
                system, user = build_triage_prompt(verdict)
                resp = await self._create(
                    max_tokens=500, temperature=0.0, system=system,
                    tools=[TRIAGE_TOOL],
                    tool_choice={"type": "tool", "name": TRIAGE_TOOL["name"]},
                    messages=[{"role": "user", "content": user}])
                for block in resp.content:
                    if getattr(block, "type", "") == "tool_use":
                        result = _validate_triage(getattr(block, "input", None))
                        if result is not None:
                            return result
            except Exception as exc:
                log.warning("AI triage failed (%s); using template", type(exc).__name__)
        return template_triage(verdict)


def _validate_triage(data: Any) -> dict[str, Any] | None:
    if not isinstance(data, dict):
        return None
    assessment = str(data.get("assessment", "")).lower()
    action = str(data.get("recommended_action", "")).lower()
    if assessment not in _LEVELS or action not in _ACTIONS:
        return None
    try:
        conf = min(1.0, max(0.0, float(data.get("confidence", 0.5))))
    except (TypeError, ValueError):
        conf = 0.5
    sigs = data.get("notable_signals")
    sigs = [_sanitize_output(str(s), 200) for s in sigs[:8]] if isinstance(sigs, list) else []
    return {"assessment": assessment, "confidence": round(conf, 2),
            "recommended_action": action, "notable_signals": sigs,
            "rationale": _sanitize_output(str(data.get("rationale", "")), 600),
            "source": "ai"}


# ---------------------------------------------------------------------- #
# Deterministic fallbacks
# ---------------------------------------------------------------------- #
_KIND_LABEL = {"url": "URL", "page": "web page", "email": "email", "file": "file",
               "text": "text message"}
_ACTION_TEXT = {
    "block": "Block it and do not interact with it; report it for takedown.",
    "warn": "Treat it with caution and verify through an official channel before acting.",
    "allow": "No action required; it appears legitimate.",
}


def template_narrative(verdict: Verdict) -> str:
    """Deterministic SOC narrative built only from the verdict (always non-empty)."""
    kind = _KIND_LABEL.get(verdict.kind.value, verdict.kind.value)
    target = defang(verdict.target, 120) or "(unnamed)"
    if verdict.level is Level.BENIGN:
        lead = (f"The {kind} {target} was assessed as benign "
                f"(risk {verdict.score}/100).")
    else:
        lead = (f"The {kind} {target} was assessed as {verdict.level.value} "
                f"(risk {verdict.score}/100).")
    parts = [lead]
    if verdict.brand and not verdict.brand.official:
        parts.append(f"It appears to impersonate {defang(verdict.brand.name, 80)} "
                     f"using a {verdict.brand.technique} technique.")
    elif verdict.brand and verdict.brand.official:
        parts.append(f"It matches an official {defang(verdict.brand.name, 80)} asset.")
    sigs = verdict.top_signals(3)
    if sigs:
        parts.append("Strongest evidence: " + "; ".join(defang(s.title, 100).rstrip(".")
                                                         for s in sigs) + ".")
    elif verdict.level is not Level.BENIGN:
        parts.append("No single signal dominates; the risk comes from combined weak evidence.")
    parts.append("Recommended action: "
                 + _ACTION_TEXT.get(verdict.action.value, "Review manually."))
    return " ".join(parts)


def template_triage(verdict: Verdict) -> dict[str, Any]:
    """Deterministic triage that mirrors the engine verdict."""
    return {
        "assessment": verdict.level.value,
        "confidence": round(verdict.confidence, 2),
        "recommended_action": verdict.action.value,
        "notable_signals": [defang(s.title, 200) for s in verdict.top_signals(5)],
        "rationale": template_narrative(verdict),
        "source": "template",
    }
