"""AgentGuard — UniPhish for AI agents.

Two faces of the same offline detection engine, aimed at protecting autonomous agents
rather than people:

* :class:`~uniphish.agent.guard.AgentGuard` — a policy/guard API an agent calls before
  it acts (:meth:`~uniphish.agent.guard.AgentGuard.check_url`,
  :meth:`~uniphish.agent.guard.AgentGuard.check_content`,
  :meth:`~uniphish.agent.guard.AgentGuard.check_tool_call`), each returning an
  explainable :class:`~uniphish.agent.guard.GuardDecision`.
* :mod:`uniphish.agent.mcp_server` — a Model Context Protocol (stdio) server exposing
  those checks and the scanners as MCP tools (``python -m uniphish.agent.mcp_server``).

The guard imports cleanly with no optional dependencies. The MCP server needs the
``mcp`` package (``uniphish[mcp]``); it is imported lazily, so importing this package or
``uniphish.agent.mcp_server`` never requires ``mcp`` until you actually
:func:`~uniphish.agent.mcp_server.build_server`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from uniphish.agent.guard import AgentGuard, GuardDecision, GuardPolicy

if TYPE_CHECKING:  # pragma: no cover
    from uniphish.agent.mcp_server import build_server, main

__all__ = ["AgentGuard", "GuardDecision", "GuardPolicy", "build_server", "main"]


def __getattr__(name: str) -> Any:
    """Lazily expose the MCP server factory without importing ``mcp`` at package load."""
    if name in ("build_server", "main"):
        from uniphish.agent import mcp_server

        return getattr(mcp_server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
