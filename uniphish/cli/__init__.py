"""UniPhish command line interface (Typer app ``uniphish``; see :mod:`uniphish.cli.main`).

The app is imported lazily so ``import uniphish.cli`` stays cheap.
"""

from __future__ import annotations

from typing import Any

__all__ = ["app"]


def __getattr__(name: str) -> Any:
    if name == "app":
        from uniphish.cli.main import app

        return app
    raise AttributeError(name)
