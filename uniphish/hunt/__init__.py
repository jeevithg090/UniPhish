"""Threat hunting: Certificate Transparency firehose monitoring.

Submodules are imported lazily so ``import uniphish.hunt`` stays cheap (the live
firehose needs the optional ``websockets`` package, imported only when used).
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_LAZY = {
    "CTHunter": "ct",
    "HuntHit": "ct",
    "HuntStats": "ct",
    "stream_certstream": "ct",
    "parse_record": "ct",
    "clean_domain": "ct",
    "CERTSTREAM_URL": "ct",
    "SAMPLE_DOMAINS": "ct",
}
__all__ = sorted(_LAZY)


def __getattr__(name: str) -> Any:
    if name in _LAZY:
        return getattr(import_module(f"uniphish.hunt.{_LAZY[name]}"), name)
    raise AttributeError(name)
