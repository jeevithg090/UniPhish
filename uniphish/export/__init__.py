"""Detection-as-code / CTI exporters (STIX 2.1, MISP, ...).

Submodules are imported lazily so importing ``uniphish.export`` stays cheap.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_LAZY = {
    "to_stix_bundle": "stix", "bundle_many": "stix", "stix_pattern": "stix",
    "taxii_envelope": "stix", "validate_bundle": "stix",
    "to_misp_event": "misp", "to_misp_feed": "misp", "misp_feed_files": "misp",
}
__all__ = sorted(_LAZY)


def __getattr__(name: str) -> Any:
    if name in _LAZY:
        return getattr(import_module(f"uniphish.export.{_LAZY[name]}"), name)
    raise AttributeError(name)
