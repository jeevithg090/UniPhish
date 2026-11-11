"""Packaged data assets (brand knowledge base, threat lists, Unicode tables, model, rules).

    from uniphish.assets import load_yaml, load_json, asset_path
    brands = load_yaml("brands.yaml")

Loads are cached; treat returned objects as read-only.
"""

from __future__ import annotations

import gzip
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

ASSETS_DIR = Path(__file__).resolve().parent


def asset_path(*parts: str) -> Path:
    """Absolute path of a packaged asset (path traversal outside ASSETS_DIR is refused)."""
    p = ASSETS_DIR.joinpath(*parts).resolve()
    if ASSETS_DIR not in p.parents and p != ASSETS_DIR:
        raise ValueError(f"asset path escapes assets dir: {parts!r}")
    return p


def _read_text(path: Path) -> str:
    if path.suffix == ".gz":
        return gzip.decompress(path.read_bytes()).decode("utf-8")
    return path.read_text(encoding="utf-8")


# Prefer libyaml's C loader when available: a cold parse of the 150 KB+ brand
# knowledge base is ~10x faster with it (~0.3 s vs ~3 s), which keeps the first URL
# scan inside the per-analyzer time budget.
_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


@lru_cache(maxsize=128)
def load_yaml(*parts: str) -> Any:
    # _YAML_LOADER is CSafeLoader/SafeLoader (never the unsafe full loader); ruff cannot
    # see that statically.
    return yaml.load(_read_text(asset_path(*parts)), Loader=_YAML_LOADER)  # noqa: S506


@lru_cache(maxsize=128)
def load_json(*parts: str) -> Any:
    return json.loads(_read_text(asset_path(*parts)))


@lru_cache(maxsize=64)
def load_lines(*parts: str) -> tuple[str, ...]:
    """Non-empty, non-comment lines of a text asset (``.txt`` or ``.txt.gz``)."""
    out = []
    for line in _read_text(asset_path(*parts)).splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return tuple(out)
