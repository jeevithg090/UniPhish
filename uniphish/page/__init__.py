"""Page (HTML document) analysis helpers: structural parsing and favicon fingerprints."""

from __future__ import annotations

from uniphish.page.favicon import favicon_mmh3, known_favicon_brand
from uniphish.page.html import (
    FormModel,
    IframeRef,
    ImageRef,
    LinkRef,
    MetaInfo,
    PageModel,
    ScriptEntropy,
    ScriptRef,
    parse_html,
)

__all__ = [
    "FormModel",
    "IframeRef",
    "ImageRef",
    "LinkRef",
    "MetaInfo",
    "PageModel",
    "ScriptEntropy",
    "ScriptRef",
    "favicon_mmh3",
    "known_favicon_brand",
    "parse_html",
]
