"""UniPhish — open-source, AI-native anti-phishing platform.

Quick start::

    import uniphish
    v = uniphish.scan_url("https://pаypal.com/signin")      # Cyrillic 'а'
    print(v.level.value, v.score, v.summary)

    v = uniphish.scan_email(open("suspicious.eml", "rb").read())
    for child in v.children:                                # links, attachments, QR codes
        print(child.kind.value, child.level.value, child.target)

Everything runs offline by default; pass ``online=True`` to enable DNS / RDAP / TLS /
feed enrichment and ``fetch_pages=True`` / ``detonate=True`` for active analysis.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__version__ = "2.0.0"

if TYPE_CHECKING:  # pragma: no cover
    from uniphish.core.types import Verdict


def _engine():
    from uniphish.core.engine import default_engine

    return default_engine()


def _run(artifact, opts: dict[str, Any]) -> Verdict:
    from uniphish.core.analyzer import AnalysisOptions

    return _engine().analyze_sync(artifact, AnalysisOptions.from_dict(opts))


def scan_url(url: str, **opts: Any) -> Verdict:
    """Analyse a URL and return an explainable :class:`~uniphish.core.types.Verdict`."""
    from uniphish.core.types import Artifact

    return _run(Artifact.from_url(url), opts)


def scan_text(text: str, **opts: Any) -> Verdict:
    """Analyse a message (SMS, chat, LLM context) for phishing / social engineering /
    prompt injection; contained URLs are analysed as children."""
    from uniphish.core.types import Artifact

    return _run(Artifact.from_text(text), opts)


def scan_email(raw: bytes | str, **opts: Any) -> Verdict:
    """Analyse a raw RFC 5322 email (.eml)."""
    from uniphish.core.types import Artifact

    return _run(Artifact.from_email(raw), opts)


def scan_page(html: str | bytes, url: str | None = None, **opts: Any) -> Verdict:
    """Analyse an HTML document (optionally with the URL it was served from)."""
    from uniphish.core.types import Artifact

    return _run(Artifact.from_page(html, url), opts)


def scan_file(data: bytes, filename: str | None = None, **opts: Any) -> Verdict:
    """Analyse a file / attachment / image (QR codes are decoded and followed)."""
    from uniphish.core.types import Artifact

    return _run(Artifact.from_file(data, filename), opts)


__all__ = ["__version__", "scan_email", "scan_file", "scan_page", "scan_text", "scan_url"]
