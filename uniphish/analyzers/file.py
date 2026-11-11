"""File / attachment analyzer: turns static file inspection into explainable signals.

Why this exists: most phishing payloads arrive as an attachment (double-extension
executables, macro documents, password-protected archives, HTML/SVG smuggling pages,
QR-code images). :mod:`uniphish.files` does the byte-level inspection and returns
objective facts plus calibrated indicators; this module is the thin, honest adapter
that maps them onto the engine's :class:`~uniphish.core.types.Signal` model, extracts
IOCs (hashes, filename, embedded URLs/domains) and spawns child artifacts so every
URL hiding inside a file is analysed like any other link.

Nothing here executes or renders the file, and no network is touched. Optional
dependencies (oletools, OpenCV) degrade to a signal-free note in ``meta["file_notes"]``.
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from uniphish.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult, register
from uniphish.core.types import (
    Artifact,
    ArtifactKind,
    Indicator,
    IndicatorType,
    Signal,
)
from uniphish.files import INDICATOR_CATALOG, analyze_file, qr_available, qr_payload_urls

log = logging.getLogger("uniphish.analyzers.file")

#: Image formats worth scanning for QR codes (quishing).
_IMAGE_TYPES = frozenset({"png", "jpeg", "gif", "bmp", "webp", "tiff"})
#: Container formats whose contents lose mark-of-the-web protection when opened.
_MOTW_TYPES = frozenset({"iso", "7z", "rar", "zip", "cab"})
_MAX_QR_URLS = 10
_MAX_DOMAINS = 50
_MAX_TITLE = 70

QR_SIGNAL = "qr.url_in_image"

_SIGNALS: dict[str, str] = {code: spec[0][:_MAX_TITLE] for code, spec in INDICATOR_CATALOG.items()}
_SIGNALS[QR_SIGNAL] = "Image carries a QR code that points to a web address"


def _host_indicator(url: str) -> Indicator | None:
    """DOMAIN (or IP) indicator for the host of ``url``; None if unparseable."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.lower().rstrip(".")
    if ":" in host:
        return Indicator(type=IndicatorType.IPV6, value=host, role="embedded")
    if host.replace(".", "").isdigit():
        return Indicator(type=IndicatorType.IPV4, value=host, role="embedded")
    return Indicator(type=IndicatorType.DOMAIN, value=host, role="embedded")


@register
class FileAnalyzer(Analyzer):
    """Static analysis of attachments, downloads and images (incl. QR quishing)."""

    name = "file"
    kinds = frozenset({ArtifactKind.FILE})
    stage = 0
    requires_online = False
    blocking = True
    description = ("Attachments: disguised executables, macros, encrypted archives, HTML/SVG "
                   "smuggling, PDF actions, QR codes; extracts embedded URLs as children")
    signals = _SIGNALS

    def applies(self, artifact: Artifact, ctx: AnalysisContext) -> bool:
        return artifact.content is not None

    def analyze_sync(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        data = artifact.content
        if data is None:
            return AnalyzerResult()
        res = AnalyzerResult()
        notes: list[str] = []
        try:
            fa = analyze_file(data, artifact.filename)
        except Exception as e:  # analyze_file never raises; belt and braces
            log.warning("file analysis failed: %s", e, exc_info=True)
            res.meta["file_notes"] = [f"static analysis failed ({type(e).__name__})"]
            return res
        facts = fa.facts
        notes.extend(fa.notes)

        for ind in fa.indicators:
            res.signals.append(Signal(
                id=ind.code, title=ind.title[:_MAX_TITLE], detail=ind.detail,
                weight=ind.weight, category="file", mitre=list(ind.mitre),
                evidence=dict(ind.evidence)))

        # ---- children: URLs found inside the file ------------------------------ #
        seen: set[str] = set()
        for u in fa.child_urls:
            if u in seen:
                continue
            seen.add(u)
            try:
                res.children.append(Artifact.from_url(u, origin="file.url", parent_id=artifact.id))
            except ValueError:
                continue

        # ---- QR codes in images ------------------------------------------------ #
        qr_urls: list[str] = []
        if facts.detected_type in _IMAGE_TYPES:
            if not qr_available():
                notes.append("OpenCV not installed; QR decoding skipped")
            else:
                try:
                    qr_urls = qr_payload_urls(data)[:_MAX_QR_URLS]
                except Exception as e:  # pragma: no cover - decode_qr never raises
                    notes.append(f"QR decoding failed ({type(e).__name__})")
        if qr_urls:
            in_email = (ctx.parent is not None and ctx.parent.kind is ArtifactKind.EMAIL) or \
                (artifact.origin or "").startswith("email")
            res.signals.append(Signal(
                id=QR_SIGNAL, title=_SIGNALS[QR_SIGNAL],
                detail=("The image contains a QR code that opens "
                        + ", ".join(qr_urls[:3])
                        + (" ..." if len(qr_urls) > 3 else "")
                        + ". QR codes in messages are a common way to hide a phishing link "
                          "from URL scanners (quishing)."),
                weight=1.0 if in_email else 0.4, category="file", mitre=["T1566.002"],
                evidence={"urls": qr_urls, "email_context": in_email}))
            for u in qr_urls:
                try:
                    res.children.append(
                        Artifact.from_url(u, origin="qr", parent_id=artifact.id))
                except ValueError:
                    continue

        # ---- indicators --------------------------------------------------------- #
        res.indicators.extend([
            Indicator(type=IndicatorType.SHA256, value=facts.sha256, role="payload"),
            Indicator(type=IndicatorType.SHA1, value=facts.sha1, role="payload"),
            Indicator(type=IndicatorType.MD5, value=facts.md5, role="payload"),
        ])
        if facts.filename:
            res.indicators.append(Indicator(type=IndicatorType.FILENAME, value=facts.filename,
                                            role="payload"))
        domains: set[str] = set()
        for u in list(fa.child_urls) + qr_urls:
            role = "qr" if u in qr_urls and u not in fa.child_urls else "embedded"
            res.indicators.append(Indicator(type=IndicatorType.URL, value=u, role=role))
            h = _host_indicator(u)
            if h and h.value not in domains and len(domains) < _MAX_DOMAINS:
                domains.add(h.value)
                h.role = role
                res.indicators.append(h)

        if facts.detected_type in _MOTW_TYPES:
            notes.append("container format: contents extracted from it may lose "
                         "mark-of-the-web protection")

        res.meta.update({
            "detected_type": facts.detected_type,
            "declared_ext": facts.declared_ext,
            "ext_mismatch": facts.ext_mismatch,
            "double_extension": facts.double_extension,
            "mime": facts.mime,
            "sha256": facts.sha256,
            "sha1": facts.sha1,
            "md5": facts.md5,
            "size": facts.size,
            "entropy": round(facts.entropy, 3),
            "file_notes": notes,
            "embedded_url_count": len(fa.child_urls),
            "qr_urls": qr_urls,
        })
        if facts.filename:
            res.meta["filename"] = facts.filename
        return res
