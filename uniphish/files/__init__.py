"""Static file/attachment analysis and QR decoding (quishing).

    from uniphish.files import analyze_file, sniff, decode_qr, qr_payload_urls

Imports are light: heavy optional dependencies (OpenCV, oletools) load lazily inside
the functions that need them.
"""

from __future__ import annotations

from uniphish.files.qr import QRCode, classify_payload, decode_qr, qr_available, qr_payload_urls
from uniphish.files.static import (
    INDICATOR_CATALOG,
    FileAnalysis,
    FileFacts,
    FileIndicator,
    analyze_file,
    sniff,
)

__all__ = [
    "INDICATOR_CATALOG", "FileAnalysis", "FileFacts", "FileIndicator", "QRCode",
    "analyze_file", "classify_payload", "decode_qr", "qr_available", "qr_payload_urls", "sniff",
]
