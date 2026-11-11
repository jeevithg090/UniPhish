"""Static, execution-free inspection of attachments and downloads.

Why: most phishing delivered as a *file* is recognisable from its structure alone — a
PE wearing a ``.pdf`` name, an encrypted zip holding one ``.lnk``, an SVG with
``<script>``, an HTML page that assembles an EXE from base64. This module sniffs the
true type from magic bytes, computes hashes/entropy, checks filename tricks
(double extension, RTLO), then dispatches to per-format inspectors that add
indicators and extract URLs for the engine to analyse as children.

Safety: bytes are only read — never executed, never extracted to disk. Archives are
listed from their central directory, XML is parsed with ``defusedxml``, every scan is
length-bounded and optional dependencies (oletools, olefile) degrade to a ``notes``
entry instead of an exception.

Public API: :func:`sniff`, :func:`analyze_file`, :class:`FileFacts`,
:class:`FileAnalysis`, :data:`INDICATOR_CATALOG`.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

from uniphish.core.types import MAX_FILE_BYTES
from uniphish.files import _archive, _markup, _office, _pdf, _script
from uniphish.files._common import (
    INDICATOR_CATALOG,
    MAX_SCAN_BYTES,
    FileIndicator,
    Findings,
    sniff_magic,
)
from uniphish.files._names import (
    EXECUTABLE_EXTS,
    SCRIPT_EXTS,
    inspect_filename,
)

log = logging.getLogger("uniphish.files")

__all__ = ["INDICATOR_CATALOG", "FileAnalysis", "FileFacts", "FileIndicator", "analyze_file",
           "sniff"]

_EXPECTED_EXTS: dict[str, frozenset[str]] = {
    "pe": frozenset({"exe", "dll", "sys", "scr", "cpl", "ocx", "drv", "efi", "pif", "com",
                     "mui", "ax", "tsp", "msstyles"}),
    "dos": frozenset({"exe", "com", "dll", "sys", "scr", "pif"}),
    "elf": frozenset({"so", "elf", "bin", "out", "o", "ko", "axf", "run"}),
    "macho": frozenset({"dylib", "bundle", "o", "bin", "app"}),
    "pdf": frozenset({"pdf", "ai", "fdf"}),
    "ole": frozenset({"doc", "xls", "ppt", "dot", "xlt", "pot", "pps", "xla", "ppa", "msi",
                      "msp", "msg", "pub", "vsd", "mpp", "wiz", "db", "hwp", "mdi", "ost",
                      "pst", "sdw", "xlm", "mpt"}),
    "ooxml": frozenset({"docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xlsb", "xltx", "xltm",
                        "xlam", "pptx", "pptm", "potx", "potm", "ppsx", "ppsm", "ppam", "sldx",
                        "sldm", "vsdx", "vsdm", "vssx", "thmx"}),
    "zip": frozenset({"zip", "zipx", "odt", "ods", "odp", "odg", "epub", "xpi", "crx", "nupkg",
                      "whl", "vsix", "kmz", "xps", "oxps", "3mf", "idml", "sketch", "key",
                      "pages", "numbers", "aar", "war", "ear", "apk", "jar"}),
    "jar": frozenset({"jar", "war", "ear", "zip", "apk", "aar"}),
    "apk": frozenset({"apk", "zip", "aab", "xapk"}),
    "rar": frozenset({"rar", "cbr"}),
    "7z": frozenset({"7z"}),
    "gzip": frozenset({"gz", "tgz", "svgz", "gzip", "emz", "wmz"}),
    "bzip2": frozenset({"bz2", "tbz2", "tbz"}),
    "xz": frozenset({"xz", "txz"}),
    "tar": frozenset({"tar"}),
    "cab": frozenset({"cab"}),
    "iso": frozenset({"iso", "img"}),
    "lnk": frozenset({"lnk"}),
    "rtf": frozenset({"rtf"}),
    "onenote": frozenset({"one", "onetoc2"}),
    "png": frozenset({"png"}),
    "jpeg": frozenset({"jpg", "jpeg", "jpe", "jfif"}),
    "gif": frozenset({"gif"}),
    "bmp": frozenset({"bmp", "dib"}),
    "webp": frozenset({"webp"}),
    "tiff": frozenset({"tif", "tiff"}),
    "ico": frozenset({"ico", "cur"}),
    "html": frozenset({"html", "htm", "xhtml", "xht", "shtml", "hta", "html5"}),
    "svg": frozenset({"svg"}),
    "xml": frozenset({"xml", "xsl", "xslt", "rss", "atom", "xsd", "plist", "config", "manifest",
                      "svg", "vml", "xaml", "csproj", "resx", "rels", "wsdl", "kml", "gpx"}),
    "script": SCRIPT_EXTS | frozenset({"txt", "sh", "bash", "pl", "rb", "php", "ps1", "psd1"}),
}
# Extensions that claim a structured binary format; plain text under one of these is fake.
_BINARY_CLAIM_EXTS = frozenset(
    set().union(*(_EXPECTED_EXTS[k] for k in
                  ("pe", "pdf", "ole", "ooxml", "zip", "rar", "7z", "png", "jpeg", "gif",
                   "bmp", "webp", "tiff", "ico", "cab", "iso", "gzip", "lnk", "onenote"))))
_TEXT_TYPES = frozenset({"text", "unknown", "empty"})
_MIME = {
    "pe": "application/vnd.microsoft.portable-executable", "dos": "application/x-msdownload",
    "elf": "application/x-elf", "macho": "application/x-mach-binary", "pdf": "application/pdf",
    "ole": "application/x-ole-storage", "ooxml": "application/vnd.openxmlformats-officedocument",
    "zip": "application/zip", "jar": "application/java-archive",
    "apk": "application/vnd.android.package-archive",
    "rar": "application/vnd.rar", "7z": "application/x-7z-compressed", "gzip": "application/gzip",
    "bzip2": "application/x-bzip2", "xz": "application/x-xz", "tar": "application/x-tar",
    "cab": "application/vnd.ms-cab-compressed", "iso": "application/x-iso9660-image",
    "lnk": "application/x-ms-shortcut", "rtf": "application/rtf", "onenote": "application/onenote",
    "png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif", "bmp": "image/bmp",
    "webp": "image/webp", "tiff": "image/tiff", "ico": "image/vnd.microsoft.icon",
    "html": "text/html", "svg": "image/svg+xml", "xml": "application/xml",
    "script": "text/plain", "text": "text/plain",
}
_EXEC_TYPES = frozenset({"pe", "dos", "elf", "macho"})
_DISGUISE_TYPES = _EXEC_TYPES | {"lnk"}
_DISK_IMAGE_EXTS = frozenset({"iso", "img", "vhd", "vhdx"})


@dataclass
class FileFacts:
    """Objective facts about a file (no judgement)."""

    filename: str | None
    detected_type: str
    declared_ext: str
    ext_mismatch: bool
    double_extension: bool
    rtlo_in_name: bool
    size: int
    sha256: str
    sha1: str
    md5: str
    entropy: float
    mime: str = "application/octet-stream"
    bidi_in_name: bool = False
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class FileAnalysis:
    """Facts + indicators + URLs for the engine to analyse as children.

    ``indicators`` holds :class:`FileIndicator` objects; use ``as_tuples()`` for the plain
    ``(code, detail, weight_hint)`` form.
    """

    facts: FileFacts
    indicators: list[FileIndicator] = field(default_factory=list)
    child_urls: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_tuples(self) -> list[tuple[str, str, float]]:
        return [i.as_tuple() for i in self.indicators]

    def to_dict(self) -> dict[str, Any]:
        return {"facts": self.facts.to_dict(),
                "indicators": [i.to_dict() for i in self.indicators],
                "child_urls": list(self.child_urls), "notes": list(self.notes)}


# --------------------------------------------------------------------------- #
# Facts
# --------------------------------------------------------------------------- #
def _entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8)."""
    if not data:
        return 0.0
    import numpy as np

    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())


_HTML_MARKERS = ("<!doctype html", "<html", "<head", "<body", "<script", "<form", "<iframe",
                 "<meta ", "<title", "<div", "<table", "<a href", "<img ", "<style", "<hta:")


def _sniff_text_type(data: bytes, ext: str) -> str:
    head = data[:4096]
    if not head:
        return "empty"
    if head.count(b"\x00") > len(head) // 3 and not head.startswith((b"\xff\xfe", b"\xfe\xff")):
        # BOM-less UTF-16 text still decodes sensibly; real binary does not.
        text = _script.decode_text(head)
    elif b"\x00" in head and not head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "unknown"
    else:
        text = _script.decode_text(head)
    low = text.lstrip("﻿ \t\r\n").lower()
    if low.startswith("<?xml") or low.startswith("<svg") or "<svg" in low[:2048]:
        if "<svg" in low[:4096]:
            return "svg"
        return "xml"
    if any(m in low[:4096] for m in _HTML_MARKERS) and low.startswith(("<", "<!")):
        return "html"
    if any(m in low[:4096] for m in _HTML_MARKERS) and ext in {"html", "htm", "hta"}:
        return "html"
    if low.startswith("#!") or ext in SCRIPT_EXTS:
        return "script"
    if low.startswith(("param(", "$ps", "function ", "set-", "import-module")):
        return "script"
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return "text" if printable >= 0.85 * max(len(text), 1) else "unknown"


def _detect(data: bytes, ext: str) -> tuple[str, _archive.ZipListing | None]:
    head = data[:0x8010]
    kind = sniff_magic(head)
    if kind == "zip":
        listing = _archive.list_zip(data)
        return (_archive.zip_flavor(listing) if listing.ok and not listing.too_many else "zip",
                listing)
    if kind is not None:
        return kind, None
    return _sniff_text_type(data, ext), None


def _ext_mismatch(detected: str, ext: str) -> bool:
    if not ext:
        return False
    expected = _EXPECTED_EXTS.get(detected)
    if expected is None:
        return detected in _TEXT_TYPES and detected != "empty" and ext in _BINARY_CLAIM_EXTS
    if detected == "script":
        return ext in _BINARY_CLAIM_EXTS
    if detected == "html" and ext in {"txt", "xml", "php", "asp", "aspx", "jsp", "eml", "mht",
                                      "mhtml", "svg"}:
        return False
    return ext not in expected


def _facts(data: bytes, filename: str | None) -> tuple[FileFacts, _archive.ZipListing | None]:
    nf = inspect_filename(filename)
    scan = data[:MAX_FILE_BYTES]
    detected, listing = _detect(scan, nf.declared_ext)
    facts = FileFacts(
        filename=filename,
        detected_type=detected,
        declared_ext=nf.declared_ext,
        ext_mismatch=_ext_mismatch(detected, nf.declared_ext),
        double_extension=nf.double_extension,
        rtlo_in_name=nf.rtlo,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        sha1=hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        entropy=round(_entropy(data), 4),
        mime=_MIME.get(detected, "application/octet-stream"),
        bidi_in_name=nf.bidi,
        truncated=len(data) > MAX_FILE_BYTES,
    )
    return facts, listing


def sniff(data: bytes, filename: str | None = None) -> FileFacts:
    """Identify a file by content (magic bytes) and compute hashes/entropy/name checks."""
    return _facts(bytes(data), filename)[0]


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def _name_indicators(facts: FileFacts, nf_ext: str, f: Findings) -> None:
    name = facts.filename or ""
    if facts.rtlo_in_name:
        f.add("file.rtlo_filename",
              f"The filename {name!r} contains a right-to-left override character that "
              "reverses how its extension is displayed.", filename=name)
    if facts.double_extension:
        nf = inspect_filename(name)
        f.add("file.double_extension",
              f"{name!r} ends in '.{nf.declared_ext}' but is dressed up as '.{nf.decoy_ext}'.",
              decoy=nf.decoy_ext, real=nf.declared_ext)
    if facts.ext_mismatch:
        if facts.detected_type in _DISGUISE_TYPES and nf_ext not in EXECUTABLE_EXTS:
            f.add("file.disguised_executable",
                  f"The content is a {facts.detected_type.upper()} program/shortcut but the "
                  f"name says '.{nf_ext}'.", detected=facts.detected_type, declared=nf_ext)
        else:
            f.add("file.ext_mismatch",
                  f"The content looks like {facts.detected_type.upper()} but the extension is "
                  f"'.{nf_ext}'.", detected=facts.detected_type, declared=nf_ext)


def _dispatch(data: bytes, facts: FileFacts, listing: _archive.ZipListing | None,
              f: Findings) -> None:
    t = facts.detected_type
    ext = facts.declared_ext
    if t in _EXEC_TYPES:
        f.add("file.type.executable", f"The file is a {t.upper()} executable.", detected=t)
        if facts.entropy > 7.2 and facts.size > 20_000:
            f.add("file.executable.packed",
                  f"Entropy {facts.entropy:.2f} bits/byte suggests packing or encryption.",
                  entropy=facts.entropy)
    elif t == "lnk":
        f.add("file.type.shortcut", "The file is a Windows shortcut (.lnk).")
        _script.analyze_lnk(data, f)
    elif t == "iso" or ext in _DISK_IMAGE_EXTS:
        f.add("file.type.disk_image", "Disk images mount without mark-of-the-web protection.")
    elif t == "onenote":
        f.add("file.type.onenote", "OneNote files can hide launchable embedded objects.")
    elif t == "script" or (t == "html" and ext == "hta"):
        f.add("file.type.script", f"The file is a script/launcher ('.{ext or 'script'}').",
              declared=ext)
        if t == "script":
            _script.analyze_script(data, f)
    if t == "ooxml":
        _office.analyze_ooxml(data, f)
        if listing is not None:
            _archive.analyze_zip(listing, f)
    elif t in ("zip", "jar", "apk") and listing is not None:
        _archive.analyze_zip(listing, f)
    elif t == "ole":
        _office.analyze_ole(data, f)
    elif t == "pdf":
        _pdf.analyze_pdf(data, f)
    elif t == "html":
        _markup.analyze_html(data, f)
    elif t == "svg":
        _markup.analyze_svg(data, f)
    elif t in ("rar", "7z", "gzip", "bzip2", "xz", "tar", "cab"):
        f.note(f"{t} archives are not listed (only zip is inspected structurally)")
    elif t == "rtf":
        f.add_urls_from_text(data[:MAX_SCAN_BYTES].decode("latin-1"))
    elif t in ("text", "xml"):
        f.add_urls_from_text(_script.decode_text(data))


def analyze_file(data: bytes, filename: str | None = None) -> FileAnalysis:
    """Inspect a file statically. Never raises on malformed input and never executes it.

    Returns :class:`FileAnalysis` with facts, indicators ``(code, detail, weight_hint)``
    and ``child_urls`` (http/https/ftp URLs found inside).
    """
    data = bytes(data)
    facts, listing = _facts(data, filename)
    f = Findings()
    if facts.truncated:
        f.note(f"file exceeds {MAX_FILE_BYTES} bytes; only the first part was inspected")
        data = data[:MAX_FILE_BYTES]
    try:
        _name_indicators(facts, facts.declared_ext, f)
    except Exception:  # pragma: no cover - defensive
        log.debug("filename checks failed", exc_info=True)
    try:
        _dispatch(data, facts, listing, f)
    except Exception as e:  # inspectors must never take the engine down
        log.warning("static analysis of %s failed: %s", facts.detected_type, e, exc_info=True)
        f.note(f"{facts.detected_type} inspection aborted ({type(e).__name__})")
    return FileAnalysis(facts=facts, indicators=f.indicators, child_urls=f.urls, notes=f.notes)
