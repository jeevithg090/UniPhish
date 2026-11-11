"""Shared plumbing for static file analysis: indicator catalog, collector, magic bytes.

Why this module exists: every per-format inspector (archives, Office, PDF, HTML/SVG,
scripts) reports through the same small :class:`Findings` collector so that indicator
codes, default weights and MITRE mappings live in exactly one place
(:data:`INDICATOR_CATALOG`). The catalog doubles as the ``signals`` declaration for the
file analyzer, so the detection docs and dashboard never drift from the code.

Everything here treats the analysed bytes as hostile: it only reads, never executes,
and every scan is length-bounded.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger("uniphish.files")

# --------------------------------------------------------------------------- #
# Resource limits
# --------------------------------------------------------------------------- #
MAX_SCAN_BYTES = 16_000_000        # text/regex scans never look past this many bytes
MAX_CHILD_URLS = 100               # URLs returned for the engine to analyse as children
MAX_URL_CHARS = 2_048              # longer "URLs" are almost certainly data blobs
MAX_ARCHIVE_ENTRIES = 5_000        # archives with more entries are not listed
MAX_MEMBER_BYTES = 5_000_000       # cap when reading one member out of a container
MAX_RELS_FILES = 200               # OOXML relationship parts inspected
MAX_DECLARED_UNCOMPRESSED = 1 << 30  # 1 GiB declared size => "zip bomb" indicator

# --------------------------------------------------------------------------- #
# Indicator catalog: code -> (title, default log-odds weight hint, MITRE ids)
# --------------------------------------------------------------------------- #
INDICATOR_CATALOG: dict[str, tuple[str, float, tuple[str, ...]]] = {
    # --- type of delivery -------------------------------------------------- #
    "file.type.executable": ("Executable program delivered as a file", 3.0, ("T1204.002",)),
    "file.type.script": ("Script file (JS/VBS/PowerShell/batch/HTA) delivered as a file", 2.5,
                         ("T1204.002", "T1059.007")),
    "file.type.shortcut": ("Windows shortcut (.lnk) delivered as a file", 3.0, ("T1204.002",)),
    "file.type.disk_image": ("Disk image (ISO/IMG/VHD) used to dodge mark-of-the-web", 2.0,
                             ("T1553.005",)),
    "file.type.html_attachment": ("HTML document delivered as a file", 0.8, ("T1566.001",)),
    "file.type.onenote": ("OneNote file delivered as a file (embedded-object lure)", 1.5,
                          ("T1204.002",)),
    "file.executable.packed": ("Executable is packed or encrypted (very high entropy)", 1.0,
                               ("T1027",)),
    # --- name / extension tricks ------------------------------------------- #
    "file.ext_mismatch": ("File content does not match its extension", 2.5, ("T1036",)),
    "file.disguised_executable": ("Executable disguised under a harmless extension", 5.0,
                                  ("T1036", "T1204.002")),
    "file.double_extension": ("Double extension hides the real file type", 3.5, ("T1036.007",)),
    "file.rtlo_filename": ("Filename uses a right-to-left override to fake its extension", 4.5,
                           ("T1036",)),
    # --- archives ----------------------------------------------------------- #
    "file.archive.encrypted": ("Password-protected archive hides its contents from scanners",
                               2.0, ("T1027",)),
    "file.archive.nested": ("Archive contains another archive or disk image", 1.0, ("T1027",)),
    "file.archive.path_traversal": ("Archive entry names escape the extraction folder", 3.0, ()),
    "file.archive.single_payload": ("Archive wraps a single executable/script/shortcut/macro "
                                    "file", 2.5, ("T1204.002",)),
    "file.archive.executable_entry": ("Archive contains an executable or script entry", 1.5,
                                      ("T1204.002",)),
    "file.archive.disguised_entry": ("Archive entry has a double extension or RTLO name", 3.0,
                                     ("T1036.007",)),
    "file.archive.bomb": ("Archive declares an extreme expansion ratio (zip bomb)", 1.5, ()),
    "file.archive.too_many_entries": ("Archive has too many entries to inspect safely", 0.5, ()),
    "file.archive.malformed": ("Archive structure is corrupt or unreadable", 0.3, ()),
    # --- Office ------------------------------------------------------------- #
    "file.office.macro": ("Office document contains VBA macros", 2.5, ("T1204.002",)),
    "file.office.autoexec": ("Macro runs automatically when the document opens", 3.0,
                             ("T1204.002",)),
    "file.office.suspicious_keywords": ("Macro uses download/execute/obfuscation keywords", 2.0,
                                        ("T1059.001",)),
    "file.office.remote_template": ("Document loads a remote template (template injection)", 4.0,
                                    ("T1204.002",)),
    "file.office.external_object": ("Document links an external OLE object or frame", 2.0, ()),
    "file.office.protocol_handler": ("Document references a risky URL protocol handler", 5.0,
                                     ("T1204.002",)),
    "file.office.dde": ("Document uses DDE field execution", 4.0, ("T1204.002",)),
    "file.office.xlm_macro": ("Excel 4.0 (XLM) macro sheet present", 3.0, ("T1204.002",)),
    "file.office.embedded_object": ("Document embeds an OLE/ActiveX object", 1.5,
                                    ("T1027.009",)),
    # --- PDF ---------------------------------------------------------------- #
    "file.pdf.open_action": ("PDF runs an action automatically on open", 1.0, ()),
    "file.pdf.javascript": ("PDF contains JavaScript", 2.5, ("T1059.007",)),
    "file.pdf.launch": ("PDF can launch an external program or file", 3.5, ("T1204.002",)),
    "file.pdf.uri": ("PDF contains outbound link(s)", 0.4, ("T1566.002",)),
    "file.pdf.embedded_file": ("PDF embeds another file", 1.5, ("T1027.009",)),
    "file.pdf.submit_form": ("PDF form submits data to a remote server", 1.5, ()),
    "file.pdf.obfuscated_names": ("PDF keywords are hex-escaped to evade scanners", 2.0,
                                  ("T1027",)),
    # --- HTML / SVG --------------------------------------------------------- #
    "file.html.smuggling.payload": ("Embedded base64 blob decodes to an executable/archive", 5.5,
                                    ("T1027.006", "T1204.002")),
    "file.html.smuggling.pattern": ("Blob + download-anchor pattern (HTML smuggling)", 3.0,
                                    ("T1027.006",)),
    "file.html.password_form": ("Attached page contains a password field", 3.5,
                                ("T1056.003",)),
    "file.html.external_form_action": ("Attached page form posts to a remote URL", 2.0,
                                       ("T1056.003",)),
    "file.html.meta_refresh": ("Attached page redirects via meta refresh", 1.5, ()),
    "file.html.obfuscated_script": ("Heavily obfuscated script (eval/atob/escape chains)", 1.5,
                                    ("T1027",)),
    "file.html.large_base64": ("Very large base64 blob embedded in the document", 1.0, ()),
    "file.html.data_uri_navigation": ("Link/frame points at an embedded data: document", 2.0,
                                      ()),
    "file.svg.script": ("SVG image contains script", 3.5, ("T1059.007",)),
    "file.svg.foreign_object": ("SVG embeds HTML via foreignObject", 2.5, ()),
    "file.svg.external_ref": ("SVG loads external content", 1.5, ()),
    "file.svg.external_link": ("SVG is wrapped in a clickable external link", 1.0, ("T1566.002",)),
    "file.svg.event_handler": ("SVG element has an on* event handler", 2.5, ("T1059.007",)),
    "file.svg.redirect": ("SVG script redirects the browser", 3.0, ("T1059.007",)),
    "file.svg.xml_entities": ("SVG declares XML entities (entity-expansion attack)", 2.0, ()),
    # --- scripts / shortcuts ------------------------------------------------ #
    "file.script.suspicious_commands": ("Script downloads or runs hidden/encoded commands", 3.0,
                                        ("T1059.001",)),
    "file.lnk.command": ("Shortcut embeds an interpreter command line", 4.0,
                         ("T1059.001", "T1204.002")),
}

# --------------------------------------------------------------------------- #
# Findings collector
# --------------------------------------------------------------------------- #


@dataclass
class FileIndicator:
    """One structural indicator. ``weight`` is a log-odds *hint* for the analyzer."""

    code: str
    detail: str
    weight: float
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def title(self) -> str:
        return INDICATOR_CATALOG[self.code][0]

    @property
    def mitre(self) -> tuple[str, ...]:
        return INDICATOR_CATALOG[self.code][2]

    def as_tuple(self) -> tuple[str, str, float]:
        """The ``(code, detail, weight_hint)`` triple of the module contract."""
        return (self.code, self.detail, self.weight)

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "title": self.title, "detail": self.detail,
                "weight": self.weight, "mitre": list(self.mitre), "evidence": self.evidence}


# Hosts that appear only as XML namespaces / schema identifiers; never real destinations.
_NAMESPACE_HOSTS = (
    "w3.org", "schemas.openxmlformats.org", "schemas.microsoft.com", "purl.org",
    "xmlsoft.org", "ns.adobe.com", "inkscape.org", "sodipodi.sourceforge.net",
    "creativecommons.org", "openoffice.org", "docs.oasis-open.org",
)
_URL_SCHEMES = ("http://", "https://", "ftp://")
_FALLBACK_URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"'`\]\}]{1,2000}")


def _is_noise_host(url: str) -> bool:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return True
    return any(host == d or host.endswith("." + d) for d in _NAMESPACE_HOSTS)


class Findings:
    """Mutable collector shared by the per-format inspectors."""

    def __init__(self) -> None:
        self.indicators: list[FileIndicator] = []
        self.urls: list[str] = []
        self.notes: list[str] = []
        self._codes: set[str] = set()
        self._urlset: set[str] = set()

    # ---- indicators ------------------------------------------------------- #
    def add(self, code: str, detail: str, weight: float | None = None,
            **evidence: Any) -> FileIndicator | None:
        """Record an indicator once per code (first detail wins). Unknown codes raise."""
        spec = INDICATOR_CATALOG[code]
        if code in self._codes:
            return None
        self._codes.add(code)
        ind = FileIndicator(code, detail, spec[1] if weight is None else weight, evidence)
        self.indicators.append(ind)
        return ind

    def has(self, code: str) -> bool:
        return code in self._codes

    def note(self, message: str) -> None:
        """Record a non-evidence remark (e.g. 'oletools unavailable')."""
        if message not in self.notes:
            self.notes.append(message)

    # ---- URLs ------------------------------------------------------------- #
    def add_url(self, url: str) -> bool:
        """Add an http/https/ftp URL for child analysis (deduped, bounded)."""
        url = (url or "").strip()
        if (not url.lower().startswith(_URL_SCHEMES) or len(url) > MAX_URL_CHARS
                or url in self._urlset or len(self.urls) >= MAX_CHILD_URLS
                or _is_noise_host(url)):
            return False
        self._urlset.add(url)
        self.urls.append(url)
        return True

    def add_urls_from_text(self, text: str, *, include_bare: bool = False) -> None:
        """Extract URLs from text-like content via ``uniphish.url.parse`` (lazy import)."""
        if not text or len(self.urls) >= MAX_CHILD_URLS:
            return
        try:
            from uniphish.url.parse import extract_urls
        except Exception:  # pragma: no cover - parse module missing/broken
            for m in _FALLBACK_URL_RE.finditer(text[:2_000_000]):
                self.add_url(m.group(0))
            return
        try:
            for e in extract_urls(text, max_urls=MAX_CHILD_URLS, include_bare=include_bare):
                self.add_url(e.url)
        except Exception:  # pragma: no cover - never let URL extraction fail the scan
            log.debug("extract_urls failed", exc_info=True)


# --------------------------------------------------------------------------- #
# Magic bytes
# --------------------------------------------------------------------------- #
_LNK_MAGIC = bytes.fromhex("4c0000000114020000000000c000000000000046")
_ONENOTE_MAGIC = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")


def sniff_magic(head: bytes) -> str | None:
    """Classify a byte prefix by magic number alone (no container introspection).

    Returns one of: pe, elf, macho, pdf, ole, zip, rar, 7z, gzip, bzip2, xz, tar, cab, iso,
    lnk, rtf, onenote, png, jpeg, gif, bmp, webp, tiff, ico — or ``None``.
    """
    if head.startswith(b"MZ") and len(head) >= 64:
        # 'MZ' alone is only two bytes (plain text can start with it): require a sane
        # e_lfanew pointer, and the 'PE\0\0' signature whenever it lies inside the prefix.
        off = int.from_bytes(head[0x3C:0x40], "little")
        if 0x40 <= off <= 0x100000:
            if off + 4 <= len(head):
                return "pe" if head[off:off + 4] == b"PE\x00\x00" else "dos"
            return "pe"
        return None
    table: tuple[tuple[bytes, str], ...] = (
        (b"\x7fELF", "elf"),
        (b"%PDF-", "pdf"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
        (b"PK\x03\x04", "zip"),
        (b"PK\x05\x06", "zip"),
        (b"Rar!\x1a\x07", "rar"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"\x1f\x8b", "gzip"),
        (b"BZh", "bzip2"),
        (b"\xfd7zXZ\x00", "xz"),
        (b"MSCF", "cab"),
        (_LNK_MAGIC, "lnk"),
        (_ONENOTE_MAGIC, "onenote"),
        (b"{\\rtf", "rtf"),
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xff\xd8\xff", "jpeg"),
        (b"GIF87a", "gif"),
        (b"GIF89a", "gif"),
        (b"BM", "bmp"),
        (b"II*\x00", "tiff"),
        (b"MM\x00*", "tiff"),
        (b"\x00\x00\x01\x00", "ico"),
        (b"\xfe\xed\xfa\xce", "macho"),
        (b"\xfe\xed\xfa\xcf", "macho"),
        (b"\xce\xfa\xed\xfe", "macho"),
        (b"\xcf\xfa\xed\xfe", "macho"),
        (b"\xca\xfe\xba\xbe", "macho"),
    )
    for magic, kind in table:
        if head.startswith(magic):
            if kind == "bmp" and len(head) > 14 and head[6:10] != b"\x00\x00\x00\x00":
                continue  # 'BM' is too short a magic to trust without the reserved field
            return kind
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "webp"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "tar"
    if len(head) > 0x8006 and head[0x8001:0x8006] == b"CD001":
        return "iso"
    return None


#: Types that, when found *decoded from an embedded blob*, indicate smuggled delivery.
SMUGGLED_TYPES = frozenset({"pe", "dos", "elf", "macho", "zip", "rar", "7z", "cab", "iso",
                            "lnk", "ole", "gzip", "onenote"})
