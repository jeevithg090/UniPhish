"""ZIP inspection without extraction.

Why: password-protected archives, nested archives, single-payload wrappers and
path-traversal names are the classic ways to smuggle a payload past mail gateways.
We read only the central directory (names, flags, declared sizes) so a zip bomb can
never be inflated here, and we refuse to list archives with an absurd entry count.
"""

from __future__ import annotations

import io
import re
import struct
import zipfile
from dataclasses import dataclass, field

from uniphish.files._common import (
    MAX_ARCHIVE_ENTRIES,
    MAX_DECLARED_UNCOMPRESSED,
    Findings,
)
from uniphish.files._names import (
    ARCHIVE_EXTS,
    EXECUTABLE_EXTS,
    MACRO_OFFICE_EXTS,
    ext_of,
    inspect_filename,
)

_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_PAYLOAD_EXTS = (
    EXECUTABLE_EXTS | MACRO_OFFICE_EXTS | frozenset({"lnk", "iso", "img", "vhd", "vhdx", "one"})
)


@dataclass
class ZipEntry:
    name: str
    size: int
    compressed: int
    encrypted: bool
    is_dir: bool


@dataclass
class ZipListing:
    """Result of reading a zip's central directory."""

    ok: bool = False
    too_many: bool = False
    error: str | None = None
    entries: list[ZipEntry] = field(default_factory=list)

    @property
    def names(self) -> list[str]:
        return [e.name for e in self.entries]


def _declared_entry_count(data: bytes) -> int | None:
    """Entry count from the End-Of-Central-Directory record (None when not found)."""
    start = max(0, len(data) - 22 - 65_535)
    i = data.rfind(b"PK\x05\x06", start)
    if i < 0 or i + 22 > len(data):
        return None
    return int(struct.unpack_from("<H", data, i + 10)[0])


def list_zip(data: bytes) -> ZipListing:
    """Read a zip's directory only. Never decompresses member data."""
    out = ZipListing()
    count = _declared_entry_count(data)
    if count is not None and (count > MAX_ARCHIVE_ENTRIES or count == 0xFFFF):
        out.too_many = True
        out.ok = True
        return out
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                out.too_many = True
                out.ok = True
                return out
            for i in infos:
                out.entries.append(
                    ZipEntry(
                        i.filename,
                        int(i.file_size),
                        int(i.compress_size),
                        bool(i.flag_bits & 0x1),
                        i.is_dir(),
                    )
                )
    except Exception as e:  # BadZipFile, NotImplementedError, struct.error, OverflowError...
        out.error = type(e).__name__
        return out
    out.ok = True
    return out


def zip_flavor(listing: ZipListing) -> str:
    """'ooxml' | 'jar' | 'apk' | 'zip' based on entry names."""
    names = {n.lower() for n in listing.names}
    if "[content_types].xml" in names and any(
        n.startswith(("word/", "xl/", "ppt/", "visio/")) for n in names
    ):
        return "ooxml"
    if "androidmanifest.xml" in names and "classes.dex" in names:
        return "apk"
    if "meta-inf/manifest.mf" in names:
        return "jar"
    return "zip"


def is_traversal(name: str) -> bool:
    """True if an entry name would escape its extraction directory."""
    n = name.replace("\\", "/")
    return (
        "\x00" in n
        or n.startswith("/")
        or bool(_DRIVE_RE.match(n))
        or any(seg == ".." for seg in n.split("/"))
    )


def analyze_zip(listing: ZipListing, f: Findings) -> None:
    """Add archive indicators for a plain (non-OOXML) zip/jar/apk listing."""
    if listing.error:
        f.add(
            "file.archive.malformed",
            f"Archive could not be read ({listing.error}).",
            error=listing.error,
        )
        return
    if listing.too_many:
        f.add(
            "file.archive.too_many_entries",
            f"Archive declares more than {MAX_ARCHIVE_ENTRIES} entries; not listed.",
        )
        return
    files = [e for e in listing.entries if not e.is_dir and not e.name.startswith("__MACOSX/")]
    enc = [e.name for e in files if e.encrypted]
    if enc:
        f.add(
            "file.archive.encrypted",
            f"{len(enc)} of {len(files)} entries are password-protected, so mail scanners "
            "cannot read them.",
            encrypted_entries=enc[:20],
            total=len(files),
        )
    nested = [e.name for e in files if ext_of(e.name) in ARCHIVE_EXTS]
    if nested:
        f.add(
            "file.archive.nested",
            f"Contains nested archive/disk image: {nested[0]!r}.",
            entries=nested[:20],
        )
    trav = [e.name for e in listing.entries if is_traversal(e.name)]
    if trav:
        f.add(
            "file.archive.path_traversal",
            f"Entry name {trav[0]!r} would extract outside the target folder.",
            entries=trav[:20],
        )
    disguised = []
    for e in files:
        nf = inspect_filename(e.name)
        if nf.double_extension or nf.rtlo:
            disguised.append(e.name)
    if disguised:
        f.add(
            "file.archive.disguised_entry",
            f"Entry {disguised[0]!r} disguises its real file type.",
            entries=disguised[:20],
        )
    payloads = [e.name for e in files if ext_of(e.name) in _PAYLOAD_EXTS]
    if len(files) == 1 and payloads:
        f.add(
            "file.archive.single_payload",
            f"The archive contains just one file, {payloads[0]!r}, which is directly "
            "runnable or macro-enabled.",
            entry=payloads[0],
        )
    elif payloads and any(ext_of(n) in EXECUTABLE_EXTS for n in payloads):
        execs = [n for n in payloads if ext_of(n) in EXECUTABLE_EXTS]
        f.add(
            "file.archive.executable_entry",
            f"Contains executable/script entry {execs[0]!r} among {len(files)} files.",
            entries=execs[:20],
        )
    total = sum(e.size for e in files)
    comp = sum(e.compressed for e in files)
    if total > MAX_DECLARED_UNCOMPRESSED or (
        total > 100 * 1024 * 1024 and comp and total / comp > 500
    ):
        f.add(
            "file.archive.bomb",
            f"Archive declares {total:,} bytes uncompressed from {comp:,} compressed.",
            declared_uncompressed=total,
            compressed=comp,
        )
