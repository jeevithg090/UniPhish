"""Filename and extension logic: declared extension, double extensions, RTLO tricks.

Why: attackers rely on how names *render* (Windows hides known extensions; a
right-to-left override reverses the tail). These helpers compute what the name really
ends in and whether it has been dressed up to look like something else.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Extensions Windows will run (or hand to an interpreter) on double-click.
EXECUTABLE_EXTS = frozenset({
    "exe", "scr", "com", "pif", "dll", "cpl", "msi", "msp", "jar", "bat", "cmd", "vbs",
    "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "ps1", "psm1", "sct", "reg", "gadget",
    "application", "appx", "msix", "sh", "py",
})
SCRIPT_EXTS = frozenset({"bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
                         "ps1", "psm1", "sct", "sh", "py", "reg"})
ARCHIVE_EXTS = frozenset({"zip", "rar", "7z", "gz", "tgz", "bz2", "xz", "tar", "cab", "iso",
                          "img", "vhd", "vhdx", "jar", "zipx", "arj", "lzh", "ace"})
MACRO_OFFICE_EXTS = frozenset({"docm", "xlsm", "pptm", "dotm", "xlam", "ppam", "sldm",
                               "xlsb", "xltm", "potm", "ppsm"})
#: Extensions an attacker puts first to make the file look like a document/image.
DECOY_EXTS = frozenset({
    "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "mp3", "mp4", "avi", "mov", "wav",
    "htm", "html", "xml", "odt", "ods", "zip", "rar", "7z", "msg", "eml", "svg",
})
#: Disk-image / launcher extensions that also count as a "real" extension in a double.
_REAL_EXTS = EXECUTABLE_EXTS | frozenset({"iso", "img", "vhd", "vhdx", "one"})

RTLO = "‮"
BIDI_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩")


def basename(filename: str) -> str:
    """Last path component (handles both ``/`` and ``\\`` separators)."""
    return filename.replace("\\", "/").rsplit("/", 1)[-1]


def ext_of(filename: str | None) -> str:
    """Lower-case extension Windows would resolve (trailing dots/spaces ignored)."""
    if not filename:
        return ""
    base = basename(filename).rstrip(" .")
    if "." not in base:
        return ""
    return base.rsplit(".", 1)[-1].strip().lower()


@dataclass(frozen=True)
class NameFacts:
    base: str
    declared_ext: str
    double_extension: bool
    decoy_ext: str
    rtlo: bool
    bidi: bool


def inspect_filename(filename: str | None) -> NameFacts:
    """Inspect a filename for double-extension and bidi-override tricks."""
    if not filename:
        return NameFacts("", "", False, "", False, False)
    base = basename(filename)
    rtlo = RTLO in base
    bidi = any(ch in BIDI_CONTROLS for ch in base)
    stripped = "".join(ch for ch in base if ch not in BIDI_CONTROLS).rstrip(" .")
    parts = [p.strip().lower() for p in stripped.split(".")]
    declared = ext_of(base)
    double = False
    decoy = ""
    if len(parts) >= 3 and parts[-1] in _REAL_EXTS:
        for p in parts[1:-1]:
            if p in DECOY_EXTS:
                double, decoy = True, p
                break
    return NameFacts(base, declared, double, decoy, rtlo, bidi)
