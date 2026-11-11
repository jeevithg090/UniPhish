"""Office document inspection (OOXML and legacy OLE) — indicators only, never execution.

Why: macro droppers, remote-template injection, DDE and protocol-handler abuse
(``ms-msdt:`` / Follina style) remain staple attachment techniques. OOXML parts are
read with size caps and parsed with ``defusedxml``; VBA analysis goes through
``oletools`` (imported lazily — when it is missing we say so in ``notes`` rather than
fail).
"""

from __future__ import annotations

import contextlib
import io
import logging
import re
import zipfile
from typing import Any

from uniphish.files._common import (
    MAX_MEMBER_BYTES,
    MAX_RELS_FILES,
    Findings,
)

log = logging.getLogger("uniphish.files")

MAX_OLE_BYTES = 12_000_000
MAX_VBA_CODE_CHARS = 1_000_000

_RISKY_SCHEMES = frozenset({
    "ms-msdt", "ms-officecmd", "search-ms", "search", "mhtml", "ms-appinstaller", "ms-word",
    "ms-excel", "ms-powerpoint", "ms-visio", "ms-access", "ms-project", "ms-publisher",
    "ms-spd", "ms-infopath", "onenote", "file",
})
_NON_LINK_REL_TYPES = frozenset({"oleobject", "frame", "subdocument", "externallink",
                                 "externallinkpath", "package", "control"})
_SCHEME_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9+.\-]{1,24}):")
_URL_IN_TARGET_RE = re.compile(r"(?i)https?://[^\s\"'<>!|]{1,2000}")
_DDE_RE = re.compile(
    r"(?i)(?:<w:instrText[^>]{0,200}>[^<]{0,2000}?\bDDE(?:AUTO)?\b"
    r"|\bw:instr\s*=\s*\"\s*DDE(?:AUTO)?\b|<(?:\w{1,10}:)?ddeLink\b)")
_EMBED_PREFIXES = ("word/embeddings/", "xl/embeddings/", "ppt/embeddings/",
                   "word/activex/", "xl/activex/", "ppt/activex/")


def _read_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, cap: int = MAX_MEMBER_BYTES) -> bytes:
    """Read at most ``cap`` decompressed bytes of one member (bomb-safe)."""
    try:
        with zf.open(info) as fh:
            return fh.read(cap)
    except Exception:
        return b""


def _parse_rels(xml: bytes) -> list[tuple[str, str, str]]:
    """Return ``(type_suffix, target, mode)`` tuples from a ``.rels`` part."""
    from defusedxml import ElementTree as DET

    try:
        root = DET.fromstring(xml)
    except Exception:
        return []
    out = []
    for el in root.iter():
        if el.tag.rsplit("}", 1)[-1] != "Relationship":
            continue
        t = (el.get("Type") or "").rsplit("/", 1)[-1].lower()
        out.append((t, el.get("Target") or "", (el.get("TargetMode") or "").lower()))
    return out


def _handle_relationships(zf: zipfile.ZipFile, infos: list[zipfile.ZipInfo], f: Findings) -> None:
    rels = [i for i in infos if i.filename.lower().endswith(".rels")][:MAX_RELS_FILES]
    template: list[str] = []
    objects: list[str] = []
    handlers: list[str] = []
    for info in rels:
        for rtype, target, mode in _parse_rels(_read_member(zf, info)):
            if mode != "external" or not target:
                continue
            m = _SCHEME_RE.match(target)
            scheme = m.group(1).lower() if m else ""
            is_unc = target.startswith("\\\\") or target.startswith("//")
            for um in _URL_IN_TARGET_RE.finditer(target):
                f.add_url(um.group(0))
            if scheme in _RISKY_SCHEMES and scheme != "file":
                handlers.append(target[:300])
            elif rtype == "attachedtemplate" and (scheme in ("http", "https", "ftp", "file")
                                                  or is_unc):
                template.append(target[:300])
            elif rtype in _NON_LINK_REL_TYPES:
                objects.append(target[:300])
    if handlers:
        f.add("file.office.protocol_handler",
              f"A relationship targets a risky protocol handler: {handlers[0]!r}.",
              targets=handlers[:10])
    if template:
        f.add("file.office.remote_template",
              f"The document pulls its template from a remote location: {template[0]!r}.",
              targets=template[:10])
    if objects:
        f.add("file.office.external_object",
              f"The document links an external object: {objects[0]!r}.", targets=objects[:10])


def analyze_ooxml(data: bytes, f: Findings) -> None:
    """Indicators for docx/xlsx/pptx-family files (ZIP + XML)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        f.note(f"OOXML container unreadable ({type(e).__name__})")
        return
    with zf:
        infos = zf.infolist()
        lower = {i.filename.lower(): i for i in infos}
        vba = next((i for n, i in lower.items() if n.endswith("vbaproject.bin")), None)
        if vba is not None:
            f.add("file.office.macro", f"VBA project present ({vba.filename}).",
                  part=vba.filename)
            blob = _read_member(zf, vba)
            if blob:
                olevba_scan(blob, "vbaProject.bin", f)
        xlm = [n for n in lower if n.startswith("xl/macrosheets/")]
        if xlm:
            f.add("file.office.xlm_macro", f"Excel 4.0 macro sheet(s): {xlm[0]}.",
                  parts=xlm[:10])
        emb = [i.filename for i in infos if i.filename.lower().startswith(_EMBED_PREFIXES)
               and not i.is_dir()]
        if emb:
            f.add("file.office.embedded_object", f"Embedded object part: {emb[0]}.",
                  parts=emb[:10])
        _handle_relationships(zf, infos, f)
        xml_parts = [i for i in infos
                     if re.match(r"(?i)^(?:word|xl|ppt)/(?:[^/]+\.xml|externalLinks/[^/]+\.xml)$",
                                 i.filename)][:40]
        for info in xml_parts:
            if _DDE_RE.search(_read_member(zf, info).decode("utf-8", "replace")):
                f.add("file.office.dde", f"DDE field found in {info.filename}.",
                      part=info.filename)
                break


def analyze_ole(data: bytes, f: Findings) -> None:
    """Indicators for legacy OLE2 Office files (doc/xls/ppt, also .msi/.msg containers)."""
    if len(data) > MAX_OLE_BYTES:
        f.note("OLE file too large for macro analysis")
        return
    has_macro_storage = False
    try:
        import olefile
    except ImportError:
        f.note("olefile not installed: OLE structure analysis skipped")
    else:
        try:
            with olefile.OleFileIO(io.BytesIO(data)) as ole:
                paths = ["/".join(p) for p in ole.listdir(streams=True, storages=True)]
        except Exception as e:
            f.note(f"OLE container unreadable ({type(e).__name__})")
            paths = []
        low = [p.lower() for p in paths]
        has_macro_storage = any(
            p.split("/")[0] in ("macros", "_vba_project_cur") or "/vba/" in "/" + p
            or p.startswith("vba/") for p in low)
        if has_macro_storage:
            f.add("file.office.macro", "OLE document contains a VBA macro storage.",
                  streams=[p for p in paths if "vba" in p.lower()][:20])
        emb = [p for p in paths if "objectpool" in p.lower() or "ole10native" in p.lower()]
        if emb:
            f.add("file.office.embedded_object", f"Embedded OLE object stream: {emb[0]}.",
                  streams=emb[:10])
    olevba_scan(data, "document.ole", f)
    for m in re.finditer(rb"https?://[\x21-\x7e]{4,300}", data[:MAX_OLE_BYTES]):
        f.add_url(m.group(0).decode("ascii", "ignore"))
    if re.search(rb"(?i)\bDDEAUTO\s+[\x20-\x7e]{1,200}|\bDDE\s+\"[\x20-\x7e]{1,200}",
                 data[:MAX_OLE_BYTES]):
        # Legacy Word stores DDE fields as plain ASCII field codes.
        f.add("file.office.dde", "DDE field code found in the OLE document body.")


# --------------------------------------------------------------------------- #
# oletools integration
# --------------------------------------------------------------------------- #
def apply_olevba(parser: Any, f: Findings) -> bool:
    """Translate an ``oletools`` ``VBA_Parser`` into indicators. Returns ``has_macros``.

    Split out from :func:`olevba_scan` so it can be unit-tested with a stand-in parser.
    """
    if not parser.detect_vba_macros():
        return False
    f.add("file.office.macro", "VBA macros detected by oletools.")
    autoexec: list[str] = []
    suspicious: list[str] = []
    try:
        results = parser.analyze_macros(show_decoded_strings=False) or []
    except Exception as e:
        f.note(f"olevba analysis failed ({type(e).__name__})")
        results = []
    for kind, keyword, _desc in results:
        k = str(kind)
        kw = str(keyword)[:200]
        if k == "AutoExec":
            autoexec.append(kw)
        elif k == "Suspicious":
            suspicious.append(kw)
        elif k == "IOC" and kw.lower().startswith(("http://", "https://", "ftp://")):
            f.add_url(kw)
    if autoexec:
        f.add("file.office.autoexec",
              f"Auto-run entry point(s): {', '.join(sorted(set(autoexec))[:5])}.",
              keywords=sorted(set(autoexec))[:20])
    if suspicious:
        f.add("file.office.suspicious_keywords",
              f"Suspicious macro keyword(s): {', '.join(sorted(set(suspicious))[:6])}.",
              keywords=sorted(set(suspicious))[:30])
    try:
        total = 0
        for _fn, _stream, _vbaname, code in parser.extract_macros():
            code = code if isinstance(code, str) else str(code)
            total += len(code)
            if total > MAX_VBA_CODE_CHARS:
                break
            f.add_urls_from_text(code)
    except Exception:
        log.debug("olevba extract_macros failed", exc_info=True)
    try:
        if parser.detect_xlm_macros():
            f.add("file.office.xlm_macro", "Excel 4.0 (XLM) macros detected by oletools.")
    except Exception:
        log.debug("olevba xlm detection failed", exc_info=True)
    return True


def olevba_scan(data: bytes, label: str, f: Findings) -> None:
    """Run oletools' VBA parser over an OLE blob (degrades to a note when unavailable)."""
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        f.note("oletools not installed: VBA macro analysis skipped")
        return
    if len(data) > MAX_OLE_BYTES:
        f.note("document too large for VBA analysis")
        return
    parser = None
    try:
        parser = VBA_Parser(label, data=data)
        apply_olevba(parser, f)
    except Exception as e:
        f.note(f"olevba could not parse the document ({type(e).__name__})")
    finally:
        if parser is not None:
            with contextlib.suppress(Exception):
                parser.close()
