"""Inert synthetic file samples (bytes built here, deterministically).

No executable, macro or exploit is produced anywhere. Stored files carry a ``.sample``
suffix when their *presented* name (the one an analyser is told) would otherwise be
dangerous or awkward on disk (double extensions, bidi controls, ``.svg`` with script).
Each entry: dict(id, stored, presented, label, category, note, headline_signal, hard, data).
"""

from __future__ import annotations

import base64

M, B = "malicious", "benign"


def F(id, stored, presented, label, cat, note, head, data, hard=False):
    return dict(id=id, stored=stored, presented=presented, label=label, category=cat,
                note=note, headline_signal=head, hard=hard, data=data)


def make_qr(text: str, scale: int = 8, border: int = 4) -> bytes:
    """Render *text* as a QR PNG with OpenCV's encoder (deterministic for fixed input)."""
    import cv2

    q = cv2.QRCodeEncoder.create().encode(text)
    q = cv2.resize(q, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
    q = cv2.copyMakeBorder(q, border * scale, border * scale, border * scale, border * scale,
                           cv2.BORDER_CONSTANT, value=255)
    ok, buf = cv2.imencode(".png", q)
    if not ok:  # pragma: no cover
        raise RuntimeError("PNG encoding failed")
    return buf.tobytes()


QR_PHISH_URL = "https://secure-paypa1-verify.test/login?ref=qr"
QR_BENIGN_URL = "https://www.example.com/menu"

DOUBLE_EXT = (b"INERT CORPUS SAMPLE - this file is plain text, not an executable.\r\n"
              b"It exists only to carry a deceptive double-extension file name.\r\n")

RTLO_NAME = "Invoice_2026‮gpj.exe"  # displays as ...exe reversed: 'Invoice_2026exe.jpg'

SVG_SCRIPT = b"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="400" height="200" viewBox="0 0 400 200">
  <rect width="400" height="200" fill="#f3f3f3"/>
  <text x="20" y="60" font-size="20">Secure document - loading...</text>
  <script type="text/javascript"><![CDATA[
    // INERT corpus sample: navigates to a reserved host only if opened in a browser.
    window.location = "https://login-portal.test/session?doc=1";
  ]]></script>
</svg>
"""

_SMUGGLE_PAYLOAD = base64.b64encode(b"INERT CORPUS SAMPLE - plain text, not a program.\n").decode()
HTML_SMUGGLING = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Shared document</title></head>
<body><p>Your document is being prepared...</p>
<script>
// INERT corpus sample: the blob below is plain text, not an executable.
var data = "{_SMUGGLE_PAYLOAD}";
var bytes = Uint8Array.from(atob(data), function (c) {{ return c.charCodeAt(0); }});
var blob = new Blob([bytes], {{type: "application/octet-stream"}});
var a = document.createElement("a");
a.href = URL.createObjectURL(blob);
a.download = "document.txt";
document.body.appendChild(a);
a.click();
</script></body></html>
""".encode()

BENIGN_NOTE = b"Meeting notes\r\n- Review sprint goals\r\n- Plan the demo\r\n"

BENIGN_SVG = b"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="120" height="120" viewBox="0 0 120 120">
  <circle cx="60" cy="60" r="50" fill="#3b82f6"/>
  <text x="60" y="68" text-anchor="middle" font-size="22" fill="#ffffff">OK</text>
</svg>
"""


def build_files() -> list[dict]:
    return [
        F("file-double-extension", "double_extension.sample", "Invoice_2026-114.pdf.exe", M,
          "double_extension", "Executable-looking name hiding behind a document extension "
          "(content is inert text).", "file.double_extension", DOUBLE_EXT),
        F("file-rtlo-name", "rtlo_name.sample", RTLO_NAME, M, "rtlo_name",
          "File name contains a right-to-left override that reverses the visible extension "
          "(content is inert text).", "file.rtlo_filename", DOUBLE_EXT),
        F("file-svg-script", "svg_with_script.svg.sample", "secure_document.svg", M,
          "svg_phishing", "SVG attachment with an embedded script that navigates away.",
          "file.svg.script", SVG_SCRIPT),
        F("file-qr-phish", "qr_phish.png", "mfa-enrol.png", M, "quishing",
          "PNG whose QR code encodes a reserved-domain look-alike sign-in URL.",
          "qr.url_in_image", make_qr(QR_PHISH_URL)),
        F("file-html-smuggling", "html_smuggling_stub.html.sample", "shared_document.html", M,
          "html_smuggling", "HTML that decodes a base64 blob into a Blob and auto-downloads it "
          "(the blob is plain text).", "file.html.smuggling.pattern", HTML_SMUGGLING),
        F("file-benign-note", "benign_note.txt", "meeting_notes.txt", B, "benign_text",
          "Plain text note.", None, BENIGN_NOTE),
        F("file-benign-svg", "benign_icon.svg", "icon.svg", B, "benign_svg",
          "Script-free SVG icon.", None, BENIGN_SVG),
        F("file-benign-qr", "benign_qr.png", "menu-qr.png", B, "benign_qr",
          "PNG QR code for an ordinary reserved-domain URL.", None, make_qr(QR_BENIGN_URL)),
    ]
