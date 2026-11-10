# Spec: static file/attachment analysis + QR decoding
OWN: uniphish/files/__init__.py, uniphish/files/static.py, uniphish/files/qr.py,
tests/files/test_static.py, tests/files/test_qr.py, tests/files/fixtures/.

PURPOSE: inspect an attachment/download/image for the structural indicators of a
malicious delivery, and decode QR codes (quishing). Never execute; defuse all parsers;
cap resource use (zip-bomb safe). Optional deps: opencv/pillow (vision), oletools/pyzipper
(office), defusedxml — import lazily and degrade gracefully (return a 'capability
unavailable' note, not a crash).

static.py: sniff(data, filename=None) -> FileFacts(detected_type (magic-byte sniffing:
PE, ELF, Office OOXML/OLE, PDF, HTML, SVG, archive zip/rar/7z, LNK, script, image, ...),
declared_ext, ext_mismatch (declared vs detected), double_extension (e.g. invoice.pdf.exe),
rtlo_in_name (RTLO char in filename), size, sha256/sha1/md5, entropy). Per type, collect
indicators (NOT execution):
- HTML/SVG: embedded <script>, large base64 blobs / atob chains, meta-refresh,
  <form>/<a> targets, embedded data: URIs -> yields child artifacts (extracted URLs) and
  an 'html smuggling' indicator when a big base64 blob decodes to a known file magic
  (EXE/ZIP) or a Blob+download anchor pattern is present (count/flag only).
- SVG: <script>, foreignObject, external <image>/<use href> -> indicators + extracted
  URLs. Parse with defusedxml.
- Archives (zip): list entries without full extraction; flag encrypted zip (password in
  the email body is a classic evasion), nested archives, path traversal names, a single
  executable/script/LNK/Office-macro payload inside; cap entry count + total size.
- Office (OOXML/OLE via oletools if present): macro presence (VBA), external relationship
  targets/remote-template injection URLs, DDE, suspicious auto-exec keywords -> indicators
  + extracted URLs.
- PDF: /OpenAction /AA /JS /JavaScript /Launch /URI presence (regex over the raw bytes is
  fine as an indicator), extracted URLs.
- Extract URLs/domains found inside any text-ish content (reuse uniphish.url.parse,
  imported lazily) and return them so the engine can analyse them as children.
Return FileFacts + indicators (list of (code, detail, weight-hint)) + child_urls.

qr.py: decode_qr(image_bytes) -> list[QRCode(data, kind (url|text|wifi|email|...))]
using opencv QRCodeDetector (+ pillow for format decode); handle multi-code images;
return [] if opencv absent. Helper qr_payload_urls(image_bytes) -> list[str].

TESTS: ext/double-extension/RTLO detection; zip with encrypted+nested+traversal entry
(synthetic, inert); svg with script+external image; html-smuggling base64 magic; PDF
/OpenAction+/URI; a generated QR PNG decodes to a URL (skip if opencv missing). All
fixtures synthetic & inert — no real malware bytes; use benign magic-byte stubs.
