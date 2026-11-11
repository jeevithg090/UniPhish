# Spec: file/attachment analyzer (+ QR quishing)
OWN: uniphish/analyzers/file.py, tests/analyzers/test_file_analyzer.py.
stage=0, blocking=True, kinds={ArtifactKind.FILE}. Depends on uniphish.files.static +
uniphish.files.qr (a10), uniphish.url.parse.

Emit signals (category 'file') from FileFacts + indicators:
- double extension / ext-mismatch / RTLO-in-name (+3, T1036.007/T1036), executable or
  script or LNK attachment (+3, T1204.002), encrypted archive (+2 — classic AV evasion),
  archive with path traversal / nested archive / single-exec payload (+2.5), Office macro
  present (+3, T1204.002) / remote-template or external relationship URL (+3.5),
  HTML-smuggling attachment (big base64 decoding to EXE/ZIP or Blob+download pattern) (+4,
  T1027.006), SVG with script / external image (+3), PDF with /OpenAction+/JS or /Launch
  (+2.5) / /URI (+1 + child url), mark-of-the-web considerations (note).
- For an image FILE, run qr.decode; each decoded URL becomes a child Artifact
  (origin='qr'); a QR that encodes a URL at all in an email context is itself a mild
  signal (+1, 'quishing') and strong if the URL is phishing (propagated).
- Extract URLs/domains inside the file (static.child_urls) as child Artifacts
  (origin='file.url').
- Indicators: sha256/sha1/md5 (file), filename, embedded urls/domains.
Respect missing optional deps (oletools/opencv): emit a note signal-free skip, not a crash.
meta: {detected_type, ext_mismatch, sha256, ...}.
TESTS: double-extension exe; encrypted+traversal zip; macro doc with remote template;
html-smuggling; svg-script; pdf openaction+uri child; QR PNG -> child url (skip if opencv
missing). All fixtures synthetic & inert.
