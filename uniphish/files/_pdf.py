"""PDF indicator scan (raw-byte token search; the PDF is never rendered or executed).

Why: malicious PDFs rely on a handful of dictionary keys (/OpenAction, /JS, /Launch,
/URI ...). Counting them is a cheap, robust structural signal. Two evasions are
handled: hex-escaped names (``/Java#53cript``) and keys hidden inside Flate-compressed
object streams (decompressed here with a hard output cap).
"""

from __future__ import annotations

import re
import zlib

from uniphish.files._common import MAX_SCAN_BYTES, Findings

_MAX_STREAMS = 200
_MAX_STREAM_OUT = 1_000_000
_MAX_TOTAL_OUT = 8_000_000

_NAME_ESC_RE = re.compile(rb"#([0-9A-Fa-f]{2})")
_STREAM_RE = re.compile(rb"stream\r?\n")
_TOKENS: dict[str, re.Pattern[bytes]] = {
    "OpenAction": re.compile(rb"/OpenAction(?![A-Za-z])"),
    "AA": re.compile(rb"/AA(?![A-Za-z])"),
    "JS": re.compile(rb"/JS(?![A-Za-z])"),
    "JavaScript": re.compile(rb"/JavaScript(?![A-Za-z])"),
    "Launch": re.compile(rb"/Launch(?![A-Za-z])"),
    "URI": re.compile(rb"/URI(?![A-Za-z])"),
    "EmbeddedFile": re.compile(rb"/EmbeddedFile(?![A-Za-z])"),
    "SubmitForm": re.compile(rb"/SubmitForm(?![A-Za-z])"),
    "ObjStm": re.compile(rb"/ObjStm(?![A-Za-z])"),
}
_URI_RE = re.compile(rb"/URI\s{0,8}\(([^)\\]{1,2000})\)")
_HEX_ESCAPED_KEY_RE = re.compile(rb"/(?:[A-Za-z]{0,12}#[0-9A-Fa-f]{2}[A-Za-z#0-9]{0,12}){1,3}")


def _unescape_names(data: bytes) -> bytes:
    return _NAME_ESC_RE.sub(lambda m: bytes([int(m.group(1), 16)]), data)


def _inflate_streams(data: bytes) -> bytes:
    """Concatenate (capped) Flate-decoded streams so hidden keys become visible."""
    out: list[bytes] = []
    total = 0
    for n, m in enumerate(_STREAM_RE.finditer(data)):
        if n >= _MAX_STREAMS or total >= _MAX_TOTAL_OUT:
            break
        chunk = data[m.end() : m.end() + 2_000_000]
        d = zlib.decompressobj()
        try:
            res = d.decompress(chunk, _MAX_STREAM_OUT)
        except zlib.error:
            continue
        total += len(res)
        out.append(res)
    return b"\n".join(out)


def analyze_pdf(data: bytes, f: Findings) -> None:
    """Add PDF indicators (``file.pdf.*``) and extracted URIs."""
    raw = data[:MAX_SCAN_BYTES]
    obfuscated = bool(_HEX_ESCAPED_KEY_RE.search(raw))
    view = _unescape_names(raw)
    hidden = _inflate_streams(view)
    if hidden:
        view = view + b"\n" + _unescape_names(hidden)
    counts = {k: len(rx.findall(view)) for k, rx in _TOKENS.items()}
    if obfuscated:
        # Only meaningful when unescaping actually revealed a keyword we care about.
        revealed = any(counts[k] for k in ("JS", "JavaScript", "Launch", "OpenAction"))
        if revealed and any(
            not rx.search(raw)
            for k, rx in _TOKENS.items()
            if k in ("JS", "JavaScript", "Launch", "OpenAction") and counts[k]
        ):
            f.add(
                "file.pdf.obfuscated_names",
                "Keywords such as /JavaScript or /OpenAction are hex-escaped (#xx) to "
                "evade simple scanners.",
            )
    if counts["OpenAction"] or counts["AA"]:
        f.add(
            "file.pdf.open_action",
            "An /OpenAction or /AA entry runs when the PDF is opened.",
            open_action=counts["OpenAction"],
            additional_actions=counts["AA"],
        )
    if counts["JS"] or counts["JavaScript"]:
        f.add(
            "file.pdf.javascript",
            "The PDF contains embedded JavaScript (/JS, /JavaScript).",
            js=counts["JS"],
            javascript=counts["JavaScript"],
        )
    if counts["Launch"]:
        f.add(
            "file.pdf.launch",
            "A /Launch action can start an external program or file.",
            launch=counts["Launch"],
        )
    if counts["EmbeddedFile"]:
        f.add(
            "file.pdf.embedded_file",
            "The PDF embeds another file (/EmbeddedFile).",
            embedded=counts["EmbeddedFile"],
        )
    if counts["SubmitForm"]:
        f.add(
            "file.pdf.submit_form",
            "A form action submits data to a remote server.",
            submit_form=counts["SubmitForm"],
        )
    uris = [m.group(1).decode("latin-1") for m in _URI_RE.finditer(view)][:200]
    if uris:
        for u in uris:
            f.add_url(u.strip())
        f.add("file.pdf.uri", f"The PDF links out to {len(uris)} URI(s).", uris=uris[:20])
    if counts["ObjStm"] and not hidden:
        f.note("PDF has object streams that could not be decompressed; hidden keys may be missed")
