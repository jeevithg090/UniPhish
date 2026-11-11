"""Script, shortcut and executable indicators (pattern search only — nothing is run).

Why: stand-alone ``.js/.vbs/.ps1/.bat/.hta`` files and ``.lnk`` shortcuts are delivered
as attachments or archive payloads; what matters is whether they carry a download
cradle, an encoded command or a hidden-window launcher. Patterns are anchored on
bounded classes (ReDoS-safe).
"""

from __future__ import annotations

import re

from uniphish.files._common import MAX_SCAN_BYTES, Findings

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("powershell_encoded", re.compile(
        r"(?i)powershell(?:\.exe)?[^\r\n]{0,200}?\s-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}")),
    ("download_cradle", re.compile(
        r"(?i)\b(?:downloadstring|downloadfile|invoke-webrequest|iwr|invoke-restmethod|"
        r"start-bitstransfer|net\.webclient|msxml2\.xmlhttp|winhttp\.winhttprequest)\b")),
    ("invoke_expression", re.compile(r"(?i)\b(?:invoke-expression|iex)\b\s*[(\s$]")),
    ("hidden_window", re.compile(r"(?i)-w(?:indowstyle)?\s+hidden|-nop\b|-noni\b")),
    ("certutil_download", re.compile(r"(?i)certutil[^\r\n]{0,80}-urlcache")),
    ("bitsadmin", re.compile(r"(?i)\bbitsadmin\b[^\r\n]{0,80}/transfer")),
    ("mshta", re.compile(r"(?i)\bmshta(?:\.exe)?\s+[\"']?(?:https?:|vbscript:|javascript:)")),
    ("regsvr32_remote", re.compile(r"(?i)regsvr32[^\r\n]{0,80}/i:https?://")),
    ("wscript_shell", re.compile(
        r"(?i)wscript\.shell|shell\.application|scripting\.filesystemobject")),
    ("base64_decode", re.compile(r"(?i)frombase64string|certutil[^\r\n]{0,40}-decode")),
    ("rundll32", re.compile(r"(?i)\brundll32(?:\.exe)?\s+[\w\\.:/-]{1,100},")),
    ("cmd_interpreter", re.compile(r"(?i)\bcmd(?:\.exe)?\s+/[ck]\b")),
)
_INTERPRETERS = ("powershell", "cmd.exe", "cmd /c", "mshta", "wscript", "cscript", "rundll32",
                 "regsvr32", "bitsadmin", "certutil")


def decode_text(data: bytes) -> str:
    """Best-effort decode of text-ish bytes (BOMs and BOM-less UTF-16 handled)."""
    data = data[:MAX_SCAN_BYTES]
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace")
    head = data[:2000]
    if len(head) >= 8 and head.count(b"\x00") > len(head) // 3:
        enc = "utf-16-le" if head[1:2] == b"\x00" else "utf-16-be"
        return data.decode(enc, "replace")
    return data.decode("utf-8", "replace")


def scan_commands(text: str) -> list[str]:
    """Names of the suspicious command patterns present in ``text``."""
    sample = text[:2_000_000]
    return [name for name, rx in _PATTERNS if rx.search(sample)]


def analyze_script(data: bytes, f: Findings) -> None:
    text = decode_text(data)
    f.add_urls_from_text(text)
    hits = scan_commands(text)
    if hits:
        f.add("file.script.suspicious_commands",
              f"Script contains download/execution patterns: {', '.join(hits[:6])}.",
              patterns=hits)


def analyze_lnk(data: bytes, f: Findings) -> None:
    """Pull ASCII and UTF-16 strings out of a shortcut and look for interpreter commands."""
    blob = data[:1_000_000]
    texts = [blob.decode("latin-1"), blob.decode("utf-16-le", "ignore"),
             blob[1:].decode("utf-16-le", "ignore")]
    hits: list[str] = []
    for t in texts:
        f.add_urls_from_text(t)
        for h in scan_commands(t):
            if h not in hits:
                hits.append(h)
    low = " ".join(texts).lower()
    interp = [i for i in _INTERPRETERS if i in low]
    if hits or interp:
        f.add("file.lnk.command",
              "The shortcut embeds an interpreter command line"
              + (f" ({', '.join(interp[:4])})." if interp else "."),
              interpreters=interp, patterns=hits)
