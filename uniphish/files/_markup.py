"""HTML and SVG attachment inspection.

Why: HTML smuggling (a base64 blob assembled into a downloadable file by script),
credential-harvesting HTML attachments and SVG-with-script "images" are leading
attachment-borne phishing vectors. We only *count and flag*: the content is never
rendered or executed, base64 blobs are decoded only for their first few bytes (to
recognise a magic number), and SVG is parsed with ``defusedxml``.
"""

from __future__ import annotations

import base64
import binascii
import logging
import re

from uniphish.files._common import (
    SMUGGLED_TYPES,
    Findings,
    sniff_magic,
)
from uniphish.files._script import decode_text

log = logging.getLogger("uniphish.files")

_MAX_BLOBS_DECODED = 50
_MAX_SVG_ELEMENTS = 200_000
_MAX_SCRIPT_CHARS = 2_000_000

_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/]{1024,}={0,2}")
_BLOB_API_RE = re.compile(
    r"(?i)\bnew\s+Blob\b|createObjectURL|msSaveOrOpenBlob|msSaveBlob|\bsaveAs\s*\(")
_DOWNLOAD_RE = re.compile(
    r"(?i)\.download\s*=|\bdownload\s*=\s*[\"']|setAttribute\(\s*[\"']download[\"']")
_ATOB_RE = re.compile(r"\batob\s*\(")
_OBFUSC_RE = re.compile(
    r"(?i)\beval\s*\(|\bunescape\s*\(|String\.fromCharCode|\bFunction\s*\(\s*[\"']"
    r"|(?:\\x[0-9a-f]{2}){16,}|(?:\\u[0-9a-f]{4}){12,}")
_REDIRECT_RE = re.compile(
    r"(?i)\b(?:window\.|document\.|top\.|self\.|parent\.)?location(?:\.href)?\s*=(?!=)"
    r"|\blocation\.(?:replace|assign)\s*\(|\bwindow\.open\s*\(")
_ATTR_RE = re.compile(
    r"""(?i)\b(?P<n>href|src|action|formaction|poster|xlink:href)\s*=\s*"""
    r"""(?:"(?P<d>[^"]{0,4096})"|'(?P<s>[^']{0,4096})'|(?P<u>[^\s>"']{1,4096}))""")
_FORM_TAG_RE = re.compile(r"(?i)<form\b[^>]{0,2000}>")
_PASSWORD_RE = re.compile(r"(?i)<input\b[^>]{0,500}?\btype\s*=\s*[\"']?password")
_META_REFRESH_RE = re.compile(
    r"(?i)<meta\b[^>]{0,1000}?http-equiv\s*=\s*[\"']?refresh[\"']?[^>]{0,1000}>")
_META_URL_RE = re.compile(r"(?i)url\s*=\s*[\"']?([^\"'>\s;]{1,2048})")
_DATA_NAV_RE = re.compile(
    r"""(?i)\b(?:href|src|action|formaction)\s*=\s*["']?\s*data:\s*([a-z0-9.+/-]{1,80})""")
_SVG_MARKER_RE = re.compile(r"(?i)<svg\b")
_FOREIGN_RE = re.compile(r"(?i)<foreignObject\b")
_EVENT_ATTR_RE = re.compile(r"""(?i)\s(on[a-z]{3,20})\s*=\s*["']""")
_SCRIPT_TAG_RE = re.compile(r"(?i)<script\b")


def scan_blobs(text: str) -> tuple[int, int, list[dict[str, object]]]:
    """Find large base64 runs; return (count, total chars, [decoded-magic findings])."""
    count = 0
    total = 0
    bad: list[dict[str, object]] = []
    for m in _B64_RUN_RE.finditer(text):
        count += 1
        total += len(m.group(0))
        if count > _MAX_BLOBS_DECODED:
            continue
        prefix = m.group(0)[:512]
        prefix = prefix[: len(prefix) // 4 * 4]
        try:
            head = base64.b64decode(prefix, validate=False)[:600]
        except (binascii.Error, ValueError):
            continue
        kind = sniff_magic(head)
        if kind in SMUGGLED_TYPES:
            bad.append({"type": kind, "offset": m.start(), "base64_chars": len(m.group(0))})
    return count, total, bad


def smuggling_checks(text: str, f: Findings) -> None:
    """Shared HTML/SVG smuggling and obfuscation indicators."""
    count, total, bad = scan_blobs(text)
    blob_api = len(_BLOB_API_RE.findall(text))
    download = len(_DOWNLOAD_RE.findall(text))
    atob = len(_ATOB_RE.findall(text))
    if bad:
        f.add("file.html.smuggling.payload",
              f"A base64 blob embedded in the document decodes to a {bad[0]['type'].upper()} "
              "file; script can drop it to disk when opened.",
              blobs=bad[:10], atob_calls=atob, blob_api=blob_api)
    if blob_api and (download or atob) and (count or atob >= 1):
        f.add("file.html.smuggling.pattern",
              "Script builds a Blob from decoded data and offers it as a download.",
              blob_api=blob_api, download_anchor=download, atob_calls=atob, base64_blobs=count)
    if count and total >= 200_000 and not bad:
        f.add("file.html.large_base64",
              f"{count} large base64 blob(s) totalling {total:,} characters are embedded.",
              blobs=count, chars=total)
    if len(_OBFUSC_RE.findall(text)) >= 3 or atob >= 3:
        f.add("file.html.obfuscated_script",
              "Script relies on eval/unescape/fromCharCode/atob chains to hide its logic.",
              atob_calls=atob)


def _attr_values(text: str) -> list[tuple[str, str]]:
    out = []
    for m in _ATTR_RE.finditer(text):
        val = m.group("d") or m.group("s") or m.group("u") or ""
        out.append((m.group("n").lower(), val.strip()))
        if len(out) >= 5000:
            break
    return out


def _abs_http(url: str) -> bool:
    u = url.lower()
    return u.startswith(("http://", "https://")) or (u.startswith("//") and len(u) > 4)


def analyze_html(data: bytes, f: Findings) -> None:
    """Indicators for an HTML document delivered as a file."""
    text = decode_text(data)
    f.add("file.type.html_attachment",
          "An HTML document was delivered as a file instead of a link; attackers use this to "
          "bypass URL filtering.")
    smuggling_checks(text, f)
    if _PASSWORD_RE.search(text):
        f.add("file.html.password_form", "The page contains a password input field.")
    form_urls: list[str] = []
    for fm in _FORM_TAG_RE.finditer(text):
        for n, v in _attr_values(fm.group(0)):
            if n == "action" and _abs_http(v):
                form_urls.append("https:" + v if v.startswith("//") else v)
    if form_urls:
        f.add("file.html.external_form_action",
              f"A form posts to a remote URL: {form_urls[0][:200]}.", actions=form_urls[:10])
        for u in form_urls:
            f.add_url(u)
    mm = _META_REFRESH_RE.search(text)
    if mm:
        um = _META_URL_RE.search(mm.group(0))
        target = um.group(1) if um else ""
        f.add("file.html.meta_refresh",
              "A <meta http-equiv=refresh> tag redirects the browser"
              + (f" to {target[:200]}." if target else "."), target=target)
        if target:
            f.add_url(target)
    for dm in _DATA_NAV_RE.finditer(text):
        mime = dm.group(1).lower()
        if mime in ("text/html", "application/xhtml+xml", "image/svg+xml") \
                or mime.startswith("application/"):
            f.add("file.html.data_uri_navigation",
                  f"A link or frame targets an embedded data: document ({mime}).", mime=mime)
            break
    for n, v in _attr_values(text):
        if n in ("href", "src", "action", "formaction", "xlink:href", "poster") and _abs_http(v):
            f.add_url("https:" + v if v.startswith("//") else v)
    f.add_urls_from_text(text)


# --------------------------------------------------------------------------- #
# SVG
# --------------------------------------------------------------------------- #
def _local(tag: object) -> str:
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def _script_checks(script_text: str, f: Findings, *, svg: bool) -> None:
    if not script_text:
        return
    if _REDIRECT_RE.search(script_text) and svg:
        f.add("file.svg.redirect", "The embedded script navigates the browser elsewhere.")
    f.add_urls_from_text(script_text)


def analyze_svg(data: bytes, f: Findings) -> None:
    """Indicators for an SVG file (script, foreignObject, external refs, event handlers)."""
    text = decode_text(data)
    smuggling_checks(text, f)
    try:
        from defusedxml import ElementTree as DET
        from defusedxml.common import DefusedXmlException
    except ImportError:  # pragma: no cover - defusedxml is a hard dependency
        f.note("defusedxml not installed: SVG parsed by pattern search only")
        _svg_fallback(text, f)
        return
    try:
        root = DET.fromstring(text.encode("utf-8", "replace"))
    except DefusedXmlException:
        f.add("file.svg.xml_entities",
              "The SVG declares XML entities or external references (blocked, not expanded).")
        _svg_fallback(text, f)
        return
    except Exception as e:
        f.note(f"SVG is not well-formed XML ({type(e).__name__}); pattern search used")
        _svg_fallback(text, f)
        return

    script_parts: list[str] = []
    script_total = 0
    external: list[str] = []
    links: list[str] = []
    handlers: list[str] = []
    js_uris = 0
    foreign = False
    scripts = 0
    for n, el in enumerate(root.iter()):
        if n >= _MAX_SVG_ELEMENTS:
            f.note("SVG has too many elements; analysis truncated")
            break
        tag = _local(el.tag)
        if tag == "script":
            scripts += 1
            body = el.text or ""
            if script_total < _MAX_SCRIPT_CHARS:
                script_parts.append(body[:_MAX_SCRIPT_CHARS])
                script_total += len(body)
        elif tag == "foreignobject":
            foreign = True
        for name, value in el.attrib.items():
            lname = _local(name)
            v = (value or "").strip()
            if lname.startswith("on") and len(lname) > 3:
                handlers.append(lname)
                script_parts.append(v[:5000])
            elif lname == "href":
                if v.lower().startswith("javascript:"):
                    js_uris += 1
                    script_parts.append(v[11:5000])
                elif _abs_http(v):
                    absurl = "https:" + v if v.startswith("//") else v
                    (links if tag == "a" else external).append(absurl)
            elif lname == "src" and tag == "script" and _abs_http(v):
                external.append(v)
    if scripts or js_uris:
        f.add("file.svg.script",
              "The SVG contains executable script"
              + (" (javascript: link)." if js_uris and not scripts else "."),
              script_elements=scripts, javascript_uris=js_uris)
    if foreign:
        f.add("file.svg.foreign_object",
              "The SVG embeds HTML through <foreignObject> (used for fake login forms).")
    if handlers:
        f.add("file.svg.event_handler",
              f"SVG elements carry event handler(s): {', '.join(sorted(set(handlers))[:5])}.",
              handlers=sorted(set(handlers)))
    if external:
        f.add("file.svg.external_ref", f"The SVG loads external content from {external[0][:200]}.",
              urls=external[:10])
    if links:
        f.add("file.svg.external_link",
              f"The SVG is clickable and links to {links[0][:200]}.", urls=links[:10])
    for u in links + external:
        f.add_url(u)
    _script_checks("\n".join(script_parts)[:_MAX_SCRIPT_CHARS], f, svg=True)


def _svg_fallback(text: str, f: Findings) -> None:
    """Pattern-only SVG checks used when XML parsing is refused or fails."""
    if _SCRIPT_TAG_RE.search(text):
        f.add("file.svg.script", "The SVG contains a <script> element.")
    if _FOREIGN_RE.search(text):
        f.add("file.svg.foreign_object", "The SVG embeds HTML through <foreignObject>.")
    ev = sorted({m.group(1).lower() for m in _EVENT_ATTR_RE.finditer(text)})
    if ev:
        f.add("file.svg.event_handler",
              f"SVG elements carry event handler(s): {', '.join(ev[:5])}.", handlers=ev)
    if _REDIRECT_RE.search(text) and f.has("file.svg.script"):
        f.add("file.svg.redirect", "The embedded script navigates the browser elsewhere.")
    for n, v in _attr_values(text):
        if n in ("href", "xlink:href", "src") and _abs_http(v):
            f.add_url("https:" + v if v.startswith("//") else v)
            f.add("file.svg.external_ref", f"The SVG references external content: {v[:200]}.")
