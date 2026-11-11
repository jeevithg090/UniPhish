"""Hostile-input-hardened RFC 5322 / MIME email parsing.

Phishing emails are malformed on purpose: duplicate ``From`` headers, broken MIME
boundaries, RFC 2047 words that decode to something other than what a naive parser
shows, filenames with bidi overrides, forwarded-as-attachment wrappers, QR codes in
``data:`` URIs. A parser that raises on such input would let it skip analysis, so
:func:`parse_email` **never raises**: whatever it cannot make sense of becomes an
entry in ``ParsedEmail.anomalies`` (stable string codes the heuristics layer can turn
into signals).

Security properties
-------------------
* Nothing is executed, rendered or fetched; HTML is only parsed (lxml via bs4).
* Sizes are bounded: input bytes, number of headers / parts / links / attachments,
  retained attachment bytes, decoded body length, nested ``message/rfc822`` depth and
  multipart depth. Hashes and ``size`` are always computed over the *full* decoded
  payload; only the retained ``data`` is capped.
* Attachment filenames are never used as paths: directory components and control
  characters are stripped, and bidi overrides are reported as an anomaly.
* All regexes that touch attacker input are linear (no nested quantifiers) and are
  applied to length-bounded strings.

The shared parse is memoised by analyzers via ``ctx.memo(MEMO_KEY, ...)``.
"""

from __future__ import annotations

import base64
import codecs
import hashlib
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import message_from_bytes, policy
from email.header import decode_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any

from uniphish.core.types import MAX_EMAIL_BYTES, MAX_URL_CHARS

log = logging.getLogger("uniphish.mail")

MEMO_KEY = "mail.parsed"

# ---- resource limits --------------------------------------------------------------
MAX_HEADERS = 2_000
MAX_HEADER_CHARS = 10_000
MAX_PARTS = 500
MAX_MULTIPART_DEPTH = 20
MAX_ATTACHMENTS = 200
MAX_ATTACHMENT_DATA = 10_000_000       # retained bytes per attachment
MAX_TOTAL_DATA = 40_000_000            # retained bytes over the whole parse
MAX_BODY_CHARS = 1_000_000
MAX_LINKS = 1_000
MAX_ANCHOR_CHARS = 300
MAX_HTML_PARSE_CHARS = 1_000_000
MAX_DATA_URI_CHARS = 14_000_000
MAX_RECEIVED_CHARS = 2_000

_BIDI = frozenset("‪‫‬‭‮⁦⁧⁨⁩‎‏")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_UNFOLD_RE = re.compile(r"\r?\n[ \t]+")
_KNOWN_CTE = frozenset({"", "7bit", "8bit", "binary", "base64", "quoted-printable"})
_SINGLETON_HEADERS = ("from", "subject", "date", "message-id", "sender", "return-path")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Address:
    """One mailbox. ``domain`` is lower-cased; ``display_name`` is RFC 2047 decoded."""

    display_name: str = ""
    addr: str = ""
    local: str = ""
    domain: str = ""

    def __bool__(self) -> bool:
        return bool(self.addr)


@dataclass(frozen=True)
class ReceivedHop:
    """One ``Received:`` header (best-effort field extraction; ``raw`` is authoritative)."""

    raw: str
    from_host: str = ""
    from_ip: str = ""
    by_host: str = ""
    with_proto: str = ""
    timestamp: datetime | None = None


@dataclass
class Attachment:
    """A non-body MIME leaf. ``data`` is capped; ``size``/hashes cover the full payload."""

    filename: str
    content_type: str
    size: int
    sha256: str
    sha1: str
    md5: str
    data: bytes = field(default=b"", repr=False)
    disposition: str | None = None
    content_id: str = ""
    is_inline: bool = False
    truncated: bool = False


@dataclass
class EmbeddedImage:
    """An image to hand to QR scanning: MIME part, or decoded ``data:`` URI from HTML."""

    data: bytes = field(repr=False)
    content_type: str
    source: str                       # "attachment" | "inline" | "data_uri"
    content_id: str = ""
    filename: str = ""


@dataclass(frozen=True)
class EmailLink:
    """A link found in the message. ``source``: html_href | html_form | html_img |
    text | meta_refresh. ``text`` is the visible anchor text (empty if none)."""

    url: str
    text: str = ""
    source: str = "html_href"
    in_html: bool = True


@dataclass
class ParsedEmail:
    message_id: str = ""
    subject: str = ""
    from_: Address = field(default_factory=Address)
    sender: Address = field(default_factory=Address)
    reply_to: list[Address] = field(default_factory=list)
    return_path: str = ""
    to: list[Address] = field(default_factory=list)
    cc: list[Address] = field(default_factory=list)
    date: datetime | None = None
    date_raw: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    received: list[ReceivedHop] = field(default_factory=list)
    x_mailer: str = ""
    list_unsubscribe: str = ""
    in_reply_to: str = ""
    text_body: str = ""
    html_body: str = ""
    html_text: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    images: list[EmbeddedImage] = field(default_factory=list)
    attached_messages: list[ParsedEmail] = field(default_factory=list)
    links: list[EmailLink] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    raw_size: int = 0

    # ---- convenience ---- #
    def header_values(self, name: str) -> list[str]:
        """All values of header ``name`` (case-insensitive), top to bottom."""
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]

    def header(self, name: str, default: str = "") -> str:
        """First value of header ``name`` (the topmost occurrence)."""
        vals = self.header_values(name)
        return vals[0] if vals else default

    @property
    def from_domain(self) -> str:
        return self.from_.domain

    @property
    def body_text(self) -> str:
        """Best human-visible text: plain body if present, else visible HTML text."""
        return self.text_body or self.html_text

    def summary(self) -> dict[str, Any]:
        """JSON-safe digest (no raw bytes), for ``meta`` in analyzer results."""
        return {
            "message_id": self.message_id, "subject": self.subject,
            "from": self.from_.addr, "from_display_name": self.from_.display_name,
            "reply_to": [a.addr for a in self.reply_to], "return_path": self.return_path,
            "to": [a.addr for a in self.to], "date": self.date.isoformat() if self.date else None,
            "hops": len(self.received), "attachments": [a.filename for a in self.attachments],
            "links": len(self.links), "attached_messages": len(self.attached_messages),
            "anomalies": list(self.anomalies), "raw_size": self.raw_size,
        }


# --------------------------------------------------------------------------- #
# Header helpers
# --------------------------------------------------------------------------- #
def _fix_str(s: str) -> str:
    """Undo surrogateescape from 8-bit header bytes and drop control characters."""
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        s = s.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return s


def _bytes_to_str(chunk: bytes, charset: str | None) -> str:
    if charset:
        try:
            return chunk.decode(codecs.lookup(charset).name, "replace")
        except (LookupError, ValueError):
            pass
    return chunk.decode("utf-8", "replace")


def decode_header_value(raw: str) -> str:
    """Unfold and RFC 2047-decode a header value; never raises; control chars -> space."""
    raw = _fix_str(str(raw))[:MAX_HEADER_CHARS]
    raw = _UNFOLD_RE.sub(" ", raw)
    try:
        parts = decode_header(raw)
        out = "".join(_bytes_to_str(c, cs) if isinstance(c, bytes) else c for c, cs in parts)
    except Exception:  # malformed encoded-words
        out = raw
    return _CTRL_RE.sub(" ", out.replace("\r", " ").replace("\n", " ")).strip()


def _parse_addresses(values: list[str]) -> list[Address]:
    if not values:
        return []
    cleaned = [_UNFOLD_RE.sub(" ", _fix_str(v))[:MAX_HEADER_CHARS] for v in values]
    try:
        pairs = getaddresses(cleaned, strict=False)
    except TypeError:  # Python without the ``strict`` keyword
        pairs = getaddresses(cleaned)
    except Exception:
        return []
    out: list[Address] = []
    for name, addr in pairs[:200]:
        addr = _CTRL_RE.sub("", addr).strip()
        name = decode_header_value(name)
        if not addr and not name:
            continue
        local, sep, domain = addr.rpartition("@")
        if not sep:
            local, domain = addr, ""
        out.append(Address(name, addr, local, domain.strip().rstrip(".").lower()))
    return out


_IP_BRACKET_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]{2,45})\]")
_IP_PAREN_RE = re.compile(r"\(([0-9A-Fa-f:.]{2,45})\)")
_RECV_FROM_RE = re.compile(r"(?i)\bfrom\s+(\S{1,255})")
_RECV_BY_RE = re.compile(r"(?i)\bby\s+(\S{1,255})")
_RECV_WITH_RE = re.compile(r"(?i)\bwith\s+(\S{1,32})")


def _valid_ip(s: str) -> str:
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return ""


def _parse_date(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        dt = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _parse_received(raw: str) -> ReceivedHop:
    raw = decode_header_value(raw)[:MAX_RECEIVED_CHARS]
    head, sep, tail = raw.rpartition(";")
    if not sep:
        head, tail = raw, ""
    by_m = _RECV_BY_RE.search(head)
    from_m = _RECV_FROM_RE.search(head)
    from_clause = head[from_m.start(): by_m.start()] if (from_m and by_m
                                                         and by_m.start() > from_m.start()) \
        else (head[from_m.start():] if from_m else "")
    ip = ""
    for rx in (_IP_BRACKET_RE, _IP_PAREN_RE):
        for m in rx.finditer(from_clause):
            ip = _valid_ip(m.group(1))
            if ip:
                break
        if ip:
            break
    with_m = _RECV_WITH_RE.search(head)
    return ReceivedHop(
        raw=raw,
        from_host=from_m.group(1).strip("();").lower() if from_m else "",
        from_ip=ip,
        by_host=by_m.group(1).strip("();").lower() if by_m else "",
        with_proto=with_m.group(1).strip(";").upper() if with_m else "",
        timestamp=_parse_date(tail.strip()),
    )


# --------------------------------------------------------------------------- #
# Body / part helpers
# --------------------------------------------------------------------------- #
def _decode_text(payload: bytes, charset: str | None, anomalies: list[str]) -> str:
    enc = None
    if charset:
        try:
            enc = codecs.lookup(charset).name
        except (LookupError, ValueError):
            _flag(anomalies, "unknown_charset")
    if enc is None:
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            text = payload.decode("cp1252", "replace")
    else:
        text = payload.decode(enc, "replace")
    return text.replace("\x00", "")[:MAX_BODY_CHARS]


def _flag(anomalies: list[str], code: str) -> None:
    if code not in anomalies:
        anomalies.append(code)


def _clean_filename(raw: str | None, anomalies: list[str]) -> str:
    if not raw:
        return ""
    name = decode_header_value(raw) if "=?" in raw else _CTRL_RE.sub(" ", _fix_str(raw))
    if any(c in _BIDI for c in name):
        _flag(anomalies, "filename_bidi_override")
    if "/" in name or "\\" in name:
        _flag(anomalies, "filename_path_components")
        name = re.split(r"[\\/]", name)[-1]
    return name.strip()[:255]


def _payload_bytes(part: Message, anomalies: list[str]) -> bytes:
    cte = str(part.get("Content-Transfer-Encoding", "")).strip().lower()
    if cte not in _KNOWN_CTE:
        _flag(anomalies, "unknown_transfer_encoding")
    try:
        data = part.get_payload(decode=True)
    except Exception:
        _flag(anomalies, "payload_decode_error")
        return b""
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8", "replace")
    return b""


# --------------------------------------------------------------------------- #
# HTML analysis (links, visible text, data-URI images)
# --------------------------------------------------------------------------- #
_HIDDEN_STYLE_RE = re.compile(
    r"(?i)display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![\d.])"
    r"|opacity\s*:\s*0(?![\d.])|max-height\s*:\s*0(?![\d.])|mso-hide\s*:\s*all")
_META_REFRESH_RE = re.compile(r"(?i)url\s*=\s*['\"]?([^'\";\s]{1,8192})")
_SKIP_SCHEMES = ("cid:", "data:")


def _clean_url(u: str) -> str:
    return _CTRL_RE.sub("", u.replace("\t", "").replace("\n", "").replace("\r", "")).strip()


def _analyze_html(html: str, anomalies: list[str]) -> tuple[str, list[EmailLink],
                                                            list[tuple[str, bytes]]]:
    """Return (visible_text, links, [(content_type, bytes) for data: images])."""
    from bs4 import BeautifulSoup  # lazy: heavy import

    html = html[:MAX_HTML_PARSE_CHARS]
    links: list[EmailLink] = []
    datas: list[tuple[str, bytes]] = []

    def add(url: str, text: str, source: str) -> None:
        url = _clean_url(url)
        if not url or url.startswith("#") or len(links) >= MAX_LINKS:
            return
        if len(url) > MAX_URL_CHARS:
            _flag(anomalies, "overlong_url")
            return
        links.append(EmailLink(url, text, source, True))

    try:
        soup = BeautifulSoup(html, "lxml")
        for m in soup.find_all("meta"):
            if str(m.get("http-equiv", "")).lower() == "refresh":
                mm = _META_REFRESH_RE.search(str(m.get("content", ""))[:2000])
                if mm:
                    add(mm.group(1), "", "meta_refresh")
        for a in soup.find_all(["a", "area"], href=True):
            text = " ".join(a.get_text(" ").split())
            if not text:
                img = a.find("img", alt=True)
                text = str(img.get("alt", "")).strip() if img else ""
            add(str(a["href"]), text[:MAX_ANCHOR_CHARS], "html_href")
        for f in soup.find_all("form", action=True):
            add(str(f["action"]), "", "html_form")
        for img in soup.find_all("img", src=True):
            src = _clean_url(str(img["src"]))
            low = src[:5].lower()
            if low == "data:":
                head, _, body = src.partition(",")
                if len(src) <= MAX_DATA_URI_CHARS and ";base64" in head.lower():
                    try:
                        raw = base64.b64decode(body, validate=False)
                    except Exception:
                        _flag(anomalies, "bad_data_uri")
                        continue
                    ctype = head[5:].split(";", 1)[0].strip().lower() or "image/png"
                    datas.append((ctype, raw[:MAX_ATTACHMENT_DATA]))
                else:
                    _flag(anomalies, "bad_data_uri")
            elif not src.lower().startswith(_SKIP_SCHEMES):
                add(src, str(img.get("alt", ""))[:MAX_ANCHOR_CHARS], "html_img")
        hidden = [t for t in soup.find_all(True)
                  if t.has_attr("hidden")
                  or _HIDDEN_STYLE_RE.search(str(t.get("style", ""))[:2000])]
        for t in hidden:
            if t.get_text(strip=True):
                _flag(anomalies, "html_hidden_text")
            t.decompose()
        for t in soup(["head", "script", "style", "noscript", "template"]):
            t.decompose()
        text = " ".join(soup.get_text(" ").split())
    except Exception:
        _flag(anomalies, "html_parse_error")
        text = " ".join(re.sub(r"(?s)<[^>]{0,2000}>", " ", html).split())
    return text[:MAX_BODY_CHARS], links, datas


# --------------------------------------------------------------------------- #
# Core builder
# --------------------------------------------------------------------------- #
class _Budget:
    """Shared retained-bytes budget across a message and its attached messages."""

    def __init__(self) -> None:
        self.data_left = MAX_TOTAL_DATA


def _build(msg: Message, depth: int, max_depth: int, raw_size: int,
           budget: _Budget) -> ParsedEmail:
    pe = ParsedEmail(raw_size=raw_size)
    an = pe.anomalies

    # ---- headers ---------------------------------------------------------------
    try:
        raw_items = list(msg.raw_items())
    except Exception:
        raw_items = list(msg.items())
    if len(raw_items) > MAX_HEADERS:
        _flag(an, "too_many_headers")
        raw_items = raw_items[:MAX_HEADERS]
    counts: dict[str, int] = {}
    for k, v in raw_items:
        name = _CTRL_RE.sub("", str(k)).strip()
        sval = _fix_str(str(v))
        if "\x00" in sval:
            _flag(an, "nul_in_header")
        pe.headers.append((name, decode_header_value(sval)))
        counts[name.lower()] = counts.get(name.lower(), 0) + 1
    for n in _SINGLETON_HEADERS:
        if counts.get(n, 0) > 1:
            _flag(an, f"duplicate_{n.replace('-', '_')}")

    def vals(name: str) -> list[str]:
        n = name.lower()
        return [_fix_str(str(v)) for k, v in raw_items if str(k).lower() == n]

    def first(name: str) -> str:
        v = vals(name)
        return decode_header_value(v[0]) if v else ""

    froms = _parse_addresses(vals("From"))
    if froms:
        pe.from_ = froms[0]
        if len(froms) > 1:
            _flag(an, "multiple_from_addresses")
    else:
        _flag(an, "no_from" if not vals("From") else "from_unparseable")
    if froms and not froms[0].addr:
        _flag(an, "from_unparseable")
    elif froms and "@" not in froms[0].addr:
        _flag(an, "from_no_domain")
    senders = _parse_addresses(vals("Sender"))
    pe.sender = senders[0] if senders else Address()
    pe.reply_to = _parse_addresses(vals("Reply-To"))
    pe.to = _parse_addresses(vals("To"))
    pe.cc = _parse_addresses(vals("Cc"))
    pe.return_path = first("Return-Path").strip("<> ")
    pe.subject = first("Subject")
    pe.message_id = first("Message-ID")
    pe.in_reply_to = first("In-Reply-To")
    pe.x_mailer = first("X-Mailer") or first("User-Agent")
    pe.list_unsubscribe = first("List-Unsubscribe")
    pe.date_raw = first("Date")
    pe.date = _parse_date(pe.date_raw)
    if not pe.date_raw:
        _flag(an, "date_missing")
    elif pe.date is None:
        _flag(an, "date_unparseable")
    if not pe.message_id:
        _flag(an, "message_id_missing")
    pe.received = [_parse_received(v) for v in vals("Received")[:100]]
    for d in msg.defects[:10]:
        _flag(an, f"defect:{type(d).__name__}")

    # ---- MIME walk (iterative; order preserved) --------------------------------
    texts: list[str] = []
    htmls: list[str] = []
    stack: list[tuple[Message, int]] = [(msg, 0)]
    nparts = 0
    while stack:
        part, mdepth = stack.pop()
        nparts += 1
        if nparts > MAX_PARTS:
            _flag(an, "too_many_parts")
            break
        try:
            for d in part.defects[:5]:
                _flag(an, f"defect:{type(d).__name__}")
            ctype = part.get_content_type()
            maintype = part.get_content_maintype()
        except Exception:
            _flag(an, "bad_content_type")
            ctype, maintype = "application/octet-stream", "application"

        if part.is_multipart() and maintype != "message":
            if mdepth >= MAX_MULTIPART_DEPTH:
                _flag(an, "multipart_depth_exceeded")
                continue
            kids = part.get_payload()
            if isinstance(kids, list):
                for kid in reversed(kids):
                    stack.append((kid, mdepth + 1))
            continue

        if maintype == "message" and part.is_multipart():
            _handle_attached(part, pe, depth, max_depth, budget)
            continue

        # leaf part
        try:
            disp = part.get_content_disposition()
        except Exception:
            disp = None
        try:
            fname = _clean_filename(part.get_filename(), an)
        except Exception:
            fname = ""
            _flag(an, "bad_filename")
        cid = str(part.get("Content-ID", "")).strip().strip("<>").strip()[:255]
        payload = _payload_bytes(part, an)

        if maintype == "multipart":  # declared multipart but no parseable children
            _flag(an, "malformed_multipart")
            body = _decode_text(payload, None, an)
            if body.strip():
                texts.append(body)
            continue
        if maintype == "text" and ctype in ("text/plain", "text/html") \
                and disp != "attachment" and not fname:
            body = _decode_text(payload, part.get_content_charset(), an)
            (htmls if ctype == "text/html" else texts).append(body)
            continue
        _add_attachment(pe, payload, ctype, fname, disp, cid, budget)

    pe.text_body = "\n".join(texts)[:MAX_BODY_CHARS]
    pe.html_body = "\n".join(htmls)[:MAX_BODY_CHARS]

    if pe.html_body:  # a part referenced as cid: from the HTML is inline whatever its header says
        low_html = pe.html_body.lower()
        referenced = {a.content_id for a in pe.attachments
                      if a.content_id and f"cid:{a.content_id.lower()}" in low_html}
        for a in pe.attachments:
            if a.content_id in referenced:
                a.is_inline = True
        for img in pe.images:
            if img.content_id in referenced:
                img.source = "inline"

    # ---- links / html text / data-URI images ------------------------------------
    if pe.html_body:
        pe.html_text, hl, datas = _analyze_html(pe.html_body, an)
        pe.links.extend(hl)
        for ctype, data in datas:
            pe.images.append(EmbeddedImage(data, ctype, "data_uri"))
    if pe.text_body:
        _text_links(pe)
    if len(pe.links) > MAX_LINKS:
        pe.links = pe.links[:MAX_LINKS]
    if not pe.text_body and not pe.html_body and not pe.attachments \
            and not pe.attached_messages:
        _flag(an, "empty_body")
    return pe


def _text_links(pe: ParsedEmail) -> None:
    from uniphish.url.parse import extract_urls  # lazy: PSL loading is slow

    try:
        found = extract_urls(pe.text_body[:MAX_BODY_CHARS], max_urls=MAX_LINKS)
    except Exception:
        _flag(pe.anomalies, "text_link_extraction_error")
        return
    body = pe.text_body
    for u in found:
        if len(pe.links) >= MAX_LINKS:
            break
        if u.bare and u.start > 0 and body[u.start - 1] == "@":
            continue  # the domain half of an email address, not a link
        if len(u.url) <= MAX_URL_CHARS:
            pe.links.append(EmailLink(u.url, "", "text", False))


def _add_attachment(pe: ParsedEmail, payload: bytes, ctype: str, fname: str,
                    disp: str | None, cid: str, budget: _Budget) -> None:
    if len(pe.attachments) >= MAX_ATTACHMENTS:
        _flag(pe.anomalies, "too_many_attachments")
        return
    keep = payload[:min(MAX_ATTACHMENT_DATA, budget.data_left)]
    truncated = len(keep) < len(payload)
    budget.data_left -= len(keep)
    if truncated:
        _flag(pe.anomalies, "attachment_data_truncated")
    is_inline = disp == "inline" or (disp is None and bool(cid))
    pe.attachments.append(Attachment(
        filename=fname, content_type=ctype, size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        sha1=hashlib.sha1(payload, usedforsecurity=False).hexdigest(),
        md5=hashlib.md5(payload, usedforsecurity=False).hexdigest(),
        data=keep, disposition=disp, content_id=cid, is_inline=is_inline,
        truncated=truncated))
    if ctype.startswith("image/") and keep:
        pe.images.append(EmbeddedImage(keep, ctype, "inline" if is_inline else "attachment",
                                       cid, fname))


def _handle_attached(part: Message, pe: ParsedEmail, depth: int, max_depth: int,
                     budget: _Budget) -> None:
    try:
        fname = _clean_filename(part.get_filename(), pe.anomalies)
        disp = part.get_content_disposition()
    except Exception:
        fname, disp = "", None
    subs = part.get_payload()
    subs = [s for s in subs if isinstance(s, Message)] if isinstance(subs, list) else []
    for sub in subs[:5]:
        try:
            blob = sub.as_bytes(policy=policy.compat32)
        except Exception:
            blob = b""
        _add_attachment(pe, blob, "message/rfc822", fname, disp or "attachment", "", budget)
        if depth + 1 > max_depth:
            _flag(pe.anomalies, "nested_message_depth_exceeded")
            continue
        try:
            pe.attached_messages.append(_build(sub, depth + 1, max_depth, len(blob), budget))
        except Exception:
            _flag(pe.anomalies, "attached_message_parse_error")


_HEADER_LINE_RE = re.compile(rb"^[\x21-\x39\x3b-\x7e]{1,200}:")


def _strip_leading_garbage(raw: bytes) -> tuple[bytes, bool]:
    """Drop leading lines that cannot be headers (mbox ``From `` line, junk).

    Python's parser treats the first non-header line as the start of the body, which
    would hide every real header behind one junk line. MUAs and MTAs are more lenient.
    Returns (raw, dropped_something_other_than_mbox_from).
    """
    pos, dropped, junk = 0, 0, False
    while dropped < 20:
        end = raw.find(b"\n", pos)
        line = raw[pos:end if end != -1 else len(raw)].rstrip(b"\r")
        if not line or line[:1] in b" \t" or _HEADER_LINE_RE.match(line) or end == -1:
            break
        if not line.startswith(b"From "):
            junk = True
        pos = end + 1
        dropped += 1
    return (raw[pos:], junk) if dropped else (raw, False)


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def parse_email(raw: bytes, *, max_depth: int = 3) -> ParsedEmail:
    """Parse a raw RFC 5322 message. **Never raises.**

    Uses ``policy.default`` and falls back to ``compat32`` if that path fails on broken
    input (``"fallback_compat32"`` anomaly). ``max_depth`` bounds nested
    ``message/rfc822`` parsing (forwarded-as-attachment chains); deeper messages are
    kept as attachments only (``"nested_message_depth_exceeded"``).
    """
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogateescape")
    elif isinstance(raw, (bytearray, memoryview)):
        raw = bytes(raw)
    elif not isinstance(raw, bytes):
        pe = ParsedEmail()
        pe.anomalies.append("invalid_input_type")
        return pe
    size = len(raw)
    truncated = size > MAX_EMAIL_BYTES
    if truncated:
        raw = raw[:MAX_EMAIL_BYTES]
    max_depth = max(0, min(int(max_depth), 10))
    raw, junk_stripped = _strip_leading_garbage(raw)

    result: ParsedEmail | None = None
    fallback = False
    for pol in (policy.default, policy.compat32):
        try:
            msg = message_from_bytes(raw, policy=pol)
            result = _build(msg, 0, max_depth, size, _Budget())
            break
        except Exception as exc:
            log.debug("email parse with %s failed: %r", pol, exc)
            fallback = True
    if result is None:
        result = ParsedEmail(raw_size=size)
        result.anomalies.append("parse_error")
        return result
    if fallback:
        _flag(result.anomalies, "fallback_compat32")
    if truncated:
        _flag(result.anomalies, "input_truncated")
    if junk_stripped:
        _flag(result.anomalies, "leading_garbage_stripped")
    return result
