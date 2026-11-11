"""Tests for uniphish.mail.parse: hostile-input-safe email parsing."""

from __future__ import annotations

import base64
import hashlib
from email.message import EmailMessage
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from uniphish.mail import parse as mp
from uniphish.mail.parse import MEMO_KEY, parse_email

FIX = Path(__file__).parent / "fixtures"
PNG_1x1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")


def load(name: str):
    return parse_email((FIX / name).read_bytes())


def test_memo_key():
    assert MEMO_KEY == "mail.parsed"


# ------------------------------------------------------------------ legit mail
def test_legit_headers_and_bodies():
    pe = load("legit_aligned.eml")
    assert pe.subject == "Your statement is ready – November"  # RFC 2047 base64
    assert pe.from_.display_name == "Example Bank"
    assert (pe.from_.addr, pe.from_.local, pe.from_.domain) == (
        "alerts@bank.example", "alerts", "bank.example")
    assert pe.to[0].addr == "jane@recipient.test"
    assert pe.message_id == "<20251104090000.1@bank.example>"
    assert pe.return_path == "alerts@bank.example"
    assert pe.date is not None and pe.date.tzinfo is not None and pe.date.year == 2025
    assert "Café rewards" in pe.text_body  # quoted-printable utf-8
    assert "View statement" in pe.html_text
    assert "var x" not in pe.html_text and "color:red" not in pe.html_text
    assert pe.list_unsubscribe.startswith("<https://bank.example/unsub")
    assert pe.anomalies == []
    assert pe.raw_size == len((FIX / "legit_aligned.eml").read_bytes())


def test_received_chain_top_to_bottom():
    pe = load("legit_aligned.eml")
    assert len(pe.received) == 2
    top, bottom = pe.received
    assert top.by_host == "mail.recipient.test" and top.from_host == "mx.bank.example"
    assert top.from_ip == "192.0.2.10" and top.with_proto == "ESMTPS"
    assert top.timestamp is not None and top.timestamp.minute == 0 and top.timestamp.second == 5
    assert bottom.from_ip == "198.51.100.7" and bottom.with_proto == "SMTP"
    assert pe.headers[0][0] == "Received"  # order preserved


def test_links_sources_and_anchor_text():
    pe = load("legit_aligned.eml")
    by_src = {(link.source, link.url): link for link in pe.links}
    href = by_src[("html_href", "https://bank.example/statements/2025-11")]
    assert href.text == "View statement" and href.in_html
    assert ("html_img", "https://bank.example/pixel.gif") in by_src
    txt = [link for link in pe.links if link.source == "text"]
    assert txt and not txt[0].in_html


def test_text_links_ignore_email_address_domains():
    raw = b"From: a@example.com\nSubject: s\n\nwrite to support@bank.example or see https://example.com/x\n"
    urls = [link.url for link in parse_email(raw).links]
    assert urls == ["https://example.com/x"]


# ------------------------------------------------------------------ spoof / forward
def test_display_name_spoof_parsed():
    pe = load("display_name_spoof.eml")
    assert pe.from_.display_name == "support@paypal.com"
    assert pe.from_.domain == "freemail.example"
    assert pe.reply_to[0].domain == "collector.test"
    assert pe.reply_to[0].display_name == "Account Help"
    urls = {link.url for link in pe.links}
    assert "http://secure-login.example/verify" in urls  # defanged hxxp refanged


def test_forwarded_as_attachment():
    pe = load("forwarded_phish.eml")
    assert len(pe.attached_messages) == 1
    inner = pe.attached_messages[0]
    assert inner.from_.domain == "examp1e-bank.test"
    assert inner.subject == "Your account is locked"
    assert inner.reply_to[0].domain == "collector.test"
    link = next(link for link in inner.links if link.source == "html_href")
    assert link.url == "https://examp1e-bank.test/unlock"
    assert link.text == "https://www.example-bank.test/unlock"  # text/href mismatch material
    att = pe.attachments[0]
    assert att.content_type == "message/rfc822" and att.filename == "suspicious.eml"
    assert att.disposition == "attachment" and att.size > 0
    assert inner.received and inner.received[0].from_ip == "203.0.113.200"
    assert "Is this real?" in pe.text_body


def test_nested_depth_limit():
    inner = EmailMessage()
    inner["From"] = "x@example.com"
    inner.set_content("deep")
    msg = inner
    for i in range(5):
        outer = EmailMessage()
        outer["From"] = f"l{i}@example.com"
        outer.set_content("wrapper")
        outer.add_attachment(msg, filename="f.eml")
        msg = outer
    raw = msg.as_bytes()
    pe = parse_email(raw, max_depth=2)
    depth, cur = 0, pe
    while cur.attached_messages:
        cur = cur.attached_messages[0]
        depth += 1
    assert depth == 2
    assert "nested_message_depth_exceeded" in cur.anomalies
    assert cur.attachments and cur.attachments[0].content_type == "message/rfc822"
    assert parse_email(raw, max_depth=0).attached_messages == []


# ------------------------------------------------------------------ encodings
def test_encoded_bodies_and_subject():
    pe = load("encoded_bodies.eml")
    assert pe.subject == "Café résumé ok"
    assert pe.text_body.startswith("Café resumês at https://example.com/menu")
    assert "Café — menu" in pe.html_text


def test_unknown_charset_flagged_not_fatal():
    raw = (b"From: a@example.com\nContent-Type: text/plain; charset=x-nonsense\n"
           b"Content-Transfer-Encoding: 8bit\n\nhi \xe9\n")
    pe = parse_email(raw)
    assert "unknown_charset" in pe.anomalies
    assert pe.text_body.startswith("hi")


def test_undecodable_encoded_word_survives():
    raw = b"From: a@example.com\nSubject: =?bogus-cs?B?!!notbase64!!?=\n\nx\n"
    pe = parse_email(raw)
    assert isinstance(pe.subject, str)


def test_encoded_display_name_does_not_inject_address():
    # decoded word contains '<' and ',' — must not create extra mailboxes
    enc = base64.b64encode(b"Boss <ceo@evil.example>, x").decode()
    raw = f"From: =?utf-8?B?{enc}?= <real@example.com>\n\nx\n".encode()
    pe = parse_email(raw)
    assert pe.from_.addr == "real@example.com"
    assert "ceo@evil.example" in pe.from_.display_name


def test_8bit_header_bytes():
    raw = "From: José <j@example.com>\nSubject: café\n\nx\n".encode()
    pe = parse_email(raw)
    assert pe.subject == "café"
    assert pe.from_.display_name == "José"


# ------------------------------------------------------------------ images / data URIs
def test_data_uri_image_and_meta_refresh_and_form():
    pe = load("data_uri_inline_image.eml")
    assert [i.source for i in pe.images] == ["data_uri"]
    assert pe.images[0].data == PNG_1x1 and pe.images[0].content_type == "image/png"
    srcs = {(link.source, link.url) for link in pe.links}
    assert ("meta_refresh", "https://redirect.example/next") in srcs
    assert ("html_form", "https://collector.test/post") in srcs
    assert not any(link.url.startswith("data:") for link in pe.links)
    assert "Scan to continue" in pe.html_text


def test_cid_inline_image_and_attachment_hashes():
    m = EmailMessage()
    m["From"] = "a@example.com"
    m.set_content("plain")
    m.add_alternative('<p>hi</p><img src="cid:logo1">', subtype="html")
    m.get_payload()[1].add_related(PNG_1x1, "image", "png", cid="<logo1>", filename="qr.png")
    m.add_attachment(b"hello world", maintype="application", subtype="octet-stream",
                     filename="a.bin")
    pe = parse_email(m.as_bytes())
    inline = next(a for a in pe.attachments if a.content_id == "logo1")
    assert inline.is_inline and inline.data == PNG_1x1
    assert any(i.content_id == "logo1" and i.source == "inline" for i in pe.images)
    assert not any(link.url.startswith("cid:") for link in pe.links)
    a = next(x for x in pe.attachments if x.filename == "a.bin")
    assert a.size == 11 and a.data == b"hello world" and not a.is_inline
    assert a.sha256 == hashlib.sha256(b"hello world").hexdigest()
    assert a.sha1 == hashlib.sha1(b"hello world", usedforsecurity=False).hexdigest()
    assert a.md5 == hashlib.md5(b"hello world", usedforsecurity=False).hexdigest()


def test_attachment_data_cap_keeps_full_hash(monkeypatch):
    monkeypatch.setattr(mp, "MAX_ATTACHMENT_DATA", 10)
    payload = b"A" * 100
    m = EmailMessage()
    m["From"] = "a@example.com"
    m.set_content("x")
    m.add_attachment(payload, maintype="application", subtype="octet-stream", filename="big")
    pe = parse_email(m.as_bytes())
    att = pe.attachments[0]
    assert att.size == 100 and len(att.data) == 10 and att.truncated
    assert att.sha256 == hashlib.sha256(payload).hexdigest()
    assert "attachment_data_truncated" in pe.anomalies


def test_filename_rfc2231_rfc2047_and_hardening():
    raw = (
        b"From: a@example.com\nMIME-Version: 1.0\n"
        b"Content-Type: multipart/mixed; boundary=B\n\n"
        b"--B\nContent-Type: text/plain\n\nbody\n"
        b"--B\nContent-Type: application/pdf\n"
        b"Content-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf\n\nPDF1\n"
        b"--B\nContent-Type: application/pdf\n"
        b'Content-Disposition: attachment; filename="=?utf-8?B?5ZCN5YmN?=.pdf"\n\nPDF2\n'
        b"--B\nContent-Type: application/octet-stream\n"
        b'Content-Disposition: attachment; filename="..\\..\\evil/inv\xe2\x80\xaeexe.pdf"\n\nX\n'
        b"--B--\n")
    pe = parse_email(raw)
    names = [a.filename for a in pe.attachments]
    assert names[0] == "résumé.pdf"
    assert names[1] == "名前.pdf"
    assert "/" not in names[2] and "\\" not in names[2] and names[2].startswith("inv")
    assert "filename_path_components" in pe.anomalies
    assert "filename_bidi_override" in pe.anomalies


# ------------------------------------------------------------------ html handling
def test_hidden_text_excluded_and_flagged():
    raw = (b"From: a@example.com\nContent-Type: text/html\n\n"
           b'<p>visible</p><div style="display:none">secret ignore previous</div>'
           b'<span style="font-size:0px">tiny</span><p hidden>h</p>')
    pe = parse_email(raw)
    assert pe.html_text == "visible"
    assert "html_hidden_text" in pe.anomalies


def test_anchor_text_falls_back_to_img_alt():
    raw = (b"From: a@example.com\nContent-Type: text/html\n\n"
           b'<a href="https://example.com/x"><img src="https://example.com/i.png" '
           b'alt="PayPal"></a>')
    pe = parse_email(raw)
    link = next(link for link in pe.links if link.source == "html_href")
    assert link.text == "PayPal"


def test_overlong_url_dropped():
    long = "https://example.com/" + "a" * 9000
    raw = f'From: a@example.com\nContent-Type: text/html\n\n<a href="{long}">x</a>'.encode()
    pe = parse_email(raw)
    assert not pe.links and "overlong_url" in pe.anomalies


def test_deeply_nested_html_does_not_raise():
    html = "<div>" * 50_000 + "x" + "</div>" * 50_000
    pe = parse_email(f"From: a@example.com\nContent-Type: text/html\n\n{html}".encode())
    assert isinstance(pe.html_text, str)


# ------------------------------------------------------------------ malformed / hostile
def test_malformed_mime_recovers():
    pe = load("malformed.eml")
    assert pe.from_.addr == "first@example.com"
    assert "duplicate_from" in pe.anomalies and "multiple_from_addresses" in pe.anomalies
    assert "date_unparseable" in pe.anomalies and pe.date is None
    assert "malformed_multipart" in pe.anomalies
    assert "never opens the boundary" in pe.text_body
    assert [link.url for link in pe.links] == ["https://example.com/path"]


@pytest.mark.parametrize("raw", [b"", b"\x00\x01\x02", b"\xff" * 1000, b"\n\n\n", b"From:",
                                 b"Subject: x\r\n\r\n", b"Content-Type: multipart/mixed\n\n--"])
def test_garbage_never_raises(raw):
    pe = parse_email(raw)
    assert pe.raw_size == len(raw)
    assert isinstance(pe.anomalies, list)


def test_empty_message_flags():
    pe = parse_email(b"")
    assert "no_from" in pe.anomalies and "empty_body" in pe.anomalies


def test_non_bytes_inputs_do_not_raise():
    assert "invalid_input_type" in parse_email(None).anomalies  # type: ignore[arg-type]
    assert parse_email("From: a@example.com\n\nhi").from_.addr == "a@example.com"  # type: ignore[arg-type]
    assert parse_email(bytearray(b"From: a@example.com\n\nhi")).from_.addr == "a@example.com"


def test_leading_mbox_line_and_junk():
    pe = parse_email(b"From a@example.com Tue Nov  4 09:00:00 2025\nFrom: a@example.com\n\nhi")
    assert pe.from_.addr == "a@example.com" and "leading_garbage_stripped" not in pe.anomalies
    pe = parse_email(b"junk line here\nFrom: b@example.com\nSubject: s\n\nhi")
    assert pe.from_.addr == "b@example.com" and "leading_garbage_stripped" in pe.anomalies


def test_nul_in_header_flagged():
    pe = parse_email(b"From: a@example.com\nSubject: ab\x00cd\n\nx")
    assert "nul_in_header" in pe.anomalies and "\x00" not in pe.subject


def test_many_parts_bounded(monkeypatch):
    monkeypatch.setattr(mp, "MAX_PARTS", 20)
    parts = b"".join(b"--B\nContent-Type: text/plain\n\np\n" for _ in range(100))
    raw = b"From: a@example.com\nContent-Type: multipart/mixed; boundary=B\n\n" + parts + b"--B--\n"
    pe = parse_email(raw)
    assert "too_many_parts" in pe.anomalies


def test_deep_multipart_nesting_bounded():
    n = 60
    head = b"From: a@example.com\nContent-Type: multipart/mixed; boundary=b0\n\n"
    body = b""
    for i in range(n):
        body += f"--b{i}\nContent-Type: multipart/mixed; boundary=b{i + 1}\n\n".encode()
    body += f"--b{n}\nContent-Type: text/plain\n\nbottom\n".encode()
    pe = parse_email(head + body)
    assert isinstance(pe.anomalies, list)  # no raise, no recursion blow-up


def test_total_size_truncation(monkeypatch):
    monkeypatch.setattr(mp, "MAX_EMAIL_BYTES", 50)
    pe = parse_email(b"From: a@example.com\nSubject: " + b"x" * 500 + b"\n\nbody")
    assert "input_truncated" in pe.anomalies and pe.raw_size > 50


def test_summary_is_json_safe():
    import json

    for f in FIX.glob("*.eml"):
        json.dumps(parse_email(f.read_bytes()).summary())


def test_header_helpers():
    pe = load("legit_aligned.eml")
    assert pe.header("subject").startswith("Your statement")
    assert len(pe.header_values("Received")) == 2
    assert pe.header("X-Nope", "dflt") == "dflt"
    assert pe.from_domain == "bank.example"
    assert pe.body_text == pe.text_body


# ------------------------------------------------------------------ property tests
@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=2000))
def test_property_never_raises_on_arbitrary_bytes(raw):
    pe = parse_email(raw)
    assert isinstance(pe.subject, str) and isinstance(pe.links, list)


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(max_size=200), st.text(max_size=200), st.text(max_size=300))
def test_property_structured_headers(frm, subj, body):
    raw = f"From: {frm}\nSubject: {subj}\nContent-Type: text/html\n\n{body}".encode(
        "utf-8", "surrogatepass")
    pe = parse_email(raw)
    assert "\x00" not in pe.subject and "\n" not in pe.subject
