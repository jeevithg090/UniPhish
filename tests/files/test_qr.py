"""QR decoding tests (generated with OpenCV's own encoder; skipped without OpenCV)."""

from __future__ import annotations

import io

import pytest

from uniphish.files import classify_payload, decode_qr, qr_available, qr_payload_urls

cv2 = pytest.importorskip("cv2")
np = pytest.importorskip("numpy")


def make_qr(text: str, scale: int = 8, border: int = 4, invert: bool = False,
            ext: str = ".png") -> bytes:
    enc = cv2.QRCodeEncoder.create()
    q = enc.encode(text)
    q = cv2.resize(q, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
    q = cv2.copyMakeBorder(q, border * scale, border * scale, border * scale, border * scale,
                           cv2.BORDER_CONSTANT, value=255)
    if invert:
        q = cv2.bitwise_not(q)
    ok, buf = cv2.imencode(ext, q)
    assert ok
    return buf.tobytes()


def test_available():
    assert qr_available()


def test_decode_url_png():
    codes = decode_qr(make_qr("https://login.example.test/verify?id=7"))
    assert [c.data for c in codes] == ["https://login.example.test/verify?id=7"]
    assert codes[0].kind == "url" and codes[0].is_url and codes[0].points
    assert qr_payload_urls(make_qr("https://login.example.test/x")) == [
        "https://login.example.test/x"]


def test_decode_jpeg_and_inverted_and_tight_crop():
    assert decode_qr(make_qr("https://a.example.test/j", ext=".jpg"))[0].data.endswith("/j")
    assert decode_qr(make_qr("https://a.example.test/inv", invert=True))[0].data.endswith("/inv")
    assert decode_qr(make_qr("https://a.example.test/tight", border=0))[0].data.endswith("/tight")


def test_multiple_codes_in_one_image():
    def arr(t):
        data = np.frombuffer(make_qr(t, border=2), np.uint8)
        return cv2.imdecode(data, cv2.IMREAD_GRAYSCALE)
    a, b = arr("https://one.example.test/1"), arr("https://two.example.test/2")
    canvas = np.full((a.shape[0], a.shape[1] + b.shape[1] + 60), 255, np.uint8)
    canvas[:, :a.shape[1]] = a
    canvas[:b.shape[0], a.shape[1] + 60:] = b
    ok, buf = cv2.imencode(".png", canvas)
    got = {c.data for c in decode_qr(buf.tobytes())}
    assert got == {"https://one.example.test/1", "https://two.example.test/2"}


def test_transparent_png_with_pillow():
    PIL = pytest.importorskip("PIL.Image")
    q = cv2.QRCodeEncoder.create().encode("https://alpha.example.test/t")
    q = cv2.resize(q, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    q = cv2.copyMakeBorder(q, 32, 32, 32, 32, cv2.BORDER_CONSTANT, value=255)
    rgba = np.dstack([q, q, q, np.where(q > 128, 0, 255).astype(np.uint8)])  # white -> transparent
    buf = io.BytesIO()
    PIL.fromarray(rgba, "RGBA").save(buf, "PNG")
    assert decode_qr(buf.getvalue())[0].data == "https://alpha.example.test/t"


def test_non_url_payloads():
    assert decode_qr(make_qr("WIFI:T:WPA;S:guest;P:notreal;;"))[0].kind == "wifi"
    assert decode_qr(make_qr("hello there"))[0].kind == "text"
    assert qr_payload_urls(make_qr("pay here https://pay.example.test/q now")) == [
        "https://pay.example.test/q"]


def test_bad_input_returns_empty():
    assert decode_qr(b"") == []
    assert decode_qr(b"not an image") == []
    assert decode_qr(b"\x89PNG\r\n\x1a\n" + b"\0" * 30) == []
    blank = cv2.imencode(".png", np.full((200, 200), 255, np.uint8))[1].tobytes()
    assert decode_qr(blank) == [] and qr_payload_urls(blank) == []


def test_pixel_budget_refused(monkeypatch):
    from uniphish.files import qr

    monkeypatch.setattr(qr, "MAX_PIXELS", 100)
    assert decode_qr(make_qr("https://a.example.test/x")) == []


def test_returns_empty_without_opencv(monkeypatch):
    from uniphish.files import qr

    monkeypatch.setattr(qr, "qr_available", lambda: False)
    assert qr.decode_qr(make_qr("https://a.example.test/x")) == []


@pytest.mark.parametrize("payload,kind", [
    ("https://x.example.test", "url"), ("HTTP://X.EXAMPLE.TEST", "url"),
    ("login.example.test/verify", "url"), ("mailto:a@example.test", "email"),
    ("tel:+10005550100", "phone"), ("smsto:+10005550100:hi", "sms"),
    ("bitcoin:bc1qexample", "crypto"), ("otpauth://totp/x?secret=ABC", "otp"),
    ("upi://pay?pa=x@y", "payment"), ("javascript:alert(1)", "uri"),
    ("intent://scan#Intent;end", "uri"), ("BEGIN:VCARD\nEND:VCARD", "vcard"),
    ("just words", "text"),
])
def test_classify(payload, kind):
    assert classify_payload(payload) == kind
