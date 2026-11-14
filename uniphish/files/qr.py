"""QR-code decoding for "quishing" (phishing links hidden in images).

Why: QR codes defeat URL scanners because the link is pixels, not text. This module
decodes every code in an image with OpenCV and classifies the payload so the engine
can analyse embedded URLs like any other link.

OpenCV and Pillow are imported lazily; when OpenCV is absent :func:`decode_qr`
returns ``[]`` (see :func:`qr_available`). Image dimensions are checked *before*
decoding so decompression bombs are refused, and several cheap preprocessing variants
(quiet-zone padding, inversion, rescaling, binarisation) are tried because real-world
phishing QR codes are often low-contrast, inverted or cropped tight.
"""

from __future__ import annotations

import io
import logging
import re
from dataclasses import dataclass

log = logging.getLogger("uniphish.files")

MAX_PIXELS = 25_000_000
MAX_SIDE = 2400
MAX_CODES = 16

_BARE_URL_RE = re.compile(
    r"(?i)^(?:www\.)?[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})*\.[a-z]{2,24}"
    r"(?::\d{1,5})?(?:[/?#]\S{0,2000})?$"
)
_CRYPTO_SCHEMES = (
    "bitcoin:",
    "ethereum:",
    "monero:",
    "litecoin:",
    "solana:",
    "tron:",
    "bitcoincash:",
    "dogecoin:",
)
_PAYMENT_SCHEMES = ("upi:", "weixin:", "alipays:", "alipay:", "paypal:", "venmo:", "pix:")


@dataclass(frozen=True)
class QRCode:
    """One decoded QR code."""

    data: str
    kind: str  # url | wifi | email | phone | sms | vcard | calendar | geo | crypto | otp |
    #             payment | uri | text
    points: tuple[tuple[float, float], ...] | None = None

    @property
    def is_url(self) -> bool:
        return self.kind == "url"


def qr_available() -> bool:
    """True when OpenCV (and numpy) can be imported."""
    try:
        import cv2  # noqa: F401
        import numpy  # noqa: F401
    except Exception:
        return False
    return True


def classify_payload(data: str) -> str:
    """Classify a decoded QR payload (see :class:`QRCode` ``kind``)."""
    s = data.strip()
    low = s.lower()
    if low.startswith(("http://", "https://", "ftp://")):
        return "url"
    if low.startswith("wifi:"):
        return "wifi"
    if low.startswith(("mailto:", "matmsg:")):
        return "email"
    if low.startswith("tel:"):
        return "phone"
    if low.startswith(("sms:", "smsto:", "mms:", "mmsto:")):
        return "sms"
    if low.startswith("begin:vcard") or low.startswith("mecard:"):
        return "vcard"
    if low.startswith(("begin:vevent", "begin:vcalendar")):
        return "calendar"
    if low.startswith("geo:"):
        return "geo"
    if low.startswith(_CRYPTO_SCHEMES):
        return "crypto"
    if low.startswith("otpauth:"):
        return "otp"
    if low.startswith(_PAYMENT_SCHEMES):
        return "payment"
    if re.match(r"^[a-z][a-z0-9+.-]{1,30}:(?://|[^\s])", low) and not _BARE_URL_RE.match(s):
        return "uri"  # intent:, javascript:, data:, custom app schemes ...
    if _BARE_URL_RE.match(s):
        return "url"
    return "text"


def _load_gray(image_bytes: bytes):  # type: ignore[no-untyped-def]
    """Decode to an 8-bit grayscale numpy array, enforcing the pixel budget."""
    import cv2
    import numpy as np

    try:
        from PIL import Image
    except ImportError:
        arr = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_GRAYSCALE)
        return arr
    with Image.open(io.BytesIO(image_bytes)) as im:
        w, h = im.size
        if w <= 0 or h <= 0 or w * h > MAX_PIXELS:
            log.debug("QR image refused: %sx%s exceeds pixel budget", w, h)
            return None
        im.load()
        if im.mode in ("RGBA", "LA") or (im.mode == "P" and "transparency" in im.info):
            rgba = im.convert("RGBA")
            bg = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
            im = Image.alpha_composite(bg, rgba)
        return np.array(im.convert("L"))


def _variants(gray):  # type: ignore[no-untyped-def]
    import cv2

    h, w = gray.shape[:2]
    if max(h, w) > MAX_SIDE:
        s = MAX_SIDE / max(h, w)
        gray = cv2.resize(gray, None, fx=s, fy=s, interpolation=cv2.INTER_AREA)
        h, w = gray.shape[:2]
    pad = max(16, min(h, w) // 12)
    padded = cv2.copyMakeBorder(gray, pad, pad, pad, pad, cv2.BORDER_CONSTANT, value=255)
    yield "padded", padded
    yield "original", gray
    yield "inverted", cv2.bitwise_not(padded)
    if max(h, w) < 800:
        yield "upscaled", cv2.resize(padded, None, fx=3, fy=3, interpolation=cv2.INTER_CUBIC)
    _, otsu = cv2.threshold(padded, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    yield "otsu", otsu
    if max(h, w) > 1200:
        yield "downscaled", cv2.resize(padded, None, fx=0.5, fy=0.5, interpolation=cv2.INTER_AREA)


def _detect(img):  # type: ignore[no-untyped-def]
    """Yield (text, points) for every code OpenCV finds in ``img``."""
    import cv2

    detectors = []
    if hasattr(cv2, "QRCodeDetectorAruco"):
        detectors.append(cv2.QRCodeDetectorAruco())
    detectors.append(cv2.QRCodeDetector())
    for det in detectors:
        try:
            ok, infos, pts, _ = det.detectAndDecodeMulti(img)
        except cv2.error:
            continue
        if not ok:
            continue
        for i, text in enumerate(infos):
            if text:
                p = None
                if pts is not None and i < len(pts):
                    p = tuple((float(x), float(y)) for x, y in pts[i])
                yield text, p


def decode_qr(image_bytes: bytes) -> list[QRCode]:
    """Decode all QR codes in an image (PNG/JPEG/GIF/BMP/WebP...). ``[]`` if none/unavailable.

    Never raises on bad images.
    """
    if not image_bytes or not qr_available():
        return []
    try:
        gray = _load_gray(image_bytes)
    except Exception as e:  # corrupt image, decompression bomb, unsupported format
        log.debug("QR: image could not be decoded (%s)", type(e).__name__)
        return []
    if gray is None or gray.size == 0:
        return []
    found: dict[str, QRCode] = {}
    try:
        for _name, img in _variants(gray):
            for text, pts in _detect(img):
                if text not in found:
                    found[text] = QRCode(text, classify_payload(text), pts)
            if len(found) >= MAX_CODES:
                break
    except Exception as e:  # pragma: no cover - OpenCV internal failure
        log.debug("QR: detector failed (%s)", type(e).__name__)
    return list(found.values())[:MAX_CODES]


def qr_payload_urls(image_bytes: bytes) -> list[str]:
    """URLs carried by QR codes in an image (direct URL payloads plus URLs inside text).

    Scheme-less payloads such as ``login.example.test/x`` are returned with ``https://``
    prepended so they can be analysed as URL artifacts.
    """
    urls: list[str] = []

    def _add(u: str) -> None:
        if u and u not in urls:
            urls.append(u)

    for code in decode_qr(image_bytes):
        s = code.data.strip()
        if code.kind == "url":
            _add(s if "://" in s else "https://" + s)
        elif code.kind in ("text", "vcard", "sms", "email", "calendar", "wifi", "uri"):
            try:
                from uniphish.url.parse import extract_urls

                for e in extract_urls(s, max_urls=20, include_bare=False):
                    _add(e.url)
            except Exception:  # pragma: no cover
                log.debug("QR: URL extraction failed", exc_info=True)
    return urls
