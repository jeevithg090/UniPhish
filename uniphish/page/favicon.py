"""Favicon fingerprinting (Shodan-style MurmurHash3).

Phishing kits are frequently cloned from a victim brand's login page and keep the
brand's favicon byte-for-byte, and kit families reuse the same icon across thousands of
deployments. The de-facto interoperable fingerprint is the signed 32-bit MurmurHash3 of
the *base64 encoding with line breaks* of the icon bytes (the exact input Shodan's
``http.favicon.hash`` uses), which lets us pivot between this tool and Shodan/Censys
queries and match against published brand/kit hash tables.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping

import mmh3

MAX_FAVICON_BYTES = 1_000_000


def favicon_mmh3(data: bytes) -> int:
    """Return the Shodan-style favicon hash (signed 32-bit MurmurHash3).

    The hash is computed over ``base64.encodebytes(data)`` (76-column lines, each
    terminated by ``\\n``). Input beyond :data:`MAX_FAVICON_BYTES` is rejected rather
    than silently truncated, because a truncated hash would never match anything.

    Raises:
        ValueError: if ``data`` is larger than :data:`MAX_FAVICON_BYTES`.
    """
    if len(data) > MAX_FAVICON_BYTES:
        raise ValueError("favicon too large to fingerprint")
    return int(mmh3.hash(base64.encodebytes(bytes(data))))


def known_favicon_brand(h: int, table: Mapping[int, str] | Mapping[str, str]) -> str | None:
    """Look up a favicon hash in a ``hash -> brand`` table.

    Keys may be ints or their decimal string form (as stored in JSON/YAML). Returns the
    brand label or ``None``.
    """
    if not table:
        return None
    hit = table.get(h)  # type: ignore[call-overload]
    if hit is None:
        hit = table.get(str(h))  # type: ignore[call-overload]
    return str(hit) if hit is not None else None
