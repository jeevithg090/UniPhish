"""Typed, lazily-loaded accessors for UniPhish's threat-intel reference lists.

Every reference list the platform needs (abused TLDs, "living off trusted sites" hosts,
URL shorteners, dynamic-DNS zones, open-redirect endpoints, free/disposable mail
providers, multilingual lure terms and the Tranco top-sites ranking) lives as data in
``uniphish/assets`` and is reachable *only* through this module, so no analyzer
hard-codes a list and every list is validated in one place.

Design properties
-----------------
* **Lazy and cached.** Nothing is read at import time; each list is parsed once on
  first use and then served from memory.
* **Label-boundary-safe host matching.** ``pages.dev`` matches ``x.pages.dev`` and
  ``pages.dev`` but never ``evilpages.dev`` — matching walks dot-separated suffixes
  instead of using ``str.endswith`` on the raw string.
* **Hostile-input-safe.** All inputs are treated as attacker-controlled: hostnames over
  253 characters never match, query strings and lure text are length-capped, and the
  lure matcher is linear time (tokenise + hash lookup, plus a first-character index for
  spaceless scripts) with no regex that can backtrack catastrophically.
* **Validated data.** Loaders raise ``ValueError`` with a precise message when a data
  file is malformed; ``tests/assets/test_lists.py`` asserts the shipped data is clean.

Nothing here performs network I/O.
"""

from __future__ import annotations

import base64
import binascii
import math
from collections.abc import Iterator
from dataclasses import dataclass, replace
from functools import lru_cache
from urllib.parse import parse_qsl, unquote

from uniphish.assets import load_lines, load_yaml
from uniphish.assets.lure_matcher import LureHit, find_lures, lure_languages

__all__ = [
    "LOTS_KINDS",
    "LotsEntry",
    "LureHit",
    "OpenRedirect",
    "find_lures",
    "is_disposable",
    "is_dyndns",
    "is_freemail",
    "is_shortener",
    "is_top_site",
    "lots_match",
    "lure_languages",
    "open_redirect_match",
    "tld_risk",
    "top_rank",
]

LOTS_KINDS = frozenset(
    {"hosting", "serverless", "forms", "storage", "docs", "ipfs", "tunnel", "blog",
     "site_builder", "file_share"}
)
_REDIRECT_ENCODINGS = frozenset(
    {"url", "base64url", "pathtail", "proofpoint_v2", "proofpoint_v3", "opaque"}
)

_MAX_HOST = 253
_MAX_QUERY = 8192
_MAX_PATH = 4096
_MAX_DEST = 4096
_MAX_QS_FIELDS = 64
_DEFAULT_MAX_LURE_CHARS = 262_144


# --------------------------------------------------------------------------- #
# Host helpers
# --------------------------------------------------------------------------- #
def _norm_host(host: str | None) -> str:
    """Lower-case, strip port/brackets/trailing dots, IDNA-encode; '' if unusable."""
    if not host:
        return ""
    h = host.strip().lower()
    if h.startswith("[") or h.count(":") > 1:  # IPv6 literal: never in these lists
        return ""
    if h.count(":") == 1:
        h, _, port = h.partition(":")
        if not port.isdigit():
            return ""
    h = h.rstrip(".")
    if not h or len(h) > _MAX_HOST * 4:
        return ""
    if not h.isascii():
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            return ""
    if len(h) > _MAX_HOST or ".." in h or h.startswith("."):
        return ""
    return h


def _suffixes(host: str) -> Iterator[str]:
    """Yield ``a.b.c``, ``b.c``, ``c`` — most specific first, on label boundaries."""
    labels = host.split(".")
    for i in range(len(labels)):
        yield ".".join(labels[i:])


def _norm_path(path: str | None) -> str:
    p = (path or "")[:_MAX_PATH]
    for sep in ("?", "#"):
        p = p.split(sep, 1)[0]
    p = p.lower()
    return p if p.startswith("/") else "/" + p


def _path_has_prefix(path: str, prefix: str) -> bool:
    """Prefix match that respects path-segment boundaries ('/scl' !~ '/sclerosis')."""
    if not prefix or prefix == "/":
        return True
    if prefix.endswith("/"):
        return path.startswith(prefix) or path == prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


def _require_mapping(data: object, name: str) -> dict:
    if not isinstance(data, dict):
        raise ValueError(f"{name}: top level must be a mapping")
    return data


def _domain_list(name: str, *keys: str) -> frozenset[str]:
    data = _require_mapping(load_yaml(name), name)
    out: set[str] = set()
    for key in keys:
        items = data.get(key)
        if not isinstance(items, list) or not items:
            raise ValueError(f"{name}: '{key}' must be a non-empty list")
        for item in items:
            if not isinstance(item, str) or not item or item != item.strip().lower():
                raise ValueError(f"{name}: bad domain entry {item!r} (must be lower-case str)")
            if "/" in item or " " in item:
                raise ValueError(f"{name}: domain entry {item!r} must be a bare host")
            out.add(item)
    return frozenset(out)


def _suffix_in(host: str | None, entries: frozenset[str]) -> bool:
    h = _norm_host(host)
    return bool(h) and any(s in entries for s in _suffixes(h))


# --------------------------------------------------------------------------- #
# TLD risk
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def _tlds() -> dict[str, float]:
    data = _require_mapping(load_yaml("tlds.yaml"), "tlds.yaml")
    table = data.get("tlds")
    if not isinstance(table, dict) or not table:
        raise ValueError("tlds.yaml: 'tlds' must be a non-empty mapping")
    out: dict[str, float] = {}
    for tld, spec in table.items():
        risk = spec.get("risk") if isinstance(spec, dict) else None
        if (not isinstance(tld, str) or tld != tld.lower() or "." in tld
                or isinstance(risk, bool) or not isinstance(risk, (int, float))
                or not math.isfinite(risk) or not 0.3 <= risk <= 1.5):
            raise ValueError(f"tlds.yaml: invalid entry {tld!r}: {spec!r}")
        out[tld] = float(risk)
    return out


def tld_risk(suffix: str | None) -> float | None:
    """Calibrated log-odds risk (0.3-1.5) of a TLD, or ``None`` if not in the abused set.

    Accepts ``"top"``, ``".top"``, a public suffix (``"co.top"``) or a full host; only
    the final label (the TLD) is looked up.
    """
    h = _norm_host((suffix or "").lstrip("."))
    if not h:
        return None
    return _tlds().get(h.rsplit(".", 1)[-1])


# --------------------------------------------------------------------------- #
# Living off trusted sites
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class LotsEntry:
    """A legitimate platform commonly abused for hosting phishing content."""

    match: str          # host suffix
    kind: str           # one of LOTS_KINDS
    name: str
    path: str = ""      # optional required path prefix ('' = any)


@lru_cache(maxsize=1)
def _lots_index() -> dict[str, tuple[LotsEntry, ...]]:
    data = _require_mapping(load_yaml("lots.yaml"), "lots.yaml")
    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("lots.yaml: 'entries' must be a non-empty list")
    index: dict[str, list[LotsEntry]] = {}
    for raw in entries:
        if not isinstance(raw, dict):
            raise ValueError(f"lots.yaml: bad entry {raw!r}")
        match, kind = raw.get("match"), raw.get("kind")
        path = raw.get("path", "") or ""
        if (not isinstance(match, str) or match != match.lower() or "/" in match
                or kind not in LOTS_KINDS or not isinstance(path, str)
                or (path and not path.startswith("/"))):
            raise ValueError(f"lots.yaml: invalid entry {raw!r}")
        entry = LotsEntry(match, kind, str(raw.get("name") or match), path.lower())
        index.setdefault(match, []).append(entry)
    # path-restricted entries first so they win over the generic entry at the same suffix
    return {k: tuple(sorted(v, key=lambda e: not e.path)) for k, v in index.items()}


def lots_match(host: str | None, path: str = "") -> LotsEntry | None:
    """Return the most specific "living off trusted sites" entry covering ``host``/``path``.

    The longest matching host suffix wins; a path-restricted entry only matches when the
    path has that prefix on a segment boundary. Callers must **not** grant reputation or
    top-site legitimacy credit to a host for which this returns an entry.
    """
    h = _norm_host(host)
    if not h:
        return None
    p = _norm_path(path)
    index = _lots_index()
    for suffix in _suffixes(h):
        for entry in index.get(suffix, ()):
            if not entry.path or _path_has_prefix(p, entry.path):
                return entry
    return None


# --------------------------------------------------------------------------- #
# Shorteners, dynamic DNS, mail providers
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def _shorteners() -> frozenset[str]:
    return _domain_list("shorteners.yaml", "domains")


@lru_cache(maxsize=1)
def _dyndns() -> frozenset[str]:
    return _domain_list("dyndns.yaml", "domains")


@lru_cache(maxsize=1)
def _freemail() -> frozenset[str]:
    return _domain_list("freemail.yaml", "global", "regional")


def is_shortener(host: str | None) -> bool:
    """True if ``host`` is (a subdomain of) a known URL-shortener / link-wrapper domain."""
    return _suffix_in(host, _shorteners())


def is_dyndns(host: str | None) -> bool:
    """True if ``host`` lies under a dynamic-DNS provider zone (``x.duckdns.org``)."""
    return _suffix_in(host, _dyndns())


def is_freemail(domain: str | None) -> bool:
    """True for a free/consumer mailbox provider domain.

    Accepts a bare domain or an address (``a@gmail.com``). Exact-domain match: email
    domains are not hierarchical, so ``gmail.com.evil.test`` and ``x.gmail.com`` are
    not free-mail domains.
    """
    d = (domain or "").rsplit("@", 1)[-1]
    h = _norm_host(d)
    return bool(h) and h in _freemail()


@lru_cache(maxsize=1)
def _disposable() -> frozenset[str]:
    out = frozenset(x.lower() for x in load_lines("disposable_domains.txt.gz"))
    if not out:
        raise ValueError("disposable_domains.txt.gz is empty")
    return out


def is_disposable(domain: str | None) -> bool:
    """True if ``domain`` (or an address) is on a disposable-mailbox blocklist.

    Subdomains of a listed domain count (disposable services wildcard their MX).
    """
    d = (domain or "").rsplit("@", 1)[-1]
    return _suffix_in(d, _disposable())


# --------------------------------------------------------------------------- #
# Open redirects
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class OpenRedirect:
    """An open-redirect / link-wrapper endpoint and, when recoverable, its destination."""

    name: str
    match: str
    path: str
    params: tuple[str, ...]
    encoding: str
    destination: str | None = None


@lru_cache(maxsize=1)
def _redirect_index() -> dict[str, tuple[OpenRedirect, ...]]:
    data = _require_mapping(load_yaml("open_redirects.yaml"), "open_redirects.yaml")
    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("open_redirects.yaml: 'entries' must be a non-empty list")
    index: dict[str, list[OpenRedirect]] = {}
    for raw in entries:
        if not isinstance(raw, dict):
            raise ValueError(f"open_redirects.yaml: bad entry {raw!r}")
        match, name = raw.get("match"), raw.get("name")
        path = raw.get("path", "") or ""
        params = raw.get("param", [])
        enc = raw.get("encoding", "url")
        if (not isinstance(match, str) or match != match.lower() or not isinstance(name, str)
                or not isinstance(path, str) or enc not in _REDIRECT_ENCODINGS
                or not isinstance(params, list) or not all(isinstance(x, str) for x in params)
                or (enc in ("url", "base64url", "proofpoint_v2") and not params)):
            raise ValueError(f"open_redirects.yaml: invalid entry {raw!r}")
        index.setdefault(match, []).append(
            OpenRedirect(name, match, path.lower(), tuple(params), enc))
    return {k: tuple(v) for k, v in index.items()}


def _clean_destination(value: str | None) -> str | None:
    if not value:
        return None
    v = value.strip()
    if len(v) > _MAX_DEST or any(ord(c) < 0x20 or ord(c) == 0x7F for c in v):
        return None
    return v if v[:8].lower().startswith(("http://", "https://")) else None


def _decode_base64url(value: str) -> str | None:
    v = value
    if len(v) > 2 and v[0].isalpha() and v[1].isdigit():   # Bing-style version prefix ("a1")
        v = v[2:]
    try:
        raw = base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
        return raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return None


def _extract_destination(entry: OpenRedirect, path: str, params: dict[str, str]) -> str | None:
    enc = entry.encoding
    if enc == "opaque":
        return None
    if enc == "proofpoint_v3":
        start = path.find("__")
        end = path.find("__;", start + 2) if start >= 0 else -1
        return _clean_destination(path[start + 2:end]) if end > start else None
    if enc == "pathtail":
        tail = path[len(entry.path.rstrip("/")):] if entry.path else path
        for seg in tail.split("/"):
            cand = _clean_destination(unquote(seg))
            if cand:
                return cand
        whole = unquote(tail)
        idx = whole.lower().find("http")
        return _clean_destination(whole[idx:]) if idx >= 0 else None
    for name in entry.params:
        value = params.get(name)
        if not value:
            continue
        if enc == "base64url":
            value = _decode_base64url(value) or ""
        elif enc == "proofpoint_v2":
            value = unquote(value.replace("_", "/").replace("-", "%"))
        cand = _clean_destination(value)
        if cand:
            return cand
    return None


def open_redirect_match(host: str | None, path: str = "", query: str = "") -> OpenRedirect | None:
    """Match a URL against known open-redirect / link-wrapper endpoints.

    Returns the endpoint with ``destination`` filled in when the wrapped URL can be
    recovered offline (``None`` for opaque wrappers or when the parameter is absent or
    not an http(s) URL). The host must match on a label boundary and the path on a
    segment boundary. ``query`` may carry a leading ``?``.
    """
    h = _norm_host(host)
    if not h:
        return None
    p_raw = (path or "")[:_MAX_PATH].split("?", 1)[0].split("#", 1)[0]
    p = _norm_path(p_raw)
    index = _redirect_index()
    params: dict[str, str] | None = None
    for suffix in _suffixes(h):
        for entry in index.get(suffix, ()):
            if not _path_has_prefix(p, entry.path):
                continue
            if params is None:
                try:
                    pairs = parse_qsl((query or "").lstrip("?")[:_MAX_QUERY],
                                      max_num_fields=_MAX_QS_FIELDS)
                except ValueError:
                    pairs = []
                params = {}
                for k, v in pairs:
                    params.setdefault(k, v)
            # use the original-case path for destination extraction (URLs are case-sensitive)
            raw_path = p_raw if p_raw.startswith("/") else "/" + p_raw
            return replace(entry, destination=_extract_destination(entry, raw_path, params))
    return None


# --------------------------------------------------------------------------- #
# Lures (matcher lives in lure_matcher.py to keep this module cohesive)
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Top sites (Tranco)
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def _top_ranks() -> dict[str, int]:
    lines = load_lines("top_sites.txt.gz")
    if not lines:
        raise ValueError("top_sites.txt.gz is empty")
    ranks: dict[str, int] = {}
    for rank, dom in enumerate(lines, start=1):
        ranks.setdefault(dom.lower(), rank)
    return ranks


def top_rank(registrable: str | None) -> int | None:
    """Tranco rank (1 = most popular) of a **registrable domain**, or ``None`` if outside
    the shipped top-100,000. The caller supplies the registrable domain (``paypal.com``,
    not ``www.paypal.com``); no suffix logic is applied here. Combine with
    :func:`lots_match` — top-ranked platforms such as ``github.io`` host arbitrary
    user content and must not confer legitimacy.
    """
    h = _norm_host(registrable)
    return _top_ranks().get(h) if h else None


def is_top_site(registrable: str | None, n: int = 10_000) -> bool:
    """True if ``registrable`` ranks within the top ``n`` Tranco domains."""
    rank = top_rank(registrable)
    return rank is not None and rank <= n
