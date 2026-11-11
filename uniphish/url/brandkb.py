"""Brand knowledge base: which brands get impersonated and which domains they really own.

Impersonation detection is only as good as its ground truth.  This module loads
``assets/brands.yaml`` and answers the questions the URL, page, mail and agent analyzers
keep asking:

* Is this host an *official* property of a brand?  (``official_brand_for_host``)  An exact
  official registrable domain or a label-boundary subdomain of one qualifies, but only if
  the host is **not** inside one of the brand's *user-content* domains (``sharepoint.com``,
  ``sites.google.com``, ``github.io``, ``web.app`` ...), where anybody can publish a page.
  ``notpaypal.com`` is not ``paypal.com``; ``evil.sharepoint.com`` is not Microsoft.
* Is this host a user-content host of some brand?  (``is_user_content_host``)
* Which brands does a text mention?  (``brands_mentioned_in``)  Token-aware for Latin
  scripts (``paypal-secure`` mentions PayPal, ``papypal`` and ``paypalsecure`` do not),
  substring-based for native scripts (CJK/Cyrillic/Arabic/... have no word separators),
  and stricter for *ambiguous* brands (``ups``, ``line``, ``orange`` ...).
* Which brand hosts this asset CDN?  (``cdn_brand_for_host``)  Phishing kits hot-link
  official logos and scripts; that is a strong brand-clone fingerprint.

Host matching uses plain label-suffix logic on purpose: the data file lists registrable
domains explicitly, so no public-suffix list is needed (and this module must not depend on
``uniphish.url.parse``).  The file is validated strictly at load time; a bad edit fails
fast with a :class:`BrandKBError` rather than silently weakening detection.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from uniphish.assets import load_yaml

log = logging.getLogger("uniphish.url")

__all__ = ["Brand", "BrandKB", "BrandKBError", "get_kb", "normalize_host"]

#: Hard cap on text scanned by :meth:`BrandKB.brands_mentioned_in` (hostile input).
MAX_TEXT_CHARS = 200_000
_MAX_TOKENS = 50_000

_LABEL = r"(?!-)[a-z0-9_-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")
_KEYWORD_RE = re.compile(r"^[a-z0-9]+(?: [a-z0-9]+)*$")
_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_TOKEN_RE = re.compile(r"[a-z0-9]+")

_ALLOWED_KEYS = frozenset(
    {
        "id", "name", "category", "regions", "official_domains", "login_hosts",
        "cdn_hosts", "user_content_domains", "keywords", "native_names", "ambiguous",
        "aliases",
    }
)  # fmt: skip

#: Words that make an *ambiguous* brand keyword ("ups", "line", "orange") credible.
_CONTEXT_WORDS = frozenset(
    {
        "account", "login", "signin", "sign", "verify", "verification", "password",
        "secure", "security", "suspended", "locked", "payment", "bank", "card",
        "delivery", "parcel", "package", "tracking", "refund", "invoice", "wallet",
        "support", "billing", "customer", "service", "official", "app", "update",
        "confirm", "authenticate", "credentials",
    }
)  # fmt: skip


class BrandKBError(ValueError):
    """The brand data file is malformed (schema, duplicate id, bad domain ...)."""


@dataclass(frozen=True, slots=True)
class Brand:
    """One impersonated brand and the domains that legitimately belong to it."""

    id: str
    name: str
    category: str
    regions: tuple[str, ...] = ("global",)
    official_domains: tuple[str, ...] = ()
    login_hosts: tuple[str, ...] = ()
    cdn_hosts: tuple[str, ...] = ()
    user_content_domains: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    native_names: tuple[str, ...] = ()
    ambiguous: bool = False
    aliases: tuple[str, ...] = ()


def normalize_host(host: str) -> str:
    """Lowercase, strip brackets/port/trailing dot; IDNA-encode non-ASCII hosts when possible.

    Returns ``""`` for anything that cannot be a hostname (whitespace, path, scheme).
    """
    if not isinstance(host, str):
        return ""
    h = host.strip().lower()
    if not h or len(h) > 1024 or any(c.isspace() or c in "/\\?#@" for c in h):
        return ""
    if h.startswith("["):  # IPv6 literal - never a brand host
        return ""
    if ":" in h:
        h, _, port = h.rpartition(":")
        if not port.isdigit():
            return ""
    h = h.rstrip(".")
    if not h:
        return ""
    if not h.isascii():
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            return h
    return h


def _is_under(host: str, domain: str) -> bool:
    """True if ``host`` equals ``domain`` or is a label-boundary subdomain of it."""
    return host == domain or host.endswith("." + domain)


def _suffixes(host: str) -> Iterable[str]:
    """Yield ``host`` and each parent domain, longest first, down to two labels."""
    labels = host.split(".")
    for i in range(len(labels) - 1):
        yield ".".join(labels[i:])


def _tuple(raw: Any, where: str, *, required: bool = False) -> tuple[str, ...]:
    if raw is None:
        if required:
            raise BrandKBError(f"{where}: required list is missing")
        return ()
    if not isinstance(raw, list) or not all(isinstance(x, str) and x.strip() for x in raw):
        raise BrandKBError(f"{where}: must be a list of non-empty strings")
    seen: dict[str, None] = {}
    for x in raw:
        seen.setdefault(x.strip(), None)
    return tuple(seen)


def _check_domain(value: str, where: str) -> str:
    if "://" in value or "/" in value or ":" in value or " " in value:
        raise BrandKBError(f"{where}: {value!r} must be a bare domain (no scheme/path/port)")
    if value != value.lower():
        raise BrandKBError(f"{where}: {value!r} must be lowercase")
    if not _DOMAIN_RE.match(value):
        raise BrandKBError(f"{where}: {value!r} is not a valid domain name")
    return value


def _build_brand(raw: Any, index: int) -> Brand:
    if not isinstance(raw, dict):
        raise BrandKBError(f"brands[{index}]: must be a mapping")
    bid = raw.get("id")
    where = f"brand {bid!r}" if isinstance(bid, str) else f"brands[{index}]"
    unknown = set(raw) - _ALLOWED_KEYS
    if unknown:
        raise BrandKBError(f"{where}: unknown keys {sorted(unknown)}")
    if not isinstance(bid, str) or not _ID_RE.match(bid):
        raise BrandKBError(f"{where}: id must be snake_case ([a-z][a-z0-9_]*)")
    for key in ("name", "category"):
        if not isinstance(raw.get(key), str) or not raw[key].strip():
            raise BrandKBError(f"{where}: {key} must be a non-empty string")
    ambiguous = raw.get("ambiguous", False)
    if not isinstance(ambiguous, bool):
        raise BrandKBError(f"{where}: ambiguous must be a boolean")

    official = _tuple(raw.get("official_domains"), f"{where}.official_domains")
    logins = _tuple(raw.get("login_hosts"), f"{where}.login_hosts")
    cdns = _tuple(raw.get("cdn_hosts"), f"{where}.cdn_hosts")
    ucs = _tuple(raw.get("user_content_domains"), f"{where}.user_content_domains")
    for group, label in ((official, "official_domains"), (logins, "login_hosts"),
                         (cdns, "cdn_hosts"), (ucs, "user_content_domains")):  # fmt: skip
        for d in group:
            _check_domain(d, f"{where}.{label}")
    overlap = set(official) & set(ucs)
    if overlap:
        raise BrandKBError(f"{where}: {sorted(overlap)} both official and user-content")
    for h in logins:
        if not any(_is_under(h, d) for d in official):
            raise BrandKBError(f"{where}: login host {h!r} is not under an official domain")

    keywords = _tuple(raw.get("keywords"), f"{where}.keywords")
    if not keywords:
        keywords = (re.sub(r"[^a-z0-9]+", "", raw["name"].lower()) or bid,)
    for kw in keywords:
        if not _KEYWORD_RE.match(kw):
            raise BrandKBError(f"{where}: keyword {kw!r} must be lowercase ASCII tokens")
    aliases = _tuple(raw.get("aliases"), f"{where}.aliases")
    natives = tuple(unicodedata.normalize("NFKC", n) for n in
                    _tuple(raw.get("native_names"), f"{where}.native_names"))  # fmt: skip
    for n in natives:
        if n.isascii():
            raise BrandKBError(f"{where}: native name {n!r} must contain non-ASCII characters")
    regions = _tuple(raw.get("regions"), f"{where}.regions") or ("global",)
    return Brand(
        id=bid, name=raw["name"].strip(), category=raw["category"].strip(),
        regions=regions, official_domains=official, login_hosts=logins, cdn_hosts=cdns,
        user_content_domains=ucs, keywords=keywords, native_names=natives,
        ambiguous=ambiguous, aliases=aliases,
    )  # fmt: skip


class BrandKB:
    """Immutable, indexed view of the brand data file."""

    def __init__(self, raw_brands: Sequence[Any]) -> None:
        brands: list[Brand] = []
        by_id: dict[str, Brand] = {}
        for i, raw in enumerate(raw_brands):
            b = _build_brand(raw, i)
            if b.id in by_id:
                raise BrandKBError(f"duplicate brand id {b.id!r}")
            by_id[b.id] = b
            brands.append(b)
        self._brands: tuple[Brand, ...] = tuple(brands)
        self._by_id = by_id

        self._official: dict[str, Brand] = {}
        self._uc: dict[str, Brand] = {}
        self._cdn: dict[str, Brand] = {}
        self._login: dict[str, Brand] = {}
        for b in brands:
            for d in b.official_domains:
                other = self._official.get(d)
                if other is not None:
                    raise BrandKBError(f"domain {d!r} official for both {other.id} and {b.id}")
                self._official[d] = b
            for d in b.user_content_domains:
                self._uc.setdefault(d, b)
            for d in b.cdn_hosts:
                self._cdn.setdefault(d, b)
            for d in b.login_hosts:
                self._login.setdefault(d, b)

        kw: dict[str, list[Brand]] = {}
        for b in brands:
            for k in (*b.keywords, *(a.lower() for a in b.aliases if _KEYWORD_RE.match(a.lower()))):
                lst = kw.setdefault(k, [])
                if b not in lst:
                    lst.append(b)
        self._keywords: tuple[tuple[str, tuple[Brand, ...]], ...] = tuple(
            sorted(((k, tuple(v)) for k, v in kw.items()), key=lambda kv: (-len(kv[0]), kv[0]))
        )
        # first-token -> [(token tuple, brands)], for token-aware matching
        self._kw_by_first: dict[str, list[tuple[tuple[str, ...], tuple[Brand, ...]]]] = {}
        for k, bs in self._keywords:
            toks = tuple(k.split(" "))
            self._kw_by_first.setdefault(toks[0], []).append((toks, bs))

        natives: dict[str, Brand] = {}
        for b in brands:
            for n in (*b.native_names, *(unicodedata.normalize("NFKC", a)
                                         for a in b.aliases if not a.isascii())):  # fmt: skip
                natives.setdefault(n.casefold(), b)
        self._natives: tuple[tuple[str, Brand], ...] = tuple(
            sorted(natives.items(), key=lambda kv: (-len(kv[0]), kv[0]))
        )

    # ------------------------------------------------------------------ lookups
    def all(self) -> tuple[Brand, ...]:
        """Every brand, in file order."""
        return self._brands

    def __len__(self) -> int:
        return len(self._brands)

    def get(self, brand_id: str) -> Brand | None:
        """Brand by id, or ``None``."""
        return self._by_id.get(brand_id)

    def is_user_content_host(self, host: str) -> Brand | None:
        """The brand whose user-content domain contains ``host`` (anyone can publish there)."""
        h = normalize_host(host)
        if not h:
            return None
        for cand in _suffixes(h):
            b = self._uc.get(cand)
            if b is not None:
                return b
        return None

    def official_brand_for_host(self, host: str) -> Brand | None:
        """The brand that officially owns ``host``, else ``None``.

        ``host`` must equal, or be a label-boundary subdomain of, an official domain, and
        must not sit inside a user-content domain (an official entry more specific than the
        user-content domain still wins).
        """
        h = normalize_host(host)
        if not h:
            return None
        for cand in _suffixes(h):  # longest (most specific) first
            brand = self._official.get(cand)
            if brand is not None:
                return brand
            if cand in self._uc:
                return None  # inside a "anyone can publish here" domain
        return None

    def login_brand_for_host(self, host: str) -> Brand | None:
        """Brand if ``host`` is exactly a canonical sign-in host (or below one)."""
        h = normalize_host(host)
        if not h or self.official_brand_for_host(h) is None:
            return None
        for cand in _suffixes(h):
            b = self._login.get(cand)
            if b is not None:
                return b
        return None

    def cdn_brand_for_host(self, host: str) -> Brand | None:
        """Brand whose official asset CDN serves ``host`` (hot-linked by clone kits)."""
        h = normalize_host(host)
        if not h:
            return None
        for cand in _suffixes(h):
            b = self._cdn.get(cand)
            if b is not None:
                return b
        return None

    # ------------------------------------------------------------------ indexes
    def keyword_index(self) -> tuple[tuple[str, tuple[Brand, ...]], ...]:
        """``(keyword, brands)`` pairs, longest keyword first (ties alphabetical)."""
        return self._keywords

    def native_name_index(self) -> tuple[tuple[str, Brand], ...]:
        """``(casefolded native name, brand)`` pairs, longest first."""
        return self._natives

    # ------------------------------------------------------------------ text
    def brands_mentioned_in(
        self, text: str, *, include_ambiguous: bool | None = None
    ) -> list[Brand]:
        """Brands mentioned in ``text``, ordered by first appearance, de-duplicated.

        * Latin keywords match whole alphanumeric tokens only, so ``paypal-secure`` and
          ``PayPal`` match but ``notpaypal`` does not.  Multi-word keywords match adjacent
          tokens (``microsoft 365``).
        * Native-script names match as substrings (no word boundaries exist in CJK etc.).
        * Ambiguous brands (``ups``, ``line``, ``orange``) match only when
          ``include_ambiguous`` is true, or - by default (``None``) - when the text also
          contains a credential/delivery/security context word.  ``False`` never matches.

        Input is truncated to ``MAX_TEXT_CHARS``.
        """
        if not isinstance(text, str) or not text:
            return []
        norm = unicodedata.normalize("NFKC", text[:MAX_TEXT_CHARS]).casefold()
        tokens = [(m.group(), m.start()) for m in _TOKEN_RE.finditer(norm)][:_MAX_TOKENS]
        words = [t for t, _ in tokens]
        has_context = include_ambiguous is True or any(w in _CONTEXT_WORDS for w in words)

        def allowed(b: Brand) -> bool:
            if not b.ambiguous:
                return True
            return include_ambiguous is True or (include_ambiguous is None and has_context)

        hits: dict[str, tuple[int, Brand]] = {}

        def record(b: Brand, pos: int) -> None:
            if b.id not in hits or pos < hits[b.id][0]:
                hits[b.id] = (pos, b)

        for i, (word, pos) in enumerate(tokens):
            for toks, brands in self._kw_by_first.get(word, ()):
                n = len(toks)
                if words[i : i + n] == list(toks):
                    for b in brands:
                        if allowed(b):
                            record(b, pos)
        for native, b in self._natives:
            pos = norm.find(native)
            if pos >= 0 and allowed(b):
                record(b, pos)
        return [b for _, b in sorted(hits.values(), key=lambda pb: (pb[0], pb[1].id))]


@lru_cache(maxsize=1)
def get_kb() -> BrandKB:
    """Process-wide cached :class:`BrandKB` built from ``assets/brands.yaml``."""
    data = load_yaml("brands.yaml")
    raw = data.get("brands") if isinstance(data, dict) else data
    if not isinstance(raw, list) or not raw:
        raise BrandKBError("brands.yaml must contain a non-empty 'brands' list")
    kb = BrandKB(raw)
    log.debug("brand KB loaded: %d brands", len(kb))
    return kb
