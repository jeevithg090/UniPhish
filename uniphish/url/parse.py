"""Hostile-input-hardened URL parsing, normalisation and extraction.

Phishing URLs are malformed on purpose: a parser that "helpfully" disagrees with the
browser is a security bug. This module parses hosts the way browsers resolve them —
control-character stripping, backslash-as-slash for special schemes, percent-decoded
hosts, IDNA (UTS #46), IPv4 in decimal/octal/hex/short forms, the ``user@host`` trick —
and exposes the registrable domain using the Public Suffix List (ICANN **and** private
sections, so ``evil.pages.dev`` is one registrable unit, not ``pages.dev``).

Nothing here raises on bad input: :func:`parse_url` always returns a :class:`ParsedURL`
with ``valid`` / ``errors`` set. That is a deliberate security property — the caller
never has to wrap parsing in try/except and risk skipping analysis of a weird URL.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache

import idna
import tldextract

SPECIAL_SCHEMES = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}
_NO_HOST_SCHEMES = {"data", "javascript", "mailto", "blob", "about", "tel", "file"}

# Characters a browser removes from a URL entirely before parsing (tab / CR / LF).
_TAB_NEWLINE = re.compile(r"[\t\r\n]")
# C0 controls + space trimmed from both ends.
_C0_SPACE = "".join(chr(c) for c in range(0x21)) + "\x7f"

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):")
_IPV4_DOTTED_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# --------------------------------------------------------------------------- #
# Public-suffix extractors (offline; bundled snapshot only, no network)
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def _extract_private() -> tldextract.TLDExtract:
    # include_psl_private_domains=True -> pages.dev, github.io, etc. are suffixes.
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                 include_psl_private_domains=True)


@lru_cache(maxsize=1)
def _extract_icann() -> tldextract.TLDExtract:
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                 include_psl_private_domains=False)


# --------------------------------------------------------------------------- #
# ParsedURL
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ParsedURL:
    """A parsed URL with the security-relevant fields precomputed.

    ``host`` is the Unicode (U-label) form lower-cased; ``host_ascii`` is the
    A-label/punycode form. ``registrable_domain`` uses the PSL *including* private
    domains (so ``a.evil.pages.dev`` → ``evil.pages.dev``); ``icann_registrable`` uses
    only the ICANN section (``pages.dev``). ``sld`` is the registrable label without
    its suffix (``paypal`` for ``paypal.co.uk``).
    """

    raw: str
    url: str
    scheme: str
    userinfo: str
    host: str
    host_ascii: str
    host_unicode: str
    port: int | None
    path: str
    query: str
    fragment: str
    labels: tuple[str, ...]
    suffix: str
    icann_suffix: str
    registrable_domain: str
    registrable_ascii: str
    icann_registrable: str
    sld: str
    subdomain: str
    is_ip: bool
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    ip_obfuscated: bool
    is_idn: bool
    idn_error: str | None
    has_userinfo: bool
    valid: bool
    errors: tuple[str, ...] = field(default_factory=tuple)

    # ---- convenience ------------------------------------------------------ #
    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def effective_port(self) -> int | None:
        return self.port if self.port is not None else SPECIAL_SCHEMES.get(self.scheme)

    @property
    def origin(self) -> str:
        p = f":{self.port}" if self.port is not None else ""
        return f"{self.scheme}://{self.host_ascii}{p}"

    @property
    def has_nonascii_host(self) -> bool:
        return any(ord(c) > 127 for c in self.host_unicode)

    @property
    def path_and_query(self) -> str:
        q = f"?{self.query}" if self.query else ""
        return f"{self.path}{q}"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.url


# --------------------------------------------------------------------------- #
# IPv4 obfuscation parsing (decimal / octal / hex / short forms)
# --------------------------------------------------------------------------- #
def _parse_ipv4_number(host: str) -> ipaddress.IPv4Address | None:
    """Parse the browser-accepted IPv4 numeric forms, or return None.

    Covers ``3232235777``, ``0xC0A80101``, ``0300.0250.0.1``, ``192.168.257``,
    ``0x7f.1`` etc. Rejects anything with a non-numeric label.
    """
    parts = host.split(".")
    if len(parts) > 4 or not host:
        return None
    nums: list[int] = []
    for part in parts:
        if part == "":
            return None
        try:
            if part.lower().startswith("0x"):
                n = int(part, 16)
            elif len(part) > 1 and part.startswith("0"):
                n = int(part, 8)
            else:
                n = int(part, 10)
        except ValueError:
            return None
        nums.append(n)
    # The last part absorbs the remaining bytes (e.g. 192.168.257 -> 192.168.1.1).
    try:
        if len(nums) == 1:
            value = nums[0]
        else:
            if any(n > 255 for n in nums[:-1]):
                return None
            remaining_bytes = 4 - (len(nums) - 1)
            if nums[-1] >= (1 << (8 * remaining_bytes)):
                return None
            value = 0
            for n in nums[:-1]:
                value = (value << 8) | n
            value = (value << (8 * remaining_bytes)) | nums[-1]
        if 0 <= value <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError):
        return None
    return None


def _normalize_host(host: str) -> tuple[str, str, str, bool, str | None, bool,
                                        ipaddress.IPv4Address | ipaddress.IPv6Address | None,
                                        bool]:
    """Return (host_unicode, host_ascii, display, is_ip, idn_error, is_idn, ip, ip_obf)."""
    # IPv6 literal
    if host.startswith("[") and host.endswith("]"):
        inner = host[1:-1].split("%", 1)[0]
        try:
            ip = ipaddress.IPv6Address(inner)
            disp = f"[{ip.compressed}]"
            return disp, disp, disp, True, None, False, ip, False
        except ipaddress.AddressValueError:
            return host, host, host, False, "invalid-ipv6", False, None, False

    host = host.rstrip(".")  # trailing-dot FQDN form
    if not host:
        return "", "", "", False, None, False, None, False

    try:
        percent_decoded = _percent_decode_host(host)
    except Exception:
        percent_decoded = host

    # Dotted-decimal IPv4 (canonical form, every label 0-255)
    if _IPV4_DOTTED_RE.match(percent_decoded):
        try:
            ip = ipaddress.IPv4Address(percent_decoded)
            s = str(ip)
            return s, s, s, True, None, False, ip, False
        except ipaddress.AddressValueError:
            pass

    # Regular domain -> IDNA both directions (UTS#46). Done BEFORE numeric-IP
    # detection so that non-ASCII digit look-alikes (e.g. superscripts) map to ASCII
    # digits first and are then recognised as the IP a browser would reach.
    lowered = percent_decoded.lower()
    is_idn = any(ord(c) > 127 for c in lowered) or "xn--" in lowered
    host_unicode = lowered
    host_ascii = lowered
    idn_error: str | None = None
    try:
        if "xn--" in lowered:
            host_unicode = idna.decode(lowered.encode("ascii"))
            host_ascii = idna.encode(host_unicode, uts46=True, transitional=False).decode("ascii")
        elif is_idn:
            host_ascii = idna.encode(lowered, uts46=True, transitional=False).decode("ascii")
            host_unicode = idna.decode(host_ascii.encode("ascii"))
    except idna.IDNAError as e:
        idn_error = str(e).split("\n")[0][:80] or "idna-error"
        try:  # best-effort UTS46 mapping without strict validation
            host_unicode = idna.uts46_remap(lowered, std3_rules=False, transitional=False)
            host_ascii = host_unicode
        except Exception:
            host_unicode = lowered
    except (UnicodeError, ValueError) as e:
        idn_error = str(e)[:80] or "unicode-error"
        host_ascii = lowered

    # Obfuscated IPv4 (decimal / hex / octal / short), on the ASCII-mapped host.
    if re.fullmatch(r"[0-9a-fx.]+", host_ascii) and any(ch.isdigit() for ch in host_ascii):
        ip4 = _parse_ipv4_number(host_ascii)
        if ip4 is not None:
            s = str(ip4)
            return s, s, s, True, None, False, ip4, host_ascii != s

    return host_unicode, host_ascii, host_unicode, False, idn_error, is_idn, None, False


def _percent_decode_host(host: str) -> str:
    if "%" not in host:
        return host
    out = bytearray()
    i = 0
    data = host.encode("utf-8")
    while i < len(data):
        if data[i] == 0x25 and i + 2 < len(data):  # '%'
            try:
                out.append(int(data[i + 1:i + 3].decode("ascii"), 16))
                i += 3
                continue
            except ValueError:
                pass
        out.append(data[i])
        i += 1
    return out.decode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# parse_url
# --------------------------------------------------------------------------- #
def _preclean(url: str) -> str:
    url = url.strip(_C0_SPACE)
    url = _TAB_NEWLINE.sub("", url)
    return url


def parse_url(url: str) -> ParsedURL:
    """Parse ``url`` into a :class:`ParsedURL`. Never raises."""
    raw = url if isinstance(url, str) else str(url)
    errors: list[str] = []
    cleaned = _preclean(raw)

    m = _SCHEME_RE.match(cleaned)
    if m:
        scheme = m.group(1).lower()
        rest = cleaned[m.end():]
    else:
        scheme = "http"
        rest = cleaned
        errors.append("scheme-inferred")

    special = scheme in SPECIAL_SCHEMES

    # Schemes that carry no authority (data:, mailto:, javascript:, ...)
    if scheme in _NO_HOST_SCHEMES or (not special and not rest.startswith("//")):
        return _bare(raw, cleaned, scheme, rest, errors)

    if special:
        rest = rest.replace("\\", "/")
    if rest.startswith("//"):
        rest = rest[2:]
    else:
        errors.append("missing-authority")

    # authority ends at first /, ?, #
    authority = rest
    tail_start = len(rest)
    for ch in "/?#":
        idx = rest.find(ch)
        if idx != -1 and idx < tail_start:
            tail_start = idx
    authority = rest[:tail_start]
    tail = rest[tail_start:]

    userinfo = ""
    has_userinfo = False
    if "@" in authority:
        userinfo, authority = authority.rsplit("@", 1)
        has_userinfo = True

    host_port = authority
    port: int | None = None
    if host_port.startswith("["):  # IPv6 literal with optional :port
        end = host_port.find("]")
        if end != -1:
            host_raw = host_port[: end + 1]
            after = host_port[end + 1:]
            if after.startswith(":"):
                port = _parse_port(after[1:], errors)
        else:
            host_raw = host_port
            errors.append("unterminated-ipv6")
    elif ":" in host_port:
        host_raw, port_str = host_port.rsplit(":", 1)
        port = _parse_port(port_str, errors)
    else:
        host_raw = host_port

    (host_unicode, host_ascii, _disp, is_ip, idn_error, is_idn, ip,
     ip_obf) = _normalize_host(host_raw)

    if idn_error:
        errors.append("idn-error")
    if not host_unicode and not is_ip:
        errors.append("empty-host")

    path, query, fragment = _split_tail(tail)

    # Registrable domain via PSL (private + ICANN sections)
    labels: tuple[str, ...] = ()
    suffix = icann_suffix = registrable = icann_registrable = sld = subdomain = ""
    registrable_ascii = ""
    if not is_ip and host_unicode:
        labels = tuple(host_unicode.split("."))
        ext_p = _extract_private()(host_unicode)
        ext_i = _extract_icann()(host_unicode)
        suffix = ext_p.suffix
        icann_suffix = ext_i.suffix
        sld = ext_p.domain
        subdomain = ext_p.subdomain
        registrable = ext_p.top_domain_under_public_suffix or (
            f"{ext_p.domain}.{ext_p.suffix}" if ext_p.domain and ext_p.suffix else host_unicode)
        icann_registrable = (f"{ext_i.domain}.{ext_i.suffix}"
                             if ext_i.domain and ext_i.suffix else "")
        try:
            registrable_ascii = (idna.encode(registrable, uts46=True,
                                             transitional=False).decode("ascii")
                                 if registrable else "")
        except Exception:
            registrable_ascii = registrable

    valid = not any(e in errors for e in ("empty-host", "idn-error", "invalid-ipv6",
                                          "invalid-port"))
    normalized = _build_normalized(scheme, host_ascii, port, path, query, is_ip)

    return ParsedURL(
        raw=raw, url=normalized, scheme=scheme, userinfo=userinfo, host=host_unicode,
        host_ascii=host_ascii, host_unicode=host_unicode, port=port, path=path, query=query,
        fragment=fragment, labels=labels, suffix=suffix, icann_suffix=icann_suffix,
        registrable_domain=registrable, registrable_ascii=registrable_ascii,
        icann_registrable=icann_registrable, sld=sld, subdomain=subdomain, is_ip=is_ip, ip=ip,
        ip_obfuscated=ip_obf, is_idn=is_idn, idn_error=idn_error, has_userinfo=has_userinfo,
        valid=valid, errors=tuple(errors),
    )


def _bare(raw: str, cleaned: str, scheme: str, rest: str, errors: list[str]) -> ParsedURL:
    """A ParsedURL for schemes without an authority component."""
    errors = [*errors, "no-authority-scheme"] if scheme in _NO_HOST_SCHEMES else errors
    return ParsedURL(
        raw=raw, url=cleaned, scheme=scheme, userinfo="", host="", host_ascii="", host_unicode="",
        port=None, path=rest, query="", fragment="", labels=(), suffix="", icann_suffix="",
        registrable_domain="", registrable_ascii="", icann_registrable="", sld="", subdomain="",
        is_ip=False, ip=None, ip_obfuscated=False, is_idn=False, idn_error=None,
        has_userinfo=False, valid=scheme in _NO_HOST_SCHEMES, errors=tuple(errors),
    )


def _parse_port(s: str, errors: list[str]) -> int | None:
    s = s.strip()
    if s == "":
        return None
    if not s.isdigit() or not (0 <= int(s) <= 65535):
        errors.append("invalid-port")
        return None
    return int(s)


def _split_tail(tail: str) -> tuple[str, str, str]:
    fragment = ""
    if "#" in tail:
        tail, fragment = tail.split("#", 1)
    query = ""
    if "?" in tail:
        tail, query = tail.split("?", 1)
    path = tail or ""
    return path, query, fragment


def _remove_dot_segments(path: str) -> str:
    if not path or ("/./" not in path and "/../" not in path
                    and not path.endswith(("/.", "/.."))):
        return path
    out: list[str] = []
    for seg in path.split("/"):
        if seg == ".":
            continue
        if seg == "..":
            if out and out[-1] != "":
                out.pop()
            continue
        out.append(seg)
    res = "/".join(out)
    return res or "/"


def _build_normalized(scheme: str, host_ascii: str, port: int | None, path: str,
                      query: str, is_ip: bool) -> str:
    if not host_ascii:
        return f"{scheme}:{path}"
    netloc = host_ascii
    if port is not None and port != SPECIAL_SCHEMES.get(scheme):
        netloc = f"{host_ascii}:{port}"
    path = _remove_dot_segments(path) if path else ""
    q = f"?{query}" if query else ""
    return f"{scheme}://{netloc}{path}{q}"


def normalize_url(url: str) -> str:
    """Canonical string for IOC matching and dedup (idempotent)."""
    p = parse_url(url)
    if not p.host_ascii and not p.is_ip:
        return p.url
    return p.url


# --------------------------------------------------------------------------- #
# host relationships
# --------------------------------------------------------------------------- #
def host_is_under(host: str, domain: str) -> bool:
    """True if ``host`` equals ``domain`` or is a label-boundary subdomain of it."""
    host = host.rstrip(".").lower()
    domain = domain.rstrip(".").lower()
    if not host or not domain:
        return False
    return host == domain or host.endswith("." + domain)


def same_site(a: str, b: str) -> bool:
    """True if two URLs/hosts share a registrable domain (private-PSL aware)."""
    ra = parse_url(a).registrable_domain or parse_url(a).host
    rb = parse_url(b).registrable_domain or parse_url(b).host
    return bool(ra) and ra == rb


# --------------------------------------------------------------------------- #
# refang / defang
# --------------------------------------------------------------------------- #
_REFANG_SUBS = [
    (re.compile(r"h\s*[\[\(\{]?x+[\]\)\}]?\s*x*ps?", re.I), None),  # handled below
]


def refang(text: str) -> str:
    """Convert defanged IOCs (``hxxp``, ``[.]``, ``(dot)`` …) back to real form."""
    t = text
    t = re.sub(r"h\s*x\s*x\s*p\s*s", "https", t, flags=re.I)
    t = re.sub(r"h\s*x\s*x\s*p", "http", t, flags=re.I)
    t = re.sub(r"f\s*x\s*p", "ftp", t, flags=re.I)
    t = re.sub(r"\[\s*(?:\.|dot)\s*\]", ".", t, flags=re.I)
    t = re.sub(r"\(\s*(?:\.|dot)\s*\)", ".", t, flags=re.I)
    t = re.sub(r"\{\s*(?:\.|dot)\s*\}", ".", t, flags=re.I)
    t = re.sub(r"\s+dot\s+", ".", t, flags=re.I)
    t = re.sub(r"\[\s*:\s*\]", ":", t)
    t = re.sub(r"\[\s*(?:/|slash)\s*\]", "/", t, flags=re.I)
    t = re.sub(r"\[\s*@\s*\]|\(\s*(?:@|at)\s*\)", "@", t, flags=re.I)
    t = re.sub(r"\[\s*at\s*\]", "@", t, flags=re.I)
    return t


def defang(url: str) -> str:
    """Render a URL safe to display/log (``https`` → ``hxxps``, ``.`` → ``[.]`` in host)."""
    p = parse_url(url)
    out = url
    out = re.sub(r"^https", "hxxps", out, flags=re.I)
    out = re.sub(r"^http", "hxxp", out, flags=re.I)
    if p.host:
        out = out.replace(p.host_ascii, p.host_ascii.replace(".", "[.]"), 1)
        if p.host_unicode != p.host_ascii:
            out = out.replace(p.host_unicode, p.host_unicode.replace(".", "[.]"), 1)
    return out.replace("@", "[@]")


# --------------------------------------------------------------------------- #
# URL extraction from free text
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ExtractedURL:
    url: str
    start: int
    end: int
    defanged: bool
    bare: bool


_SCHEME_URL_RE = re.compile(
    r"""(?xi)
    \b(?:https?|ftp)://
    [^\s<>"'`\]\}]+
    """)
_WWW_RE = re.compile(r"""(?xi)\bwww\d{0,3}\.[^\s<>"'`\]\}]+""")
# Bare domain: label(.label)+ optional path; the suffix is validated against PSL after.
_BARE_RE = re.compile(
    r"""(?xi)
    \b
    (?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?\.)+
    [a-z¡-￿]{2,24}
    (?:/[^\s<>"'`\]\}]*)?
    """)
_DEFANG_HINT = re.compile(r"(?i)hxxp|\[\.\]|\(\.\)|\[dot\]|\(dot\)|\[:\]|\[/\]")
_MAX_EXTRACT_CHARS = 2_000_000
_TRAILING = ".,;:!?)]}>\"'`"


def _strip_trailing(url: str) -> str:
    while url and url[-1] in _TRAILING:
        if url[-1] == ")" and url.count("(") > url.count(")"):
            break
        if url[-1] == "]" and url.count("[") > url.count("]"):
            break
        url = url[:-1]
    return url


# RFC 6761 / 7686 special-use TLDs: not in the PSL, but valid URL hosts that appear in
# shared (and defanged) IOCs, so extraction should recognise them.
_SPECIAL_TLDS = {"test", "example", "invalid", "localhost", "onion", "local"}


def _valid_suffix(host: str) -> bool:
    ext = _extract_private()(host)
    if ext.suffix and ext.domain:
        return True
    last = host.rsplit(".", 1)[-1].lower()
    return "." in host and last in _SPECIAL_TLDS


def extract_urls(text: str, *, max_urls: int = 500,
                 include_bare: bool = True) -> list[ExtractedURL]:
    """Find URLs in free text (scheme URLs, ``www.`` hosts, defanged forms, and — when
    ``include_bare`` — bare registrable domains validated against the PSL).

    Spans index into the *original* text. Defanged IOCs are refanged in ``.url`` but
    their spans still point at the original defanged substring.
    """
    if not text:
        return []
    scan = text[:_MAX_EXTRACT_CHARS]
    found: list[ExtractedURL] = []
    claimed: list[tuple[int, int]] = []

    def _overlaps(s: int, e: int) -> bool:
        return any(s < ce and e > cs for cs, ce in claimed)

    def _add(s: int, e: int, raw_match: str, bare: bool) -> None:
        stripped = _strip_trailing(raw_match)
        if not stripped:
            return
        e = s + len(stripped)
        if _overlaps(s, e):
            return
        defanged = bool(_DEFANG_HINT.search(stripped))
        url = refang(stripped) if defanged else stripped
        p = parse_url(url)
        host = p.host_unicode
        if not p.is_ip and (not host or not _valid_suffix(host)):
            return
        claimed.append((s, e))
        found.append(ExtractedURL(url=normalize_url(url) if p.valid else url,
                                  start=s, end=e, defanged=defanged, bare=bare))

    # Refang a working copy so hxxp:// and [.] forms match the scheme/bare regexes,
    # but keep offsets identical (refang here only shrinks on multi-char subs, so we
    # match on the original text and detect the defang hint per-match instead).
    for rx, bare in ((_SCHEME_URL_RE, False), (_WWW_RE, False)):
        for m in rx.finditer(scan):
            _add(m.start(), m.end(), m.group(0), bare)

    # Defanged scheme URLs (hxxp://, hxxps[:]//)
    for m in re.finditer(r"(?i)\bh\s*x+\s*ps?\s*(?:://|\[:\]//|:\[/\]\[/\])"
                         r"[^\s<>\"'`\]\}]+", scan):
        _add(m.start(), m.end(), m.group(0), False)

    if include_bare:
        for m in _BARE_RE.finditer(scan):
            _add(m.start(), m.end(), m.group(0), True)
        # defanged bare domains: example[.]com/login
        for m in re.finditer(
                r"(?xi)\b(?:[a-z0-9-]+\s*[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]\s*)+[a-z]{2,24}"
                r"(?:/[^\s<>\"'`\]\}]*)?", scan):
            _add(m.start(), m.end(), m.group(0), True)

    found.sort(key=lambda u: u.start)
    # dedupe by normalized url preserving first occurrence
    seen: set[str] = set()
    out: list[ExtractedURL] = []
    for u in found:
        key = u.url.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
        if len(out) >= max_urls:
            break
    return out


def hosts_in(text: str) -> list[str]:
    """Registrable domains mentioned in ``text`` (convenience over extract_urls)."""
    seen: list[str] = []
    for e in extract_urls(text):
        rd = parse_url(e.url).registrable_domain
        if rd and rd not in seen:
            seen.append(rd)
    return seen


def iter_hosts(urls: Iterable[str]) -> list[str]:  # pragma: no cover - convenience
    return [parse_url(u).host for u in urls]
