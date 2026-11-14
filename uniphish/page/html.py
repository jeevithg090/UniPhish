"""Structural parsing of HTML documents into phishing-relevant facts.

Credential-harvesting pages reveal themselves structurally: a password form that posts to
another site, a ``data:`` form action, a meta-refresh hop, a hidden full-page iframe,
packed/obfuscated inline script, JS that writes to the clipboard (ClickFix). This module
extracts those facts into a plain :class:`PageModel` that analyzers (and tests) can
reason about without touching HTML again.

Security properties: the document is *never* executed or rendered; input is truncated to
:data:`MAX_HTML_CHARS`; every collection is capped; all regexes are linear (single
character classes or fixed alternations, applied to length-bounded strings); parsing
never raises (a failure yields a model with ``parse_error`` set).
"""

from __future__ import annotations

import logging
import math
import re
import warnings
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Comment, MarkupResemblesLocatorWarning
from bs4.element import Tag

from uniphish.url.parse import parse_url

log = logging.getLogger("uniphish.page")

MAX_HTML_CHARS = 2_000_000
MAX_TAGS = 20_000  # elements examined per document
MAX_ITEMS = 1_000  # cap per collection (links, scripts, images, ...)
MAX_TEXT_CHARS = 200_000
MAX_SCRIPT_SCAN = 200_000  # chars of a single inline script that are regex-scanned
MAX_ATTR_CHARS = 4_000

#: Default brand keywords for the cheap text pass; analyzers cross-check with BrandKB.
DEFAULT_BRAND_KEYWORDS: tuple[str, ...] = (
    "paypal",
    "microsoft",
    "office 365",
    "outlook",
    "onedrive",
    "sharepoint",
    "google",
    "gmail",
    "apple",
    "icloud",
    "amazon",
    "facebook",
    "instagram",
    "meta",
    "linkedin",
    "netflix",
    "dropbox",
    "docusign",
    "adobe",
    "wells fargo",
    "chase",
    "bank of america",
    "citibank",
    "hsbc",
    "barclays",
    "coinbase",
    "binance",
    "metamask",
    "ledger",
    "steam",
    "discord",
    "telegram",
    "whatsapp",
    "dhl",
    "fedex",
    "ups",
    "usps",
    "irs",
    "okta",
    "github",
    "zoom",
    "webmail",
    "cloudflare",
)

_CRED_NAME_RE = re.compile(
    r"pass|pwd|otp|2fa|mfa|totp|pin|cvv|cvc|ssn|card|secret|login|user|email|mail|"
    r"token|auth|code|account|seed|mnemonic|phrase",
    re.I,
)
_CRED_EXCLUDE_RE = re.compile(r"csrf|xsrf|authenticity|nonce|viewstate|honeypot", re.I)
_EVAL_RE = re.compile(
    r"\b(?:eval|Function|atob|unescape|fromCharCode)\s*\(|document\s*\.\s*write(?:ln)?\s*\("
)
_NET_RE = re.compile(
    r"\bfetch\s*\(|XMLHttpRequest|\bsendBeacon\b|\$\s*\.\s*(?:post|ajax)\b|\baxios\b|"
    r"\.submit\s*\(",
    re.I,
)
_CLIPBOARD_RE = re.compile(
    r"navigator\s*\.\s*clipboard\s*\.\s*write(?:Text)?\s*\(|"
    r"execCommand\s*\(\s*['\"]copy['\"]",
    re.I,
)
_B64_RE = re.compile(r"[A-Za-z0-9+/=_\-]{40,}")
_WS_RE = re.compile(r"\s+")
_TAB_NL_RE = re.compile(r"[\t\r\n]")
_C0_SPACE = "".join(chr(c) for c in range(0x21)) + "\x7f"
_SUSPICIOUS_COMMENT_RE = re.compile(
    r"phish|victim|scam|\bkit\b|saved from url|mirrored from|cloned|telegram|bot\s*token|"
    r"panel|logs?\.txt|result[s]?\.txt|exfil|drop\s*mail|send\s*to\s*mail|"
    r"coded by|created by|developed by|\bcrack(?:ed|er)\b|anti-?bot|"
    r"redirect.{0,20}(?:victim|bot)",
    re.I,
)


@dataclass
class MetaInfo:
    """Selected ``<meta>`` values (lower-cased keys resolved, values stripped)."""

    description: str = ""
    refresh_target: str = ""  # resolved absolute URL ("" when no meta refresh)
    refresh_delay: float | None = None
    csp: str = ""
    referrer: str = ""
    generator: str = ""
    og_site_name: str = ""
    theme_color: str = ""


@dataclass
class FormModel:
    """One ``<form>`` and the credential-harvesting facts derived from it."""

    action: str = ""  # resolved absolute (or "" when absent)
    method: str = "get"
    is_cross_origin: bool = False  # action (or a submit formaction) leaves the base site
    has_password: bool = False
    has_hidden_credential: bool = False
    input_names: list[str] = field(default_factory=list)
    submits_to_data_uri: bool = False
    submits_offsite_js: bool = False  # onsubmit handler posts via fetch/XHR/beacon
    autocomplete_off: bool = False
    action_host: str = ""


@dataclass
class LinkRef:
    href: str
    text: str = ""
    rel: str = ""
    target: str = ""


@dataclass
class ScriptRef:
    src: str = ""
    inline_len: int = 0
    is_external: bool = False
    host: str = ""


@dataclass
class IframeRef:
    src: str = ""
    sandbox: str | None = None
    hidden: bool = False


@dataclass
class ImageRef:
    src: str = ""
    alt: str = ""


@dataclass
class ScriptEntropy:
    """Longest base64-ish blob in inline scripts and its Shannon entropy (bits/char)."""

    max_blob_len: int = 0
    entropy: float = 0.0


@dataclass
class PageModel:
    """Structural facts extracted from one HTML document."""

    title: str = ""
    meta: MetaInfo = field(default_factory=MetaInfo)
    lang: str = ""
    base_href: str = ""
    visible_text: str = ""
    text_len: int = 0
    forms: list[FormModel] = field(default_factory=list)
    password_input_count: int = 0
    password_field_present: bool = False
    links: list[LinkRef] = field(default_factory=list)
    external_link_hosts: list[str] = field(default_factory=list)
    scripts: list[ScriptRef] = field(default_factory=list)
    iframes: list[IframeRef] = field(default_factory=list)
    images: list[ImageRef] = field(default_factory=list)
    favicons: list[tuple[str, str]] = field(default_factory=list)  # (href, rel)
    has_eval_like: int = 0  # count of eval/Function/atob/... call sites
    inline_script_entropy: ScriptEntropy = field(default_factory=ScriptEntropy)
    external_form_post: bool = False
    resource_hosts: set[str] = field(default_factory=set)
    brand_text_hits: dict[str, int] = field(default_factory=dict)
    meta_refresh_offsite: bool = False
    clipboard_write: int = 0  # count of clipboard-write call sites (ClickFix)
    suspicious_comment_count: int = 0
    truncated: bool = False
    parse_error: str = ""


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
class _HostCache:
    """Memoised ``url -> (host, registrable)`` so repeated hosts are parsed once."""

    def __init__(self) -> None:
        self._c: dict[str, tuple[str, str]] = {}

    def get(self, url: str) -> tuple[str, str]:
        hit = self._c.get(url)
        if hit is None:
            if not url.lower().startswith(
                ("http://", "https://", "//", "ftp://", "ws://", "wss://")
            ):
                hit = ("", "")
            else:
                try:
                    p = parse_url(url)
                    host = p.host_ascii or p.host
                    hit = (host, (p.registrable_ascii or host) if host else "")
                except Exception:  # pragma: no cover - parse_url is documented not to raise
                    hit = ("", "")
            if len(self._c) < 5_000:
                self._c[url] = hit
        return hit


def _clean(s: str | None, limit: int = 300) -> str:
    return _WS_RE.sub(" ", s or "").strip()[:limit]


def _resolve(base: str | None, ref: object) -> str:
    """Resolve ``ref`` against ``base`` the way a browser would; never raises."""
    if not isinstance(ref, str):
        return ""
    ref = _TAB_NL_RE.sub("", ref[:MAX_ATTR_CHARS]).strip(_C0_SPACE)
    if not ref:
        return ""
    if ref.lower().startswith(
        ("data:", "javascript:", "vbscript:", "mailto:", "tel:", "blob:", "about:")
    ):
        return ref
    try:
        return urljoin(base, ref) if base else ref
    except ValueError:
        return ref


def _attr(tag: Tag, name: str) -> str:
    v = tag.get(name)
    if isinstance(v, list):
        v = " ".join(v)
    return v if isinstance(v, str) else ""


def _is_hidden_frame(tag: Tag) -> bool:
    if tag.has_attr("hidden"):
        return True
    style = _WS_RE.sub("", _attr(tag, "style").lower())
    if (
        "display:none" in style
        or "visibility:hidden" in style
        or "opacity:0" in style
        or "width:0" in style
        or "height:0" in style
        or "left:-" in style
    ):
        return True
    for dim in ("width", "height"):
        v = _attr(tag, dim).strip().lower().rstrip("px")
        if v in {"0", "1"}:
            return True
    return False


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _parse_refresh(content: str) -> tuple[float | None, str]:
    """Parse ``"5; url=http://x"`` into ``(delay, url)`` without backtracking regexes."""
    content = content[:2_000].strip()
    if not content:
        return None, ""
    sep = min((i for i in (content.find(";"), content.find(",")) if i >= 0), default=-1)
    if sep < 0:
        head, tail = content, ""
        # "5 url=..." form
        parts = content.split(None, 1)
        if len(parts) == 2:
            head, tail = parts
    else:
        head, tail = content[:sep], content[sep + 1 :]
    try:
        delay: float | None = max(0.0, float(head.strip())) if head.strip() else 0.0
    except ValueError:
        delay = None
    tail = tail.strip()
    if tail[:3].lower() == "url":
        tail = tail[3:].lstrip()
        if tail.startswith("="):
            tail = tail[1:].lstrip()
    tail = tail.strip().strip("'\"").strip()
    return delay, tail


def _script_text(tag: Tag) -> str:
    return tag.get_text() if tag.contents else ""


def _brand_hits(text: str, keywords: Iterable[str]) -> dict[str, int]:
    low = text.lower()
    out: dict[str, int] = {}
    for kw in keywords:
        k = kw.lower().strip()
        if not k:
            continue
        # word-boundary-ish count without regex: check neighbours are non-alphanumeric
        n = 0
        start = 0
        while True:
            i = low.find(k, start)
            if i < 0:
                break
            before = low[i - 1] if i > 0 else " "
            after = low[i + len(k)] if i + len(k) < len(low) else " "
            if not before.isalnum() and not after.isalnum():
                n += 1
            start = i + len(k)
            if n >= 1000:
                break
        if n:
            out[k] = n
    return out


# --------------------------------------------------------------------------- #
# main entry point
# --------------------------------------------------------------------------- #
def parse_html(
    html: str, base_url: str | None = None, *, brand_keywords: Iterable[str] | None = None
) -> PageModel:
    """Parse ``html`` into a :class:`PageModel`. Never executes content; never raises.

    ``base_url`` is the page's own URL: relative references are resolved against it
    (honouring a ``<base href>``) and "cross-origin" means *different registrable
    domain* from it. Without ``base_url`` every absolute http(s) target counts as
    external. ``brand_keywords`` overrides :data:`DEFAULT_BRAND_KEYWORDS` for the
    cheap brand-text pass.
    """
    model = PageModel()
    if not isinstance(html, str):
        html = html.decode("utf-8", "replace") if isinstance(html, (bytes, bytearray)) else ""
    if len(html) > MAX_HTML_CHARS:
        html = html[:MAX_HTML_CHARS]
        model.truncated = True
    if not html.strip():
        return model
    try:
        _extract(html, base_url, model, brand_keywords)
    except Exception as exc:  # defensive: hostile markup must never crash analysis
        log.warning("html parse failed: %s", type(exc).__name__)
        model.parse_error = f"{type(exc).__name__}: {exc}"[:200]
    return model


def _extract(
    html: str, base_url: str | None, m: PageModel, brand_keywords: Iterable[str] | None
) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", MarkupResemblesLocatorWarning)
        soup = BeautifulSoup(html, "lxml")
    # One pass over the tree: per-name buckets + comments (repeated find_all is O(n) each).
    by_name: dict[str, list[Tag]] = {}
    comments: list[Comment] = []
    all_tags: list[Tag] = []
    for node in soup.descendants:
        if isinstance(node, Tag):
            if len(all_tags) >= MAX_TAGS:
                m.truncated = True
                break
            all_tags.append(node)
            by_name.setdefault(node.name, []).append(node)
        elif isinstance(node, Comment):
            comments.append(node)

    def by(*names: str) -> list[Tag]:
        return [t for n in names for t in by_name.get(n, ())]

    hosts = _HostCache()
    base_host, base_reg = hosts.get(base_url) if base_url else ("", "")

    # <base href> -------------------------------------------------------------------
    eff_base = base_url
    base_tag = next((t for t in by("base") if t.has_attr("href")), None)
    if isinstance(base_tag, Tag):
        bh = _resolve(base_url, _attr(base_tag, "href"))
        if bh.lower().startswith(("http://", "https://")):
            m.base_href = bh
            eff_base = bh

    def is_external(url: str) -> bool:
        host, reg = hosts.get(url)
        if not host:
            return False
        return not (base_reg and reg == base_reg)

    # <html lang>, <title> ------------------------------------------------------------
    root = next(iter(by("html")), None)
    if isinstance(root, Tag):
        m.lang = _clean(_attr(root, "lang"), 35)
    if by("title"):
        m.title = _clean(by("title")[0].get_text(), 300)

    # meta ----------------------------------------------------------------------------
    for tag in by("meta")[:500]:
        name = (_attr(tag, "name") or _attr(tag, "property")).lower().strip()
        equiv = _attr(tag, "http-equiv").lower().strip()
        content = _clean(_attr(tag, "content"), 2_000)
        if name == "description" and not m.meta.description:
            m.meta.description = content
        elif name == "referrer":
            m.meta.referrer = content
        elif name == "generator":
            m.meta.generator = content
        elif name == "og:site_name":
            m.meta.og_site_name = content
        elif name == "theme-color":
            m.meta.theme_color = content
        if equiv == "content-security-policy":
            m.meta.csp = content
        elif equiv == "refresh" and not m.meta.refresh_target:
            delay, target = _parse_refresh(_attr(tag, "content"))
            m.meta.refresh_delay = delay
            if target:
                m.meta.refresh_target = _resolve(eff_base, target)
                m.meta_refresh_offsite = is_external(m.meta.refresh_target)

    # comments ------------------------------------------------------------------------
    for c in comments[:2_000]:
        if _SUSPICIOUS_COMMENT_RE.search(str(c)[:2_000]):
            m.suspicious_comment_count += 1

    resource_hosts: set[str] = set()

    def note_resource(url: str) -> None:
        host, _ = hosts.get(url)
        if host and is_external(url):
            resource_hosts.add(host)

    # forms ---------------------------------------------------------------------------
    for ftag in by("form")[:MAX_ITEMS]:
        m.forms.append(_build_form(ftag, eff_base, hosts, is_external, note_resource))
    m.external_form_post = any(
        f.is_cross_origin and (f.method == "post" or f.has_password) for f in m.forms
    )

    # password inputs anywhere (forms are often synthesised by JS or malformed) -------
    m.password_input_count = sum(
        1 for i in by("input")[:5_000] if _attr(i, "type").strip().lower() == "password"
    )
    m.password_field_present = m.password_input_count > 0

    # links ---------------------------------------------------------------------------
    ext_hosts: dict[str, None] = {}
    for a in [a for a in by("a") if a.has_attr("href")][: MAX_ITEMS * 2]:
        href = _resolve(eff_base, _attr(a, "href"))
        if len(m.links) < MAX_ITEMS:
            m.links.append(
                LinkRef(
                    href=href,
                    text=_clean(a.get_text(), 200),
                    rel=_clean(_attr(a, "rel"), 100),
                    target=_clean(_attr(a, "target"), 30),
                )
            )
        host, _ = hosts.get(href)
        if host and is_external(href) and len(ext_hosts) < MAX_ITEMS:
            ext_hosts[host] = None
    m.external_link_hosts = list(ext_hosts)

    # scripts + obfuscation indicators -------------------------------------------------
    best_blob = ""
    js_chunks: list[str] = []
    for s in by("script")[:MAX_ITEMS]:
        src = _attr(s, "src")
        if src:
            rsrc = _resolve(eff_base, src)
            host, _ = hosts.get(rsrc)
            m.scripts.append(ScriptRef(src=rsrc, inline_len=0, is_external=bool(host), host=host))
            note_resource(rsrc)
        text = _script_text(s)
        if text.strip():
            if not src:
                m.scripts.append(ScriptRef(inline_len=len(text)))
            js_chunks.append(text[:MAX_SCRIPT_SCAN])
    # inline event handlers participate in eval/clipboard counting
    handler_chunks: list[str] = []
    for t in all_tags:
        for aname, aval in t.attrs.items():
            if aname.startswith("on") and isinstance(aval, str) and len(handler_chunks) < 2_000:
                handler_chunks.append(aval[:MAX_ATTR_CHARS])
    for chunk in js_chunks:
        m.has_eval_like += len(_EVAL_RE.findall(chunk))
        m.clipboard_write += len(_CLIPBOARD_RE.findall(chunk))
        for b in _B64_RE.finditer(chunk):
            if len(b.group()) > len(best_blob):
                best_blob = b.group()
    for chunk in handler_chunks:
        m.has_eval_like += len(_EVAL_RE.findall(chunk))
        m.clipboard_write += len(_CLIPBOARD_RE.findall(chunk))
    if best_blob:
        m.inline_script_entropy = ScriptEntropy(len(best_blob), round(_shannon(best_blob), 4))

    # iframes / embeds / images / favicons / other resources ---------------------------
    for fr in by("iframe", "frame")[:MAX_ITEMS]:
        src = _resolve(eff_base, _attr(fr, "src"))
        sandbox = _attr(fr, "sandbox") if fr.has_attr("sandbox") else None
        m.iframes.append(IframeRef(src=src, sandbox=sandbox, hidden=_is_hidden_frame(fr)))
        note_resource(src)
    for img in by("img")[:MAX_ITEMS]:
        src = _resolve(eff_base, _attr(img, "src"))
        m.images.append(ImageRef(src=src, alt=_clean(_attr(img, "alt"), 200)))
        note_resource(src)
    for ln in [t for t in by("link") if t.has_attr("href")][:MAX_ITEMS]:
        rel = " ".join(ln.get("rel") or []) if isinstance(ln.get("rel"), list) else _attr(ln, "rel")
        rel = rel.lower().strip()
        href = _resolve(eff_base, _attr(ln, "href"))
        if "icon" in rel.split():
            m.favicons.append((href, rel))
        note_resource(href)
    for t in by("embed", "object", "source", "video", "audio")[:MAX_ITEMS]:
        note_resource(_resolve(eff_base, _attr(t, "src") or _attr(t, "data")))
    m.resource_hosts = resource_hosts

    # visible text ---------------------------------------------------------------------
    for c in comments:
        c.extract()
    for t in by("script", "style", "noscript", "template", "head"):
        t.decompose()
    text = _clean(soup.get_text(" "), MAX_TEXT_CHARS)
    m.visible_text = text
    m.text_len = len(text)

    # cheap brand pass over title + visible text
    kws = tuple(brand_keywords) if brand_keywords is not None else DEFAULT_BRAND_KEYWORDS
    m.brand_text_hits = _brand_hits(f"{m.title} {text}", kws)


def _build_form(
    ftag: Tag, base: str | None, hosts: _HostCache, is_external, note_resource
) -> FormModel:
    raw_action = _attr(ftag, "action")
    action = _resolve(base, raw_action)
    method = _attr(ftag, "method").strip().lower()
    f = FormModel(action=action, method=method if method in {"get", "post", "dialog"} else "get")
    f.action_host = hosts.get(action)[0]
    f.submits_to_data_uri = action.lower().startswith("data:")
    f.is_cross_origin = is_external(action)
    note_resource(action)

    ac = _attr(ftag, "autocomplete").strip().lower() == "off"
    names: list[str] = []
    for inp in ftag.find_all(["input", "textarea", "select", "button"], limit=500):
        itype = _attr(inp, "type").strip().lower()
        name = _clean(_attr(inp, "name") or _attr(inp, "id"), 100)
        if inp.name == "input" and itype == "password":
            f.has_password = True
        if (
            inp.name == "input"
            and itype == "hidden"
            and name
            and _CRED_NAME_RE.search(name)
            and not _CRED_EXCLUDE_RE.search(name)
        ):
            f.has_hidden_credential = True
        if name and len(names) < 200:
            names.append(name)
        if _attr(inp, "autocomplete").strip().lower() == "off":
            ac = True
        fa = _attr(inp, "formaction")
        if fa and inp.name in {"input", "button"}:
            rfa = _resolve(base, fa)
            note_resource(rfa)
            if rfa.lower().startswith("data:"):
                f.submits_to_data_uri = True
            if is_external(rfa):
                f.is_cross_origin = True
    f.input_names = names
    f.autocomplete_off = ac
    onsubmit = _attr(ftag, "onsubmit")[:MAX_ATTR_CHARS]
    f.submits_offsite_js = bool(onsubmit and _NET_RE.search(onsubmit))
    return f
