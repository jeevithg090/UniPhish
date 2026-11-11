"""Active analyzers: SSRF-safe page fetch (+ redirect chain) and sandbox detonation.

Why this exists
---------------
Static URL analysis reasons about a link's *shape*. These two analyzers reason about
where the link actually *goes* and what the page actually *does* — the ground truth a
phishing operator tries hardest to hide:

``FetchAnalyzer`` (stage 30, ``options.fetch_pages``)
    Fetches the URL through :func:`uniphish.core.net.safe_fetch` — the only SSRF-proof
    gateway — and follows the redirect chain. It records every hop and the landing URL
    as indicators, hands the resolved document to the rest of the engine as a child
    ``PAGE`` artifact (so the page / kit / injection analyzers run on *real* content),
    and flags a chain that reveals a living-off-trusted-sites host, a shortener's risky
    terminal or a brand hand-off, a ``data:`` URI landing, or an attempt to redirect the
    scanner at a private address (an SSRF probe).

``DetonationAnalyzer`` (stage 30, ``options.detonate``)
    Renders the URL in a hardened, sandboxed headless browser
    (:mod:`uniphish.intel.detonate`) to catch JavaScript-built phishing that a static
    fetch never sees: cloaking (the rendered DOM differs materially from the served
    HTML), a runtime clipboard write (ClickFix), and a client-side redirect to another
    host/brand. The rendered DOM is routed back through the engine as a child artifact so
    the structural / kit / prompt-injection matchers evaluate the assembled attack.

Both are time-bounded and fault-isolated, touch the network only via the safe gateway
and the sandboxed browser, and never execute downloaded content on the host.
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from uniphish.assets.lists import is_dyndns, is_shortener, lots_match, tld_risk
from uniphish.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult, register
from uniphish.core.net import FetchResult, safe_fetch
from uniphish.core.types import (
    Artifact,
    ArtifactKind,
    ArtifactTooLarge,
    Indicator,
    IndicatorType,
    Signal,
)
from uniphish.intel.detonate import DetonationResult, detonate, playwright_available
from uniphish.page.html import PageModel, parse_html
from uniphish.url.brandkb import get_kb
from uniphish.url.brands import brand_impersonation
from uniphish.url.parse import ParsedURL, parse_url

log = logging.getLogger("uniphish.analyzers.fetch")

# ---- tuning ---------------------------------------------------------------- #
_W_REDIRECT_CROSS = 1.5
_W_DATA_URI = 2.0
_W_SSRF = 2.0
_W_CLOAKING = 2.5
_W_RUNTIME_CLIPBOARD = 3.0
_W_JS_REDIRECT = 2.0

_MAX_REDIRECTS = 8
_MAX_HOP_INDICATORS = 12
_MAX_CLIP_CHARS = 300
_HIGH_RISK_TLD = 1.0           # tld_risk log-odds at/above which a landing TLD is "risky"

# Content types we turn into a child PAGE artifact (everything else HTML-ish is sniffed).
_HTML_CTYPES = ("text/html", "application/xhtml+xml", "application/xhtml")
_HTML_SNIFF = (b"<!doctype html", b"<html", b"<head", b"<body", b"<form", b"<script")
# Response bodies worth inspecting as a downloaded FILE rather than a page.
_FILE_CTYPE_PREFIXES = ("application/", "image/", "font/", "audio/", "video/")
_NOT_FILE_CTYPES = ("application/xhtml+xml", "application/xhtml")


def _host(url: str | None) -> str:
    if not url:
        return ""
    p = parse_url(url)
    return p.host_ascii if p.valid or p.host_ascii else ""


def _registrable(url: str | None) -> str:
    if not url:
        return ""
    p = parse_url(url)
    return p.registrable_domain or p.host_ascii


def _ip_indicator(ip: str, role: str) -> Indicator | None:
    ip = (ip or "").strip()
    if not ip:
        return None
    itype = IndicatorType.IPV6 if ":" in ip else IndicatorType.IPV4
    return Indicator(type=itype, value=ip, role=role)


def _looks_html(body: bytes, content_type: str | None) -> bool:
    ct = (content_type or "").lower()
    if ct.startswith(_HTML_CTYPES):
        return True
    head = body[:2048].lstrip().lower()
    return any(tok in head for tok in _HTML_SNIFF)


def _is_fileish(content_type: str | None) -> bool:
    ct = (content_type or "").lower()
    if ct in _NOT_FILE_CTYPES:
        return False
    return ct.startswith(_FILE_CTYPE_PREFIXES)


def _is_ssrf_block(reason: str | None) -> bool:
    """True when a safe_fetch refusal indicates an attempt to reach a private address."""
    if not reason:
        return False
    low = reason.lower()
    return ("non-public" in low or "resolves to non-public" in low
            or "numeric host obfuscation" in low or "hex host obfuscation" in low)


def _data_uri_hop(result: FetchResult) -> str | None:
    """The ``data:`` target a redirect pointed at, if the chain tried to land on one."""
    for hop in result.chain:
        loc = (hop.location or "").strip()
        if loc[:5].lower() == "data:":
            return loc
    if (result.blocked_reason or "").lower().startswith("scheme not allowed: data"):
        return result.chain[-1].url if result.chain else None
    return None


def _filename_from_url(url: str | None) -> str | None:
    if not url:
        return None
    path = urlsplit(url).path
    name = path.rsplit("/", 1)[-1] if path else ""
    return name[:120] or None


class _ActiveBase(Analyzer):
    """Shared guards for the active (online, URL-only) analyzers."""

    kinds = frozenset({ArtifactKind.URL})
    stage = 30
    requires_online = True

    def applies(self, artifact: Artifact, ctx: AnalysisContext) -> bool:
        if artifact.kind is not ArtifactKind.URL or not artifact.url:
            return False
        p = parse_url(artifact.url)
        return p.scheme in ("http", "https") and bool(p.host_ascii)


@register
class FetchAnalyzer(_ActiveBase):
    """Statically fetch the URL (SSRF-safe), follow redirects, expose the real landing."""

    name = "fetch"
    requires_detonation = False
    description = ("Safely fetches the URL and follows its redirect chain; exposes the "
                   "landing page as a child artifact and flags risky redirect hand-offs")
    signals = {
        "fetch.redirect_cross": "Redirect chain crosses into a risky or unrelated host",
        "fetch.landing_data_uri": "Redirect chain ends at an inline data: URI",
        "fetch.ssrf_blocked": "Page tried to redirect the scanner to a private address",
    }

    def applies(self, artifact: Artifact, ctx: AnalysisContext) -> bool:
        return bool(ctx.options.fetch_pages) and super().applies(artifact, ctx)

    async def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        res = AnalyzerResult()
        start = parse_url(artifact.url or "")
        budget = min(ctx.options.analyzer_timeout_s, max(1.0, ctx.settings.http_timeout_s))
        result = await safe_fetch(
            artifact.url or "",
            timeout=budget,
            follow_redirects=True,
            max_redirects=_MAX_REDIRECTS,
        )

        res.meta["fetch"] = {
            "final_url": result.final_url,
            "status": result.status,
            "ip": result.ip,
            "redirects": max(0, len(result.chain) - 1),
            "content_type": result.content_type,
            "truncated": result.truncated,
            "https": (result.final_url or "").lower().startswith("https://"),
            "error": result.error,
            "blocked_reason": result.blocked_reason,
        }

        self._indicators(result, res)
        self._redirect_signals(start, result, res)
        self._landing_child(artifact, result, res)
        return res

    # ------------------------------------------------------------------ #
    def _indicators(self, result: FetchResult, res: AnalyzerResult) -> None:
        final = result.final_url or result.url
        seen: set[str] = set()
        added = 0
        for hop in result.chain:
            url = hop.url
            if not url or url == final or url in seen:
                continue
            seen.add(url)
            if added < _MAX_HOP_INDICATORS:
                res.indicators.append(Indicator(type=IndicatorType.URL, value=url,
                                                role="redirect"))
                added += 1
        if final:
            res.indicators.append(Indicator(type=IndicatorType.URL, value=final, role="landing"))
            host = _host(final)
            if host and not parse_url(final).is_ip:
                res.indicators.append(Indicator(type=IndicatorType.DOMAIN, value=host,
                                                role="landing"))
        ind = _ip_indicator(result.ip or "", "landing")
        if ind is not None:
            res.indicators.append(ind)

    # ------------------------------------------------------------------ #
    def _redirect_signals(self, start: ParsedURL, result: FetchResult,
                          res: AnalyzerResult) -> None:
        # SSRF probe: a redirect tried to send the scanner at a private address.
        if _is_ssrf_block(result.blocked_reason):
            res.signals.append(Signal(
                id="fetch.ssrf_blocked",
                title="Page tried to redirect the scanner to a private address",
                detail="Following this link led to a request for a private / internal "
                       f"address, which was refused ({result.blocked_reason}). Legitimate "
                       "sites do not redirect visitors at internal infrastructure; this is a "
                       "server-side request forgery probe.",
                weight=_W_SSRF, category="fetch",
                evidence={"blocked_reason": result.blocked_reason,
                          "chain": [h.url for h in result.chain][:_MAX_REDIRECTS]}))

        # data: URI landing — credential capture / HTML-smuggling without a real endpoint.
        data_target = _data_uri_hop(result)
        if data_target is not None:
            res.signals.append(Signal(
                id="fetch.landing_data_uri",
                title="Redirect chain ends at an inline data: URI",
                detail="The link redirects to an inline data: document rather than a hosted "
                       "page. Phishing uses this to render a credential form or smuggle a "
                       "payload straight from the URL, leaving no server to block.",
                weight=_W_DATA_URI, category="fetch", mitre=["T1566.002", "T1027.006"],
                evidence={"data_uri_prefix": data_target[:80]}))

        # Risky redirect hand-off (LOTS / dynamic DNS / brand change / shortener terminal).
        reasons, evidence = self._crossing(start, result)
        if reasons:
            final_host = _host(result.final_url)
            res.signals.append(Signal(
                id="fetch.redirect_cross",
                title="Redirect chain crosses into a risky or unrelated host",
                detail=self._crossing_detail(start, final_host, reasons),
                weight=_W_REDIRECT_CROSS, category="fetch", mitre=["T1566.002"],
                evidence=evidence))

    @staticmethod
    def _crossing(start: ParsedURL, result: FetchResult) -> tuple[list[str], dict]:
        final_url = result.final_url or result.url
        final = parse_url(final_url)
        final_host = final.host_ascii
        final_path = final.path
        start_host = start.host_ascii
        start_reg = start.registrable_domain or start_host
        final_reg = final.registrable_domain or final_host
        changed = bool(final_reg) and final_reg != start_reg

        lots_landing = lots_match(final_host, final_path)
        if lots_landing is None:
            for hop in result.chain:
                hit = lots_match(_host(hop.url), "")
                if hit is not None:
                    lots_landing = hit
                    break
        dyndns_landing = is_dyndns(final_host)
        start_short = is_shortener(start_host)

        start_brand = brand_impersonation(start)
        kb = get_kb()
        final_owner = kb.official_brand_for_host(final_host) if final_host else None
        brand_change = bool(
            start_brand is not None and final_owner is not None
            and start_brand.brand != final_owner.id)

        suffix = (final.suffix.rsplit(".", 1)[-1] if final.suffix else None)
        risk = tld_risk(suffix)
        risky_tld = risk is not None and risk >= _HIGH_RISK_TLD

        reasons: list[str] = []
        if lots_landing is not None:
            reasons.append("lots_landing")
        if dyndns_landing:
            reasons.append("dyndns_landing")
        if brand_change:
            reasons.append("brand_change")
        if start_short and changed and (reasons or risky_tld):
            reasons.append("shortener_terminal")

        if not reasons:
            return [], {}
        evidence = {
            "reasons": reasons,
            "start_host": start_host,
            "final_host": final_host,
            "start_registrable": start_reg,
            "final_registrable": final_reg,
            "registrable_changed": changed,
            "lots_host": lots_landing.name if lots_landing is not None else None,
            "dynamic_dns": dyndns_landing,
            "start_is_shortener": start_short,
            "risky_tld": risky_tld,
            "from_brand": start_brand.brand if start_brand else None,
            "to_brand": final_owner.id if final_owner else None,
        }
        return reasons, evidence

    @staticmethod
    def _crossing_detail(start: ParsedURL, final_host: str, reasons: list[str]) -> str:
        bits = []
        if "lots_landing" in reasons:
            bits.append("a free hosting / trusted-cloud service often abused for phishing")
        if "dyndns_landing" in reasons:
            bits.append("a dynamic-DNS host")
        if "brand_change" in reasons:
            bits.append("a domain belonging to a different brand")
        if "shortener_terminal" in reasons:
            bits.append("the risky destination hidden behind a link shortener")
        where = "; ".join(bits) or "an unrelated host"
        src = start.host_ascii or "the provided link"
        dst = final_host or "another host"
        return (f"The link {src} redirects to {dst}, which is {where}. Redirect hand-offs like "
                "this move the victim from a trusted-looking link to the attacker's real "
                "landing page.")

    # ------------------------------------------------------------------ #
    def _landing_child(self, artifact: Artifact, result: FetchResult,
                       res: AnalyzerResult) -> None:
        body = result.body or b""
        final = result.final_url or result.url
        if not body or not (result.ok or 200 <= result.status < 300):
            return
        if _looks_html(body, result.content_type):
            try:
                res.children.append(Artifact.from_page(
                    body, url=final, origin="fetch.page", parent_id=artifact.id,
                    charset=result.charset or "utf-8"))
            except (ArtifactTooLarge, ValueError):
                res.meta.setdefault("fetch_notes", []).append("landing page too large to analyse")
            return
        if _is_fileish(result.content_type):
            try:
                res.children.append(Artifact.from_file(
                    body, filename=_filename_from_url(final), mime=result.content_type,
                    origin="fetch.download", parent_id=artifact.id))
            except (ArtifactTooLarge, ValueError):
                res.meta.setdefault("fetch_notes", []).append("downloaded file too large")


@register
class DetonationAnalyzer(_ActiveBase):
    """Render the URL in a sandboxed browser to catch JavaScript-built phishing."""

    name = "detonate"
    requires_detonation = True
    description = ("Renders the URL in a hardened sandboxed headless browser to detect "
                   "cloaking, runtime clipboard writes (ClickFix) and client-side redirects")
    signals = {
        "fetch.cloaking": "Rendered page differs materially from the static HTML",
        "fetch.runtime_clipboard": "Page writes to the clipboard when rendered (ClickFix)",
        "fetch.js_redirect": "Page uses script to redirect to another site when rendered",
    }

    async def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        res = AnalyzerResult()
        if not playwright_available():
            res.meta["detonation"] = "skipped: Playwright is not installed"
            return res

        budget = max(2.0, min(ctx.options.analyzer_timeout_s, ctx.settings.http_timeout_s * 2))
        det = await detonate(url=artifact.url, timeout_s=budget)
        res.meta["detonation"] = {
            "final_url": det.final_url,
            "navigation_chain": det.navigation_chain[:_MAX_REDIRECTS],
            "clipboard_writes": len(det.clipboard_writes),
            "console_errors": len(det.console_errors),
            "downloads": det.download_urls[:5],
            "elapsed_ms": det.elapsed_ms,
            "error": det.error,
        }
        if not det.ok or not det.dom_html:
            if det.error:
                res.meta["detonation_error"] = det.error
            return res

        static_model = await self._static_model(artifact)
        rendered_model = parse_html(det.dom_html, det.final_url or artifact.url)

        self._cloaking_signal(static_model, rendered_model, res)
        self._clipboard_signal(det, res)
        self._js_redirect_signal(artifact, det, res)
        self._rendered_child(artifact, det, static_model, rendered_model, ctx, res)
        return res

    # ------------------------------------------------------------------ #
    async def _static_model(self, artifact: Artifact) -> PageModel | None:
        """Best-effort pre-JS HTML, used only as the cloaking baseline."""
        try:
            result = await safe_fetch(artifact.url or "", timeout=5.0, follow_redirects=True,
                                      max_redirects=_MAX_REDIRECTS)
        except Exception:  # safe_fetch never raises, but stay defensive
            return None
        if not result.body or not _looks_html(result.body, result.content_type):
            return None
        return parse_html(result.text(), result.final_url or artifact.url)

    def _cloaking_signal(self, static: PageModel | None, rendered: PageModel,
                         res: AnalyzerResult) -> None:
        if static is None:
            return
        differs, evidence = _materially_differs(static, rendered)
        if not differs:
            return
        res.signals.append(Signal(
            id="fetch.cloaking",
            title="Rendered page differs materially from the static HTML",
            detail="The document served to a scanner is benign, but running its scripts "
                   "assembles a different page (for example a credential form appears). "
                   "Serving one page to crawlers and another to victims is a hallmark of "
                   "phishing kits.",
            weight=_W_CLOAKING, confidence=0.9, category="fetch",
            mitre=["T1027", "T1497"], evidence=evidence))

    def _clipboard_signal(self, det: DetonationResult, res: AnalyzerResult) -> None:
        if not det.clipboard_writes:
            return
        sample = det.clipboard_writes[0][:_MAX_CLIP_CHARS]
        res.signals.append(Signal(
            id="fetch.runtime_clipboard",
            title="Page writes to the clipboard when rendered (ClickFix)",
            detail="When rendered, the page silently copied text to the visitor's clipboard "
                   f"({len(det.clipboard_writes)} write(s)). ClickFix attacks plant a command "
                   "this way and then tell the victim to paste it into the Run dialog or a "
                   "terminal.",
            weight=_W_RUNTIME_CLIPBOARD, category="fetch", mitre=["T1204.004", "T1059.001"],
            evidence={"writes": len(det.clipboard_writes), "sample": sample}))
        # A URL hidden in the pasted command is itself an IOC.
        for text in det.clipboard_writes[:3]:
            low = text.lower()
            for token in ("http://", "https://"):
                idx = low.find(token)
                if idx != -1:
                    url = text[idx:].split()[0][:500]
                    res.indicators.append(Indicator(type=IndicatorType.URL, value=url,
                                                    role="payload",
                                                    context="URL found in clipboard payload"))
                    break

    def _js_redirect_signal(self, artifact: Artifact, det: DetonationResult,
                            res: AnalyzerResult) -> None:
        final = det.final_url
        if not final or final.startswith("data:"):
            return
        start_reg = _registrable(artifact.url)
        final_reg = _registrable(final)
        if not final_reg or final_reg == start_reg:
            return
        res.indicators.append(Indicator(type=IndicatorType.URL, value=final, role="landing"))
        res.signals.append(Signal(
            id="fetch.js_redirect",
            title="Page uses script to redirect to another site when rendered",
            detail=f"Rendering the page navigated it from {_host(artifact.url) or 'the link'} "
                   f"to {_host(final)} via client-side script, a redirect invisible to anyone "
                   "inspecting the original link.",
            weight=_W_JS_REDIRECT, category="fetch", mitre=["T1566.002"],
            evidence={"start_registrable": start_reg, "final_registrable": final_reg,
                      "final_url": final,
                      "navigation_chain": det.navigation_chain[:_MAX_REDIRECTS]}))

    def _rendered_child(self, artifact: Artifact, det: DetonationResult,
                        static: PageModel | None, rendered: PageModel,
                        ctx: AnalysisContext, res: AnalyzerResult) -> None:
        """Route the rendered DOM back through the engine for page/kit/injection analysis.

        Only when it adds coverage the static path does not already have: a materially
        different (cloaked) DOM, or when no static fetch ran this request.
        """
        differs = static is not None and _materially_differs(static, rendered)[0]
        if not (differs or not ctx.options.fetch_pages):
            return
        try:
            res.children.append(Artifact.from_page(
                det.dom_html, url=det.final_url or artifact.url,
                origin="fetch.rendered", parent_id=artifact.id))
        except (ArtifactTooLarge, ValueError):
            res.meta.setdefault("detonation_notes", []).append("rendered DOM too large to analyse")


def _materially_differs(static: PageModel, rendered: PageModel) -> tuple[bool, dict]:
    """Heuristic: did rendering assemble a meaningfully more phishing-relevant page?"""
    new_password = rendered.password_field_present and not static.password_field_present
    more_forms = len(rendered.forms) > len(static.forms) and rendered.password_field_present
    new_clipboard = rendered.clipboard_write > 0 and static.clipboard_write == 0
    sim = _text_similarity(static.visible_text, rendered.visible_text)
    grew = (rendered.text_len > 200 and rendered.text_len > static.text_len * 1.5)
    textual = sim < 0.4 and grew
    differs = bool(new_password or more_forms or new_clipboard or textual)
    evidence = {
        "static_password": static.password_field_present,
        "rendered_password": rendered.password_field_present,
        "static_forms": len(static.forms),
        "rendered_forms": len(rendered.forms),
        "static_clipboard": static.clipboard_write,
        "rendered_clipboard": rendered.clipboard_write,
        "text_similarity": round(sim, 3),
        "static_text_len": static.text_len,
        "rendered_text_len": rendered.text_len,
    }
    return differs, evidence


def _text_similarity(a: str, b: str) -> float:
    """Jaccard similarity of the two texts' word sets (1.0 == identical, 0.0 == disjoint)."""
    ta = set(a.lower().split())
    tb = set(b.lower().split())
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union else 1.0


__all__ = ["FetchAnalyzer", "DetonationAnalyzer"]
