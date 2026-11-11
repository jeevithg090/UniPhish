"""HTML page analyzer: turns a parsed :class:`~uniphish.page.html.PageModel` into signals.

Why this exists
---------------
Credential-harvesting pages give themselves away *structurally*, independent of the
domain: a password form that posts to another site, a ``data:`` form action, packed
script, a clipboard write behind a fake CAPTCHA (ClickFix), a hidden full-page iframe,
a meta-refresh hop. They also give themselves away *semantically*: the page says
"PayPal" in its title but is served from a domain PayPal does not own. This analyzer
combines both families, and tempers them with legitimacy evidence (an official brand
domain showing its own branding).

Design notes
------------
* Pure static analysis (stage 0, offline). The document is never rendered or executed;
  parsing is delegated to :func:`uniphish.page.html.parse_html`, which bounds all sizes.
* Weights follow the scale in ``docs/dev/build-contract.md``. Where a cue is common on
  legitimate pages (a "copy" button, a long inline blob), the signal's ``confidence`` is
  lowered unless corroborating context is present, so the fused score stays calibrated
  without dropping the evidence from the explanation.
* Living-off-trusted-sites hosting never earns legitimacy credit: the "consistent
  branding" and top-site exemptions are disabled whenever the host is a LOTS host.
* Every regex here runs on length-bounded text and uses fixed alternations only.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from uniphish.assets import load_yaml
from uniphish.assets.lists import is_dyndns, is_shortener, is_top_site, lots_match, tld_risk
from uniphish.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult, register
from uniphish.core.types import (
    Artifact,
    ArtifactKind,
    BrandMatch,
    Indicator,
    IndicatorType,
    Signal,
)
from uniphish.page.favicon import favicon_mmh3, known_favicon_brand
from uniphish.page.html import FormModel, PageModel, parse_html
from uniphish.url.brandkb import Brand, get_kb
from uniphish.url.brands import split_host
from uniphish.url.parse import ParsedURL, parse_url

log = logging.getLogger("uniphish.analyzers.page")

MEMO_KEY = "page.model"
MAX_CHILDREN = 8
_TEXT_WINDOW = 60_000          # chars of visible text scanned for brands
_LOGIN_WINDOW = 3_000          # chars scanned for sign-in wording
_LURE_WINDOW = 30_000          # chars scanned for ClickFix wording
_HEADER_WINDOW = 400           # "prominent" region of the visible text

_OTP_NAME_RE = re.compile(
    r"otp|2fa|mfa|totp|one[-_ ]?time|passcode|(?:verif\w{0,10}|security|auth\w{0,10}|sms|"
    r"login|confirm\w{0,10})[-_ ]?code", re.I)
_LOGIN_RE = re.compile(
    r"sign[\s-]?in|log[\s-]?in|password|passcode|verif(?:y|ication)|authenticat|2fa|"
    r"two[\s-]?factor|security check|account", re.I)
# "Sign in with Google" / "Continue with Apple" are social-login buttons, not impersonation.
_SOCIAL_LOGIN_RE = re.compile(
    r"(?:sign|log)[\s-]?(?:in|up)\s{1,3}(?:with|using|via)\s{1,3}\w{1,30}|"
    r"continue\s{1,3}(?:with|using)\s{1,3}\w{1,30}|"
    r"(?:with|via|using)\s{1,3}your\s{1,3}\w{1,30}\s{1,3}account", re.I)
_PLUS_SPACES_RE = re.compile(r"\s*\+\s*")

_LURE_HUMAN = ("verify you are human", "verify you're human", "not a robot", "captcha",
               "human verification", "verify that you are human", "are you human")
_LURE_KEYS = ("win+r", "windows key+r", "ctrl+v", "cmd+v", "run dialog", "open the run",
              "windows run", "press ctrl", "paste it", "paste the")
_LURE_SHELL = ("powershell", "cmd.exe", "command prompt", "mshta", "terminal")

_FAVICON_ASSET = "favicon_hashes.yaml"
_favicon_cache: dict[str, str] | None = None


def _favicon_table() -> dict[str, str]:
    """Optional ``hash -> brand`` table from ``assets/favicon_hashes.yaml`` (may be absent)."""
    global _favicon_cache
    if _favicon_cache is None:
        table: dict[str, str] = {}
        try:
            raw = load_yaml(_FAVICON_ASSET)
            if isinstance(raw, dict):
                raw = raw.get("hashes", raw)
            if isinstance(raw, dict):
                table = {str(k): str(v) for k, v in raw.items()}
        except Exception as exc:  # missing/malformed asset must never break analysis
            log.debug("favicon table unavailable: %s", type(exc).__name__)
        _favicon_cache = table
    return _favicon_cache


def _host_of(url: str) -> str:
    p = parse_url(url) if url else None
    return p.host_ascii if p and p.valid else ""


def _uniq(seq: list[str]) -> list[str]:
    return list(dict.fromkeys(seq))


@register
class PageAnalyzer(Analyzer):
    name = "page"
    kinds = frozenset({ArtifactKind.PAGE})
    stage = 0
    requires_online = False
    blocking = True
    description = "HTML structure: credential forms, brand/content mismatch, obfuscation, ClickFix"
    signals = {
        "page.form.password_cross_origin": "Password form posts to a different website",
        "page.form.password_data_uri": "Password form submits to an inline data: URI",
        "page.form.password_offsite_js": "Password form is submitted by script to an outside site",
        "page.form.otp_offsite": "One-time-code form posts to a different website",
        "brand.content_mismatch": "Page presents a brand it does not belong to",
        "brand.favicon_mismatch": "Page uses a brand's favicon on an unrelated domain",
        "page.obfuscated_script": "Page contains packed or obfuscated inline script",
        "page.clipboard_write": "Page script writes to the clipboard",
        "page.clickfix_lure": "Page tells the visitor to paste a command into Run or a terminal",
        "page.meta_refresh_offsite": "Page automatically redirects to another website",
        "page.iframe_hidden_offsite": "Page hides an embedded frame from another website",
        "page.brand_consistent": "Page branding matches the official domain serving it",
    }

    def applies(self, artifact: Artifact, ctx: AnalysisContext) -> bool:
        return artifact.kind is ArtifactKind.PAGE

    # ------------------------------------------------------------------ #
    def analyze_sync(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        res = AnalyzerResult()
        html = artifact.html()
        page_url = artifact.url or ""
        page: PageModel = ctx.memo(MEMO_KEY, lambda: parse_html(html, page_url or None))
        purl = parse_url(page_url) if page_url else None
        if purl is not None and not purl.valid:
            purl = None
        host = purl.host_ascii if purl else ""
        kb = get_kb()

        lots = lots_match(host, purl.path) if purl and host else None
        page_brand = kb.official_brand_for_host(host) if host and lots is None else None
        url_brand = ctx.brand()
        if page_brand is None and url_brand is not None and url_brand.official and lots is None:
            page_brand = kb.get(url_brand.brand)

        res.meta.update({
            "title": page.title,
            "forms": len(page.forms),
            "password_fields": page.password_input_count,
        })
        if page.truncated:
            res.meta["page_truncated"] = True
        if page.parse_error:
            res.meta["page_parse_error"] = page.parse_error

        self._form_signals(page, purl, page_brand, res)
        self._brand_signals(artifact, page, purl, page_brand, lots, url_brand, res)
        self._script_signals(page, res)
        self._navigation_signals(page, purl, res)
        self._children(page, purl, res)
        return res

    # ------------------------------------------------------------------ #
    # forms
    # ------------------------------------------------------------------ #
    @staticmethod
    def _action_is_exempt(form: FormModel, page_brand: Brand | None) -> bool:
        """A form posting to another host of the *same* official brand is not suspicious."""
        if page_brand is None or not form.action_host:
            return False
        kb = get_kb()
        target = kb.official_brand_for_host(form.action_host) or kb.login_brand_for_host(
            form.action_host) or kb.cdn_brand_for_host(form.action_host)
        return target is not None and target.id == page_brand.id

    def _form_signals(self, page: PageModel, purl: ParsedURL | None, page_brand: Brand | None,
                      res: AnalyzerResult) -> None:
        known_origin = purl is not None
        data_forms: list[FormModel] = []
        cross: list[FormModel] = []
        js: list[FormModel] = []
        otp: list[tuple[FormModel, list[str]]] = []
        for f in page.forms:
            if f.has_password:
                if f.submits_to_data_uri:
                    data_forms.append(f)
                elif f.is_cross_origin and not self._action_is_exempt(f, page_brand):
                    cross.append(f)
                elif f.submits_offsite_js:
                    js.append(f)
            elif f.is_cross_origin or f.submits_offsite_js or f.submits_to_data_uri:
                names = [n for n in f.input_names if _OTP_NAME_RE.search(n)]
                if names and not self._action_is_exempt(f, page_brand):
                    otp.append((f, names))

        if data_forms:
            res.signals.append(Signal(
                id="page.form.password_data_uri",
                title="Password form submits to an inline data: URI",
                detail="A form containing a password field submits to a data: URI, which "
                       "lets the page capture credentials with embedded script instead of "
                       "sending them to a normal login endpoint.",
                weight=5.0, category="page", mitre=["T1056.003", "T1566.002"],
                evidence={"forms": len(data_forms), "action_scheme": "data"}))

        if cross:
            hosts = _uniq([f.action_host or "another site" for f in cross])
            shown = ", ".join(hosts[:3])
            res.signals.append(Signal(
                id="page.form.password_cross_origin",
                title="Password form posts to a different website",
                detail=f"The login form on this page sends the entered password to {shown}, "
                       "which is not the site serving the page.",
                weight=4.0, confidence=1.0 if known_origin else 0.8, category="page",
                mitre=["T1056.003", "T1566.002"],
                evidence={"action_hosts": hosts[:10], "actions": [f.action for f in cross][:5],
                          "insecure_http": any(f.action.lower().startswith("http://")
                                               for f in cross),
                          "page_url_known": known_origin}))
            for h in hosts[:3]:
                if h != "another site":
                    res.indicators.append(Indicator(
                        type=IndicatorType.DOMAIN, value=h, role="exfil-endpoint",
                        context="Receives credentials submitted on the page"))

        if js:
            res.signals.append(Signal(
                id="page.form.password_offsite_js",
                title="Password form is submitted by script to an outside site",
                detail="A form with a password field is submitted through fetch/XHR style "
                       "script rather than a plain form post, a common way to send "
                       "credentials to an attacker endpoint.",
                weight=3.0, confidence=0.9, category="page", mitre=["T1056.003"],
                evidence={"forms": len(js)}))

        if otp:
            fields = _uniq([n for _, names in otp for n in names])[:10]
            hosts = _uniq([f.action_host for f, _ in otp if f.action_host])
            where = f" to {hosts[0]}" if hosts else ""
            res.signals.append(Signal(
                id="page.form.otp_offsite",
                title="One-time-code form posts to a different website",
                detail=f"A form asking for a verification code ({', '.join(fields[:3])}) "
                       f"submits it{where} outside this site. Relaying MFA codes is how "
                       "adversary-in-the-middle phishing defeats two-factor authentication.",
                weight=2.5, category="page", mitre=["T1111", "T1557"],
                evidence={"fields": fields, "action_hosts": hosts[:10]}))

    # ------------------------------------------------------------------ #
    # brand / content
    # ------------------------------------------------------------------ #
    def _brand_signals(self, artifact: Artifact, page: PageModel, purl: ParsedURL | None,
                       page_brand: Brand | None, lots: Any, url_brand: BrandMatch | None,
                       res: AnalyzerResult) -> None:
        kb = get_kb()
        head = f"{page.title} {page.meta.og_site_name}".strip()
        text = page.visible_text[:_TEXT_WINDOW]
        title_brands = kb.brands_mentioned_in(head) if head else []
        text_brands = kb.brands_mentioned_in(text) if text else []
        res.meta["brands_in_content"] = _uniq([b.id for b in title_brands + text_brands])

        has_cred_form = page.password_field_present or any(
            f.has_password or f.has_hidden_credential for f in page.forms)
        loginish = bool(_LOGIN_RE.search(f"{head} {text[:_LOGIN_WINDOW]}"))

        # Candidate: the brand the page most prominently claims to be.
        claimed: Brand | None = None
        where = ""
        if title_brands:
            claimed, where = title_brands[0], "title"
        elif text_brands and (has_cred_form or loginish):
            stripped = _SOCIAL_LOGIN_RE.sub(" ", text)
            if stripped != text:
                text_brands = kb.brands_mentioned_in(stripped)
            prominent = kb.brands_mentioned_in(stripped[:_HEADER_WINDOW])
            if prominent and len(text_brands) <= 2:
                claimed, where = prominent[0], "text"

        # ---- legitimacy: official domain with its own branding ---------- #
        if page_brand is not None:
            mentioned = {b.id for b in title_brands + text_brands}
            if page_brand.id in mentioned:
                res.signals.append(Signal(
                    id="page.brand_consistent",
                    title="Page branding matches the official domain serving it",
                    detail=f"The page refers to {page_brand.name} and is served from a "
                           f"{page_brand.name} domain ({purl.host if purl else ''}).",
                    weight=-1.0, category="page",
                    evidence={"brand": page_brand.id, "host": purl.host if purl else ""}))
                res.brand = BrandMatch(
                    brand=page_brand.id, name=page_brand.name, technique="official",
                    confidence=0.8, legit_domains=list(page_brand.official_domains[:5]),
                    evidence="page content matches the official domain", official=True)
            return  # an official domain is never a content-mismatch or favicon candidate

        if purl is None:
            return  # without the serving URL there is nothing to compare the content with

        reg = purl.registrable_domain or purl.host
        top_site = lots is None and bool(reg) and is_top_site(reg)

        # ---- brand content vs domain ------------------------------------ #
        if claimed is not None and not top_site:
            if has_cred_form:
                conf = 0.9
            elif loginish:
                conf = 0.7
            else:
                conf = 0.35
            boosted = (url_brand is not None and not url_brand.official
                       and url_brand.brand == claimed.id)
            if boosted:
                conf = min(1.0, conf + 0.1)
            domains = list(claimed.official_domains[:5])
            host_txt = purl.host or purl.host_ascii
            res.signals.append(Signal(
                id="brand.content_mismatch",
                title=f"Page presents itself as {claimed.name} but is not on its domain",
                detail=f"The page {'title' if where == 'title' else 'text'} references "
                       f"{claimed.name}, yet it is served from {host_txt}, which is not a "
                       f"{claimed.name} domain"
                       f"{' (hosted on ' + lots.name + ')' if lots is not None else ''}.",
                weight=3.5, confidence=conf, category="brand",
                mitre=["T1566.002", "T1036"],
                evidence={"brand": claimed.id, "found_in": where, "host": host_txt,
                          "official_domains": domains, "credential_form": has_cred_form,
                          "lots_host": lots.name if lots is not None else None,
                          "url_analyzer_agrees": boosted}))
            res.brand = BrandMatch(
                brand=claimed.id, name=claimed.name, technique="content",
                confidence=min(0.95, conf), legit_domains=domains,
                evidence=f"{claimed.name} referenced in page {where}; host {host_txt}",
                official=False)

        # ---- favicon fingerprint ---------------------------------------- #
        fav = self._favicon_brand(artifact)
        if fav is not None and (kb.official_brand_for_host(purl.host_ascii) is None
                                or lots is not None):
            res.signals.append(Signal(
                id="brand.favicon_mismatch",
                title=f"Page uses the {fav.name} favicon on an unrelated domain",
                detail=f"The page's favicon is byte-identical to {fav.name}'s, but the "
                       f"page is served from {purl.host}.",
                weight=3.0, category="brand", mitre=["T1036"],
                evidence={"brand": fav.id, "host": purl.host}))
            if res.brand is None:
                res.brand = BrandMatch(
                    brand=fav.id, name=fav.name, technique="content", confidence=0.6,
                    legit_domains=list(fav.official_domains[:5]),
                    evidence="favicon hash matches the brand's icon", official=False)

    @staticmethod
    def _favicon_brand(artifact: Artifact) -> Brand | None:
        """Brand whose known favicon hash matches ``meta['favicon_hash'|'favicon_bytes']``."""
        meta = artifact.meta or {}
        h: int | None = None
        try:
            if meta.get("favicon_hash") is not None:
                h = int(meta["favicon_hash"])
            elif isinstance(meta.get("favicon_bytes"), (bytes, bytearray)):
                h = favicon_mmh3(bytes(meta["favicon_bytes"]))
        except (ValueError, TypeError):
            return None
        if h is None:
            return None
        table = meta.get("favicon_table")
        label = known_favicon_brand(h, table if isinstance(table, dict) and table
                                    else _favicon_table())
        if not label:
            return None
        kb = get_kb()
        b = kb.get(label)
        if b is None:
            low = label.casefold()
            b = next((x for x in kb.all() if x.name.casefold() == low), None)
        return b

    # ------------------------------------------------------------------ #
    # scripts / obfuscation / ClickFix
    # ------------------------------------------------------------------ #
    def _script_signals(self, page: PageModel, res: AnalyzerResult) -> None:
        has_cred = page.password_field_present or any(f.has_password for f in page.forms)
        ent = page.inline_script_entropy
        evals = page.has_eval_like
        big_blob = ent.max_blob_len >= 1_500 and ent.entropy >= 4.5
        mid_blob = ent.max_blob_len >= 300 and ent.entropy >= 4.5
        if big_blob or (evals >= 3 and mid_blob) or evals >= 10:
            res.signals.append(Signal(
                id="page.obfuscated_script",
                title="Page contains packed or obfuscated inline script",
                detail=f"Inline script holds an encoded blob of {ent.max_blob_len} characters "
                       f"(entropy {ent.entropy:.1f} bits/char) and {evals} eval/decode "
                       "call sites, a pattern used to hide credential-capture logic from "
                       "scanners.",
                weight=2.0, confidence=1.0 if has_cred else 0.6, category="page",
                mitre=["T1027"],
                evidence={"max_blob_len": ent.max_blob_len, "entropy": ent.entropy,
                          "eval_like_calls": evals, "credential_form": has_cred}))

        lure = self._clickfix_terms(page.visible_text[:_LURE_WINDOW])
        if page.clipboard_write > 0:
            res.signals.append(Signal(
                id="page.clipboard_write",
                title="Page script writes to the clipboard",
                detail=f"Script on this page copies text to the visitor's clipboard "
                       f"({page.clipboard_write} call site(s))"
                       f"{', alongside instructions to paste a command' if lure else ''}. "
                       "ClickFix attacks use this to plant a command the victim is told to run.",
                weight=2.5, confidence=1.0 if lure else 0.5, category="page",
                mitre=["T1204.004"],
                evidence={"clipboard_write_calls": page.clipboard_write,
                          "lure_terms": lure}))
        if lure:
            res.signals.append(Signal(
                id="page.clickfix_lure",
                title="Page tells the visitor to paste a command into Run or a terminal",
                detail="The visible text combines a human-verification prompt or shell "
                       "reference with keyboard instructions (" + ", ".join(lure[:4]) + "), "
                       "the social-engineering step of a ClickFix attack.",
                weight=2.0, category="page", mitre=["T1204.004"],
                evidence={"lure_terms": lure}))

    @staticmethod
    def _clickfix_terms(text: str) -> list[str]:
        """ClickFix wording found in ``text`` (empty unless the combination is present)."""
        low = _PLUS_SPACES_RE.sub("+", text.lower())
        human = [t for t in _LURE_HUMAN if t in low]
        keys = [t for t in _LURE_KEYS if t in low]
        shell = [t for t in _LURE_SHELL if t in low]
        if keys and (human or shell) or (human and shell):
            return human + keys + shell
        return []

    # ------------------------------------------------------------------ #
    # navigation: meta refresh, hidden iframes
    # ------------------------------------------------------------------ #
    def _navigation_signals(self, page: PageModel, purl: ParsedURL | None,
                            res: AnalyzerResult) -> None:
        target = page.meta.refresh_target
        if page.meta_refresh_offsite and target and target.lower().startswith(("http:", "https:")):
            th = _host_of(target)
            delay = page.meta.refresh_delay
            after = f" after {delay:g} s" if delay else ""
            res.signals.append(Signal(
                id="page.meta_refresh_offsite",
                title="Page automatically redirects to another website",
                detail=f"A meta-refresh tag sends the visitor to {th or target[:80]}"
                       f"{after}"
                       ", a lightweight redirect hop used by phishing chains.",
                weight=1.5, category="page", mitre=["T1566.002"],
                evidence={"target": target[:500], "host": th,
                          "delay": page.meta.refresh_delay}))

        hidden: list[str] = []
        for fr in page.iframes:
            src = fr.src
            if not fr.hidden or not src.lower().startswith(("http:", "https:")):
                continue
            h = _host_of(src)
            if not h:
                continue
            if purl is not None and (_same_site(h, purl)):
                continue
            hidden.append(h)
        if hidden:
            hosts = _uniq(hidden)
            res.signals.append(Signal(
                id="page.iframe_hidden_offsite",
                title="Page hides an embedded frame from another website",
                detail=f"An invisible or off-screen frame loads content from {hosts[0]}, "
                       "which can silently relay or capture visitor input.",
                weight=2.0, confidence=1.0 if purl is not None else 0.7, category="page",
                mitre=["T1189"], evidence={"hosts": hosts[:10]}))

    # ------------------------------------------------------------------ #
    # children
    # ------------------------------------------------------------------ #
    def _children(self, page: PageModel, purl: ParsedURL | None, res: AnalyzerResult) -> None:
        seen: set[str] = set()
        own = purl.url if purl else None

        def add(url: str, origin: str, **meta: Any) -> None:
            if len(res.children) >= MAX_CHILDREN or not url:
                return
            if not url.lower().startswith(("http://", "https://")):
                return
            key = url.split("#", 1)[0]
            if key in seen or key == own:
                return
            try:
                child = Artifact.from_url(url, origin=origin, **meta)
            except ValueError:  # includes ArtifactTooLarge / empty
                return
            seen.add(key)
            res.children.append(child)

        for f in page.forms:
            if f.is_cross_origin and f.action and not f.submits_to_data_uri:
                add(f.action, "page.form_action", has_password=f.has_password)
        if page.meta_refresh_offsite and page.meta.refresh_target:
            add(page.meta.refresh_target, "page.refresh")
        for s in page.scripts:
            if s.src and s.is_external and _interesting_host(s.host):
                add(s.src, "page.script")


def _site_key(p: ParsedURL) -> str:
    """Registrable-domain key that also works for unlisted TLDs such as ``.test``."""
    parts = split_host(p)
    return f"{parts.sld}.{parts.suffix}" if parts.sld and parts.suffix else p.host


def _same_site(host: str, purl: ParsedURL) -> bool:
    other = parse_url(f"https://{host}/")
    a, b = _site_key(other), _site_key(purl)
    return bool(a) and a == b


def _interesting_host(host: str) -> bool:
    """Script hosts worth analysing: shorteners, dynamic DNS, LOTS, raw IPs, risky TLDs."""
    if not host:
        return False
    p = parse_url(f"https://{host}/")
    if p.is_ip:
        return True
    if is_shortener(host) or is_dyndns(host) or lots_match(host) is not None:
        return True
    risk = tld_risk(p.suffix.rsplit(".", 1)[-1] if p.suffix else None)
    return risk is not None and risk >= 1.0


__all__ = ["PageAnalyzer", "MEMO_KEY", "MAX_CHILDREN"]
