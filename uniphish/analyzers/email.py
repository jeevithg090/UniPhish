"""Email analyzer: authentication, sender spoofing, BEC language, and child fan-out.

Why this module exists
----------------------
Most phishing arrives as email, and the cheapest, most reliable evidence is in the
*envelope*: did the message authenticate as the domain it claims, does the display
name claim a brand the address does not belong to, does Reply-To quietly redirect the
conversation, is it a no-link "wire the money / buy gift cards" request. This analyzer
turns the hostile-input-safe parse (:mod:`uniphish.mail.parse`) and the header-only
SPF/DKIM/DMARC evaluation (:mod:`uniphish.mail.auth`) into explainable signals, and
hands every link, attachment, inline image and forwarded message to the engine as a
child artifact so their risk propagates to the parent.

Design notes
------------
* Offline and pure: it only reads the message. The one optional side input is a
  read-only lookup of the local store (``sender_seen_before`` in ``meta``).
* Authentication is evidence in *both* directions. An aligned DMARC pass is only
  credited as legitimacy when the authenticated domain is a *known* sender (an official
  brand domain or a top-ranked site that is not a user-content/"living off trusted
  sites" host and not a free mailbox provider); attackers authenticate their own
  domains too, so an unknown aligned pass earns only a token credit.
* Brand display-name spoofing and look-alike sender domains share the ``brand``
  category (correlated evidence is damped by the scorer); header, BEC and link cues are
  ``email``; protocol results are ``auth``; language pressure is ``social``.
* Every regex that sees attacker text is linear and applied to length-bounded input.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import unicodedata
from datetime import timezone
from pathlib import Path
from urllib.parse import urlsplit

from uniphish.assets.lists import is_dyndns, is_freemail, is_top_site, lots_match
from uniphish.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult, register
from uniphish.core.types import (
    Artifact,
    ArtifactKind,
    ArtifactTooLarge,
    BrandMatch,
    Indicator,
    IndicatorType,
    Signal,
)
from uniphish.mail.auth import (
    AuthResult,
    analyze_auth,
    display_name_domain_mismatches,
    domains_aligned,
    org_domain,
    reply_to_differs_from_from,
)
from uniphish.mail.parse import MEMO_KEY, ParsedEmail, parse_email
from uniphish.url.brandkb import Brand, get_kb

log = logging.getLogger("uniphish.analyzers.email")

MAX_BODY_SCAN = 50_000
MAX_CHILD_LINKS = 100
MAX_INDICATORS = 250
_SOCIAL_CLAMP = 5.0

_MOBILE_RE = re.compile(
    r"sent from my (?:iphone|ipad|android|mobile(?: device)?|blackberry|samsung|phone)"
    r"|(?:can(?:'|’)?t|cannot|unable to) (?:take|talk|answer|receive)(?: any)? "
    r"(?:calls?|phone)", re.IGNORECASE)
_DYNAMIC_HOST_RE = re.compile(
    r"(?:^|[.-])(?:dsl|adsl|cable|dyn|dynamic|dhcp|pool|ppp|broadband|cust|customer|resi|"
    r"residential|home)(?:[.-]|\d|$)", re.IGNORECASE)
_ANCHOR_DOMAIN_RE = re.compile(
    r"(?:https?://)?(?P<host>(?:www\.)?(?:[a-z0-9-]{1,63}\.){1,5}[a-z]{2,24})"
    r"(?::\d{1,5})?(?:/\S{0,200})?", re.IGNORECASE)
_BRAND_SPOOF_TECHNIQUES = frozenset(
    {"homoglyph", "idn", "bitsquat", "typosquat", "combosquat", "subdomain"})

_HEADER_MALFORMED = frozenset({
    "no_from", "from_unparseable", "from_no_domain", "nul_in_header", "malformed_multipart",
    "too_many_headers", "multipart_depth_exceeded", "bad_content_type"})


def _safe(s: str, n: int = 80) -> str:
    """Printable, length-bounded rendering of attacker text (no bidi/control chars)."""
    out = "".join("?" if unicodedata.category(c).startswith("C") else c for c in s[:n * 2])
    return out[:n] + ("…" if len(out) > n else "")


def _sig(sid: str, title: str, detail: str, weight: float, category: str, *,
         mitre: list[str] | None = None, evidence: dict | None = None,
         confidence: float = 1.0) -> Signal:
    return Signal(id=sid, title=title, detail=detail, weight=weight, category=category,
                  mitre=mitre or [], evidence=evidence or {}, confidence=confidence)


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_known_sender(domain: str) -> bool:
    """Official brand domain, or a top-10k site that is not a shared/free platform."""
    if not domain or is_freemail(domain):
        return False
    kb = get_kb()
    if kb.official_brand_for_host(domain) is not None:
        return True
    if kb.is_user_content_host(domain) is not None or lots_match(domain) is not None:
        return False
    return is_top_site(org_domain(domain), 10_000)


def _sender_seen_before(ctx: AnalysisContext, addr: str) -> bool | None:
    """Has the local store seen this sender address? ``None`` when unknown/no store."""
    if not addr:
        return None
    try:
        path = Path(ctx.settings.db_path)
        if str(path) != ":memory:" and not path.exists():
            return None
        from uniphish.store import Store

        with Store(path) as st:
            return bool(st.search_indicator("email", addr))
    except Exception:  # pragma: no cover - store is optional
        log.debug("store lookup failed", exc_info=True)
        return None


def _brands_in_display_name(name: str) -> list[Brand]:
    from uniphish.url.confusables import ascii_fold

    kb = get_kb()
    found = list(kb.brands_mentioned_in(name))
    try:
        for b in kb.brands_mentioned_in(ascii_fold(name)):
            if all(b.id != x.id for x in found):
                found.append(b)
    except Exception:  # pragma: no cover - defensive
        log.debug("ascii_fold brand scan failed", exc_info=True)
    return found


def _brand_match(b: Brand, technique: str, conf: float, evidence: str) -> BrandMatch:
    return BrandMatch(brand=b.id, name=b.name, technique=technique, confidence=conf,
                      legit_domains=list(b.official_domains), evidence=evidence)


@register
class EmailAnalyzer(Analyzer):
    name = "email"
    kinds = frozenset({ArtifactKind.EMAIL})
    stage = 0
    requires_online = False
    blocking = True
    description = "Email headers, SPF/DKIM/DMARC, sender spoofing, BEC language, child fan-out"
    signals = {
        "auth.dmarc.fail": "DMARC failed for the sender's domain",
        "auth.dmarc.unaligned": "Message did not authenticate as the From domain",
        "auth.spf.fail": "SPF check failed for the sending server",
        "auth.spf.softfail": "SPF soft-failed for the sending server",
        "auth.dkim.fail": "DKIM signature failed verification",
        "auth.forged_results": "Sender planted a fake Authentication-Results header",
        "auth.aligned_pass.known": "Authenticated as a well-known sender (DMARC aligned)",
        "auth.aligned_pass": "Authenticated as its own From domain (DMARC aligned)",
        "brand.sender.display_name": "Sender name claims a brand the address does not belong to",
        "brand.sender.lookalike_domain": "Sender domain imitates a known brand",
        "email.sender.display_name_domain": "Sender name embeds a different domain or address",
        "email.reply_to.mismatch": "Replies are redirected to a different domain",
        "email.return_path.mismatch": "Envelope sender domain differs from the From domain",
        "email.message_id.domain_mismatch": "Message-ID domain differs from the From domain",
        "email.header.duplicate_from": "Message has multiple From headers or addresses",
        "email.header.malformed": "Message headers are malformed in a way used to evade filters",
        "email.header.missing_fields": "Message lacks standard Date or Message-ID headers",
        "email.header.date_skew": "Date header disagrees with the first Received timestamp",
        "email.received.dynamic_origin": "Message originated from a dynamic/residential host",
        "email.attachment.bidi_filename": "Attachment name uses a right-to-left override",
        "email.html.hidden_text": "HTML hides text from the reader",
        "email.link.anchor_mismatch": "Link text shows one site but goes to another",
        "email.link.dangerous_scheme": "Link uses a javascript: or data: address",
        "email.bec.payment_pressure": "No-link payment/gift-card demand from a suspect sender",
        "email.bec.payment_secrecy": "Confidential payment request with no links",
        "email.bec.mobile_excuse": "'Sent from mobile' excuse combined with reply redirection",
        "social.email.pressure": "Email uses pressure and manipulation language",
        "social.email.otp_request": "Email asks the reader to hand over a one-time code",
        "social.email.callback_number": "Email pushes the reader to phone a number (callback scam)",
    }

    def applies(self, artifact: Artifact, ctx: AnalysisContext) -> bool:
        return artifact.kind is ArtifactKind.EMAIL and artifact.content is not None

    # ------------------------------------------------------------------ #
    def analyze_sync(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        raw = artifact.content or b""
        pe: ParsedEmail = ctx.memo(MEMO_KEY, lambda: parse_email(raw))
        auth = analyze_auth(pe)
        res = AnalyzerResult()
        self._auth_signals(pe, auth, res)
        spoof = self._sender_signals(pe, auth, res)
        self._header_signals(pe, auth, res)
        self._content_signals(pe, auth, spoof, res)
        self._children_and_indicators(pe, spoof, res)
        res.meta.update(self._meta(pe, auth, ctx))
        return res

    # ---------------------------------------------------------------- auth #
    def _auth_signals(self, pe: ParsedEmail, a: AuthResult, res: AnalyzerResult) -> None:
        sigs = res.signals
        dom = a.from_domain or pe.from_domain
        if a.dmarc.status == "fail":
            sigs.append(_sig(
                "auth.dmarc.fail", "DMARC failed for the sender's domain",
                f"The receiving server reported DMARC failure for {_safe(dom)}"
                f"{' (policy ' + a.dmarc.policy + ')' if a.dmarc.policy else ''}: the message "
                "was not authorised by the domain it claims to come from.", 2.5, "auth",
                mitre=["T1566"], evidence={"dmarc": a.dmarc.status, "policy": a.dmarc.policy,
                                           "from_domain": dom}))
        elif a.has_auth_results and not a.dmarc_aligned:
            sigs.append(_sig(
                "auth.dmarc.unaligned", "Message did not authenticate as the From domain",
                f"Neither SPF nor DKIM passed in alignment with {_safe(dom)} "
                f"(spf={a.spf.status}, dkim={a.dkim.status}, dmarc={a.dmarc.status}).",
                1.5, "auth", mitre=["T1566"],
                evidence={"spf": a.spf.status, "dkim": a.dkim.status, "dmarc": a.dmarc.status}))
        if a.spf.status == "fail":
            sigs.append(_sig(
                "auth.spf.fail", "SPF check failed for the sending server",
                f"The sending IP {a.spf.client_ip or '(unknown)'} is not permitted to send for "
                f"{_safe(a.spf.domain or dom)}.", 1.5, "auth", mitre=["T1566"],
                evidence={"domain": a.spf.domain, "client_ip": a.spf.client_ip}))
        elif a.spf.status == "softfail":
            sigs.append(_sig(
                "auth.spf.softfail", "SPF soft-failed for the sending server",
                f"SPF for {_safe(a.spf.domain or dom)} marked the sending IP as probably "
                "unauthorised (~all).", 0.8, "auth", evidence={"domain": a.spf.domain}))
        if a.dkim.status == "fail":
            sigs.append(_sig(
                "auth.dkim.fail", "DKIM signature failed verification",
                "A DKIM signature is present but did not verify, so the message may have "
                "been altered or the signature forged.", 1.0, "auth",
                evidence={"domains": [s.domain for s in a.dkim.signatures if s.domain][:5]}))
        forged = [n for n in a.notes if n.startswith("ignored_untrusted_authentication_results")]
        if forged:
            sigs.append(_sig(
                "auth.forged_results", "Sender planted a fake Authentication-Results header",
                "An Authentication-Results header was injected below the receiving server's "
                "own result; it was ignored, but only attackers add these.", 2.0, "auth",
                mitre=["T1656"], evidence={"note": forged[0]}))
        if a.dmarc_aligned and a.authenticated_domain and a.dmarc.status != "fail":
            ad = a.authenticated_domain
            if _is_known_sender(ad):
                sigs.append(_sig(
                    "auth.aligned_pass.known", "Authenticated as a well-known sender",
                    f"Message passed SPF/DKIM aligned with {_safe(ad)}, a well-known sender "
                    "domain.", -1.5, "auth", evidence={"authenticated_domain": ad}))
            elif not is_freemail(ad):
                sigs.append(_sig(
                    "auth.aligned_pass", "Authenticated as its own From domain",
                    f"Message passed SPF/DKIM aligned with {_safe(ad)}. This only proves the "
                    "sender controls that domain, not that the domain is trustworthy.",
                    -0.3, "auth", evidence={"authenticated_domain": ad}))

    # -------------------------------------------------------------- sender #
    def _sender_signals(self, pe: ParsedEmail, a: AuthResult, res: AnalyzerResult) -> dict:
        """Emit spoofing signals; return flags later used by BEC logic."""
        flags = {"display_spoof": False, "lookalike": False, "reply_swap": False,
                 "freemail": False}
        sigs, frm = res.signals, pe.from_
        kb = get_kb()
        fdom = frm.domain
        freemail = bool(fdom) and is_freemail(fdom)
        flags["freemail"] = freemail
        display = frm.display_name

        # --- display name claims a brand (by name or by embedded domain/address) ---
        claimed: dict[str, tuple[Brand, str]] = {}
        if display:
            for b in _brands_in_display_name(display[:300]):
                claimed.setdefault(b.id, (b, "name"))
        mismatches = display_name_domain_mismatches(pe) if fdom else []
        other_domains: list[str] = []
        for d in mismatches:
            b = kb.official_brand_for_host(d)
            if b is not None:
                claimed[b.id] = (b, "domain")
            else:
                other_domains.append(d)
        for b, how in claimed.values():
            owner = kb.official_brand_for_host(fdom) if fdom else None
            if owner is not None and owner.id == b.id:
                continue
            via_esp = (not freemail and a.dmarc_aligned and _is_known_sender(fdom)
                       and how == "name")
            weight = 1.5 if via_esp else 3.5
            kind = ("a free mailbox provider" if freemail else
                    "an unrelated domain")
            sigs.append(_sig(
                "brand.sender.display_name", "Sender name claims a brand it does not own",
                f"The From display name \"{_safe(display)}\" "
                f"{'names' if how == 'name' else 'embeds an address/domain of'} {b.name}, but "
                f"the message was sent from {_safe(frm.addr or fdom or '?')} on {kind}.",
                weight, "brand", mitre=["T1656"],
                evidence={"brand": b.id, "display_name": display[:120], "from": frm.addr,
                          "claimed_via": how, "freemail": freemail}))
            res.brand = self._best_brand(res.brand, _brand_match(
                b, "sender", 0.7 if via_esp else 0.9,
                f"From display name claims {b.name} but address is {frm.addr}"))
            flags["display_spoof"] = True
            res.techniques.append("display_name_spoof")
            break  # one signal per message; the strongest claim is the first named
        if other_domains and not flags["display_spoof"]:
            sigs.append(_sig(
                "email.sender.display_name_domain",
                "Sender name embeds a different domain or address",
                f"The From display name \"{_safe(display)}\" mentions "
                f"{_safe(other_domains[0])}, while the real sender domain is {_safe(fdom)}.",
                2.0, "email", mitre=["T1656"],
                evidence={"display_name": display[:120], "mentioned": other_domains[:5],
                          "from_domain": fdom}))
            flags["display_spoof"] = True
            res.techniques.append("display_name_spoof")

        # --- look-alike sender (From, then Reply-To) domain ---
        from uniphish.url.brands import brand_impersonation

        for role, dom in (("From", fdom), *(("Reply-To", r.domain) for r in pe.reply_to[:3])):
            if not dom:
                continue
            bm = brand_impersonation(f"https://{dom}/", min_confidence=0.6)
            if bm is None or bm.official or bm.technique not in _BRAND_SPOOF_TECHNIQUES:
                continue
            sigs.append(_sig(
                "brand.sender.lookalike_domain", "Sender domain imitates a known brand",
                f"The {role} domain {_safe(dom)} imitates {bm.name} ({bm.technique}): "
                f"{bm.evidence}", 3.0, "brand", mitre=["T1656", "T1583.001"],
                evidence={"brand": bm.brand, "technique": bm.technique, "domain": dom,
                          "role": role}, confidence=min(1.0, max(0.6, bm.confidence))))
            res.brand = self._best_brand(res.brand, bm)
            res.techniques.append("lookalike_sender")
            flags["lookalike"] = True
            res.indicators.append(Indicator(type=IndicatorType.DOMAIN, value=dom,
                                            role="sender", malicious=True,
                                            context=f"imitates {bm.name}"))
            break

        # --- Reply-To redirection ---
        if reply_to_differs_from_from(pe):
            rdom = next((r.domain for r in pe.reply_to if r.domain
                         and not domains_aligned(r.domain, fdom)), "")
            bulk_ok = bool(pe.list_unsubscribe) and a.dmarc_aligned
            weight = 0.8 if bulk_ok else 2.0
            what = "a free mailbox provider" if is_freemail(rdom) else "an unrelated domain"
            sigs.append(_sig(
                "email.reply_to.mismatch", "Replies are redirected to a different domain",
                f"Reply-To points to {_safe(rdom)} ({what}) while the message claims to come "
                f"from {_safe(fdom)}; answering would send your reply to someone else.",
                weight, "email", mitre=["T1656"],
                evidence={"from_domain": fdom, "reply_to_domain": rdom,
                          "reply_to_freemail": is_freemail(rdom), "bulk_sender": bulk_ok}))
            res.techniques.append("reply_to_swap")
            flags["reply_swap"] = True

        # --- Return-Path / Message-ID alignment ---
        rp_dom = pe.return_path.rsplit("@", 1)[-1].strip("<> ").lower() \
            if "@" in pe.return_path else ""
        if rp_dom and fdom and not domains_aligned(rp_dom, fdom) and not a.dmarc_aligned:
            sigs.append(_sig(
                "email.return_path.mismatch", "Envelope sender domain differs from From",
                f"The bounce address is on {_safe(rp_dom)} but the visible sender is on "
                f"{_safe(fdom)}, and the message does not authenticate as the visible domain.",
                1.0, "email", evidence={"return_path_domain": rp_dom, "from_domain": fdom}))
        mid = pe.message_id.strip("<> ")
        mid_dom = mid.rsplit("@", 1)[-1].lower() if "@" in mid else ""
        if mid_dom and fdom and not domains_aligned(mid_dom, fdom) and not a.dmarc_aligned:
            sigs.append(_sig(
                "email.message_id.domain_mismatch", "Message-ID domain differs from From",
                f"The Message-ID was generated on {_safe(mid_dom)}, not the claimed sender "
                f"domain {_safe(fdom)}.", 0.6, "email",
                evidence={"message_id_domain": mid_dom, "from_domain": fdom}))
        return flags

    @staticmethod
    def _best_brand(cur: BrandMatch | None, new: BrandMatch) -> BrandMatch:
        return new if cur is None or new.confidence > cur.confidence else cur

    # ------------------------------------------------------------- headers #
    def _header_signals(self, pe: ParsedEmail, a: AuthResult, res: AnalyzerResult) -> None:
        sigs, an = res.signals, set(pe.anomalies)
        if an & {"duplicate_from", "multiple_from_addresses"}:
            sigs.append(_sig(
                "email.header.duplicate_from", "Message has multiple From headers or addresses",
                "Several From headers/addresses make different mail clients display different "
                "senders — a known spoofing trick.", 2.0, "email", mitre=["T1656"],
                evidence={"anomalies": sorted(an & {"duplicate_from",
                                                    "multiple_from_addresses"})}))
        bad = sorted(an & _HEADER_MALFORMED)
        bad += sorted(x for x in an if x.startswith("defect:"))[:3]
        if bad:
            sigs.append(_sig(
                "email.header.malformed", "Message headers are malformed",
                "Structural defects (" + ", ".join(bad[:5]) + ") are common in messages "
                "crafted to slip past filters.", 0.8, "email", evidence={"anomalies": bad[:10]}))
        missing = sorted(an & {"date_missing", "date_unparseable", "message_id_missing"})
        if missing:
            sigs.append(_sig(
                "email.header.missing_fields", "Message lacks standard Date or Message-ID",
                "Legitimate mail servers always add valid Date and Message-ID headers "
                f"(missing/invalid: {', '.join(missing)}).", 0.4, "email",
                evidence={"anomalies": missing}))
        if "filename_bidi_override" in an:
            sigs.append(_sig(
                "email.attachment.bidi_filename", "Attachment name uses a right-to-left override",
                "An attachment filename contains a bidirectional override character, used to "
                "disguise an executable as a harmless document.", 2.5, "email",
                mitre=["T1036", "T1036.007"], evidence={"anomaly": "filename_bidi_override"}))
        if "html_hidden_text" in an:
            sigs.append(_sig(
                "email.html.hidden_text", "HTML hides text from the reader",
                "The HTML body contains invisible text, used to dilute spam filters or to "
                "inject instructions for AI assistants.", 0.8, "email",
                evidence={"anomaly": "html_hidden_text"}))
        # Date vs first Received timestamp
        if pe.date and pe.received and pe.received[0].timestamp:
            try:
                d = pe.date if pe.date.tzinfo else pe.date.replace(tzinfo=timezone.utc)
                r = pe.received[0].timestamp
                r = r if r.tzinfo else r.replace(tzinfo=timezone.utc)
                skew = (d - r).total_seconds()
                if skew > 86_400 or skew < -7 * 86_400:
                    sigs.append(_sig(
                        "email.header.date_skew", "Date header disagrees with delivery time",
                        f"The Date header is {abs(skew) / 86_400:.1f} days "
                        f"{'after' if skew > 0 else 'before'} the first Received timestamp.",
                        0.4, "email", evidence={"skew_seconds": int(skew)}))
            except (TypeError, ValueError, OverflowError):  # pragma: no cover
                pass
        # Originating hop (oldest Received)
        for hop in reversed(pe.received):
            host = (hop.from_host or "")[:255]
            if not (host or hop.from_ip):
                continue
            if host and not host.replace(".", "").isdigit() and (
                    _DYNAMIC_HOST_RE.search(host) or is_dyndns(host)):
                sigs.append(_sig(
                    "email.received.dynamic_origin",
                    "Message originated from a dynamic/residential host",
                    f"The oldest Received hop names {_safe(host)}"
                    f"{' [' + hop.from_ip + ']' if hop.from_ip else ''}, which looks like a "
                    "consumer or dynamic-DNS connection, not a mail server.", 0.8, "email",
                    evidence={"host": host, "ip": hop.from_ip}))
            break

    # ------------------------------------------------------------- content #
    def _content_signals(self, pe: ParsedEmail, a: AuthResult, flags: dict,
                         res: AnalyzerResult) -> None:
        sigs = res.signals
        body = (pe.body_text or "")[:MAX_BODY_SCAN]
        http_links = [lk for lk in pe.links if lk.source != "html_img"
                      and lk.url.lower().startswith(("http://", "https://"))]
        self._link_signals(pe, res)
        text = f"{pe.subject}\n{body}".strip()
        if not text:
            return
        try:
            from uniphish.nlp import analyze_text, detect_otp_request
            se = analyze_text(text)
            otp = detect_otp_request(text)
        except Exception:  # pragma: no cover - nlp is optional
            log.debug("nlp unavailable", exc_info=True)
            return
        if se.log_odds >= 0.5:
            top = ", ".join(t.term for t in se.tactics[:4])
            sigs.append(_sig(
                "social.email.pressure", "Email uses pressure and manipulation language",
                f"The message uses {se.dominant_tactic or 'pressure'} tactics"
                f"{' (' + _safe(top, 100) + ')' if top else ''}.",
                min(se.log_odds, _SOCIAL_CLAMP), "social",
                evidence={"score": se.score, "tactics": sorted(se.tactic_scores),
                          "languages": se.languages[:3]}))
        if otp:
            sigs.append(_sig(
                "social.email.otp_request", "Email asks for a one-time code",
                "The message asks the reader to reply with or hand over a verification code, "
                "which attackers use to take over accounts.", 2.5, "social",
                mitre=["T1111"], evidence={}))
        suspect = (flags["freemail"] or flags["lookalike"] or flags["display_spoof"]
                   or flags["reply_swap"] or a.dmarc.status == "fail")
        if se.phone_numbers and not http_links and (
                se.has_payment_ask or se.urgency_score >= 0.1 or se.dominant_tactic):
            sigs.append(_sig(
                "social.email.callback_number", "Email pushes the reader to phone a number",
                f"The message has no links but asks you to call {se.phone_numbers[0]} "
                "(callback / TOAD phishing).", 2.0, "social", mitre=["T1566.004"],
                evidence={"phone_numbers": se.phone_numbers[:3]}))
            res.techniques.append("callback_phishing")
            for ph in se.phone_numbers[:3]:
                res.indicators.append(Indicator(type=IndicatorType.PHONE, value=ph,
                                                role="callback"))
        pressure = se.urgency_score >= 0.1 or se.authority_score > 0 or \
            "secrecy" in se.tactic_scores
        if not http_links and se.has_payment_ask:
            if suspect and pressure:
                sigs.append(_sig(
                    "email.bec.payment_pressure",
                    "No-link payment or gift-card demand from a suspect sender",
                    "A link-free message demands payment/gift cards with urgency or secrecy, "
                    "from a sender that is spoofed, free-mail or redirects replies: classic "
                    "business-email-compromise.", 3.0, "email", mitre=["T1656", "T1566"],
                    evidence={"tactics": sorted(se.tactic_scores), "freemail": flags["freemail"],
                              "reply_swap": flags["reply_swap"]}))
                res.techniques.append("bec")
            elif "secrecy" in se.tactic_scores:
                sigs.append(_sig(
                    "email.bec.payment_secrecy", "Confidential payment request with no links",
                    "The message asks for a payment and for the reader to keep it quiet.",
                    1.0, "email", evidence={"tactics": sorted(se.tactic_scores)}))
        m = _MOBILE_RE.search(body)
        if m and (flags["reply_swap"] or flags["freemail"] or flags["display_spoof"]
                  or a.dmarc.status == "fail"):
            sigs.append(_sig(
                "email.bec.mobile_excuse", "'Sent from mobile' excuse with reply redirection",
                f"The text \"{_safe(m.group(0), 50)}\" is used to excuse odd wording and "
                "avoid phone verification, alongside a spoofed or redirected sender.",
                1.5, "email", mitre=["T1656"], evidence={"phrase": m.group(0)[:60]}))

    def _link_signals(self, pe: ParsedEmail, res: AnalyzerResult) -> None:
        kb = get_kb()
        worst: tuple[float, str, str, str] | None = None
        dangerous = 0
        count = 0
        for lk in pe.links:
            scheme = lk.url[:12].lower().lstrip()
            if scheme.startswith(("javascript:", "data:", "vbscript:")):
                dangerous += 1
                continue
            if lk.source != "html_href" or not lk.text:
                continue
            m = _ANCHOR_DOMAIN_RE.fullmatch(lk.text.strip()[:300])
            if not m:
                continue
            ahost, hhost = m.group("host").lower(), _host_of(lk.url)
            if not hhost or domains_aligned(ahost, hhost):
                continue
            count += 1
            brand = kb.official_brand_for_host(ahost)
            target = kb.official_brand_for_host(hhost)
            w = 2.5 if brand is not None and (target is None or target.id != brand.id) else 1.2
            if worst is None or w > worst[0]:
                worst = (w, ahost, hhost, brand.name if brand else "")
        if worst:
            w, ahost, hhost, bname = worst
            res.signals.append(_sig(
                "email.link.anchor_mismatch", "Link text shows one site but goes to another",
                f"A link displays {_safe(ahost)}{' (' + bname + ')' if bname else ''} but "
                f"actually leads to {_safe(hhost)}.", w, "email", mitre=["T1566.002"],
                evidence={"shown": ahost, "actual": hhost, "count": count}))
        if dangerous:
            res.signals.append(_sig(
                "email.link.dangerous_scheme", "Link uses a javascript: or data: address",
                f"{dangerous} link(s) use a script or data URI, which legitimate mail "
                "does not.", 2.0, "email", mitre=["T1566.002"], evidence={"count": dangerous}))

    # ----------------------------------------------------- children / IOCs #
    def _children_and_indicators(self, pe: ParsedEmail, flags: dict,
                                 res: AnalyzerResult) -> None:
        ind: dict[tuple[str, str], Indicator] = {i.key(): i for i in res.indicators}

        def add(t: IndicatorType, v: str, role: str | None = None, ctx: str | None = None):
            if v and len(ind) < MAX_INDICATORS:
                ind.setdefault((t.value, v.lower()), Indicator(type=t, value=v, role=role,
                                                               context=ctx))

        if pe.from_.addr:
            add(IndicatorType.EMAIL, pe.from_.addr, "sender")
        if pe.from_.domain:
            add(IndicatorType.DOMAIN, pe.from_.domain, "sender")
        for r in pe.reply_to:
            if r.addr and r.domain and not domains_aligned(r.domain, pe.from_.domain):
                add(IndicatorType.EMAIL, r.addr, "reply-to")
                add(IndicatorType.DOMAIN, r.domain, "reply-to")
        for hop in pe.received:
            try:
                ip = ipaddress.ip_address(hop.from_ip) if hop.from_ip else None
            except ValueError:
                ip = None
            if ip is not None and ip.is_global:
                add(IndicatorType.IPV4 if ip.version == 4 else IndicatorType.IPV6,
                    str(ip), "relay")

        children: list[Artifact] = []

        def child(factory, *args, **kw) -> None:
            try:
                children.append(factory(*args, **kw))
            except (ArtifactTooLarge, ValueError):
                log.debug("child skipped", exc_info=True)

        seen_hashes: set[str] = set()
        for att in pe.attachments:
            add(IndicatorType.SHA256, att.sha256, "attachment", att.filename)
            add(IndicatorType.SHA1, att.sha1, "attachment", att.filename)
            add(IndicatorType.MD5, att.md5, "attachment", att.filename)
            add(IndicatorType.FILENAME, att.filename, "attachment")
        for att in pe.attachments:
            if not att.data or att.sha256 in seen_hashes:
                continue
            seen_hashes.add(att.sha256)
            if att.content_type == "message/rfc822" and not att.truncated:
                child(Artifact.from_email, att.data, origin="email.attached",
                      filename=att.filename, sha256=att.sha256)
            else:
                child(Artifact.from_file, att.data, att.filename, att.content_type,
                      origin="email.attachment", sha256=att.sha256,
                      truncated=att.truncated, inline=att.is_inline)
        for i, img in enumerate(pe.images):
            if not img.data:
                continue
            child(Artifact.from_file, img.data, img.filename or f"image-{i + 1}",
                  img.content_type, origin="email.image", image_source=img.source)

        links = [lk for lk in pe.links if lk.source != "html_img"
                 and lk.url.lower().startswith(("http://", "https://", "ftp://"))]
        anchor_bad = {lk.url for lk in links if lk.text and (m := _ANCHOR_DOMAIN_RE.fullmatch(
            lk.text.strip()[:300])) and not domains_aligned(
                m.group("host").lower(), _host_of(lk.url))}
        links.sort(key=lambda lk: (lk.url not in anchor_bad, lk.source != "html_href"))
        seen_urls: set[str] = set()
        for lk in links:
            if lk.url in seen_urls or len(seen_urls) >= MAX_CHILD_LINKS:
                continue
            seen_urls.add(lk.url)
            child(Artifact.from_url, lk.url, origin="email.link", anchor_text=lk.text[:300],
                  link_source=lk.source, sender_domain=pe.from_domain)
            add(IndicatorType.URL, lk.url, "link")
            host = _host_of(lk.url)
            if host:
                add(IndicatorType.DOMAIN, host, "link")
        res.children.extend(children)
        res.indicators = list(ind.values())

    # --------------------------------------------------------------- meta #
    def _meta(self, pe: ParsedEmail, a: AuthResult, ctx: AnalysisContext) -> dict:
        return {
            "subject": _safe(pe.subject, 200),
            "from": pe.from_.addr,
            "from_display_name": _safe(pe.from_.display_name, 120),
            "reply_to": [r.addr for r in pe.reply_to][:5],
            "return_path": pe.return_path,
            "message_id": pe.message_id,
            "auth": {"spf": a.spf.status, "dkim": a.dkim.status, "dmarc": a.dmarc.status,
                     "dmarc_aligned": a.dmarc_aligned, "has_results": a.has_auth_results,
                     "authenticated_domain": a.authenticated_domain, "notes": a.notes[:10]},
            "counts": {"links": len(pe.links), "attachments": len(pe.attachments),
                       "images": len(pe.images), "attached_messages": len(pe.attached_messages),
                       "received_hops": len(pe.received)},
            "email_anomalies": list(pe.anomalies)[:30],
            "sender_seen_before": _sender_seen_before(ctx, pe.from_.addr),
        }
