"""Text / message analyzer: smishing, chat, WhatsApp and other social-engineering text.

Why this exists
---------------
Most consumer phishing now arrives as a short message (SMS, WhatsApp, Telegram,
iMessage) rather than as an e-mail: "Your parcel is on hold, pay the fee: <link>".
There is no header, no HTML and often no attachment, so the evidence is the *language*
and the *link*. This analyzer turns the multilingual pressure model in
:mod:`uniphish.nlp` into explainable signals, pulls every URL out as a child artifact
(so the URL analyzers judge it and the engine propagates its risk to the message), and
adds message-level checks that need both halves: a named brand whose domain does not
match any link, a callback number on a tech-support lure, a request for a one-time
code, a gift-card / wire request, or a request for a crypto recovery phrase.

Everything is offline, deterministic and bounded: the input is truncated before any
matching and the only regexes applied to attacker text are linear.

Weights follow the build contract scale. All signals are in category ``social`` except
the brand/link mismatch, which is independent evidence (``brand``).
"""

from __future__ import annotations

import logging
import re

from uniphish.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult, register
from uniphish.core.types import (
    Artifact,
    ArtifactKind,
    BrandMatch,
    Indicator,
    IndicatorType,
    Signal,
)
from uniphish.nlp import SEResult, TacticHit, analyze_text
from uniphish.url.brandkb import Brand, get_kb
from uniphish.url.parse import extract_urls, parse_url

log = logging.getLogger("uniphish.analyzers.text")

#: Characters of text examined for URLs / seed-phrase patterns.
MAX_SCAN_CHARS = 200_000
#: Child artifacts emitted per message (the engine also caps at ``max_children``).
MAX_LINKS = 25
#: Pressure log-odds are clipped here before conversion to a signal weight.
PRESSURE_CAP = 5.0

# Seed / recovery phrase: linear patterns, no nested quantifiers.
_SEED_RE = re.compile(
    r"(?i)\b(?:seed|recovery|secret|mnemonic|backup)[ \-]?(?:phrase|words?)\b"
    r"|\b(?:12|24|twelve|twenty[- ]four)[ \-]words?\b"
    r"|\bprivate[ \-]key\b"
    r"|\bfrase[ \-](?:semilla|secreta|de[ \-]recuperaci[oó]n|de[ \-]recupera[cç][aã]o)\b"
    r"|\bpalavras[ \-]de[ \-]recupera[cç][aã]o\b"
)
_SEED_ASK_RE = re.compile(
    r"(?i)\b(?:enter|send|provide|share|submit|verify|validate|import|confirm|type|paste|"
    r"reply|give|tell|input|connect|restore|sync|synchronize|ingresa|ingrese|introduce|"
    r"env[ií]a|envie|comparte|proporciona|digite|informe|insira|confirma)\w*"
)
_NEGATION_RE = re.compile(
    r"(?i)\b(?:never|don'?t|do not|dont|won'?t|will not|nunca|jam[aá]s|no (?:compartas|env[ií]es)|"
    r"n[aã]o (?:compartilhe|envie)|nie)\b"
)
_CALL_RE = re.compile(
    r"(?i)\b(?:call|dial|phone|ring|contact|llama|llame|llamar|ligue|ligar|"
    r"telefone|appelez|rufen)\b|कॉल"
)
_HIGH_PRESSURE_TACTICS = frozenset({"urgency", "threat", "techsupport", "authority", "tax"})


def _w(x: float) -> float:
    return round(x, 2)


def _clip(text: str, n: int = 160) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"


def pressure_weight(log_odds: float) -> float:
    """Map an NLP pressure log-odds (capped at 5) to a signal weight (0 .. 3.7).

    Weak language stays weak (half weight up to 1.0); strong language scales at 0.8.
    """
    lo = min(max(log_odds, 0.0), PRESSURE_CAP)
    if lo <= 1.0:
        return _w(0.5 * lo)
    return _w(0.5 + 0.8 * (lo - 1.0))


@register
class TextAnalyzer(Analyzer):
    name = "text"
    kinds = frozenset({ArtifactKind.TEXT})
    stage = 0
    requires_online = False
    blocking = True
    description = (
        "Smishing / chat / social-engineering language (urgency, authority, OTP, "
        "payment, callback, crypto asks) plus link extraction and brand-link mismatch"
    )
    signals = {
        "social.pressure": "Message uses pressure tactics typical of phishing",
        "social.urgent_credential_ask": "Urgent request to verify or enter account credentials",
        "social.otp_request": "Message asks you to hand over a one-time code",
        "social.payment_request": "Message asks for a payment, gift cards or a wire transfer",
        "social.callback_number": "Message pushes you to call a phone number",
        "social.crypto_seed_request": "Message asks for a crypto wallet recovery phrase",
        "social.link_in_pressure_message": "Pressure message pushes you to open a link",
        "social.brand_link_mismatch": "Message names a brand but links to an unrelated site",
    }

    def applies(self, artifact: Artifact, ctx: AnalysisContext) -> bool:
        return bool((artifact.text or "").strip())

    # ------------------------------------------------------------------ main
    def analyze_sync(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        text = artifact.text or ""
        scan = text[:MAX_SCAN_CHARS]
        res = AnalyzerResult()
        try:
            se = analyze_text(scan, lang_hint=artifact.meta.get("lang"))
        except Exception:  # pragma: no cover - nlp never raises, belt and braces
            log.exception("nlp analysis failed")
            se = analyze_text("")

        links = self._links(scan)
        res.children = [self._child(u, artifact) for u in links][:MAX_LINKS]
        res.children = [c for c in res.children if c is not None]
        link_urls = [c.url for c in res.children if c.url]

        brands = self._brands(scan)

        self._pressure_signals(se, scan, link_urls, brands, res)
        self._ask_signals(se, scan, res)
        self._brand_mismatch(se, link_urls, brands, res)

        res.meta.update(
            {
                "languages": list(se.languages),
                "tactics": {k: round(v, 3) for k, v in se.tactic_scores.items()},
                "text.dominant_tactic": se.dominant_tactic,
                "text.pressure_score": round(se.score, 3),
                "text.links": link_urls,
                "text.phone_numbers": list(se.phone_numbers),
                "text.truncated": se.truncated or len(text) > MAX_SCAN_CHARS,
            }
        )
        return res

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _links(scan: str) -> list[str]:
        try:
            return [e.url for e in extract_urls(scan, max_urls=MAX_LINKS)]
        except Exception:  # pragma: no cover - extract_urls is hardened
            log.exception("url extraction failed")
            return []

    @staticmethod
    def _child(url: str, parent: Artifact) -> Artifact | None:
        try:
            return Artifact.from_url(url, origin="text.link", parent_id=parent.id)
        except ValueError:  # empty or oversized URL (ArtifactTooLarge is a ValueError)
            return None

    @staticmethod
    def _brands(scan: str) -> list[Brand]:
        try:
            return get_kb().brands_mentioned_in(scan)
        except Exception:  # pragma: no cover
            log.exception("brand lookup failed")
            return []

    @staticmethod
    def _best_hit(hits: list[TacticHit], tactics: frozenset[str] | None = None) -> TacticHit | None:
        pool = [h for h in hits if tactics is None or h.tactic in tactics]
        return max(pool, key=lambda h: h.weight, default=None)

    # --------------------------------------------------------------- signals
    def _pressure_signals(
        self, se: SEResult, scan: str, links: list[str], brands: list[Brand], res: AnalyzerResult
    ) -> None:
        w = pressure_weight(se.log_odds)
        top = self._best_hit(se.tactics)
        if w >= 0.25 and se.tactics:
            tactics = sorted(se.tactic_scores, key=lambda k: -se.tactic_scores[k])
            named = ", ".join(t for t in tactics if t != "cta")[:120] or "pressure"
            res.signals.append(
                Signal(
                    id="social.pressure",
                    title="Message uses pressure tactics typical of phishing",
                    detail=f"Language matched: {named}. Strongest phrase: "
                    f"“{_clip(top.term, 60) if top else ''}” "
                    f"(languages: {', '.join(se.languages) or 'unknown'}).",
                    weight=w,
                    category="social",
                    span=(top.start, top.end) if top else None,
                    mitre=["T1566"] if w >= 1.5 else [],
                    evidence={
                        "log_odds": round(se.log_odds, 2),
                        "tactics": dict(se.tactic_scores),
                        "terms": [h.term for h in se.tactics[:8]],
                        "languages": list(se.languages),
                    },
                )
            )

        if se.has_credential_ask and se.urgency_score >= 0.25:
            full = se.authority_score > 0 or bool(brands)
            hit = self._best_hit(se.tactics, frozenset({"credential"})) or top
            res.signals.append(
                Signal(
                    id="social.urgent_credential_ask",
                    title="Urgent request to verify or enter account credentials",
                    detail="The message combines time pressure with a request to confirm, "
                    "verify or enter account details"
                    + (", and claims authority or names a known brand." if full else "."),
                    weight=2.5 if full else 1.5,
                    category="social",
                    span=(hit.start, hit.end) if hit else None,
                    mitre=["T1566", "T1598"],
                    evidence={
                        "urgency": round(se.urgency_score, 2),
                        "authority": round(se.authority_score, 2),
                        "brands": [b.id for b in brands[:3]],
                    },
                )
            )

        if links and w >= 1.0:
            res.signals.append(
                Signal(
                    id="social.link_in_pressure_message",
                    title="Pressure message pushes you to open a link",
                    detail=f"A message using pressure language contains {len(links)} "
                    f"link(s); the first points to {parse_url(links[0]).host or links[0]}.",
                    weight=1.0,
                    category="social",
                    mitre=["T1566.002"],
                    evidence={"links": links[:5]},
                )
            )

    def _ask_signals(self, se: SEResult, scan: str, res: AnalyzerResult) -> None:
        if se.has_otp_ask:
            hit = self._best_hit(se.tactics, frozenset({"otp"}))
            res.signals.append(
                Signal(
                    id="social.otp_request",
                    title="Message asks you to hand over a one-time code",
                    detail="Legitimate services never ask you to reply with or read out a "
                    "verification code; attackers use it to take over accounts.",
                    weight=3.0,
                    category="social",
                    span=(hit.start, hit.end) if hit else None,
                    mitre=["T1621", "T1111", "T1566"],
                    evidence={"term": hit.term if hit else None},
                )
            )

        if se.has_payment_ask:
            hit = self._best_hit(se.tactics, frozenset({"payment"}))
            secret = se.tactic_scores.get("secrecy", 0.0) > 0
            res.signals.append(
                Signal(
                    id="social.payment_request",
                    title="Message asks for a payment, gift cards or a wire transfer",
                    detail="The text requests money or gift-card codes"
                    + (
                        " and asks you to keep it secret, a classic BEC / impersonation pattern."
                        if secret
                        else "."
                    ),
                    weight=2.5,
                    category="social",
                    span=(hit.start, hit.end) if hit else None,
                    mitre=["T1657", "T1656"],
                    evidence={"term": hit.term if hit else None, "secrecy": secret},
                )
            )

        self._callback(se, scan, res)
        self._seed(se, scan, res)

    def _callback(self, se: SEResult, scan: str, res: AnalyzerResult) -> None:
        if not se.phone_numbers:
            return
        techsupport = se.tactic_scores.get("techsupport", 0.0) > 0
        pressured = any(h.tactic in _HIGH_PRESSURE_TACTICS for h in se.tactics)
        call_word = bool(_CALL_RE.search(scan))
        # A bare number in friendly chat is not evidence; a number plus a lure is.
        if not (techsupport or (pressured and call_word)):
            return
        numbers = list(se.phone_numbers[:5])
        res.signals.append(
            Signal(
                id="social.callback_number",
                title="Message pushes you to call a phone number",
                detail="A lure about an account, virus or charge tells you to call "
                f"{', '.join(numbers)}; callback (TOAD) phishing moves the attack "
                "to a voice call.",
                weight=2.0,
                category="social",
                mitre=["T1566.004", "T1598.004"],
                evidence={"phone_numbers": numbers, "techsupport": techsupport},
            )
        )
        for n in numbers:
            res.indicators.append(
                Indicator(
                    type=IndicatorType.PHONE,
                    value=n,
                    role="callback",
                    malicious=None,
                    context="callback number in lure message",
                )
            )

    def _seed(self, se: SEResult, scan: str, res: AnalyzerResult) -> None:
        for m in _SEED_RE.finditer(scan):
            before = scan[max(0, m.start() - 80) : m.start()]
            after = scan[m.end() : m.end() + 40]
            near = scan[max(0, m.start() - 80) : m.end() + 40]
            neg = _NEGATION_RE.search(scan[max(0, m.start() - 40) : m.end() + 20])
            if neg or not _SEED_ASK_RE.search(before + " " + after):
                continue
            res.signals.append(
                Signal(
                    id="social.crypto_seed_request",
                    title="Message asks for a crypto wallet recovery phrase",
                    detail="Anyone asking for a seed / recovery phrase or private key is "
                    "trying to drain a wallet; no real service ever needs it.",
                    weight=4.0,
                    category="social",
                    span=(m.start(), m.end()),
                    mitre=["T1657", "T1566"],
                    evidence={"match": _clip(m.group(0), 40), "context": _clip(near, 120)},
                )
            )
            return

    def _brand_mismatch(
        self, se: SEResult, links: list[str], brands: list[Brand], res: AnalyzerResult
    ) -> None:
        if not brands or not links:
            return
        kb = get_kb()
        hosts = []
        for u in links:
            p = parse_url(u)
            hosts.append(p.host_ascii or p.host)
        for b in brands:
            for h in hosts:
                owner = (
                    kb.official_brand_for_host(h)
                    or kb.login_brand_for_host(h)
                    or kb.cdn_brand_for_host(h)
                )
                if owner is not None and owner.id == b.id:
                    return  # at least one link legitimately belongs to a named brand
        brand = brands[0]
        pressured = (
            se.log_odds >= 0.5 or se.has_credential_ask or se.has_payment_ask or se.has_otp_ask
        )
        shown = ", ".join(sorted(set(h for h in hosts if h))[:3])
        res.signals.append(
            Signal(
                id="social.brand_link_mismatch",
                title=f"Message names {brand.name} but links to an unrelated site",
                detail=f"The text mentions {brand.name}, yet the link(s) point to {shown}, "
                f"which is not a {brand.name} domain.",
                weight=2.0 if pressured else 1.2,
                category="brand",
                mitre=["T1656", "T1566.002"],
                evidence={
                    "brand": brand.id,
                    "link_hosts": hosts[:5],
                    "official_domains": list(brand.official_domains[:5]),
                },
            )
        )
        res.brand = BrandMatch(
            brand=brand.id,
            name=brand.name,
            technique="content",
            confidence=0.6 if pressured else 0.45,
            legit_domains=list(brand.official_domains[:10]),
            evidence=f"message names {brand.name}; links go to {shown}",
            official=False,
        )
        res.techniques.append("brand_link_mismatch")
