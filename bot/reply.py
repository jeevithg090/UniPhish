"""Pure reply builder for the UniPhish Telegram bot.

Why this module exists: everything that decides *what the bot says* lives here, with no
Telegram dependency and no I/O, so it can be unit-tested without a live connection and
reused by other chat front-ends. :mod:`bot.telegram_bot` is only the thin I/O layer.

Safety rules enforced here (the bot's output is read by people who are, by definition,
looking at hostile content):

* **Every link is defanged** (``hxxps://evil[.]example``) and stripped of user-info,
  query string and fragment, so a reply can never be a clickable phishing link and never
  echoes tokens or credentials that were embedded in a URL.
* **User text is never echoed.** The card is built from engine signal titles, the brand
  name and normalised link targets only. Anything secret-looking (``password=...``, long
  opaque tokens, card-number-like digit runs) is redacted on the way out regardless.
* Control, zero-width and bidi characters are removed so a crafted brand/file name cannot
  reorder or hide card text.
* The scan is offline by default and never persists the analysed message.
"""

from __future__ import annotations

import html
import logging
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from uniphish.core.types import Verdict

log = logging.getLogger("uniphish.bot")

#: Longest message text handed to the engine (Telegram itself caps messages at 4096).
MAX_SCAN_CHARS = 20_000
#: Telegram's hard limit for one message is 4096 characters; stay below it.
MAX_CARD_CHARS = 3_900
MAX_REASONS = 4
MAX_LINKS = 3
MAX_MITRE = 4
MAX_EXTRA_URLS = 20
_MAX_LINK_CHARS = 120
_MAX_REASON_CHARS = 200

LEVEL_EMOJI = {
    "malicious": "\U0001f534",
    "suspicious": "\U0001f7e0",
    "benign": "\U0001f7e2",
    "none": "\U0001f50e",
}

# --------------------------------------------------------------------------- #
# Localised card strings. Reasons come from the engine and stay in English.
# --------------------------------------------------------------------------- #
_STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "malicious": "Likely phishing",
        "suspicious": "Suspicious",
        "benign": "No threat found",
        "risk": "Risk",
        "impersonates": "Impersonates",
        "why": "Why",
        "links": "Links",
        "mitre": "MITRE ATT&CK",
        "todo": "What to do",
        "none": "Nothing to check",
        "advice_malicious": (
            "Do not click, reply or enter any details. Delete the message "
            "and report it. If you already interacted, change your password "
            "and contact the real organisation through its official app or "
            "website."
        ),
        "advice_suspicious": (
            "Be careful. Do not click links or share codes. Check with the "
            "sender through a channel you already trust."
        ),
        "advice_benign": (
            "No phishing indicators found. This is not a guarantee: never share "
            "passwords or one-time codes."
        ),
        "advice_none": "Send or forward me a link, a message or an email (.eml) to check.",
    },
    "es": {
        "malicious": "Probable phishing",
        "suspicious": "Sospechoso",
        "benign": "No se detectaron amenazas",
        "risk": "Riesgo",
        "impersonates": "Suplanta a",
        "why": "Por qué",
        "links": "Enlaces",
        "mitre": "MITRE ATT&CK",
        "todo": "Qué hacer",
        "none": "Nada que revisar",
        "advice_malicious": (
            "No hagas clic, no respondas ni introduzcas datos. Elimina el "
            "mensaje y denúncialo. Si ya interactuaste, cambia tu contraseña "
            "y contacta con la organización real desde su app o sitio web "
            "oficial."
        ),
        "advice_suspicious": (
            "Actúa con cautela. No hagas clic en enlaces ni compartas "
            "códigos. Verifica con el remitente por un canal que ya "
            "conozcas."
        ),
        "advice_benign": (
            "No se encontraron indicios de phishing. No es una garantía: nunca "
            "compartas contraseñas ni códigos de un solo uso."
        ),
        "advice_none": "Envíame o reenvíame un enlace, un mensaje o un correo (.eml).",
    },
    "fr": {
        "malicious": "Hameçonnage probable",
        "suspicious": "Suspect",
        "benign": "Aucune menace détectée",
        "risk": "Risque",
        "impersonates": "Usurpe",
        "why": "Pourquoi",
        "links": "Liens",
        "mitre": "MITRE ATT&CK",
        "todo": "Que faire",
        "none": "Rien à vérifier",
        "advice_malicious": (
            "Ne cliquez pas, ne répondez pas et ne saisissez aucune "
            "information. Supprimez le message et signalez-le. Si vous avez "
            "déjà interagi, changez votre mot de passe et contactez la vraie "
            "organisation via son application ou son site officiel."
        ),
        "advice_suspicious": (
            "Restez prudent. Ne cliquez sur aucun lien et ne partagez aucun "
            "code. Vérifiez auprès de l'expéditeur par un canal que vous "
            "connaissez déjà."
        ),
        "advice_benign": (
            "Aucun indice d'hameçonnage trouvé. Ce n'est pas une garantie : ne "
            "partagez jamais vos mots de passe ni vos codes à usage unique."
        ),
        "advice_none": "Envoyez-moi ou transférez-moi un lien, un message ou un e-mail (.eml).",
    },
    "de": {
        "malicious": "Wahrscheinlich Phishing",
        "suspicious": "Verdächtig",
        "benign": "Keine Bedrohung gefunden",
        "risk": "Risiko",
        "impersonates": "Gibt sich aus als",
        "why": "Warum",
        "links": "Links",
        "mitre": "MITRE ATT&CK",
        "todo": "Was zu tun ist",
        "none": "Nichts zu prüfen",
        "advice_malicious": (
            "Nicht klicken, nicht antworten und keine Daten eingeben. "
            "Nachricht löschen und melden. Falls Sie bereits reagiert haben, "
            "ändern Sie Ihr Passwort und kontaktieren Sie die echte "
            "Organisation über ihre offizielle App oder Website."
        ),
        "advice_suspicious": (
            "Vorsicht. Keine Links öffnen und keine Codes weitergeben. "
            "Fragen Sie beim Absender über einen Ihnen bekannten Kanal "
            "nach."
        ),
        "advice_benign": (
            "Keine Phishing-Hinweise gefunden. Das ist keine Garantie: Geben "
            "Sie niemals Passwörter oder Einmalcodes weiter."
        ),
        "advice_none": "Senden oder leiten Sie mir einen Link, eine Nachricht oder eine "
        "E-Mail (.eml) weiter.",
    },
    "pt": {
        "malicious": "Provável phishing",
        "suspicious": "Suspeito",
        "benign": "Nenhuma ameaça encontrada",
        "risk": "Risco",
        "impersonates": "Imita",
        "why": "Por quê",
        "links": "Links",
        "mitre": "MITRE ATT&CK",
        "todo": "O que fazer",
        "none": "Nada para verificar",
        "advice_malicious": (
            "Não clique, não responda e não informe dados. Apague a mensagem "
            "e denuncie. Se já interagiu, troque sua senha e contate a "
            "organização verdadeira pelo app ou site oficial."
        ),
        "advice_suspicious": (
            "Tenha cautela. Não clique em links nem compartilhe códigos. "
            "Confirme com o remetente por um canal que você já conhece."
        ),
        "advice_benign": (
            "Nenhum indício de phishing encontrado. Isso não é garantia: nunca "
            "compartilhe senhas ou códigos de uso único."
        ),
        "advice_none": "Envie ou encaminhe um link, uma mensagem ou um e-mail (.eml).",
    },
    "ru": {
        "malicious": "Вероятный фишинг",
        "suspicious": "Подозрительно",
        "benign": "Угроз не найдено",
        "risk": "Риск",
        "impersonates": "Выдаёт себя за",
        "why": "Почему",
        "links": "Ссылки",
        "mitre": "MITRE ATT&CK",
        "todo": "Что делать",
        "none": "Нечего проверять",
        "advice_malicious": (
            "Не переходите по ссылкам, не отвечайте и не вводите данные. "
            "Удалите сообщение и сообщите о нём. Если вы уже взаимодействовали, "
            "смените пароль и свяжитесь с настоящей организацией через её "
            "официальное приложение или сайт."
        ),
        "advice_suspicious": (
            "Будьте осторожны. Не переходите по ссылкам и не сообщайте коды. "
            "Уточните у отправителя по уже известному вам каналу."
        ),
        "advice_benign": (
            "Признаков фишинга не найдено. Это не гарантия: никогда не сообщайте "
            "пароли и одноразовые коды."
        ),
        "advice_none": "Отправьте или перешлите ссылку, сообщение или письмо (.eml).",
    },
    "hi": {
        "malicious": "संभावित फ़िशिंग",
        "suspicious": "संदिग्ध",
        "benign": "कोई ख़तरा नहीं मिला",
        "risk": "जोखिम",
        "impersonates": "नकल कर रहा है",
        "why": "कारण",
        "links": "लिंक",
        "mitre": "MITRE ATT&CK",
        "todo": "क्या करें",
        "none": "जाँचने के लिए कुछ नहीं",
        "advice_malicious": (
            "लिंक पर क्लिक न करें, जवाब न दें और कोई जानकारी न भरें। संदेश हटाएँ "
            "और रिपोर्ट करें। यदि आप पहले ही जवाब दे चुके हैं, तो पासवर्ड बदलें और "
            "असली संस्था से उसके आधिकारिक ऐप या वेबसाइट के ज़रिए संपर्क करें।"
        ),
        "advice_suspicious": (
            "सावधान रहें। लिंक पर क्लिक न करें और कोड साझा न करें। भेजने वाले से "
            "किसी जाने-पहचाने माध्यम से पुष्टि करें।"
        ),
        "advice_benign": (
            "फ़िशिंग के कोई संकेत नहीं मिले। यह गारंटी नहीं है: पासवर्ड या वन-टाइम कोड कभी साझा न करें।"
        ),
        "advice_none": "कोई लिंक, संदेश या ईमेल (.eml) भेजें या फ़ॉरवर्ड करें।",
    },
}
SUPPORTED_LANGS: tuple[str, ...] = tuple(_STRINGS)


def pick_language(hint: str | None, detected: Iterable[str] = ()) -> str:
    """Choose a card language: explicit hint, then detected languages, then English.

    ``hint`` may be a Telegram ``language_code`` such as ``"pt-br"``; only the primary
    subtag is used. Unsupported languages fall back to English.
    """
    for cand in (hint, *detected):
        if not cand:
            continue
        primary = str(cand).lower().replace("_", "-").split("-", 1)[0]
        if primary in _STRINGS:
            return primary
    return "en"


# --------------------------------------------------------------------------- #
# Sanitising helpers (all regexes are linear: bounded quantifiers, disjoint classes)
# --------------------------------------------------------------------------- #
_CTRL_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏ -‮⁠-⁯﻿]")
_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'\u0000- ]{1,2048}")
_SCHEME_RE = re.compile(r"(?i)\b(h)tt(ps?)(://)")
_FTP_RE = re.compile(r"(?i)\bf(t)p(://)")
_DOT_RE = re.compile(r"(?<=[A-Za-z0-9])\.(?=[A-Za-z0-9])")
_SECRET_KV_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|passcode|pin|token|secret|api[_-]?key|otp|cvv)"
    r"\s{0,3}[:=]\s{0,3}[^\s&]{1,128}"
)
_AT_RE = re.compile(r"(?<!\[)@(?!\])")
_OPAQUE_RE = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def clean(text: str, limit: int = _MAX_REASON_CHARS) -> str:
    """Bound ``text`` and strip control / zero-width / bidi characters."""
    return _CTRL_RE.sub("", str(text))[:limit]


def redact(text: str) -> str:
    """Mask credential-looking substrings (``password=..``, long opaque tokens, card runs)."""
    out = _SECRET_KV_RE.sub(lambda m: f"{m.group(1)}=[redacted]", text)
    out = _CARD_RE.sub("[redacted number]", out)
    return _OPAQUE_RE.sub("[redacted]", out)


def defang_text(text: str, limit: int = _MAX_REASON_CHARS) -> str:
    """Make free text inert: scheme -> ``hxxp``, dots between alphanumerics -> ``[.]``,
    ``@`` -> ``[@]``, secrets redacted. Idempotent."""
    s = redact(clean(text, limit))
    s = _SCHEME_RE.sub(lambda m: f"hxx{m.group(2)}{m.group(3)}", s)
    s = _FTP_RE.sub(lambda m: f"fxp{m.group(2)}", s)
    s = _DOT_RE.sub("[.]", s)
    return _AT_RE.sub("[@]", s)


def defang_url(url: str, limit: int = _MAX_LINK_CHARS) -> str:
    """Defang one URL for display: no user-info, no query/fragment, dots bracketed.

    The query string is dropped (it is where tokens and victim identifiers live) and
    replaced by ``?…`` so the reader still knows one existed.
    """
    s = clean(url, 2048).strip()
    scheme = ""
    m = re.match(r"(?i)([a-z][a-z0-9+.\-]{0,15})://", s)
    if m:
        scheme, s = m.group(1).lower(), s[m.end() :]
    cut = min((i for i in (s.find("/"), s.find("?"), s.find("#")) if i >= 0), default=len(s))
    authority, rest = s[:cut], s[cut:]
    authority = authority.rsplit("@", 1)[-1]  # drop user:password@
    had_query = "?" in rest or "#" in rest
    path = re.split(r"[?#]", rest, maxsplit=1)[0]
    shown = authority + redact(path) + ("?…" if had_query else "")
    shown = _DOT_RE.sub("[.]", shown)
    if scheme in {"http", "https"}:
        scheme = "hxxp" + ("s" if scheme == "https" else "")
    elif scheme == "ftp":
        scheme = "fxp"
    out = f"{scheme}://{shown}" if scheme else shown
    if len(out) > limit:
        out = out[: limit - 1] + "…"
    return out


def _esc(text: str) -> str:
    return html.escape(text, quote=False)


# --------------------------------------------------------------------------- #
# The card
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class CardLink:
    """A child artifact (link or attachment) listed on the card, already defanged."""

    text: str
    level: str
    kind: str = "url"


@dataclass(frozen=True)
class ReplyCard:
    """Everything the bot says about one scan. All strings are display-ready and inert."""

    level: str  # malicious | suspicious | benign | none
    score: int
    headline: str
    advice: str
    lang: str = "en"
    kind: str = "text"
    brand: str | None = None
    brand_technique: str | None = None
    reasons: tuple[str, ...] = ()
    links: tuple[CardLink, ...] = ()
    mitre: tuple[str, ...] = ()
    subject: str | None = None
    note: str | None = None  # optional extra line (e.g. AI analyst narrative)
    verdict_id: str | None = None
    labels: dict[str, str] = field(default_factory=dict, repr=False)

    @property
    def emoji(self) -> str:
        return LEVEL_EMOJI.get(self.level, LEVEL_EMOJI["none"])

    @property
    def is_threat(self) -> bool:
        return self.level in {"malicious", "suspicious"}

    def with_note(self, note: str | None) -> ReplyCard:
        """Return a copy carrying an extra defanged note line."""
        from dataclasses import replace

        return replace(self, note=defang_text(note, 600) if note else None)

    def _label(self, key: str) -> str:
        return self.labels.get(key) or _STRINGS["en"][key]

    def to_html(self) -> str:
        """Telegram HTML-parse-mode text (every dynamic value is escaped)."""
        head = f"{self.emoji} <b>{_esc(self.headline)}</b>"
        if self.level != "none":
            head += f" — {_esc(self._label('risk'))} {self.score}/100"
        lines = [head]
        if self.subject:
            lines.append(f"✉️ <i>{_esc(self.subject)}</i>")
        if self.brand and self.is_threat:
            lines.append(
                f"\U0001f3af {_esc(self._label('impersonates'))}: <b>{_esc(self.brand)}</b>"
            )
        if self.reasons:
            lines += ["", f"<b>{_esc(self._label('why'))}</b>"]
            lines += [f"• {_esc(r)}" for r in self.reasons]
        if self.links:
            lines += ["", f"<b>{_esc(self._label('links'))}</b>"]
            for ln in self.links:
                icon = LEVEL_EMOJI.get(ln.level, "")
                clip = "\U0001f4ce" if ln.kind == "file" else icon
                lines.append(f"{clip} <code>{_esc(ln.text)}</code>")
        if self.mitre:
            lines += ["", f"<b>{_esc(self._label('mitre'))}</b>: " + _esc("; ".join(self.mitre))]
        if self.note:
            lines += ["", f"\U0001f9e0 {_esc(self.note)}"]
        lines += ["", f"<b>{_esc(self._label('todo'))}</b>", _esc(self.advice)]
        text = "\n".join(lines)
        if len(text) > MAX_CARD_CHARS:  # pragma: no cover - bounded by the caps above
            text = text[: MAX_CARD_CHARS - 1] + "…"
        return text

    def to_text(self) -> str:
        """Plain-text rendering (HTML tags stripped, entities unescaped)."""
        return html.unescape(re.sub(r"</?(?:b|i|code)>", "", self.to_html()))

    def as_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "score": self.score,
            "headline": self.headline,
            "brand": self.brand,
            "brand_technique": self.brand_technique,
            "reasons": list(self.reasons),
            "links": [{"text": x.text, "level": x.level, "kind": x.kind} for x in self.links],
            "mitre": list(self.mitre),
            "advice": self.advice,
            "lang": self.lang,
            "kind": self.kind,
            "subject": self.subject,
            "verdict_id": self.verdict_id,
        }


# --------------------------------------------------------------------------- #
# Verdict -> card
# --------------------------------------------------------------------------- #
def _reasons(verdict: Verdict) -> tuple[str, ...]:
    """Strongest malicious signals across the verdict tree, de-duplicated by title."""
    ranked: list[tuple[float, str]] = []
    for v in verdict.walk():
        for s in v.signals:
            if s.id.startswith("engine."):
                continue  # generic "contains malicious url": the child's own signals say why
            eff = s.contribution if s.contribution is not None else s.weight
            if eff > 0:
                ranked.append((eff, s.title))
    ranked.sort(key=lambda t: t[0], reverse=True)
    out: list[str] = []
    seen: set[str] = set()
    for _, title in ranked:
        shown = defang_text(title).rstrip(".")
        if shown and shown.lower() not in seen:
            seen.add(shown.lower())
            out.append(shown)
        if len(out) >= MAX_REASONS:
            break
    if not out and verdict.level.value != "benign" and verdict.summary:
        out.append(defang_text(verdict.summary).rstrip("."))
    return tuple(out)


def _links(verdict: Verdict) -> tuple[CardLink, ...]:
    kids = [
        c
        for c in verdict.walk()
        if c is not verdict
        and c.level.value != "benign"
        and c.kind.value in {"url", "file", "page"}
    ]
    kids.sort(key=lambda c: c.score, reverse=True)
    out: list[CardLink] = []
    seen: set[str] = set()
    for c in kids:
        text = defang_url(c.target) if c.kind.value == "url" else defang_text(c.target, 80)
        if text and text not in seen:
            seen.add(text)
            out.append(CardLink(text, c.level.value, "file" if c.kind.value == "file" else "url"))
        if len(out) >= MAX_LINKS:
            break
    if not out and verdict.kind.value == "url" and verdict.level.value != "benign":
        out.append(CardLink(defang_url(verdict.target), verdict.level.value))
    return tuple(out)


def _mitre(verdict: Verdict) -> tuple[str, ...]:
    seen: dict[str, str] = {}
    for v in verdict.walk():
        for m in v.mitre:
            seen.setdefault(m.id, m.name)
    return tuple(f"{tid} {clean(name, 70)}" for tid, name in list(seen.items())[:MAX_MITRE])


def _brand(verdict: Verdict) -> tuple[str | None, str | None]:
    for v in verdict.walk():
        b = v.brand
        if b is not None and not b.official:
            return clean(b.name, 60), b.technique
    return None, None


def card_from_verdict(verdict: Verdict, *, lang: str = "en", kind: str | None = None) -> ReplyCard:
    """Render an engine :class:`~uniphish.core.types.Verdict` as a :class:`ReplyCard`."""
    lang = lang if lang in _STRINGS else "en"
    s = _STRINGS[lang]
    level = verdict.level.value
    threat = level != "benign"
    brand, technique = _brand(verdict) if threat else (None, None)
    subject = verdict.meta.get("subject") if verdict.kind.value == "email" else None
    return ReplyCard(
        level=level,
        score=int(verdict.score),
        headline=s[level],
        advice=s[f"advice_{level}"],
        lang=lang,
        kind=kind or verdict.kind.value,
        brand=brand,
        brand_technique=technique,
        reasons=_reasons(verdict) if threat else (),
        links=_links(verdict) if threat else (),
        mitre=_mitre(verdict) if threat else (),
        subject=defang_text(subject, 100) if isinstance(subject, str) and subject else None,
        verdict_id=verdict.id,
        labels=s,
    )


def empty_card(lang: str = "en") -> ReplyCard:
    """The 'nothing to check' card."""
    s = _STRINGS[lang if lang in _STRINGS else "en"]
    return ReplyCard(
        level="none",
        score=0,
        headline=s["none"],
        advice=s["advice_none"],
        lang=lang,
        kind="none",
        labels=s,
    )


# --------------------------------------------------------------------------- #
# Scanning entry points
# --------------------------------------------------------------------------- #
def _opts(online: bool, fetch_pages: bool) -> dict[str, Any]:
    return {
        "online": bool(online),
        "fetch_pages": bool(fetch_pages and online),
        "persist": False,
        "timeout_s": 20.0,
    }


def _detect_language(text: str) -> list[str]:
    try:
        from uniphish.nlp import analyze_text

        return list(analyze_text(text).languages)
    except Exception:
        log.debug("language detection failed", exc_info=True)
        return []


def build_reply_with_verdict(
    text: str | None,
    *,
    lang: str | None = None,
    extra_urls: Sequence[str] = (),
    online: bool = False,
    fetch_pages: bool = False,
    scan: Callable[..., Verdict] | None = None,
) -> tuple[ReplyCard, Verdict | None]:
    """Like :func:`build_reply` but also returns the engine verdict (``None`` if no scan ran
    or the engine failed). Used by front-ends that want to add an AI analyst note."""
    body = clean(text or "", MAX_SCAN_CHARS) if text else ""
    hidden = [clean(u, 2048).strip() for u in list(extra_urls)[:MAX_EXTRA_URLS] if u]
    hidden = [u for u in hidden if u and u not in body]
    if hidden:
        body = body + "\n" + "\n".join(hidden)
    if not body.strip():
        return empty_card(pick_language(lang)), None
    chosen = pick_language(lang, _detect_language(body))
    try:
        if scan is None:
            import uniphish

            scan = uniphish.scan_text
        verdict = scan(body, **_opts(online, fetch_pages))
    except Exception:
        log.exception("text scan failed")
        return _failure_card(chosen), None
    return card_from_verdict(verdict, lang=chosen, kind="text"), verdict


def build_reply(
    text: str | None,
    *,
    lang: str | None = None,
    extra_urls: Sequence[str] = (),
    online: bool = False,
    fetch_pages: bool = False,
    scan: Callable[..., Verdict] | None = None,
) -> ReplyCard:
    """Scan a message and return the reply card (pure: no Telegram, no persistence).

    Args:
        text: the message or forwarded text. The whole text is analysed as a TEXT
            artifact, so smishing language and every contained link are scored together.
        lang: language hint (e.g. Telegram ``language_code``); otherwise the language is
            detected from the text. Unsupported languages fall back to English.
        extra_urls: URLs hidden behind Telegram "text link" entities (anchor text that
            differs from the real target). They are appended to the scanned text.
        online / fetch_pages: enable network enrichment / page fetching (off by default).
        scan: injection point replacing ``uniphish.scan_text`` (tests).

    Never raises on hostile input; an engine failure yields a conservative
    "could not check" suspicious card rather than a false all-clear.
    """
    return build_reply_with_verdict(
        text, lang=lang, extra_urls=extra_urls, online=online, fetch_pages=fetch_pages, scan=scan
    )[0]


def _failure_card(lang: str) -> ReplyCard:
    s = _STRINGS[lang if lang in _STRINGS else "en"]
    return ReplyCard(
        level="suspicious",
        score=50,
        headline=s["suspicious"],
        advice=s["advice_suspicious"],
        lang=lang,
        kind="error",
        reasons=("The automatic check could not be completed",),
        labels=s,
    )


_HTML_EXT = (".html", ".htm", ".xhtml")
_EMAIL_EXT = (".eml",)


def classify_upload(data: bytes, filename: str | None) -> str:
    """Return ``'email'``, ``'page'`` or ``'file'`` for an uploaded document."""
    name = (filename or "").lower()
    head = data[:2048].lstrip().lower()
    if name.endswith(_EMAIL_EXT):
        return "email"
    if name.endswith(_HTML_EXT) or head.startswith((b"<!doctype html", b"<html")):
        return "page"
    return "file"


def build_file_reply(
    data: bytes,
    filename: str | None = None,
    *,
    lang: str | None = None,
    online: bool = False,
    fetch_pages: bool = False,
    scan_file: Callable[..., Verdict] | None = None,
    scan_email: Callable[..., Verdict] | None = None,
    scan_page: Callable[..., Verdict] | None = None,
) -> ReplyCard:
    """Scan an uploaded document / image (QR codes are decoded) and return a card.

    ``.eml`` goes through the email analyzer (headers, authentication, links,
    attachments), HTML through the page analyzer, anything else through the file
    analyzer. Callers must enforce their size cap before calling.
    """
    chosen = pick_language(lang)
    if not data:
        return empty_card(chosen)
    kind = classify_upload(data, filename)
    try:
        import uniphish

        opts = _opts(online, fetch_pages)
        if kind == "email":
            verdict = (scan_email or uniphish.scan_email)(data, **opts)
        elif kind == "page":
            verdict = (scan_page or uniphish.scan_page)(data, None, **opts)
        else:
            verdict = (scan_file or uniphish.scan_file)(
                data, clean(filename or "", 255) or None, **opts
            )
    except Exception:
        log.exception("file scan failed")
        return _failure_card(chosen)
    return card_from_verdict(verdict, lang=chosen, kind=kind)


__all__ = [
    "MAX_CARD_CHARS",
    "MAX_SCAN_CHARS",
    "SUPPORTED_LANGS",
    "CardLink",
    "ReplyCard",
    "build_file_reply",
    "build_reply",
    "build_reply_with_verdict",
    "card_from_verdict",
    "classify_upload",
    "clean",
    "defang_text",
    "defang_url",
    "empty_card",
    "pick_language",
    "redact",
]
