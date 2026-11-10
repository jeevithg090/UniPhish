"""Core data model shared by every UniPhish component.

Everything the platform analyses is an :class:`Artifact` (a URL, an HTML page, a raw
email, a file, a free-text message). Analyzers turn an artifact into
:class:`Signal` objects — atomic, explainable pieces of evidence — plus extracted
:class:`Indicator` objects (IOCs) and optional child artifacts (an email's links and
attachments, a QR code's URL, a redirect target). The engine fuses the signals into a
single, explainable :class:`Verdict`.

Design rules
------------
* **Signals carry signed log-odds weights.** Positive = evidence of maliciousness,
  negative = evidence of legitimacy. Fusion is additive in log-odds space (see
  :mod:`uniphish.core.scoring`), so every verdict decomposes exactly into per-signal
  contributions — no black boxes.
* **Artifacts are internal, verdicts are external.** Artifacts may hold raw bytes and
  never leave the process; verdicts are pydantic models that serialise cleanly to
  JSON for the API, the dashboard, SIEM exports and STIX.
* **Size limits are enforced at construction** — the first line of defence against
  resource-exhaustion inputs.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

ENGINE_VERSION = "2.0.0"

# --------------------------------------------------------------------------- #
# Input size limits (bytes / characters). Enforced by Artifact constructors.
# --------------------------------------------------------------------------- #
MAX_URL_CHARS = 8_192
MAX_TEXT_CHARS = 1_000_000
MAX_PAGE_BYTES = 5_000_000
MAX_EMAIL_BYTES = 25_000_000
MAX_FILE_BYTES = 25_000_000


class ArtifactTooLarge(ValueError):
    """Raised when an input exceeds the configured size limit."""


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class ArtifactKind(str, Enum):
    URL = "url"
    PAGE = "page"      # an HTML document (optionally with the URL it was served from)
    EMAIL = "email"    # a raw RFC 5322 message (.eml)
    FILE = "file"      # an attachment / download / image
    TEXT = "text"      # SMS, chat message, document text, LLM context, ...


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_weight(cls, weight: float) -> Severity:
        """Map a signed log-odds weight to a display severity (benign evidence -> INFO)."""
        if weight >= 4.0:
            return cls.CRITICAL
        if weight >= 2.5:
            return cls.HIGH
        if weight >= 1.2:
            return cls.MEDIUM
        if weight > 0.0:
            return cls.LOW
        return cls.INFO


class Level(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Action(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class IndicatorType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    EMAIL = "email"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    FILENAME = "filename"
    PHONE = "phone"
    CRYPTO_WALLET = "crypto_wallet"
    ASN = "asn"
    CERT_SHA256 = "cert_sha256"
    USER_AGENT = "user_agent"


# --------------------------------------------------------------------------- #
# Artifacts (internal)
# --------------------------------------------------------------------------- #
def _digest(*parts: bytes) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
        h.update(b"\x00")
    return h.hexdigest()


@dataclass(eq=False)
class Artifact:
    """A thing to analyse. Build with the ``from_*`` constructors, not directly.

    Attributes:
        kind: what this is.
        url: the URL (URL artifacts) or the URL a PAGE was served from (may be None).
        content: raw bytes (PAGE html, EMAIL rfc822, FILE data).
        text: decoded text (TEXT artifacts).
        filename / mime: FILE metadata (mime may be sniffed by analyzers).
        origin: provenance label for children, e.g. ``"email.link"``,
            ``"email.attachment"``, ``"qr"``, ``"redirect"``, ``"page.form_action"``.
        parent_id: id of the artifact this was extracted from.
        meta: free-form context supplied by the producer (e.g. link anchor text).
    """

    kind: ArtifactKind
    url: str | None = None
    content: bytes | None = None
    text: str | None = None
    filename: str | None = None
    mime: str | None = None
    origin: str | None = None
    parent_id: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)
    _id: str | None = field(default=None, repr=False)

    # ---- identity --------------------------------------------------------- #
    @property
    def id(self) -> str:
        """Stable content-derived id (sha256 prefix). Same input -> same id."""
        if self._id is None:
            body = self.content if self.content is not None else (self.text or "").encode()
            self._id = _digest(self.kind.value.encode(), (self.url or "").encode(), body)[:24]
        return self._id

    @property
    def sha256(self) -> str | None:
        """SHA-256 of the raw content (for FILE/EMAIL/PAGE), else None."""
        return hashlib.sha256(self.content).hexdigest() if self.content is not None else None

    @property
    def label(self) -> str:
        """Short human-readable label used as the verdict ``target``."""
        if self.kind is ArtifactKind.URL:
            return self.url or ""
        if self.kind is ArtifactKind.PAGE:
            return self.url or f"page:{self.id[:12]}"
        if self.kind is ArtifactKind.FILE:
            return self.filename or f"file:{self.id[:12]}"
        if self.kind is ArtifactKind.EMAIL:
            return str(self.meta.get("subject") or f"email:{self.id[:12]}")
        text = (self.text or "").strip().replace("\n", " ")
        return text[:120] + ("…" if len(text) > 120 else "")

    # ---- constructors ----------------------------------------------------- #
    @classmethod
    def from_url(cls, url: str, *, origin: str | None = None, parent_id: str | None = None,
                 **meta: Any) -> Artifact:
        url = (url or "").strip()
        if not url:
            raise ValueError("empty URL")
        if len(url) > MAX_URL_CHARS:
            raise ArtifactTooLarge(f"URL longer than {MAX_URL_CHARS} characters")
        return cls(ArtifactKind.URL, url=url, origin=origin, parent_id=parent_id, meta=meta)

    @classmethod
    def from_page(cls, html: str | bytes, url: str | None = None, *, origin: str | None = None,
                  parent_id: str | None = None, **meta: Any) -> Artifact:
        data = html.encode("utf-8", "replace") if isinstance(html, str) else bytes(html)
        if len(data) > MAX_PAGE_BYTES:
            raise ArtifactTooLarge(f"page larger than {MAX_PAGE_BYTES} bytes")
        return cls(ArtifactKind.PAGE, url=url, content=data, mime="text/html", origin=origin,
                   parent_id=parent_id, meta=meta)

    @classmethod
    def from_email(cls, raw: bytes | str, *, origin: str | None = None,
                   parent_id: str | None = None, **meta: Any) -> Artifact:
        data = raw.encode("utf-8", "replace") if isinstance(raw, str) else bytes(raw)
        if len(data) > MAX_EMAIL_BYTES:
            raise ArtifactTooLarge(f"email larger than {MAX_EMAIL_BYTES} bytes")
        return cls(ArtifactKind.EMAIL, content=data, mime="message/rfc822", origin=origin,
                   parent_id=parent_id, meta=meta)

    @classmethod
    def from_file(cls, data: bytes, filename: str | None = None, mime: str | None = None, *,
                  origin: str | None = None, parent_id: str | None = None,
                  **meta: Any) -> Artifact:
        if len(data) > MAX_FILE_BYTES:
            raise ArtifactTooLarge(f"file larger than {MAX_FILE_BYTES} bytes")
        return cls(ArtifactKind.FILE, content=bytes(data), filename=filename, mime=mime,
                   origin=origin, parent_id=parent_id, meta=meta)

    @classmethod
    def from_text(cls, text: str, *, origin: str | None = None, parent_id: str | None = None,
                  **meta: Any) -> Artifact:
        if len(text) > MAX_TEXT_CHARS:
            raise ArtifactTooLarge(f"text longer than {MAX_TEXT_CHARS} characters")
        return cls(ArtifactKind.TEXT, text=text, origin=origin, parent_id=parent_id, meta=meta)

    # ---- helpers ---------------------------------------------------------- #
    def html(self) -> str:
        """Decoded HTML for PAGE artifacts (best-effort charset handling)."""
        if self.content is None:
            return ""
        charset = str(self.meta.get("charset") or "utf-8")
        try:
            return self.content.decode(charset, "replace")
        except LookupError:
            return self.content.decode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# Evidence (external, serialisable)
# --------------------------------------------------------------------------- #
class _Model(BaseModel):
    model_config = ConfigDict(use_enum_values=False, populate_by_name=True)


class Signal(_Model):
    """One atomic, explainable piece of evidence.

    ``weight`` is a signed log-odds contribution. Calibrate against this scale:

    ======  =====================================================================
    weight  meaning
    ======  =====================================================================
    +6..+8  decisive (known-bad IOC from a live feed, AiTM kit fingerprint)
    +3..+5  strong (homoglyph impersonation of a brand, credential form posting
            to a foreign host on a lookalike domain, ClickFix clipboard payload)
    +1..+2  moderate (abused TLD, newly registered domain, urgency language)
    +0.2..1 weak / contextual (long URL, many hyphens)
    -1..-4  legitimacy evidence (exact official brand domain, top-1k site,
            DMARC pass aligned with a known sender)
    ======  =====================================================================
    """

    id: str = Field(description="Stable namespaced code, e.g. 'url.brand.homoglyph'.")
    title: str = Field(description="Short human-readable title.")
    detail: str = Field(default="", description="Plain-language explanation with specifics.")
    weight: float = Field(description="Signed log-odds contribution (+ malicious / - benign).")
    category: str = Field(description="Evidence family: url, unicode, brand, ml, page, kit, "
                                      "email, auth, social, file, infra, reputation, agent, "
                                      "engine.")
    severity: Severity | None = Field(default=None,
                                      description="Display severity; derived from weight if unset.")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0,
                              description="Analyzer confidence; scales the weight in fusion.")
    analyzer: str = Field(default="", description="Producing analyzer (set by the engine).")
    evidence: dict[str, Any] = Field(default_factory=dict,
                                     description="Machine-readable supporting data.")
    mitre: list[str] = Field(default_factory=list,
                             description="MITRE ATT&CK / ATLAS technique ids.")
    tags: list[str] = Field(default_factory=list)
    span: tuple[int, int] | None = Field(default=None,
                                         description="Optional [start, end) char span in target.")
    contribution: float | None = Field(default=None,
                                       description="Effective log-odds after fusion damping "
                                                   "(set by the scorer).")

    def model_post_init(self, __context: Any) -> None:  # noqa: D401 - pydantic hook
        if self.severity is None:
            self.severity = Severity.from_weight(self.weight)


class Indicator(_Model):
    """An extracted observable (IOC)."""

    type: IndicatorType
    value: str
    role: str | None = Field(default=None, description="e.g. 'landing', 'sender', "
                                                      "'exfil-endpoint', 'payload', 'redirect'.")
    malicious: bool | None = Field(default=None,
                                   description="True if this observable itself is judged bad.")
    context: str | None = None

    def key(self) -> tuple[str, str]:
        return (self.type.value, self.value.lower())


class BrandMatch(_Model):
    """A brand the artifact appears to impersonate (or legitimately belong to)."""

    brand: str = Field(description="Brand id from the knowledge base, e.g. 'paypal'.")
    name: str = Field(description="Display name, e.g. 'PayPal'.")
    technique: str = Field(description="homoglyph | idn | typosquat | combosquat | subdomain | "
                                       "path | bitsquat | content | sender | official")
    confidence: float = Field(ge=0.0, le=1.0)
    legit_domains: list[str] = Field(default_factory=list)
    evidence: str = ""
    official: bool = Field(default=False,
                           description="True when the artifact IS the brand's official asset.")


class MitreTechnique(_Model):
    id: str
    name: str
    tactic: str = ""
    framework: str = "attack"     # 'attack' (MITRE ATT&CK) or 'atlas' (MITRE ATLAS, AI systems)
    url: str = ""


class AnalyzerRun(_Model):
    name: str
    status: str = Field(description="ok | error | timeout | skipped")
    duration_ms: float = 0.0
    signals: int = 0
    error: str | None = None


class Verdict(_Model):
    """The engine's explainable decision about one artifact (and its children)."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    engine_version: str = ENGINE_VERSION

    kind: ArtifactKind
    target: str
    artifact_id: str
    origin: str | None = None

    risk: float = Field(ge=0.0, le=1.0, description="Fused probability-like risk.")
    score: int = Field(ge=0, le=100, description="risk * 100, rounded.")
    logit: float = Field(description="Fused log-odds (prior + contributions).")
    level: Level
    action: Action
    confidence: float = Field(ge=0.0, le=1.0, description="Margin-based decision confidence.")
    summary: str = ""

    signals: list[Signal] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    brand: BrandMatch | None = None
    techniques: list[str] = Field(default_factory=list,
                                  description="Attack-construction technique codes.")
    mitre: list[MitreTechnique] = Field(default_factory=list)
    children: list[Verdict] = Field(default_factory=list)
    analyzers: list[AnalyzerRun] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict,
                                 description="Artifact facts (subject, sender, title, hashes...).")
    duration_ms: float = 0.0

    # ---- convenience ------------------------------------------------------ #
    def top_signals(self, n: int = 5, *, malicious_only: bool = True) -> list[Signal]:
        sig = [s for s in self.signals if (s.contribution or s.weight) > 0] if malicious_only \
            else list(self.signals)
        return sorted(sig, key=lambda s: abs(s.contribution if s.contribution is not None
                                             else s.weight), reverse=True)[:n]

    def walk(self):
        """Yield this verdict and all descendants (depth-first)."""
        yield self
        for c in self.children:
            yield from c.walk()

    def all_indicators(self) -> list[Indicator]:
        seen: dict[tuple[str, str], Indicator] = {}
        for v in self.walk():
            for i in v.indicators:
                seen.setdefault(i.key(), i)
        return list(seen.values())


Verdict.model_rebuild()
