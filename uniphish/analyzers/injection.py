"""Prompt-injection analyzer — the detection core of UniPhish AgentGuard.

Classic phishing targets a *human*; prompt injection targets the *AI agent* reading
content on the human's behalf. A web page, email, document or chat message can carry
instructions that try to hijack an agent: make it ignore its system prompt, reveal that
prompt, send the conversation or credentials to an attacker, run a shell command, or
approve a transaction. This module detects that content and explains it, mapping every
hit to MITRE ATLAS (attacks on AI systems).

Two things make the problem hard, and this module addresses both:

* **Indirect injection hides in low-visibility surfaces.** On a page, the payload is
  rarely in the body text a person reads — it is in an HTML comment, an ``alt`` /
  ``aria-label`` attribute, a ``<meta>`` tag, or an element made invisible with
  ``display:none`` / white-on-white colour / a 0px font. Agents flatten all of that into
  the text they consume, so :func:`scan_html` pulls those hidden surfaces out of the raw
  HTML and scans them too (and marks hits ``hidden`` → MITRE ATLAS *indirect* injection).
* **Payloads are obfuscated.** The same instruction can be smuggled in Unicode Tag
  characters (invisible ASCII), split with zero-width characters (``i<ZWSP>gnore``),
  spelled with homoglyphs (Cyrillic ``іgnоrе``) or base64/hex-encoded. Before matching,
  this module de-obfuscates with :mod:`uniphish.url.scripts` /
  :mod:`uniphish.url.confusables` and emits a dedicated *obfuscation* signal when a
  decode reveals an instruction that was not visible in the raw text.

Everything here is pure, deterministic and offline. Matched content is treated strictly
as **data**: it is quoted (defanged) as evidence and never followed or executed. All
regexes are linear and applied to length-bounded input (ReDoS-safe); the patterns live
in ``uniphish/assets/injection_patterns.yaml``, not in code.

:func:`scan_text` and :func:`scan_html` are the reusable primitives the AgentGuard MCP
server calls directly; :class:`InjectionAnalyzer` wraps them for the engine.
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
import warnings
from dataclasses import dataclass
from functools import lru_cache

from uniphish.assets import load_yaml
from uniphish.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult, register
from uniphish.core.types import (
    Artifact,
    ArtifactKind,
    Indicator,
    IndicatorType,
    Signal,
)
from uniphish.url.confusables import ascii_fold
from uniphish.url.scripts import decode_tag_chars, find_invisible

log = logging.getLogger("uniphish.analyzer.injection")

# --------------------------------------------------------------------------- #
# Bounds (every input is treated as hostile)
# --------------------------------------------------------------------------- #
MAX_SEGMENT_CHARS = 100_000  # per text segment actually regex-scanned
MAX_HTML_CHARS = 2_000_000  # raw HTML examined for hidden surfaces
MAX_BLOBS = 25  # encoded blobs decoded per segment
MAX_BLOB_CHARS = 20_000  # longest encoded blob considered
MAX_DEOBF_CHARS = 20_000  # prefix examined by the invisible/tag/homoglyph passes
MAX_DECODED_CHARS = 16_384  # decoded bytes scanned per blob
MAX_HIDDEN_SEGMENTS = 4_000  # low-visibility nodes / attributes collected
MAX_HITS = 400  # hits returned per scan (defensive cap)

#: ATLAS ids for the two LLM prompt-injection sub-techniques.
_ATLAS_DIRECT = "AML.T0051.000"
_ATLAS_INDIRECT = "AML.T0051.001"

#: Human-readable titles for each emitted signal (also the catalog in ``signals``).
_TITLES: dict[str, str] = {
    "instruction_override": "Content tells an AI agent to ignore its instructions",
    "role_hijack": "Content fakes system/assistant turns to hijack an AI agent",
    "exfiltration": "Content tells an AI agent to send data to an attacker",
    "tool_abuse": "Content tells an AI agent to run commands or approve actions",
    "data_leak": "Content asks an AI agent to reveal its hidden system prompt",
    "obfuscation": "Hidden or encoded instructions aimed at an AI agent",
}

_WS_RE = re.compile(r"\s+")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Encoded-blob detectors (single character classes → linear / ReDoS-safe).
_B64_RE = re.compile(r"[A-Za-z0-9+/_\-]{24,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9A-Fa-f]{2}){16,}")
_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]}]{1,300}")
_EMAIL_RE = re.compile(r"[\w.+\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63}){1,5}")


# --------------------------------------------------------------------------- #
# Compiled pattern tables (loaded once from YAML)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class _Pat:
    rx: re.Pattern[str]
    weight: float
    mitre: tuple[str, ...]
    lang: str
    gate: tuple[str, ...] = ()  # lowercase literal(s); >=1 must be present for rx to match


@dataclass(frozen=True)
class _Tactic:
    name: str
    weight: float
    mitre: tuple[str, ...]
    pats: tuple[_Pat, ...]


@dataclass(frozen=True)
class _Rules:
    tactics: tuple[_Tactic, ...]
    obf_weight: float
    obf_mitre: tuple[str, ...]
    turn_rx: re.Pattern[str] | None
    turn_weight: float
    turn_mitre: tuple[str, ...]
    turn_min_distinct: int


def _compile(pattern: str) -> re.Pattern[str] | None:
    try:
        return re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    except re.error as exc:  # pragma: no cover - guards a malformed asset
        log.warning("injection pattern failed to compile (%s): %.60s", exc, pattern)
        return None


@lru_cache(maxsize=1)
def _rules() -> _Rules:
    data = load_yaml("injection_patterns.yaml") or {}
    tactics: list[_Tactic] = []
    for name, spec in (data.get("tactics") or {}).items():
        base_w = float(spec.get("weight", 1.0))
        base_m = tuple(spec.get("mitre") or ())
        pats: list[_Pat] = []
        for entry in spec.get("patterns") or ():
            rx = _compile(str(entry.get("re", "")))
            if rx is None:
                continue
            pats.append(
                _Pat(
                    rx=rx,
                    weight=float(entry.get("weight", base_w)),
                    mitre=base_m + tuple(entry.get("mitre") or ()),
                    lang=str(entry.get("lang", "en")),
                    gate=tuple(str(g).lower() for g in (entry.get("gate") or ())),
                )
            )
        if pats:
            tactics.append(_Tactic(name=name, weight=base_w, mitre=base_m, pats=tuple(pats)))
    obf = data.get("obfuscation") or {}
    tm = data.get("turn_markers") or {}
    return _Rules(
        tactics=tuple(tactics),
        obf_weight=float(obf.get("weight", 4.0)),
        obf_mitre=tuple(obf.get("mitre") or ("AML.T0068", "AML.T0051")),
        turn_rx=_compile(str(tm["pattern"])) if tm.get("pattern") else None,
        turn_weight=float(tm.get("weight", 3.5)),
        turn_mitre=tuple(tm.get("mitre") or ("AML.T0051",)),
        turn_min_distinct=int(tm.get("min_distinct", 2)),
    )


# --------------------------------------------------------------------------- #
# Result type
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class InjectionHit:
    """One detected prompt-injection attempt.

    ``tactic`` is the emitted signal family (``instruction_override``, ``role_hijack``,
    ``exfiltration``, ``tool_abuse``, ``data_leak`` or ``obfuscation``). ``term`` is the
    defanged offending text. ``start``/``end`` are character offsets in the scanned
    segment when meaningful (``None`` for obfuscated matches whose span lives in decoded
    or transformed text). ``method`` records how it was found (``plain`` or the
    de-obfuscation route); ``hidden`` marks low-visibility (indirect) placement;
    ``source`` labels where it came from (``text``, ``comment``, ``attr``, ``meta``,
    ``hidden``, ``visible``, ``title``). ``underlying`` is the real tactic behind an
    obfuscation hit.
    """

    tactic: str
    weight: float
    term: str
    lang: str = "en"
    method: str = "plain"
    hidden: bool = False
    source: str = "text"
    start: int | None = None
    end: int | None = None
    mitre: tuple[str, ...] = ()
    underlying: str | None = None


# --------------------------------------------------------------------------- #
# Low-level matching helpers
# --------------------------------------------------------------------------- #
def _norm(s: str) -> str:
    return _WS_RE.sub(" ", s).strip().lower()


def _defang(s: str, limit: int = 200) -> str:
    """Render matched (attacker-controlled) text safe and compact for display."""
    s = _CTRL_RE.sub("", s)
    s = "".join(ch if (ch.isprintable() or ch in " \t") else "�" for ch in s)
    s = _WS_RE.sub(" ", s).strip()
    s = s.replace("http", "hxxp")
    return s[:limit] + "…" if len(s) > limit else s


@dataclass
class _RawHit:
    tactic: str
    weight: float
    term: str
    start: int
    end: int
    mitre: tuple[str, ...]
    lang: str


def _plain_matches(text: str) -> list[_RawHit]:
    """All tactic-pattern matches in ``text`` (spans are offsets within ``text``).

    A pattern's ``gate`` (a set of lowercase literal substrings, at least one of which
    must appear in any text it can match) is checked first: if none of a pattern's gate
    tokens occur in ``text``, the pattern cannot match and its (window-backtracking)
    regex is skipped. This keeps the scan linear and cheap on adversarial keyword spam
    without changing which inputs match — a gate is a necessary condition only.
    """
    out: list[_RawHit] = []
    if not text:
        return out
    low = text.lower()
    for tactic in _rules().tactics:
        for pat in tactic.pats:
            if pat.gate and not any(tok in low for tok in pat.gate):
                continue
            for n, m in enumerate(pat.rx.finditer(text)):
                if n >= 50:
                    break
                out.append(
                    _RawHit(
                        tactic.name, pat.weight, m.group(0), m.start(), m.end(), pat.mitre, pat.lang
                    )
                )
            if len(out) >= MAX_HITS * 2:
                return out
    return out


def _turn_marker_hit(text: str) -> _RawHit | None:
    """Fabricated multi-turn conversation (>= min_distinct distinct role markers)."""
    r = _rules()
    if r.turn_rx is None or ":" not in text:  # every turn marker ends with ':'
        return None
    roles: dict[str, int] = {}
    first: int | None = None
    for m in r.turn_rx.finditer(text):
        role = (m.group(1) or "").lower()
        roles[role] = roles.get(role, 0) + 1
        if first is None:
            first = m.start()
        if len(roles) > 12:
            break
    if len(roles) >= r.turn_min_distinct:
        end = (first or 0) + 80
        return _RawHit(
            "role_hijack",
            r.turn_weight,
            text[first or 0 : end],
            first or 0,
            min(end, len(text)),
            r.turn_mitre,
            "en",
        )
    return None


def _strip_indices(text: str, drop: set[int]) -> str:
    if not drop:
        return text
    return "".join(ch for i, ch in enumerate(text) if i not in drop)


def _find_blobs(text: str) -> list[tuple[str, str, int, int]]:
    """Encoded blobs ``(kind, blob, start, end)`` that might hide an instruction."""
    out: list[tuple[str, str, int, int]] = []
    for kind, rx in (("base64", _B64_RE), ("hex", _HEX_RE)):
        for m in rx.finditer(text):
            blob = m.group(0)
            if 24 <= len(blob) <= MAX_BLOB_CHARS:
                out.append((kind, blob, m.start(), m.end()))
            if len(out) >= MAX_BLOBS:
                return out[:MAX_BLOBS]
    return out


def _decode_blob(kind: str, blob: str) -> str | None:
    """Best-effort decode of an encoded blob to text; ``None`` if it is not text."""
    try:
        if kind == "hex":
            raw = bytes.fromhex(blob[:MAX_BLOB_CHARS])
        else:
            s = blob.replace("-", "+").replace("_", "/")
            s += "=" * (-len(s) % 4)
            raw = base64.b64decode(s, validate=False)
    except (ValueError, binascii.Error):
        return None
    if not raw:
        return None
    dec = raw[:MAX_DECODED_CHARS].decode("utf-8", "ignore")
    # Require it to look like instruction text, not binary noise.
    letters = sum(ch.isalpha() for ch in dec)
    if letters < 8 or letters < len(dec) * 0.4:
        return None
    return dec


# --------------------------------------------------------------------------- #
# Core scan (plain + de-obfuscation) for one text segment
# --------------------------------------------------------------------------- #
def _scan(text: str, *, source: str = "text", hidden: bool = False) -> list[InjectionHit]:
    """Scan one text segment for plain and obfuscated prompt-injection attempts."""
    if not text:
        return []
    text = text[:MAX_SEGMENT_CHARS]
    hits: list[InjectionHit] = []

    raw = _plain_matches(text)
    raw_keys = {(h.tactic, _norm(h.term)) for h in raw}
    for h in raw:
        hits.append(
            InjectionHit(
                tactic=h.tactic,
                weight=h.weight,
                term=_defang(h.term),
                lang=h.lang,
                method="plain",
                hidden=hidden,
                source=source,
                start=h.start,
                end=h.end,
                mitre=h.mitre,
            )
        )

    tm = _turn_marker_hit(text)
    if tm is not None:
        hits.append(
            InjectionHit(
                tactic=tm.tactic,
                weight=tm.weight,
                term=_defang(tm.term),
                lang="en",
                method="plain",
                hidden=hidden,
                source=source,
                start=tm.start,
                end=tm.end,
                mitre=tm.mitre,
            )
        )

    # ---- de-obfuscation passes → "obfuscation" signal ------------------------------ #
    obf = _rules()
    seen_obf: set[tuple[str, str]] = set()

    def _emit_obf(m: _RawHit, method: str, start: int | None, end: int | None) -> None:
        key = (method, _norm(m.term))
        if key in seen_obf or len(hits) >= MAX_HITS:
            return
        seen_obf.add(key)
        hits.append(
            InjectionHit(
                tactic="obfuscation",
                weight=obf.obf_weight,
                term=_defang(m.term),
                lang=m.lang,
                method=method,
                hidden=True,
                source=source,
                start=start,
                end=end,
                mitre=obf.obf_mitre + m.mitre,
                underlying=m.tactic,
            )
        )

    # The invisible / tag / homoglyph passes examine a bounded prefix: these tricks
    # smuggle a *short* instruction, and scan_html already isolates each hidden surface
    # (comment, attribute, invisible element) as its own segment, so the cap only limits
    # de-obfuscation depth inside one large block, never a hidden element's own content.
    # Pure-ASCII text has no invisible / tag / homoglyph obfuscation to undo, so the
    # fast ``isascii`` check skips these (slower, per-character) passes entirely.
    deobf = text[:MAX_DEOBF_CHARS]
    if not deobf.isascii():
        # 1. Unicode Tag smuggling (invisible ASCII carried in U+E00xx).
        decoded_tags = decode_tag_chars(deobf)
        if decoded_tags:
            for m in _plain_matches(decoded_tags):
                _emit_obf(m, "tag-smuggled", None, None)

        # 2. Zero-width / invisible split (e.g. "i<ZWSP>gnore previous instructions")
        #    -> a de-noised copy with the invisibles removed.
        invisible = find_invisible(deobf)
        cleaned = _strip_indices(deobf, {i for i, _, _ in invisible}) if invisible else deobf
        if invisible:
            for m in _plain_matches(cleaned):
                if (m.tactic, _norm(m.term)) not in raw_keys:
                    _emit_obf(m, "zero-width", None, None)

        # 3. Homoglyph obfuscation (Cyrillic/Greek look-alikes folded to ASCII). Folding
        #    the de-noised text also collapses combined invisible+homoglyph splits.
        folded = ascii_fold(cleaned)
        if folded != cleaned:
            for m in _plain_matches(folded):
                if (m.tactic, _norm(m.term)) not in raw_keys:
                    _emit_obf(m, "homoglyph", None, None)

    # 4. Base64 / hex encoded instruction blobs.
    for kind, blob, bstart, bend in _find_blobs(text):
        dec = _decode_blob(kind, blob)
        if not dec:
            continue
        for m in _plain_matches(dec):
            _emit_obf(m, kind, bstart, bend)

    return hits[:MAX_HITS]


# --------------------------------------------------------------------------- #
# Public primitives (reused by the AgentGuard MCP server)
# --------------------------------------------------------------------------- #
def scan_text(text: str) -> list[InjectionHit]:
    """Detect prompt-injection attempts in free text (SMS, chat, document, LLM context).

    Pure, deterministic and offline. Runs plain pattern matching plus de-obfuscation
    (Unicode-tag, zero-width, homoglyph, base64/hex). Matched content is treated as data
    and is never followed or executed.
    """
    return _scan(text or "", source="text", hidden=False)


def scan_html(html: str, base_url: str | None = None) -> list[InjectionHit]:
    """Detect prompt-injection attempts in an HTML page, including hidden surfaces.

    Beyond the visible text, this pulls the low-visibility content indirect injection
    hides in — HTML comments, ``alt`` / ``aria`` / ``title`` attributes, ``<meta>``
    values and elements made invisible with CSS — and scans each. Hidden hits are marked
    ``hidden=True`` (MITRE ATLAS indirect injection). Never executes or renders the page.
    """
    hits: list[InjectionHit] = []
    for source, is_hidden, text in _html_segments(html or "", base_url):
        hits.extend(_scan(text, source=source, hidden=is_hidden))
    return _dedupe(hits)


def _dedupe(hits: list[InjectionHit]) -> list[InjectionHit]:
    """Collapse duplicate findings, preferring the hidden / higher-weight instance."""
    best: dict[tuple[str, str, str], InjectionHit] = {}
    for h in hits:
        key = (h.tactic, _norm(h.term), h.method)
        cur = best.get(key)
        if cur is None or (h.hidden, h.weight) > (cur.hidden, cur.weight):
            best[key] = h
    return list(best.values())[:MAX_HITS]


# --------------------------------------------------------------------------- #
# HTML hidden-surface extraction
# --------------------------------------------------------------------------- #
_WHITES = frozenset(
    {
        "#fff",
        "#ffffff",
        "#fefefe",
        "white",
        "rgb(255,255,255)",
        "rgba(255,255,255,1)",
        "transparent",
    }
)
_HIDE_STYLE = (
    "display:none",
    "visibility:hidden",
    "opacity:0",
    "opacity:.0",
    "opacity:0.0",
    "font-size:0",
    "font-size:1px",
    "font-size:2px",
    "text-indent:-",
    "clip:rect(0",
    "width:0",
    "height:0",
    "left:-",
    "top:-",
    "position:absolute;left:-",
)
_HIDE_ATTRS = ("alt", "aria-label", "aria-description", "title", "data-tooltip")
_META_HIDDEN_NAMES = frozenset(
    {
        "description",
        "keywords",
        "author",
        "subject",
        "abstract",
        "summary",
        "dc.description",
        "generator",
    }
)


def _style_map(style: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for decl in style.split(";")[:40]:
        if ":" in decl:
            k, _, v = decl.partition(":")
            out[k.strip().lower()] = v.strip().lower()
    return out


def _is_low_visibility(tag) -> bool:
    try:
        if tag.has_attr("hidden"):
            return True
        if str(tag.get("aria-hidden", "")).lower() == "true":
            return True
        style = _WS_RE.sub("", str(tag.get("style") or "")).lower()
        if any(tok in style for tok in _HIDE_STYLE):
            return True
        sm = _style_map(str(tag.get("style") or ""))
        color = sm.get("color", "").replace(" ", "")
        bg = (sm.get("background-color") or sm.get("background") or "").replace(" ", "")
        if color and color in _WHITES and (not bg or bg in _WHITES):
            return True
        if color and bg and color == bg:
            return True
    except Exception:  # pragma: no cover - defensive against odd node types
        return False
    return False


def _html_segments(html: str, base_url: str | None) -> list[tuple[str, bool, str]]:
    """Yield ``(source, hidden, text)`` segments: visible text plus hidden surfaces."""
    html = html[:MAX_HTML_CHARS]
    segments: list[tuple[str, bool, str]] = []
    if not html.strip():
        return segments

    # Robust visible text / title / meta description via the shared page parser.
    try:
        from uniphish.page import parse_html

        model = parse_html(html, base_url)
        if model.visible_text:
            segments.append(("visible", False, model.visible_text))
        if model.title:
            segments.append(("title", False, model.title))
        if model.meta.description:
            segments.append(("meta", True, model.meta.description))
    except Exception:  # pragma: no cover - parse_html is documented not to raise
        log.debug("page parse failed during injection scan")

    # Hidden surfaces straight from the raw DOM.
    try:
        from bs4 import BeautifulSoup, Comment
        from bs4.element import Tag

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            soup = BeautifulSoup(html, "lxml")
    except Exception:  # pragma: no cover - lxml/bs4 import or parse failure
        return segments

    comments: list[str] = []
    attrs: list[str] = []
    metas: list[str] = []
    low_vis: list[str] = []
    budget = MAX_HIDDEN_SEGMENTS
    for node in soup.descendants:
        if budget <= 0:
            break
        if isinstance(node, Comment):
            comments.append(str(node))
            budget -= 1
            continue
        if not isinstance(node, Tag):
            continue
        budget -= 1
        if node.name == "meta":
            name = (node.get("name") or node.get("property") or "").lower().strip()
            if name in _META_HIDDEN_NAMES:
                content = node.get("content")
                if isinstance(content, str) and content.strip():
                    metas.append(content)
            continue
        for aname in _HIDE_ATTRS:
            val = node.get(aname)
            if isinstance(val, str) and val.strip():
                attrs.append(val)
        if _is_low_visibility(node):
            txt = node.get_text(" ", strip=True)
            if txt:
                low_vis.append(txt)

    if comments:
        segments.append(("comment", True, "\n".join(comments)[:MAX_SEGMENT_CHARS]))
    if attrs:
        segments.append(("attr", True, "\n".join(attrs)[:MAX_SEGMENT_CHARS]))
    if metas:
        segments.append(("meta", True, "\n".join(metas)[:MAX_SEGMENT_CHARS]))
    if low_vis:
        segments.append(("hidden", True, "\n".join(low_vis)[:MAX_SEGMENT_CHARS]))
    return segments


# --------------------------------------------------------------------------- #
# Exfiltration endpoint extraction (IOCs — observed, never contacted)
# --------------------------------------------------------------------------- #
def _exfil_indicators(text: str) -> list[Indicator]:
    """Extract URL/email endpoints that injection content asks the agent to send to."""
    out: list[Indicator] = []
    seen: set[tuple[str, str]] = set()
    exfil = next((t for t in _rules().tactics if t.name == "exfiltration"), None)
    if exfil is None or not text:
        return out
    text = text[:MAX_SEGMENT_CHARS]
    for pat in exfil.pats:
        for m in pat.rx.finditer(text):
            window = text[m.start() : m.end() + 160]
            for um in _URL_RE.finditer(window):
                _add_ind(out, seen, IndicatorType.URL, um.group(0))
            for em in _EMAIL_RE.finditer(window):
                _add_ind(out, seen, IndicatorType.EMAIL, em.group(0))
            if len(out) >= 20:
                return out
    return out


def _add_ind(
    out: list[Indicator], seen: set[tuple[str, str]], itype: IndicatorType, value: str
) -> None:
    value = value.rstrip(".,);]>\"'").strip()
    key = (itype.value, value.lower())
    if value and key not in seen and len(out) < 20:
        seen.add(key)
        out.append(
            Indicator(
                type=itype,
                value=value,
                role="exfil-endpoint",
                context="prompt-injection exfiltration target",
            )
        )


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #
@register
class InjectionAnalyzer(Analyzer):
    """Detect content that tries to hijack an AI agent reading it (prompt injection)."""

    name = "injection"
    kinds = frozenset({ArtifactKind.TEXT, ArtifactKind.PAGE})
    stage = 0
    requires_online = False
    blocking = True
    description = (
        "Prompt injection aimed at AI agents: instruction override, role "
        "hijack, data exfiltration/leakage, tool abuse, including hidden and "
        "obfuscated (Unicode-tag/zero-width/homoglyph/base64) payloads."
    )
    signals = {f"agent.injection.{tactic}": title for tactic, title in _TITLES.items()}

    def applies(self, artifact: Artifact, ctx: AnalysisContext) -> bool:
        if artifact.kind is ArtifactKind.TEXT:
            return bool(artifact.text)
        return bool(artifact.content)

    def analyze_sync(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        if artifact.kind is ArtifactKind.PAGE:
            html = artifact.html()
            hits = ctx.memo("injection.html", lambda: scan_html(html, artifact.url))
            scan_blob = html
        else:
            text = artifact.text or ""
            hits = ctx.memo("injection.text", lambda: scan_text(text))
            scan_blob = text
        if not hits:
            return AnalyzerResult()

        page_indirect = artifact.kind is ArtifactKind.PAGE

        # Strongest hit per emitted signal id (correlated 'agent' evidence is damped by
        # the scorer, so one signal per tactic keeps the verdict clean and explainable).
        best: dict[str, InjectionHit] = {}
        counts: dict[str, int] = {}
        for h in hits:
            sid = f"agent.injection.{h.tactic}"
            counts[sid] = counts.get(sid, 0) + 1
            cur = best.get(sid)
            if cur is None or (h.weight, h.hidden) > (cur.weight, cur.hidden):
                best[sid] = h

        signals: list[Signal] = []
        for sid, h in best.items():
            signals.append(
                Signal(
                    id=sid,
                    title=_TITLES.get(h.tactic, "Prompt-injection attempt"),
                    detail=_detail(h, counts[sid]),
                    weight=h.weight,
                    category="agent",
                    confidence=1.0,
                    mitre=_mitre_for(h, page_indirect),
                    span=(h.start, h.end) if h.start is not None and h.end is not None else None,
                    evidence=_evidence(h, counts[sid]),
                )
            )

        tactics = sorted({h.underlying or h.tactic for h in hits})
        techniques = ["prompt_injection", *(t for t in tactics if t != "obfuscation")]
        if any(h.tactic == "obfuscation" for h in hits):
            techniques.append("prompt_injection_obfuscation")

        indicators = _exfil_indicators(scan_blob)
        meta = {
            "injection": {
                "tactics": tactics,
                "hidden": any(h.hidden for h in hits),
                "obfuscated": any(h.tactic == "obfuscation" for h in hits),
                "hits": sum(counts.values()),
            }
        }
        return AnalyzerResult(
            signals=signals, indicators=indicators, techniques=techniques, meta=meta
        )


def _mitre_for(h: InjectionHit, page_indirect: bool) -> list[str]:
    ids = set(h.mitre)
    ids.add(_ATLAS_INDIRECT if (h.hidden or page_indirect) else _ATLAS_DIRECT)
    return sorted(ids)


def _detail(h: InjectionHit, count: int) -> str:
    where = {
        "comment": "an HTML comment",
        "attr": "an alt/aria/title attribute",
        "meta": "a <meta> tag",
        "hidden": "a visually hidden element",
        "visible": "the page text",
        "title": "the page title",
        "text": "the text",
    }.get(h.source, "the content")
    if h.tactic == "obfuscation":
        method = {
            "tag-smuggled": "invisible Unicode Tag characters",
            "zero-width": "zero-width / invisible characters",
            "homoglyph": "homoglyph look-alike characters",
            "base64": "a base64-encoded blob",
            "hex": "a hex-encoded blob",
        }.get(h.method, h.method)
        under = h.underlying or "instruction"
        lead = (
            f"An instruction aimed at an AI agent was hidden in {where} using {method}"
            f" (decoded tactic: {under})."
        )
    else:
        lead = f"Detected a prompt-injection attempt ({h.tactic}) in {where}" + (
            " — low-visibility / indirect placement." if h.hidden else "."
        )
    extra = f" {count} matches." if count > 1 else ""
    return f"{lead} Offending text: “{h.term}”.{extra}"


def _evidence(h: InjectionHit, count: int) -> dict:
    ev: dict[str, object] = {
        "tactic": h.tactic,
        "method": h.method,
        "source": h.source,
        "hidden": h.hidden,
        "match": h.term,
        "matches": count,
        "lang": h.lang,
    }
    if h.underlying:
        ev["decoded_tactic"] = h.underlying
    return ev
