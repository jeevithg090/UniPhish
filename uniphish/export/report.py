"""Analyst report generator: one self-contained, offline, XSS-safe report per verdict.

Why this exists: a verdict in JSON is for machines and a STIX bundle is for threat-intel
platforms, but the person who closes the ticket needs a document they can read, print,
attach and forward. This module renders a :class:`~uniphish.core.types.Verdict` as

* :func:`render_report` - a single HTML page (all CSS inline, inline SVG gauge and
  contribution waterfall, **no JavaScript and no external assets**, a restrictive
  ``Content-Security-Policy`` meta tag) that is safe to e-mail, archive or embed.
* :func:`report_markdown` - a ticketing-friendly plain-text version (Jira, GitHub, ...).
* :func:`to_pdf` - the HTML printed by headless Chromium when the optional ``sandbox``
  extra (Playwright) is installed; otherwise the HTML is written and the result says so.

Safety model. Everything inside a verdict that an attacker influenced (the analysed URL,
page title, e-mail subject, signal details, indicator values, brand evidence ...) is
treated as hostile:

* Jinja2 runs with autoescape on; the only raw markup that reaches the page is built in
  this module from escaped pieces (SVG, highlighted target).
* Every URL, host, e-mail address and file name is **defanged** (``hxxps://evil[.]test``)
  so nothing is clickable or auto-linked, and control, bidi and invisible characters are
  replaced with visible ``<U+XXXX>`` tokens so a Trojan-Source style name cannot disguise
  itself. The only ``href`` values in the report are MITRE technique links rebuilt from
  strictly validated technique ids - never taken from the verdict.
* Output is deterministic: timestamps come from the verdict, never from the clock.
"""

from __future__ import annotations

import json
import logging
import math
import re
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from markupsafe import Markup, escape

from uniphish.core import mitre as _mitre
from uniphish.core.scoring import PRIOR_LOGIT, logit
from uniphish.core.types import ArtifactKind, Indicator, Signal, Verdict

log = logging.getLogger("uniphish.export")

TEMPLATE_NAME = "report.html.j2"
TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "server" / "templates"

MAX_TARGET_CHARS = 4_000        # displayed characters of the analysed target
MAX_FIELD_CHARS = 600           # any other free-text field
MAX_SIGNAL_ROWS = 200
MAX_IOC_ROWS = 500
MAX_TREE_NODES = 200
MAX_TREE_DEPTH = 8
MAX_WATERFALL = 12              # individually drawn signals; the rest fold into "other"
MAX_JSON_CHARS = 150_000
MAX_SPANS = 64

_TECH_ID_RE = re.compile(r"^(?:T\d{4}(?:\.\d{3})?|AML\.T\d{4}(?:\.\d{3})?)$")
_SCHEME_RE = re.compile(r"\b(?:https?|ftps?)(?=://)", re.IGNORECASE)
_IPV4_RE = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d)")
_WS_RE = re.compile(r"\s+")
_HIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


# --------------------------------------------------------------------------- #
# Neutralising untrusted text
# --------------------------------------------------------------------------- #
def _is_invisible(ch: str) -> bool:
    """True for control/format/private/unassigned chars and non-ASCII whitespace."""
    cat = unicodedata.category(ch)
    return cat in _HIDDEN_CATEGORIES or (cat == "Zs" and ch != " ")


def _pieces(text: str) -> list[str]:
    """Per-character defanged rendering (one string per input character)."""
    swap: set[int] = set()
    for m in _SCHEME_RE.finditer(text):
        swap.update((m.start() + 1, m.start() + 2))          # "tt" -> "xx"
    ip_dots = {i for m in _IPV4_RE.finditer(text) for i in range(m.start(), m.end())
               if text[i] == "."}
    n = len(text)
    out: list[str] = []
    for i, c in enumerate(text):
        if i in swap:
            out.append("x")
        elif c == "." and 0 < i < n - 1 and text[i - 1].isalnum() and text[i + 1].isalnum() \
                and (i in ip_dots or not (text[i - 1].isdigit() and text[i + 1].isdigit())):
            out.append("[.]")
        elif c == "@" and not (0 < i < n - 1 and text[i - 1] == "[" and text[i + 1] == "]"):
            out.append("[@]")
        elif _is_invisible(c):
            out.append(f"<U+{ord(c):04X}>")
        else:
            out.append(c)
    return out


def defang_text(value: object, limit: int = MAX_FIELD_CHARS, *, oneline: bool = True) -> str:
    """Defang URLs/hosts/addresses and make invisible characters visible.

    Idempotent, never raises, bounded by ``limit`` input characters (an ellipsis marks a
    cut). With ``oneline`` whitespace runs collapse to one space first.
    """
    text = str(value if value is not None else "")
    if oneline:
        text = _WS_RE.sub(" ", text).strip()
    cut = len(text) > limit
    text = text[:limit]
    return "".join(_pieces(text)) + ("…" if cut else "")


def _plain(value: object, limit: int = 80) -> str:
    """Neutralise invisible characters only (no defanging) - for identifiers like ``url.x``."""
    text = _WS_RE.sub(" ", str(value if value is not None else "")).strip()[:limit]
    return "".join(f"<U+{ord(c):04X}>" if _is_invisible(c) else c for c in text)


def _defang_json(obj: Any) -> Any:
    """Recursively defang string values that contain a URL scheme (for the JSON appendix)."""
    if isinstance(obj, str):
        return defang_text(obj, 4_000, oneline=False) if "://" in obj else obj
    if isinstance(obj, list):
        return [_defang_json(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _defang_json(v) for k, v in obj.items()}
    return obj


def _defang_scheme(text: str) -> str:
    """Scheme-only defang (keeps the text copy-pasteable, e.g. a STIX pattern)."""
    return _SCHEME_RE.sub(lambda m: m.group(0).lower().replace("tt", "xx"), text)


# --------------------------------------------------------------------------- #
# Highlighted target
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    title: str
    salient: bool


def _int(v: object) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _collect_spans(verdict: Verdict, length: int) -> list[_Span]:
    """Character spans of incriminating signals (and ML-salient characters)."""
    spans: list[_Span] = []

    def add(s0: object, e0: object, title: str, salient: bool) -> None:
        a, b = _int(s0), _int(e0)
        if a is None or b is None:
            return
        a, b = max(0, a), min(length, b)
        if a < b and len(spans) < MAX_SPANS:
            spans.append(_Span(a, b, title, salient))

    for s in verdict.signals:
        if s.weight <= 0:
            continue
        title = defang_text(s.title, 90)
        if s.span:
            add(s.span[0], s.span[1], title, False)
        raw = s.evidence.get("spans") if isinstance(s.evidence, dict) else None
        if isinstance(raw, list):
            for item in raw[:16]:
                if isinstance(item, dict):
                    add(item.get("start"), item.get("end"), title, True)
    return spans


def _highlight(text: str, spans: list[_Span]) -> Markup:
    """Defanged text with ``<mark>`` on evidence spans and flags on non-ASCII/invisible."""
    pieces = _pieces(text)
    hl = [False] * len(text)
    for sp in spans:
        for i in range(sp.start, min(sp.end, len(text))):
            hl[i] = True
    out: list[str] = []
    run: list[str] = []
    cur: tuple[bool, bool, bool] | None = None

    def flush() -> None:
        if not run:
            return
        body = str(escape("".join(run)))
        h, na, inv = cur  # type: ignore[misc]
        if h or na or inv:
            cls = " ".join(c for c, f in (("hl", h), ("na", na), ("inv", inv)) if f)
            out.append(f'<mark class="{cls}">{body}</mark>')
        else:
            out.append(body)
        run.clear()

    for i, ch in enumerate(text):
        key = (hl[i], ord(ch) > 127 and not _is_invisible(ch), _is_invisible(ch))
        if key != cur:
            flush()
            cur = key
        run.append(pieces[i])
    flush()
    return Markup("".join(out))  # noqa: S704 - built from escaped pieces


# --------------------------------------------------------------------------- #
# Inline SVG (gauge + waterfall)
# --------------------------------------------------------------------------- #
def _thresholds() -> tuple[float, float]:
    try:
        from uniphish.core.config import get_settings
        st = get_settings()
        return float(st.suspicious_threshold), float(st.malicious_threshold)
    except Exception:  # pragma: no cover - settings are always loadable in practice
        return 0.5, 0.85


def _arc(cx: float, cy: float, r: float, s0: float, s1: float) -> str:
    def pt(s: float) -> tuple[float, float]:
        ang = math.pi * (1.0 - s / 100.0)
        return cx + r * math.cos(ang), cy - r * math.sin(ang)
    (x0, y0), (x1, y1) = pt(s0), pt(s1)
    return f"M {x0:.2f} {y0:.2f} A {r:g} {r:g} 0 0 1 {x1:.2f} {y1:.2f}"


def gauge_svg(score: int, level: str) -> Markup:
    """Semicircular 0-100 risk gauge with the benign/suspicious/malicious bands."""
    score = max(0, min(100, int(score)))
    sus, mal = (t * 100.0 for t in _thresholds())
    cx, cy, r = 110.0, 108.0, 88.0
    ang = math.pi * (1.0 - score / 100.0)
    nx, ny = cx + (r - 14) * math.cos(ang), cy - (r - 14) * math.sin(ang)
    label = f"Risk score {score} out of 100, {level}"
    return Markup(  # noqa: S704 - numeric values and escaped label only
        f'<svg class="gauge" viewBox="0 0 220 140" role="img" aria-label="{escape(label)}" '
        f'xmlns="http://www.w3.org/2000/svg"><title>{escape(label)}</title>'
        f'<path class="g-benign" d="{_arc(cx, cy, r, 0, sus)}" fill="none" stroke-width="16"/>'
        f'<path class="g-susp" d="{_arc(cx, cy, r, sus, mal)}" fill="none" stroke-width="16"/>'
        f'<path class="g-mal" d="{_arc(cx, cy, r, mal, 100)}" fill="none" stroke-width="16"/>'
        f'<line class="g-needle" x1="{cx:g}" y1="{cy:g}" x2="{nx:.2f}" y2="{ny:.2f}" '
        f'stroke-width="3" stroke-linecap="round"/><circle class="g-hub" cx="{cx:g}" '
        f'cy="{cy:g}" r="6"/><text class="g-score" x="{cx:g}" y="{cy + 26:g}" '
        f'text-anchor="middle">{score}</text></svg>')


def _contrib(s: Signal) -> float:
    return float(s.contribution if s.contribution is not None else s.weight * s.confidence)


def _waterfall_rows(verdict: Verdict) -> list[tuple[str, float, str, str]]:
    """(label, delta, kind, tooltip) rows: prior, top signals, other, total."""
    sigs = sorted(verdict.signals, key=lambda s: abs(_contrib(s)), reverse=True)
    shown, hidden = sigs[:MAX_WATERFALL], sigs[MAX_WATERFALL:]
    shown.sort(key=_contrib, reverse=True)
    rows: list[tuple[str, float, str, str]] = [
        ("Prior (base rate)", PRIOR_LOGIT, "prior", "Log-odds before any evidence")]
    for s in shown:
        c = _contrib(s)
        rows.append((defang_text(s.title, 60), c, "pos" if c >= 0 else "neg",
                     defang_text(f"{s.id}: {s.title}", 200)))
    other = sum(_contrib(s) for s in hidden) + (
        verdict.logit - PRIOR_LOGIT - sum(_contrib(s) for s in sigs))
    if abs(other) >= 0.005:
        parts = [f"{len(hidden)} more signal(s)"] if hidden else []
        parts.append("child evidence / clamping")
        rows.append(("Other evidence", other, "other", "; ".join(parts)))
    rows.append(("Final log-odds", verdict.logit, "total",
                 f"risk {verdict.risk:.4f} -> score {verdict.score}"))
    return rows


def waterfall_svg(verdict: Verdict) -> Markup:
    """Signal contribution waterfall: prior -> each signal -> final log-odds."""
    rows = _waterfall_rows(verdict)
    sus_t, mal_t = _thresholds()
    marks = [(logit(sus_t), "suspicious"), (logit(mal_t), "malicious")]
    spans: list[tuple[float, float]] = []
    cum = 0.0
    for _, delta, kind, _ in rows:
        if kind in ("prior", "total"):
            spans.append((0.0, delta))
            cum = delta if kind == "prior" else cum
        else:
            spans.append((cum, cum + delta))
            cum += delta
    xs = [v for pair in spans for v in pair] + [m[0] for m in marks]
    lo, hi = min(xs), max(xs)
    pad = max(0.4, (hi - lo) * 0.04)
    lo, hi = lo - pad, hi + pad
    left, width, row_h, top = 262.0, 440.0, 26.0, 22.0
    height = top + row_h * len(rows) + 8

    def x(v: float) -> float:
        return left + (v - lo) / (hi - lo) * width

    out = [f'<svg class="waterfall" viewBox="0 0 760 {height:g}" role="img" '
           f'aria-label="Signal contribution waterfall" xmlns="http://www.w3.org/2000/svg">'
           f'<title>Signal contribution waterfall (log-odds)</title>']
    for v, name in marks:
        out.append(f'<line class="thr" x1="{x(v):.1f}" y1="{top - 6:g}" x2="{x(v):.1f}" '
                   f'y2="{height - 6:g}"/><text class="thr-l" x="{x(v):.1f}" y="10" '
                   f'text-anchor="middle">{name}</text>')
    for i, ((label, delta, kind, tip), (a, b)) in enumerate(zip(rows, spans, strict=True)):
        y = top + i * row_h
        x0, x1 = sorted((x(a), x(b)))
        out.append(
            f'<g><title>{escape(tip)}</title>'
            f'<text class="w-label" x="0" y="{y + 16:g}">{escape(label)}</text>'
            f'<rect class="bar-{kind}" x="{x0:.1f}" y="{y + 3:g}" '
            f'width="{max(x1 - x0, 1.5):.1f}" height="{row_h - 8:g}" rx="2"/>'
            f'<text class="w-val" x="755" y="{y + 16:g}" text-anchor="end">'
            f'{delta:+.2f}</text></g>')
    out.append("</svg>")
    return Markup("".join(out))  # noqa: S704 - built from escaped pieces


# --------------------------------------------------------------------------- #
# Context assembly
# --------------------------------------------------------------------------- #
def _ind_row(ind: Indicator) -> dict[str, Any]:
    return {"type": ind.type.value, "value": defang_text(ind.value, 400),
            "role": _plain(ind.role, 60) if ind.role else "",
            "malicious": ind.malicious, "context": defang_text(ind.context, 160)
            if ind.context else ""}


def _mitre_rows(verdict: Verdict) -> list[dict[str, Any]]:
    """Unique techniques across the tree, rebuilt from the catalog (never from verdict urls)."""
    ids: dict[str, set[str]] = {}
    for v in verdict.walk():
        for t in v.mitre:
            ids.setdefault(t.id, set())
        for s in v.signals:
            for tid in s.mitre:
                ids.setdefault(tid, set()).add(s.id)
    rows: list[dict[str, Any]] = []
    for tid in sorted(ids):
        valid = bool(_TECH_ID_RE.match(tid)) and tid in _mitre.CATALOG
        t = _mitre.resolve(tid) if valid else None
        rows.append({
            "id": _plain(tid, 40), "name": defang_text(t.name if t else tid, 120),
            "tactic": t.tactic if t else "", "framework": t.framework if t else "unknown",
            "url": t.url if t and t.url.startswith(("https://attack.mitre.org/",
                                                    "https://atlas.mitre.org/")) else "",
            "signals": [_plain(s, 80) for s in sorted(ids[tid])][:8]})
    return rows


def _tree(verdict: Verdict) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    truncated = False

    def visit(v: Verdict, depth: int) -> None:
        nonlocal truncated
        if len(rows) >= MAX_TREE_NODES or depth > MAX_TREE_DEPTH:
            truncated = True
            return
        rows.append({
            "depth": depth, "kind": v.kind.value, "origin": _plain(v.origin or "", 40),
            "target": defang_text(v.target, 110), "level": v.level.value, "score": v.score,
            "brand": defang_text(v.brand.name, 60) if v.brand and not v.brand.official else "",
            "signals": len(v.signals)})
        for c in v.children:
            visit(c, depth + 1)

    visit(verdict, 0)
    return rows, truncated


def _facts(meta: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for k in sorted(meta, key=str)[:40]:
        v = meta[k]
        if isinstance(v, (dict, list, tuple)):
            try:
                v = json.dumps(v, ensure_ascii=True, default=str)
            except (TypeError, ValueError):
                v = repr(v)
        out.append((defang_text(k, 60), defang_text(v, 300)))
    return out


def _stix_pattern(verdict: Verdict) -> str | None:
    try:
        from uniphish.export.stix import build_pattern, select_indicators
        pat = build_pattern(select_indicators(verdict))
    except Exception:  # optional section: never break the report
        log.debug("STIX pattern unavailable", exc_info=True)
        return None
    return _defang_scheme(pat)[:MAX_JSON_CHARS] if pat else None


def _json_appendix(verdict: Verdict) -> tuple[str, bool]:
    text = json.dumps(_defang_json(verdict.model_dump(mode="json")), indent=2,
                      ensure_ascii=True, default=str)
    if len(text) > MAX_JSON_CHARS:
        return text[:MAX_JSON_CHARS] + "\n... [truncated]", True
    return text, False


def _paragraphs(text: str | None) -> list[str]:
    if not text or not text.strip():
        return []
    chunks = re.split(r"\n\s*\n", text.strip()[:4_000])
    return [defang_text(c, 4_000) for c in chunks if c.strip()][:12]


def _default_title(verdict: Verdict) -> str:
    return f"UniPhish analyst report - {verdict.kind.value} - {defang_text(verdict.target, 60)}"


def build_context(verdict: Verdict, *, ai_narrative: str | None = None,
                  title: str | None = None) -> dict[str, Any]:
    """Assemble the (already neutralised) template context. Public for testing/embedding."""
    target_raw = verdict.target[:MAX_TARGET_CHARS]
    use_spans = verdict.kind in (ArtifactKind.URL, ArtifactKind.TEXT, ArtifactKind.PAGE)
    spans = _collect_spans(verdict, len(target_raw)) if use_spans else []
    sigs = sorted(verdict.signals, key=lambda s: abs(_contrib(s)), reverse=True)
    inds = verdict.all_indicators()
    tree, tree_cut = _tree(verdict)
    raw_json, json_cut = _json_appendix(verdict)
    brand = verdict.brand
    return {
        "title": defang_text(title, 160) if title else _default_title(verdict),
        "id": _plain(verdict.id, 64),
        "created": verdict.created_at.isoformat(timespec="seconds"),
        "engine_version": _plain(verdict.engine_version, 30),
        "kind": verdict.kind.value, "origin": _plain(verdict.origin or "", 40),
        "level": verdict.level.value, "action": verdict.action.value,
        "score": verdict.score, "risk_pct": f"{verdict.risk * 100:.1f}",
        "logit": f"{verdict.logit:+.2f}", "confidence_pct": f"{verdict.confidence * 100:.0f}",
        "duration_ms": f"{verdict.duration_ms:.0f}",
        "summary": defang_text(verdict.summary, 800),
        "gauge": gauge_svg(verdict.score, verdict.level.value),
        "waterfall": waterfall_svg(verdict),
        "brand": None if brand is None else {
            "name": defang_text(brand.name, 80), "technique": _plain(brand.technique, 40),
            "confidence_pct": f"{brand.confidence * 100:.0f}", "official": brand.official,
            "legit_domains": [defang_text(d, 120) for d in brand.legit_domains[:8]],
            "evidence": defang_text(brand.evidence, 300)},
        "techniques": [_plain(t, 40) for t in verdict.techniques[:20]],
        "target": _highlight(target_raw, spans),
        "target_cut": len(verdict.target) > MAX_TARGET_CHARS,
        "span_rows": [{"text": defang_text(target_raw[s.start:s.end], 80), "title": s.title,
                       "salient": s.salient} for s in spans],
        "facts": _facts(verdict.meta),
        "signals": [{
            "id": _plain(s.id, 80), "title": defang_text(s.title, 160),
            "detail": defang_text(s.detail, 500), "category": _plain(s.category, 30),
            "severity": (s.severity.value if s.severity else "info"),
            "weight": f"{s.weight:+.2f}", "contribution": f"{_contrib(s):+.2f}",
            "positive": _contrib(s) >= 0, "confidence": f"{s.confidence:.2f}",
            "analyzer": _plain(s.analyzer, 30),
            "mitre": [_plain(m, 30) for m in s.mitre[:8]]}
            for s in sigs[:MAX_SIGNAL_ROWS]],
        "signals_total": len(sigs),
        "iocs": [_ind_row(i) for i in inds[:MAX_IOC_ROWS]],
        "iocs_total": len(inds),
        "ioc_list": "\n".join(defang_text(i.value, 400) for i in inds[:MAX_IOC_ROWS]),
        "mitre": _mitre_rows(verdict),
        "tree": tree, "tree_truncated": tree_cut,
        "runs": [{"name": _plain(a.name, 40), "status": _plain(a.status, 20),
                  "duration_ms": f"{a.duration_ms:.1f}", "signals": a.signals,
                  "error": defang_text(a.error, 200) if a.error else ""}
                 for a in verdict.analyzers],
        "narrative": _paragraphs(ai_narrative),
        "stix_pattern": _stix_pattern(verdict),
        "raw_json": raw_json, "json_truncated": json_cut,
    }


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
class ReportTemplateError(RuntimeError):
    """The packaged report template is missing (check package-data in pyproject)."""


@lru_cache(maxsize=1)
def _env() -> Environment:
    if not (TEMPLATE_DIR / TEMPLATE_NAME).is_file():
        raise ReportTemplateError(f"report template not found: {TEMPLATE_DIR / TEMPLATE_NAME}")
    return Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True,
                       undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)


def render_report(verdict: Verdict, *, ai_narrative: str | None = None,
                  title: str | None = None) -> str:
    """Render a self-contained, offline, XSS-safe HTML analyst report for ``verdict``.

    Args:
        verdict: the verdict (children included) to report on.
        ai_narrative: optional analyst narrative (e.g. ``AIAnalyst.narrative``); escaped
            and defanged like everything else.
        title: optional page title (escaped); defaults to kind + defanged target.
    """
    ctx = build_context(verdict, ai_narrative=ai_narrative, title=title)
    return _env().get_template(TEMPLATE_NAME).render(r=ctx)


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def _md(text: object, limit: int = MAX_FIELD_CHARS, *, fang: bool = True) -> str:
    """Escape a (defanged) string for use inside a Markdown table cell / sentence."""
    s = defang_text(text, limit) if fang else _plain(text, limit)
    s = re.sub(r"([\\`*_{}\[\]<>|#~])", r"\\\1", s)
    return s


def _code(text: object, limit: int = 300, *, fang: bool = True) -> str:
    """Inline code span. ``<``/``>`` become ``‹``/``›`` so raw tags never survive even in
    renderers (Jira, chat) that do not treat code spans as literal."""
    s = defang_text(text, limit) if fang else _plain(text, limit)
    s = s.replace("<", "‹").replace(">", "›")
    longest = max((len(m) for m in re.findall(r"`+", s)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def report_markdown(verdict: Verdict, *, ai_narrative: str | None = None) -> str:
    """Ticketing-friendly Markdown (defanged, escaped) version of the report."""
    c = build_context(verdict, ai_narrative=ai_narrative)
    L: list[str] = [
        "# UniPhish analyst report", "",
        f"**Verdict:** {c['level'].upper()} - score **{c['score']}/100** "
        f"(risk {c['risk_pct']}%, log-odds {c['logit']}, confidence {c['confidence_pct']}%) "
        f"- recommended action: **{c['action']}**", "",
        f"- Target ({c['kind']}): {_code(verdict.target, 300)}",
        f"- Verdict id: {_code(c['id'], fang=False)}  "
        f"Engine: {_md(c['engine_version'], fang=False)}  Created: {c['created']}"]
    if c["summary"]:
        L += ["", f"> {_md(c['summary'], 800)}"]
    b = c["brand"]
    if b:
        state = "official asset" if b["official"] else "impersonated brand"
        L += ["", f"**Brand ({state}):** {_md(b['name'])} - technique "
                  f"{_md(b['technique'], fang=False)}, confidence {b['confidence_pct']}%"]
        if b["legit_domains"]:
            L.append("Legitimate domains: " + ", ".join(_code(d) for d in b["legit_domains"]))
    if c["techniques"]:
        L += ["", "**Construction techniques:** "
              + ", ".join(_code(t, fang=False) for t in c["techniques"])]
    if c["narrative"]:
        L += ["", "## AI narrative (machine-generated, verify before acting)", ""]
        L += [f"{_md(p, 4000)}\n" for p in c["narrative"]]
    L += ["", f"## Signals ({c['signals_total']})", "",
          "| Contribution | Weight | Severity | Category | Signal | Detail |",
          "|---:|---:|---|---|---|---|"]
    for s in c["signals"]:
        L.append(f"| {s['contribution']} | {s['weight']} | {s['severity']} | "
                 f"{_md(s['category'], fang=False)} | {_code(s['id'], fang=False)} "
                 f"{_md(s['title'])} | {_md(s['detail'], 300)} |")
    L += ["", f"## Indicators of compromise ({c['iocs_total']}, defanged)", "",
          "| Type | Value | Role | Malicious |", "|---|---|---|---|"]
    for i in c["iocs"]:
        mal = {True: "yes", False: "no", None: "-"}[i["malicious"]]
        L.append(f"| {i['type']} | {_code(i['value'], 400)} | "
                 f"{_md(i['role'], fang=False)} | {mal} |")
    if c["mitre"]:
        L += ["", "## MITRE ATT&CK / ATLAS", ""]
        for m in c["mitre"]:
            link = f" ([reference]({m['url']}))" if m["url"] else ""
            tactic = f" - {_md(m['tactic'], fang=False)}" if m["tactic"] else ""
            L.append(f"- {_code(m['id'], fang=False)} {_md(m['name'])}{tactic}{link}")
    L += ["", "## Artifact tree", ""]
    for t in c["tree"]:
        brand = f" - {_md(t['brand'])}" if t["brand"] else ""
        L.append(f"{'  ' * t['depth']}- {t['kind']} {_code(t['target'], 120)} = "
                 f"{t['level']} {t['score']}/100{brand}")
    if c["runs"]:
        L += ["", "## Analyzer runs", "", "| Analyzer | Status | ms | Signals |",
              "|---|---|---:|---:|"]
        L += [f"| {_md(r['name'], fang=False)} | {_md(r['status'], fang=False)} | "
              f"{r['duration_ms']} | {r['signals']} |" for r in c["runs"]]
    if c["stix_pattern"]:
        pattern = c["stix_pattern"].replace("```", "'''").replace("<", "‹").replace(">", "›")
        L += ["", "## STIX pattern (scheme defanged)", "", "```", pattern, "```"]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class PdfResult:
    """Outcome of :func:`to_pdf`: where the file went and in which format."""

    path: Path
    format: str                # "pdf" or "html" (fallback)
    note: str | None = None

    @property
    def is_pdf(self) -> bool:
        return self.format == "pdf"


def _print_pdf(html: str, out: Path, timeout_s: float) -> None:
    """Print ``html`` to PDF with headless Chromium: JS disabled, every request aborted."""
    from playwright.sync_api import sync_playwright  # optional extra

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            context = browser.new_context(java_script_enabled=False)
            context.route("**/*", lambda route: route.abort())
            page = context.new_page()
            page.set_content(html, wait_until="load", timeout=int(timeout_s * 1000))
            page.pdf(path=str(out), format="A4", print_background=True,
                     margin={"top": "14mm", "bottom": "14mm", "left": "12mm", "right": "12mm"})
        finally:
            browser.close()


def to_pdf(verdict: Verdict, path: str | Path, *, ai_narrative: str | None = None,
           title: str | None = None, timeout_s: float = 30.0) -> PdfResult:
    """Write the report to ``path`` as PDF; fall back to HTML when PDF is unavailable.

    PDF needs the optional ``sandbox`` extra (``pip install 'uniphish[sandbox]'`` then
    ``playwright install chromium``). Without it (or on any rendering failure) the HTML
    is written instead - to ``path`` if it already ends in ``.html``/``.htm``, else to
    ``path`` with an ``.html`` suffix - and ``PdfResult.note`` says why. Never raises for
    a missing browser; filesystem errors propagate.
    """
    html = render_report(verdict, ai_narrative=ai_narrative, title=title)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    reason: str
    try:
        import playwright  # noqa: F401
    except ImportError:
        reason = "playwright is not installed"
    else:
        try:
            # A worker thread keeps Playwright's sync API usable inside a running event loop.
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(_print_pdf, html, out, timeout_s).result(timeout=timeout_s + 15)
            return PdfResult(out, "pdf")
        except Exception as exc:  # browser missing, timeout, crash ...
            log.warning("PDF rendering failed: %s", exc)
            reason = f"PDF rendering failed ({type(exc).__name__})"
    html_path = out if out.suffix.lower() in (".html", ".htm") else out.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")
    return PdfResult(html_path, "html",
                     f"{reason}; wrote HTML instead. PDF output needs the optional 'sandbox' "
                     "extra: pip install 'uniphish[sandbox]' && playwright install chromium")


__all__ = ["PdfResult", "ReportTemplateError", "build_context", "defang_text", "gauge_svg",
           "render_report", "report_markdown", "to_pdf", "waterfall_svg"]
