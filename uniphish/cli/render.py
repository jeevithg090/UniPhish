"""Rich renderables for the UniPhish command line.

Why this module exists: ``scan`` and ``batch`` (and anything else that prints a
:class:`~uniphish.core.types.Verdict`) need one consistent, *safe* way to show
attacker-controlled strings in a terminal.

Safety rules enforced here
--------------------------
* **Nothing is interpreted as rich markup.** Every untrusted string is turned into a
  :class:`rich.text.Text`, so ``[red]`` or ``[link=...]`` inside a phishing URL or email
  subject can never restyle output or create a clickable hyperlink.
* **Control characters never reach the terminal.** C0/C1 controls (including ESC, which
  starts ANSI sequences) and invisible/bidi *format* characters (e.g. U+202E) are shown
  as visible ``<U+XXXX>`` tokens, so an analyst sees the trick instead of being fooled.
* **URLs are defanged by default** (``http`` -> ``hxxp``, ``.`` -> ``[.]``, ``@`` ->
  ``[@]``) so nothing printed here is accidentally clickable. Decimal numbers such as
  ``99.5`` are left alone; dotted-quad IPv4 addresses are defanged.
* Non-ASCII characters inside URL-like text are flagged (bold magenta) because
  homoglyph look-alikes are visually identical to the Latin letters they imitate.

All functions are pure with respect to the verdict; they only build renderables.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Sequence
from typing import Any

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from uniphish.core.types import ArtifactKind, Indicator, IndicatorType, Level, Verdict

__all__ = [
    "LEVEL_STYLE", "analyzer_timing", "batch_table", "catalog_table", "child_tree",
    "defang", "defang_map", "highlighted_source", "indicators_table", "mitre_chips",
    "render_report", "risk_gauge", "safe_text", "sanitize", "verdict_header", "waterfall",
]

LEVEL_STYLE: dict[Level, str] = {
    Level.BENIGN: "bold green",
    Level.SUSPICIOUS: "bold yellow",
    Level.MALICIOUS: "bold red",
}
_LEVEL_LABEL: dict[Level, str] = {
    Level.BENIGN: "SAFE", Level.SUSPICIOUS: "SUSPICIOUS", Level.MALICIOUS: "MALICIOUS",
}

# Characters shown verbatim even though they are "control": layout whitespace only.
_KEEP_CONTROL = {"\n", "\t"}
# Scheme prefix that gets defanged. Linear-time: fixed alternation, no nested quantifiers.
_SCHEME_RE = re.compile(r"\b(?:https?|ftp)://", re.IGNORECASE)
_IPV4_RE = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d])")
_HASH_TYPES = {IndicatorType.SHA256, IndicatorType.SHA1, IndicatorType.MD5,
               IndicatorType.CERT_SHA256}
MAX_RENDER_CHARS = 4_000       # hard cap on any single untrusted string we render
_GAUGE_WIDTH = 32


# --------------------------------------------------------------------------- #
# Untrusted text -> safe text
# --------------------------------------------------------------------------- #
def _is_invisible(ch: str) -> bool:
    """True for characters that must be made visible (controls and format chars)."""
    if ch in _KEEP_CONTROL:
        return False
    cat = unicodedata.category(ch)
    return cat in {"Cc", "Cf", "Zl", "Zp"} or ch == "\x7f"


def _defang_pieces(text: str) -> list[str]:
    """Per-character defanged replacement pieces (len == len(text))."""
    swap: set[int] = set()
    for m in _SCHEME_RE.finditer(text):
        # 'http' -> 'hxxp', 'https' -> 'hxxps', 'ftp' -> 'fxp': replace the 't's of the
        # scheme name (positions 1.. up to the last 't' before the optional 's'/'p').
        word = m.group(0)[:-3].lower()
        for off, c in enumerate(word):
            if c == "t" and off >= 1 and off <= (2 if word.startswith("http") else 1):
                swap.add(m.start() + off)
    ip_dots = {i for m in _IPV4_RE.finditer(text)
               for i in range(m.start(), m.end()) if text[i] == "."}
    out: list[str] = []
    n = len(text)
    for i, c in enumerate(text):
        if i in swap:
            out.append("x")
        elif c == "." and 0 < i < n - 1 and text[i - 1].isalnum() and text[i + 1].isalnum() \
                and (i in ip_dots or not (text[i - 1].isdigit() and text[i + 1].isdigit())):
            out.append("[.]")
        elif c == "@":
            out.append("[@]")
        else:
            out.append(c)
    return out


def defang_map(text: str) -> tuple[str, list[int]]:
    """Defang ``text`` and return ``(defanged, offsets)``.

    ``offsets[i]`` is where raw character ``i`` starts in the defanged string
    (``offsets[len(text)]`` is the total length), so spans can be translated.
    """
    text = text[:MAX_RENDER_CHARS]
    pieces = _defang_pieces(text)
    offsets: list[int] = []
    pos = 0
    for p in pieces:
        offsets.append(pos)
        pos += len(p)
    offsets.append(pos)
    return "".join(pieces), offsets


def defang(text: str) -> str:
    """Make a URL / address / hostname inert for display. Idempotent."""
    return defang_map(str(text))[0]


def sanitize(text: str, *, limit: int = MAX_RENDER_CHARS) -> str:
    """Replace control and invisible format characters with visible ``<U+XXXX>`` tokens."""
    return "".join(f"<U+{ord(c):04X}>" if _is_invisible(c) else c for c in str(text)[:limit])


def safe_text(text: str, *, do_defang: bool = True, spans: Iterable[tuple[int, int]] = (),
              flag_non_ascii: bool = False, style: str = "", limit: int = MAX_RENDER_CHARS,
              span_style: str = "bold white on red") -> Text:
    """Build a :class:`~rich.text.Text` from untrusted ``text``.

    Args:
        do_defang: defang URL-ish punctuation (see module docstring).
        spans: ``[start, end)`` ranges in the *original* text to highlight.
        flag_non_ascii: style non-ASCII characters (homoglyph review).
        limit: truncate the input first (an ellipsis is appended when cut).
    """
    raw = str(text)
    truncated = len(raw) > limit
    raw = raw[:limit]
    pieces = _defang_pieces(raw) if do_defang else list(raw)
    marked = bytearray(len(raw))
    for s, e in spans:
        s, e = max(0, int(s)), min(len(raw), int(e))
        for i in range(s, e):
            marked[i] = 1
    out = Text(style=style, overflow="fold")
    buf: list[str] = []
    cur = ""

    def flush() -> None:
        if buf:
            out.append("".join(buf), style=cur or None)
            buf.clear()

    for i, ch in enumerate(raw):
        piece = pieces[i]
        piece_style = ""
        if len(ch) == 1 and _is_invisible(ch):
            piece, piece_style = f"<U+{ord(ch):04X}>", "reverse"
        elif flag_non_ascii and ord(ch) > 127:
            piece_style = "bold magenta"
        if marked[i]:
            piece_style = f"{piece_style} {span_style}".strip()
        if piece_style != cur:
            flush()
            cur = piece_style
        buf.append(piece)
    flush()
    if truncated:
        out.append("…", style="dim")
    return out


def _brief(text: str, n: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


# --------------------------------------------------------------------------- #
# Verdict pieces
# --------------------------------------------------------------------------- #
def risk_gauge(verdict: Verdict, width: int = _GAUGE_WIDTH) -> Text:
    """A fixed-width risk bar with the suspicious/malicious thresholds marked."""
    filled = round(verdict.risk * width)
    style = LEVEL_STYLE[verdict.level]
    t = Text()
    t.append("█" * filled, style=style)
    t.append("░" * (width - filled), style="dim")
    t.append(f" {verdict.score:>3}/100 ", style="bold")
    t.append(_LEVEL_LABEL[verdict.level], style=style)
    return t


def verdict_header(verdict: Verdict, *, do_defang: bool = True,
                   source: str | None = None) -> Panel:
    """Top panel: gauge, level/action, brand, summary and the analysed target."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", justify="right", no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row("risk", risk_gauge(verdict))
    action = Text(verdict.action.value.upper(), style=LEVEL_STYLE[verdict.level])
    action.append(f"   confidence {verdict.confidence:.0%}   logit {verdict.logit:+.2f}",
                  style="dim")
    grid.add_row("action", action)
    if verdict.brand is not None:
        b = verdict.brand
        txt = Text()
        txt.append(b.name, style="bold")
        txt.append(f"  ({'official asset' if b.official else b.technique}, "
                   f"{b.confidence:.0%})", style="dim")
        grid.add_row("brand", txt)
        if b.evidence and not b.official:
            grid.add_row("", safe_text(_brief(b.evidence, 200), do_defang=do_defang, style="dim"))
    if verdict.techniques:
        grid.add_row("technique", Text(", ".join(verdict.techniques[:8]), style="cyan"))
    target = source if (source and verdict.kind in {ArtifactKind.URL}) else verdict.target
    grid.add_row("target", safe_text(_brief(target, 300), do_defang=do_defang,
                                     flag_non_ascii=verdict.kind is ArtifactKind.URL))
    grid.add_row("summary", safe_text(verdict.summary, do_defang=do_defang))
    title = Text(f" {verdict.kind.value} ", style="bold")
    return Panel(grid, title=title, title_align="left",
                 border_style=LEVEL_STYLE[verdict.level].replace("bold ", ""))


def _bar(value: float, scale: float, width: int = 14) -> Text:
    n = 0 if scale <= 0 else max(1, round(abs(value) / scale * width)) if value else 0
    n = min(n, width)
    if value >= 0:
        return Text("█" * n, style="red")
    return Text("█" * n, style="green")


def waterfall(verdict: Verdict, *, do_defang: bool = True, max_rows: int | None = 15,
              show_evidence: bool = False) -> RenderableType:
    """Signal contribution breakdown: prior + every signal = fused log-odds.

    Rows are sorted by absolute effective contribution (the engine's order). Red bars
    push toward *malicious*, green bars toward *legitimate*.
    """
    signals = list(verdict.signals)
    if not signals:
        return Text("No signals fired — nothing in this artifact raised or lowered risk.",
                    style="dim")
    shown = signals if max_rows is None else signals[:max_rows]
    scale = max((abs(s.contribution if s.contribution is not None else s.weight)
                 for s in signals), default=1.0)
    table = Table(title="Why this verdict (log-odds contribution per signal)",
                  title_justify="left", expand=True, header_style="bold",
                  show_lines=False, pad_edge=False)
    table.add_column("Δ", justify="right", no_wrap=True, width=7)
    table.add_column("effect", no_wrap=True, width=14)
    table.add_column("Signal", ratio=1, overflow="fold")
    for s in shown:
        c = s.contribution if s.contribution is not None else s.weight
        cell = Text()
        cell.append_text(safe_text(s.title, do_defang=do_defang, style="bold"))
        cell.append(f"  [{s.id}]", style="dim")
        if s.detail:
            cell.append("\n")
            cell.append_text(safe_text(_brief(s.detail, 220), do_defang=do_defang, style="dim"))
        if show_evidence and s.evidence:
            ev = ", ".join(f"{k}={_brief(str(v), 60)}" for k, v in list(s.evidence.items())[:6])
            cell.append("\n")
            cell.append_text(safe_text(ev, do_defang=do_defang, style="italic dim"))
        sign_style = "red" if c >= 0 else "green"
        table.add_row(Text(f"{c:+.2f}", style=sign_style), _bar(c, scale), cell)
    if len(signals) > len(shown):
        table.add_row("", "", Text(f"… {len(signals) - len(shown)} more signal(s); "
                                   "use --explain or --json to see all", style="dim"))
    total = sum((s.contribution or 0.0) for s in signals)
    foot = Text(f"prior {verdict.logit - total:+.2f}  +  signals {total:+.2f}  "
                f"=  logit {verdict.logit:+.2f}  ->  risk {verdict.risk:.1%}", style="dim")
    return Group(table, foot)


def mitre_chips(verdict: Verdict) -> Text | None:
    """ATT&CK / ATLAS technique ids as coloured chips (``None`` when there are none)."""
    if not verdict.mitre:
        return None
    t = Text()
    for m in verdict.mitre:
        style = "black on cyan" if m.framework == "attack" else "black on magenta"
        t.append(f" {m.id} ", style=style)
        t.append(f" {_brief(m.name, 48)}  ", style="dim")
    return t


def _ioc_value(ind: Indicator, do_defang: bool) -> Text:
    do = do_defang and ind.type not in _HASH_TYPES
    return safe_text(_brief(ind.value, 160), do_defang=do,
                     flag_non_ascii=ind.type in {IndicatorType.URL, IndicatorType.DOMAIN})


def indicators_table(verdict: Verdict, *, do_defang: bool = True,
                     max_rows: int | None = 25) -> Table | None:
    """De-duplicated IOCs across the verdict tree (``None`` when empty)."""
    inds = verdict.all_indicators()
    if not inds:
        return None
    inds.sort(key=lambda i: (not i.malicious, i.type.value))
    table = Table(title="Indicators of compromise" + (" (defanged)" if do_defang else ""),
                  title_justify="left", header_style="bold", expand=True)
    table.add_column("type", no_wrap=True)
    table.add_column("value", ratio=1, overflow="fold")
    table.add_column("role", no_wrap=True)
    table.add_column("bad", no_wrap=True, justify="center")
    shown = inds if max_rows is None else inds[:max_rows]
    for i in shown:
        bad = Text("yes", style="red") if i.malicious else Text("", style="dim")
        table.add_row(i.type.value, _ioc_value(i, do_defang), i.role or "", bad)
    if len(inds) > len(shown):
        table.add_row("", Text(f"… {len(inds) - len(shown)} more (use --json)", style="dim"),
                      "", "")
    return table


def child_tree(verdict: Verdict, *, do_defang: bool = True,
               max_nodes: int = 100) -> Tree | None:
    """The artifact tree (links, attachments, QR payloads, redirects) with per-node risk."""
    if not verdict.children:
        return None
    budget = [max_nodes]

    def label(v: Verdict) -> Text:
        t = Text()
        t.append(f"{v.score:>3} ", style=LEVEL_STYLE[v.level])
        t.append(f"{v.kind.value} ", style="bold")
        t.append_text(safe_text(_brief(v.target, 90), do_defang=do_defang,
                                flag_non_ascii=v.kind is ArtifactKind.URL))
        t.append(f"  {v.level.value}", style=LEVEL_STYLE[v.level])
        if v.origin:
            t.append(f"  ({v.origin})", style="dim")
        return t

    def add(node: Tree, v: Verdict) -> None:
        for c in v.children:
            if budget[0] <= 0:
                node.add(Text("… more nodes omitted", style="dim"))
                return
            budget[0] -= 1
            add(node.add(label(c)), c)

    root = Tree(label(verdict), guide_style="dim")
    add(root, verdict)
    return root


def analyzer_timing(verdict: Verdict) -> Table | None:
    """Per-analyzer status/timing for the top-level artifact (``None`` if none ran)."""
    if not verdict.analyzers:
        return None
    table = Table(title=f"Analyzers ({verdict.duration_ms:.0f} ms total)", title_justify="left",
                  header_style="bold")
    table.add_column("analyzer")
    table.add_column("status")
    table.add_column("ms", justify="right")
    table.add_column("signals", justify="right")
    table.add_column("note", overflow="fold")
    colours = {"ok": "green", "skipped": "dim", "error": "red", "timeout": "yellow"}
    for a in sorted(verdict.analyzers, key=lambda r: -r.duration_ms):
        table.add_row(a.name, Text(a.status, style=colours.get(a.status, "")),
                      f"{a.duration_ms:.1f}", str(a.signals),
                      sanitize(_brief(a.error or "", 120)))
    return table


def highlighted_source(source: str, verdict: Verdict, *, do_defang: bool = True,
                       limit: int = 800) -> Panel | None:
    """Show the analysed text/URL with the spans signals pointed at highlighted.

    ``None`` when no signal carries a span (nothing to highlight).
    """
    spans = [s.span for s in verdict.signals if s.span and (s.contribution or s.weight) > 0]
    if not spans:
        return None
    shown = safe_text(source, do_defang=do_defang, spans=spans, limit=limit,
                      flag_non_ascii=verdict.kind is ArtifactKind.URL)
    return Panel(shown, title="Highlighted evidence", title_align="left",
                 border_style="dim")


def render_report(console: Any, verdict: Verdict, *, source: str | None = None,
                  do_defang: bool = True, explain: bool = False,
                  ai: dict[str, Any] | None = None) -> None:
    """Print the full scan report for one verdict to ``console``.

    Args:
        source: original URL / text, used for span highlighting (never re-analysed).
        explain: show every signal plus machine evidence instead of the top rows.
        ai: optional ``{"narrative": str, "triage": dict}`` from the AI analyst.
    """
    console.print(verdict_header(verdict, do_defang=do_defang, source=source))
    if source is not None and verdict.kind in {ArtifactKind.URL, ArtifactKind.TEXT}:
        hl = highlighted_source(source, verdict, do_defang=do_defang)
        if hl is not None:
            console.print(hl)
    console.print(waterfall(verdict, do_defang=do_defang,
                            max_rows=None if explain else 15, show_evidence=explain))
    chips = mitre_chips(verdict)
    if chips is not None:
        console.print(Panel(chips, title="MITRE ATT&CK / ATLAS", title_align="left",
                            border_style="dim"))
    for renderable in (indicators_table(verdict, do_defang=do_defang,
                                        max_rows=None if explain else 25),
                       child_tree(verdict, do_defang=do_defang),
                       analyzer_timing(verdict)):
        if renderable is not None:
            console.print(renderable)
    if ai:
        console.print(_ai_panel(ai, do_defang=do_defang))


def _ai_panel(ai: dict[str, Any], *, do_defang: bool) -> Panel:
    triage = ai.get("triage") or {}
    parts: list[RenderableType] = [safe_text(str(ai.get("narrative", "")), do_defang=do_defang)]
    if triage:
        t = Text(style="dim")
        t.append("\nSecond opinion: ")
        t.append(sanitize(str(triage.get("assessment", "?"))), style="bold")
        t.append(f"  confidence {sanitize(str(triage.get('confidence', '?')))}  "
                 f"action {sanitize(str(triage.get('recommended_action', '?')))}")
        parts.append(t)
    src = triage.get("source", "template")
    sub = "AI analyst" if src == "ai" else "template (no AI key; deterministic fallback)"
    return Panel(Group(*parts), title=f"Analyst narrative — {sub}", title_align="left",
                 border_style="blue")


# --------------------------------------------------------------------------- #
# Batch + catalog
# --------------------------------------------------------------------------- #
def batch_table(rows: Sequence[dict[str, Any]], *, do_defang: bool = True) -> Table:
    """Summary table for ``batch``. Each row: ``line, input, error, verdict``."""
    table = Table(title=f"Batch results ({len(rows)})", title_justify="left",
                  header_style="bold", expand=True)
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("level", no_wrap=True)
    table.add_column("score", justify="right", no_wrap=True)
    table.add_column("brand", no_wrap=True)
    table.add_column("input", ratio=1, overflow="fold")
    table.add_column("top reason", ratio=1, overflow="fold")
    for r in rows:
        v: Verdict | None = r.get("verdict")
        raw = safe_text(_brief(r["input"], 70), do_defang=do_defang,
                        flag_non_ascii=v is not None and v.kind is ArtifactKind.URL)
        if v is None:
            table.add_row(str(r["line"]), Text("ERROR", style="bold red"), "", "", raw,
                          Text(sanitize(_brief(r.get("error") or "", 100)), style="red"))
            continue
        top = v.top_signals(1)
        brand = v.brand.name if v.brand and not v.brand.official else ""
        table.add_row(str(r["line"]), Text(_LEVEL_LABEL[v.level], style=LEVEL_STYLE[v.level]),
                      str(v.score), sanitize(brand), raw,
                      safe_text(top[0].title if top else "", do_defang=do_defang, style="dim"))
    return table


def catalog_table(catalog: dict[str, dict[str, str]]) -> Table:
    """The signal catalog (``core.analyzer.signal_catalog()``) as a table."""
    table = Table(title=f"Signal catalog ({len(catalog)} signals)", title_justify="left",
                  header_style="bold", expand=True)
    table.add_column("signal id", no_wrap=True, overflow="fold")
    table.add_column("analyzer", no_wrap=True)
    table.add_column("meaning", ratio=1, overflow="fold")
    for sid in sorted(catalog):
        entry = catalog[sid]
        table.add_row(sid, entry.get("analyzer", ""), entry.get("title", ""))
    return table
