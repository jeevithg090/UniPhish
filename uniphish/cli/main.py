"""``uniphish`` command line: scan, batch, export, catalog, serve, hunt, version.

Why this module exists: analysts and CI pipelines need the whole engine from a shell,
with output that is safe to paste into a ticket (URLs defanged, no terminal-escape
injection — see :mod:`uniphish.cli.render`) and machine formats (JSON, CSV, STIX, ...)
that are byte-for-byte what the engine produced.

Conventions
-----------
* Exit code ``0`` success, ``1`` operational failure (nothing to export, ``--fail-on``
  threshold reached), ``2`` bad input or usage.
* Offline by default. ``--online`` enables network enrichment; ``--fetch`` and
  ``--detonate`` need the network too and therefore imply ``--online``.
* Diagnostics go to stderr; only requested data goes to stdout, so
  ``uniphish scan x --json | jq`` always works.
* A path argument is only ever *read*, never executed. ``batch`` treats lines strictly
  as URLs or text (never as paths), so a hostile list cannot make it read local files.
"""

from __future__ import annotations

import asyncio
import csv
import importlib
import importlib.util
import io
import json
import re
import sys
from collections.abc import Callable
from enum import Enum
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from uniphish.cli import render
from uniphish.core.types import (
    MAX_EMAIL_BYTES,
    MAX_FILE_BYTES,
    MAX_PAGE_BYTES,
    MAX_TEXT_CHARS,
    MAX_URL_CHARS,
    Artifact,
    ArtifactKind,
    ArtifactTooLarge,
    Level,
    Verdict,
)

app = typer.Typer(
    name="uniphish",
    help="UniPhish 2 - explainable anti-phishing detection for URLs, pages, emails, "
    "files and text.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode=None,
    pretty_exceptions_enable=False,
)

EXIT_FAIL = 1
EXIT_USAGE = 2
MAX_BATCH_LINES = 10_000


class InputType(str, Enum):
    auto = "auto"
    url = "url"
    text = "text"
    email = "email"
    page = "page"
    file = "file"


class FailOn(str, Enum):
    none = "none"
    suspicious = "suspicious"
    malicious = "malicious"


class ExportFormat(str, Enum):
    stix = "stix"
    misp = "misp"
    sigma = "sigma"
    suricata = "suricata"
    yara = "yara"
    ecs = "ecs"


class InputError(Exception):
    """The user's input could not be turned into an artifact (exit code 2)."""


# Consoles are created per call (not at import) so they bind to the *current*
# sys.stdout/sys.stderr - required for CliRunner and for piping.
def _out() -> Console:
    return Console(highlight=False)


def _err() -> Console:
    return Console(stderr=True, highlight=False)


def _die(message: str, code: int = EXIT_USAGE) -> typer.Exit:
    _err().print(render.safe_text(f"error: {message}", do_defang=False, style="bold red"))
    return typer.Exit(code)


# --------------------------------------------------------------------------- #
# Input detection
# --------------------------------------------------------------------------- #
_SCHEME_URL_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://\S+$", re.IGNORECASE)
_BARE_HOST_RE = re.compile(
    r"^(?:www\.)?[^\s/@:?#.]+(?:\.[^\s/@:?#.]+)+(?:[:/?#]\S*)?$", re.IGNORECASE
)
_PSEUDO_URL_RE = re.compile(r"^(?:data|javascript|vbscript):\S", re.IGNORECASE)
_HTML_RE = re.compile(r"<(?:!doctype\s+html|html|head|body|form|script|iframe)\b", re.IGNORECASE)
_SVG_RE = re.compile(rb"<svg\b", re.IGNORECASE)
_EMAIL_HEADERS = frozenset(
    {
        "from",
        "to",
        "subject",
        "date",
        "received",
        "message-id",
        "mime-version",
        "content-type",
        "return-path",
        "reply-to",
        "authentication-results",
        "x-mailer",
    }
)
_TEXT_EXT = {".txt", ".text", ".md", ".log", ".csv"}
_EMAIL_EXT = {".eml"}
_HTML_EXT = {".html", ".htm", ".xhtml", ".shtml"}
# Extensions that make a bare, non-existent word read as a mistyped file name rather
# than a hostname. Deliberately excludes real TLDs such as .zip and .mov.
_FILE_EXT_HINT = {
    "eml",
    "html",
    "htm",
    "txt",
    "msg",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "exe",
    "lnk",
    "iso",
    "img",
    "csv",
    "ppt",
    "pptx",
    "js",
    "vbs",
    "ps1",
    "bat",
    "dll",
    "rtf",
    "xhtml",
}


def looks_like_url(s: str) -> bool:
    """True if ``s`` is a single token that reads as a URL (scheme or bare host form)."""
    s = s.strip()
    if not s or len(s) > MAX_URL_CHARS or any(c.isspace() for c in s):
        return False
    return bool(_SCHEME_URL_RE.match(s) or _PSEUDO_URL_RE.match(s) or _BARE_HOST_RE.match(s))


def looks_like_email(data: bytes) -> bool:
    """True if ``data`` starts with an RFC 5322 header block (needs >= 2 known headers)."""
    head = data[:8192].decode("utf-8", "replace").lstrip("﻿\r\n ")
    names: set[str] = set()
    for line in head.splitlines()[:80]:
        if not line.strip():
            break
        if line[0] in " \t":
            continue
        name, sep, _ = line.partition(":")
        if not sep and not line.startswith("From "):
            return False
        if sep:
            names.add(name.strip().lower())
    known = names & _EMAIL_HEADERS
    return len(known) >= 2 and bool(known & {"from", "received", "mime-version", "subject"})


def looks_like_html(text: str) -> bool:
    return bool(_HTML_RE.search(text[:4096]))


def _looks_binary(data: bytes) -> bool:
    chunk = data[:8192]
    if b"\x00" in chunk:
        return True
    try:
        chunk.decode("utf-8")
    except UnicodeDecodeError as e:
        # A multi-byte char cut by the 8 KiB window is fine; anything earlier is binary.
        return e.start < len(chunk) - 4
    return False


def _decode(data: bytes) -> str:
    return data.decode("utf-8-sig", "replace")


def _from_bytes(data: bytes, kind: InputType, name: str | None) -> Artifact:
    """Build an artifact from raw bytes (file contents or stdin) honouring ``kind``."""
    if not data.strip(b" \t\r\n\x00") and kind is not InputType.file:
        raise InputError("input is empty")
    ext = Path(name).suffix.lower() if name else ""
    if kind is InputType.auto:
        if ext in _EMAIL_EXT:
            kind = InputType.email
        elif ext in _HTML_EXT:
            kind = InputType.page
        elif _SVG_RE.search(data[:4096]) or _looks_binary(data):
            kind = InputType.file
        elif looks_like_email(data):
            kind = InputType.email
        elif looks_like_html(_decode(data[:4096])):
            kind = InputType.page
        else:
            text = _decode(data)
            kind = (
                InputType.url if (ext not in _TEXT_EXT and looks_like_url(text)) else InputType.text
            )
    if kind is InputType.email:
        return Artifact.from_email(data, origin="cli")
    if kind is InputType.page:
        return Artifact.from_page(data, origin="cli")
    if kind is InputType.file:
        return Artifact.from_file(data, Path(name).name if name else None, origin="cli")
    text = _decode(data)
    if kind is InputType.url:
        return Artifact.from_url(text.strip().splitlines()[0] if text.strip() else "", origin="cli")
    return Artifact.from_text(text, origin="cli")


def _from_string(value: str, kind: InputType) -> Artifact:
    """Build an artifact from a literal command-line string."""
    if kind is InputType.file:
        raise InputError(
            "--type file needs a path (or '-' for stdin); not a file: "
            f"{render.sanitize(value[:80])!r}"
        )
    if kind is InputType.auto:
        raw = value.encode("utf-8", "replace")
        if looks_like_url(value):
            kind = InputType.url
        elif "\n" in value and looks_like_email(raw):
            kind = InputType.email
        elif looks_like_html(value):
            kind = InputType.page
        else:
            kind = InputType.text
    if kind is InputType.url:
        return Artifact.from_url(value.strip(), origin="cli")
    if kind is InputType.email:
        return Artifact.from_email(value, origin="cli")
    if kind is InputType.page:
        return Artifact.from_page(value, origin="cli")
    return Artifact.from_text(value, origin="cli")


def _pathlike(value: str) -> bool:
    """Heuristic: does a non-existent ``value`` look like a mistyped file path?"""
    if re.match(r"^[a-z][a-z0-9+.\-]*://", value, re.IGNORECASE):
        return False
    if value.startswith(("/", "./", "../", "~", ".\\")) or "\\" in value:
        return True
    if "/" in value or any(c.isspace() for c in value):
        return False
    return value.rsplit(".", 1)[-1].lower() in _FILE_EXT_HINT and "." in value


def _read_limited(fh: Any, limit: int, what: str) -> bytes:
    data = fh.read(limit + 1)
    if len(data) > limit:
        raise InputError(f"{what} is larger than the {limit:,}-byte limit")
    return data


def _size_limit(kind: InputType, ext: str) -> int:
    if kind is InputType.email or ext in _EMAIL_EXT:
        return MAX_EMAIL_BYTES
    if kind is InputType.page or ext in _HTML_EXT:
        return MAX_PAGE_BYTES
    if kind is InputType.text or kind is InputType.url or ext in _TEXT_EXT:
        return MAX_TEXT_CHARS * 4
    return max(MAX_FILE_BYTES, MAX_EMAIL_BYTES)


def load_input(
    value: str, kind: InputType = InputType.auto, stdin: Any = None
) -> tuple[Artifact, str | None]:
    """Turn the ``scan``/``export`` argument into an artifact.

    Returns ``(artifact, source)`` where ``source`` is the original URL/text, used for
    highlighting. ``'-'`` reads stdin; an existing path is read (never executed);
    anything else is a literal URL or text. Raises :class:`InputError` for unusable input.
    """
    try:
        if value == "-":
            fh = stdin if stdin is not None else sys.stdin.buffer
            data = _read_limited(fh, _size_limit(kind, ""), "stdin")
            art = _from_bytes(data, kind, None)
        elif not value.strip():
            raise InputError("input is empty")
        else:
            p: Path | None = None
            if (
                kind not in (InputType.url, InputType.text)
                and "\n" not in value
                and len(value) < 4096
            ):
                try:
                    cand = Path(value).expanduser()
                    if cand.exists():
                        p = cand
                except (OSError, ValueError):
                    p = None
            if p is not None:
                if p.is_dir():
                    raise InputError(f"{value!r} is a directory, not a file")
                if not p.is_file():
                    raise InputError(f"{value!r} is not a regular file")
                try:
                    with p.open("rb") as fh:
                        data = _read_limited(fh, _size_limit(kind, p.suffix.lower()), str(p))
                except OSError as e:
                    raise InputError(f"cannot read {value!r}: {e.strerror or e}") from e
                art = _from_bytes(data, kind, p.name)
            elif kind is InputType.auto and _pathlike(value):
                raise InputError(
                    f"no such file: {render.sanitize(value[:200])!r} "
                    "(use --type text to analyse it as a literal string)"
                )
            else:
                art = _from_string(value, kind)
    except ArtifactTooLarge as e:
        raise InputError(str(e)) from e
    except ValueError as e:
        raise InputError(str(e)) from e
    source = (
        art.url
        if art.kind is ArtifactKind.URL
        else (art.text if art.kind is ArtifactKind.TEXT else None)
    )
    return art, source


# --------------------------------------------------------------------------- #
# Engine helpers
# --------------------------------------------------------------------------- #
def _options(online: bool, fetch: bool, detonate: bool, explain: bool, ai: bool) -> Any:
    from uniphish.core.analyzer import AnalysisOptions

    return AnalysisOptions(
        online=True if (online or fetch or detonate) else None,
        fetch_pages=fetch,
        detonate=detonate,
        explain=explain,
        ai_report=ai,
    )


def _implied_online_note(online: bool, fetch: bool, detonate: bool) -> None:
    if (fetch or detonate) and not online:
        _err().print("note: --fetch/--detonate need the network; enabling --online.", style="dim")


def _scan(artifact: Artifact, options: Any) -> Verdict:
    from uniphish.core.engine import default_engine

    return default_engine().analyze_sync(artifact, options)


def _ai_report(verdict: Verdict) -> dict[str, Any]:
    from uniphish.ai import AIAnalyst

    async def _go() -> dict[str, Any]:
        analyst = AIAnalyst()
        narrative, triage = await asyncio.gather(
            analyst.narrative(verdict), analyst.triage(verdict)
        )
        return {"narrative": narrative, "triage": triage}

    return asyncio.run(_go())


_LEVEL_RANK = {Level.BENIGN: 0, Level.SUSPICIOUS: 1, Level.MALICIOUS: 2}


def _threshold_hit(levels: list[Level], fail_on: FailOn) -> bool:
    if fail_on is FailOn.none:
        return False
    need = 1 if fail_on is FailOn.suspicious else 2
    return any(_LEVEL_RANK[lv] >= need for lv in levels)


def _write(path: Path, text: str) -> None:
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as e:
        raise _die(f"cannot write {path}: {e.strerror or e}", EXIT_FAIL) from e


def _echo(text: str) -> None:
    """Write machine output verbatim to stdout (no rich wrapping or markup)."""
    sys.stdout.write(text if text.endswith("\n") else text + "\n")
    sys.stdout.flush()


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
@app.command()
def scan(
    input: str = typer.Argument(
        ..., metavar="INPUT", help="URL, text, or path to an .eml/.html/file; '-' reads stdin."
    ),
    type: InputType = typer.Option(
        InputType.auto,
        "--type",
        "-t",
        case_sensitive=False,
        help="Force the input type (default: auto-detect).",
    ),
    online: bool = typer.Option(False, "--online", help="Enable DNS/RDAP/TLS/feed enrichment."),
    fetch: bool = typer.Option(
        False, "--fetch", help="Fetch the URL's content safely (implies --online)."
    ),
    detonate: bool = typer.Option(
        False, "--detonate", help="Render in a sandboxed browser (implies --online)."
    ),
    explain: bool = typer.Option(
        False, "--explain", help="Show every signal with its evidence; enable saliency."
    ),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Add an analyst narrative (uses the Anthropic API only if "
        "ANTHROPIC_API_KEY is set; otherwise a local template).",
    ),
    json_out: bool = typer.Option(False, "--json", help="Print the raw verdict as JSON."),
    defang_out: bool = typer.Option(
        True, "--defang/--no-defang", help="Defang URLs/addresses in terminal output."
    ),
    fail_on: FailOn = typer.Option(
        FailOn.none,
        "--fail-on",
        case_sensitive=False,
        help="Exit 1 if the verdict reaches this level.",
    ),
) -> None:
    """Scan one input and print an explainable verdict."""
    try:
        artifact, source = load_input(input, type)
    except InputError as e:
        raise _die(str(e)) from e
    _implied_online_note(online, fetch, detonate)
    verdict = _scan(artifact, _options(online, fetch, detonate, explain, ai))
    ai_data = _ai_report(verdict) if ai else None
    if json_out:
        payload = verdict.model_dump(mode="json")
        if ai_data is not None:
            payload["ai"] = ai_data
        _echo(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        render.render_report(
            _out(), verdict, source=source, do_defang=defang_out, explain=explain, ai=ai_data
        )
    if _threshold_hit([verdict.level], fail_on):
        raise typer.Exit(EXIT_FAIL)


# --------------------------------------------------------------------------- #
# batch
# --------------------------------------------------------------------------- #
_CSV_FIELDS = [
    "line",
    "input",
    "kind",
    "level",
    "score",
    "risk",
    "action",
    "brand",
    "techniques",
    "top_signals",
    "summary",
    "error",
]


def _csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection (leading = + - @ tab CR)."""
    s = "" if value is None else str(value)
    s = s.replace("\r", " ").replace("\n", " ")
    return "'" + s if s[:1] in {"=", "+", "-", "@", "\t"} else s


def batch_csv(rows: list[dict[str, Any]], do_defang: bool) -> str:
    """Rows -> CSV text (formula-injection safe; optionally defanged)."""
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, lineterminator="\n")
    w.writeheader()
    fx: Callable[[str], str] = render.defang if do_defang else (lambda s: s)
    for r in rows:
        v: Verdict | None = r["verdict"]
        base = {
            "line": r["line"],
            "input": _csv_safe(fx(r["input"])),
            "error": _csv_safe(r.get("error")),
        }
        if v is not None:
            base.update(
                {
                    "kind": v.kind.value,
                    "level": v.level.value,
                    "score": v.score,
                    "risk": f"{v.risk:.4f}",
                    "action": v.action.value,
                    "brand": _csv_safe(v.brand.name if v.brand and not v.brand.official else ""),
                    "techniques": _csv_safe(";".join(v.techniques)),
                    "top_signals": _csv_safe(";".join(s.id for s in v.top_signals(3))),
                    "summary": _csv_safe(fx(v.summary)),
                }
            )
        w.writerow(base)
    return buf.getvalue()


def batch_json(rows: list[dict[str, Any]]) -> str:
    out = [
        {
            "line": r["line"],
            "input": r["input"],
            "error": r.get("error"),
            "verdict": r["verdict"].model_dump(mode="json") if r["verdict"] else None,
        }
        for r in rows
    ]
    return json.dumps(out, indent=2, ensure_ascii=False)


def _read_batch_lines(source: str) -> list[tuple[int, str]]:
    try:
        if source == "-":
            data = _read_limited(sys.stdin.buffer, MAX_URL_CHARS * MAX_BATCH_LINES, "stdin")
        else:
            with Path(source).expanduser().open("rb") as fh:
                data = _read_limited(fh, MAX_URL_CHARS * MAX_BATCH_LINES, source)
    except OSError as e:
        raise InputError(f"cannot read {source!r}: {e.strerror or e}") from e
    lines: list[tuple[int, str]] = []
    for n, line in enumerate(_decode(data).splitlines(), 1):
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append((n, line))
    if not lines:
        raise InputError("no inputs found (one URL or message per line; '#' starts a comment)")
    if len(lines) > MAX_BATCH_LINES:
        raise InputError(f"too many inputs ({len(lines):,}); the limit is {MAX_BATCH_LINES:,}")
    return lines


async def _run_batch(
    lines: list[tuple[int, str]], options: Any, concurrency: int
) -> list[dict[str, Any]]:
    from uniphish.core.engine import default_engine

    engine = default_engine()
    sem = asyncio.Semaphore(max(1, concurrency))

    async def one(n: int, text: str) -> dict[str, Any]:
        row: dict[str, Any] = {"line": n, "input": text, "error": None, "verdict": None}
        try:
            art = (
                Artifact.from_url(text, origin="batch")
                if looks_like_url(text)
                else Artifact.from_text(text, origin="batch")
            )
            async with sem:
                row["verdict"] = await engine.analyze(art, options)
        except Exception as e:  # one bad line must never abort the batch
            row["error"] = f"{type(e).__name__}: {e}"[:300]
        return row

    return list(await asyncio.gather(*(one(n, t) for n, t in lines)))


@app.command()
def batch(
    file: str = typer.Argument(
        ..., metavar="FILE", help="File with one URL or message per line ('-' = stdin)."
    ),
    online: bool = typer.Option(False, "--online", help="Enable network enrichment."),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON (stdout unless -o)."),
    csv_out: bool = typer.Option(False, "--csv", help="Emit CSV (stdout unless -o)."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write JSON/CSV here (format from flag or .csv)."
    ),
    concurrency: int = typer.Option(
        8, "--concurrency", "-c", min=1, max=64, help="Inputs analysed at once."
    ),
    defang_out: bool = typer.Option(
        True, "--defang/--no-defang", help="Defang the table and CSV (JSON is always raw)."
    ),
    fail_on: FailOn = typer.Option(
        FailOn.none,
        "--fail-on",
        case_sensitive=False,
        help="Exit 1 if any verdict reaches this level.",
    ),
) -> None:
    """Scan many inputs concurrently and print a summary table."""
    if json_out and csv_out:
        raise _die("choose either --json or --csv, not both")
    fmt = "json" if json_out else "csv" if csv_out else None
    if output is not None and fmt is None:
        fmt = "csv" if output.suffix.lower() == ".csv" else "json"
    try:
        lines = _read_batch_lines(file)
    except InputError as e:
        raise _die(str(e)) from e
    rows = asyncio.run(_run_batch(lines, _options(online, False, False, False, False), concurrency))
    payload = None
    if fmt == "json":
        payload = batch_json(rows)
    elif fmt == "csv":
        payload = batch_csv(rows, defang_out)
    if payload is not None and output is None:
        _echo(payload)
    else:
        if payload is not None and output is not None:
            _write(output, payload)
        con = _out()
        con.print(render.batch_table(rows, do_defang=defang_out))
        counts = {
            lv: sum(1 for r in rows if r["verdict"] and r["verdict"].level is lv) for lv in Level
        }
        errors = sum(1 for r in rows if r["verdict"] is None)
        con.print(
            f"{len(rows)} scanned: {counts[Level.MALICIOUS]} malicious, "
            f"{counts[Level.SUSPICIOUS]} suspicious, {counts[Level.BENIGN]} safe, "
            f"{errors} error(s)"
        )
        if payload is not None and output is not None:
            con.print(f"wrote {fmt} to {output}")
    if _threshold_hit([r["verdict"].level for r in rows if r["verdict"]], fail_on):
        raise typer.Exit(EXIT_FAIL)


# --------------------------------------------------------------------------- #
# export
# --------------------------------------------------------------------------- #
def _export(verdict: Verdict, fmt: ExportFormat, include_benign: bool) -> str:
    """Render ``verdict`` in ``fmt``. Raises ValueError when nothing is deployable."""
    if fmt is ExportFormat.stix:
        from uniphish.export.stix import to_stix_bundle

        return json.dumps(to_stix_bundle(verdict, include_benign=include_benign), indent=2)
    if fmt is ExportFormat.misp:
        from uniphish.export.misp import to_misp_event

        return json.dumps(to_misp_event(verdict, include_benign=include_benign), indent=2)
    if fmt is ExportFormat.sigma:
        from uniphish.export.sigma import to_sigma_yaml

        return to_sigma_yaml(verdict, allow_benign=include_benign)
    if fmt is ExportFormat.suricata:
        from uniphish.export.suricata import to_suricata_rules

        rules = to_suricata_rules(verdict, allow_benign=include_benign)
        if not rules:
            raise ValueError("verdict yields no deployable Suricata rules")
        return "\n".join(rules)
    if fmt is ExportFormat.yara:
        from uniphish.export.yara import to_yara

        return to_yara(verdict, allow_benign=include_benign)
    from uniphish.export.ecs import to_ndjson

    return to_ndjson(verdict, allow_benign=include_benign)


@app.command()
def export(
    input: str = typer.Argument(..., metavar="INPUT", help="Same inputs as 'scan'."),
    format: ExportFormat = typer.Option(
        ...,
        "--format",
        "-f",
        case_sensitive=False,
        help="stix | misp | sigma | suricata | yara | ecs",
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write here, not stdout."),
    type: InputType = typer.Option(InputType.auto, "--type", "-t", case_sensitive=False),
    online: bool = typer.Option(False, "--online", help="Enable network enrichment."),
    include_benign: bool = typer.Option(
        False, "--include-benign", help="Also export artifacts judged benign."
    ),
) -> None:
    """Scan an input, then emit a detection-as-code / CTI artifact."""
    try:
        artifact, _ = load_input(input, type)
    except InputError as e:
        raise _die(str(e)) from e
    verdict = _scan(artifact, _options(online, False, False, False, False))
    try:
        text = _export(verdict, format, include_benign)
    except ValueError as e:
        raise _die(
            f"nothing to export as {format.value}: {e} "
            f"(verdict is {verdict.level.value}, {verdict.score}/100; "
            "use --include-benign to force)",
            EXIT_FAIL,
        ) from e
    except ImportError as e:
        raise _die(
            f"the {format.value} exporter needs an optional dependency: {e}", EXIT_FAIL
        ) from e
    if output is not None:
        _write(output, text if text.endswith("\n") else text + "\n")
        _err().print(f"wrote {format.value} export to {output}", style="dim")
    else:
        _echo(text)


# --------------------------------------------------------------------------- #
# catalog / serve / hunt / version
# --------------------------------------------------------------------------- #
@app.command()
def catalog(
    json_out: bool = typer.Option(False, "--json", help="Print the catalog as JSON."),
    analyzer: str | None = typer.Option(
        None, "--analyzer", "-a", help="Only signals from this analyzer."
    ),
    search: str | None = typer.Option(
        None, "--search", "-s", help="Only ids/titles containing this text."
    ),
) -> None:
    """List every signal the engine can emit."""
    from uniphish.analyzers import load_builtin_analyzers
    from uniphish.core.analyzer import signal_catalog

    load_builtin_analyzers()
    cat = signal_catalog()
    if analyzer:
        cat = {k: v for k, v in cat.items() if v["analyzer"] == analyzer}
    if search:
        q = search.lower()
        cat = {k: v for k, v in cat.items() if q in k.lower() or q in v["title"].lower()}
    if json_out:
        _echo(json.dumps(dict(sorted(cat.items())), indent=2, ensure_ascii=False))
        return
    if not cat:
        raise _die("no signals match", EXIT_FAIL)
    _out().print(render.catalog_table(cat))


def _is_loopback(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
    port: int = typer.Option(8080, "--port", min=1, max=65535, help="Bind port."),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload (development only)."),
) -> None:
    """Launch the HTTP API (needs the 'server' extra)."""
    try:
        import uvicorn
    except ImportError as e:
        raise _die(
            "the API server needs the 'server' extra: pip install 'uniphish[server]'", EXIT_FAIL
        ) from e
    try:
        found = importlib.util.find_spec("uniphish.server.app") is not None
    except (ImportError, ValueError):
        found = False
    if not found:
        raise _die("uniphish.server.app is not available in this installation", EXIT_FAIL)
    if not _is_loopback(host):
        from uniphish.core.config import get_settings

        if not get_settings().api_keys:
            _err().print(
                "warning: binding to a non-loopback address with no "
                "UNIPHISH_API_KEYS set - the API will be unauthenticated.",
                style="bold yellow",
            )
    uvicorn.run("uniphish.server.app:app", host=host, port=port, reload=reload)


@app.command(
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
        "help_option_names": [],
    }
)
def hunt(ctx: typer.Context) -> None:
    """Brand-impersonation hunting (delegates to uniphish.hunt.ct when installed)."""
    try:
        mod = importlib.import_module("uniphish.hunt.ct")
    except ImportError as e:
        raise _die(
            f"hunting is not available: uniphish.hunt.ct is not installed ({e})", EXIT_FAIL
        ) from e
    args = list(ctx.args)
    target = getattr(mod, "app", None)
    if target is not None and callable(target):
        target(args=args, prog_name="uniphish hunt")
        return
    entry = getattr(mod, "main", None)
    if callable(entry):
        rc = entry(args)
        if isinstance(rc, int) and rc:
            raise typer.Exit(rc)
        return
    raise _die("uniphish.hunt.ct exposes neither 'app' nor 'main'", EXIT_FAIL)


def _version_string() -> str:
    from uniphish import __version__
    from uniphish.core.types import ENGINE_VERSION

    return f"uniphish {__version__} (engine {ENGINE_VERSION})"


@app.command()
def version() -> None:
    """Print the UniPhish and engine versions."""
    _echo(_version_string())


def _root_version(value: bool) -> None:
    if value:
        _echo(_version_string())
        raise typer.Exit()


@app.callback()
def _root(
    _version: bool = typer.Option(
        False, "--version", callback=_root_version, is_eager=True, help="Show the version and exit."
    ),
) -> None:
    """UniPhish 2 command line."""


def main() -> None:  # pragma: no cover - thin console-script shim
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
