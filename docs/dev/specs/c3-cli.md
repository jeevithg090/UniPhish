# Spec: command-line interface
OWN: uniphish/cli/__init__.py, uniphish/cli/main.py, uniphish/cli/render.py,
tests/cli/test_cli.py. Typer + rich. Entry point `uniphish` (already in pyproject
[project.scripts] = uniphish.cli.main:app).

Commands:
- uniphish scan <input> [--type auto|url|text|email|page|file] [--online] [--fetch]
  [--detonate] [--explain] [--ai] [--json] [--defang/--no-defang] : detect the input type
  (a path -> read file/eml/html by extension/sniff; '-' -> stdin; otherwise a URL/text),
  run the engine, pretty-print a rich report (risk gauge/bar, level, brand, the signal
  contribution breakdown, highlighted salient spans, MITRE chips, IOCs defanged, child
  tree, analyzer timing) or --json for the raw Verdict.
- uniphish batch <file> [--online] [--json|--csv] : one input per line; concurrent; summary
  table + optional JSON/CSV out.
- uniphish export <input> --format stix|misp|sigma|suricata|yara|ecs [-o file] : scan then
  emit the detection-as-code artifact.
- uniphish catalog : print the signal catalog (core.analyzer.signal_catalog) as a table.
- uniphish serve [--host --port --reload] : launch the API (uvicorn) if server extra
  present; clear message if not.
- uniphish hunt ... : thin wrapper delegating to uniphish.hunt.ct if present (optional).
- uniphish version.
render.py: rich renderables reused by scan/batch (gauge, waterfall, highlighted text,
tree). Defang all URLs in terminal output by default.
TESTS (offline, Typer CliRunner): scan a homoglyph URL -> exit 0, output shows malicious +
brand; --json valid; batch; export stix produces JSON; a benign URL prints safe; file/stdin
inputs; unknown-input handling. No network (online off).
