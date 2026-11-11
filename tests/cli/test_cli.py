"""CLI tests: offline, driven through Typer's CliRunner against the real engine.

All fixtures are synthetic and inert (reserved ``.test``/``example.*`` names). The
network is blocked by ``tests/conftest.py``; no test passes ``--online``.
"""

from __future__ import annotations

import csv
import io
import json
import sys
import types
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from uniphish.cli import main as cli
from uniphish.cli import render

runner = CliRunner()
ENV = {"COLUMNS": "200", "NO_COLOR": "1"}

HOMOGLYPH = "https://pаypal.com/signin"       # Cyrillic 'a'
COMBOSQUAT = "https://paypa1-secure-login.test/signin"
BENIGN = "https://www.python.org/"

EML = (
    "From: PayPal Support <support@paypa1-alerts.test>\n"
    "To: victim@example.com\n"
    "Subject: Urgent: verify your account\n"
    "Date: Mon, 03 Mar 2025 10:00:00 +0000\n"
    "Message-ID: <abc@paypa1-alerts.test>\n"
    "MIME-Version: 1.0\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "\n"
    "Your account is limited. Sign in now at https://paypa1-secure-login.test/signin "
    "to avoid suspension.\n"
)

HTML = (
    "<html><head><title>PayPal - Log in</title></head><body>"
    "<form action='https://collector.example.test/post' method='post'>"
    "<input name='email'><input type='password' name='pw'></form></body></html>"
)


def run(*args: str, input: str | bytes | None = None):
    return runner.invoke(cli.app, list(args), input=input, env=ENV)


@pytest.fixture(scope="module", autouse=True)
def _warm_engine():
    """Build the shared engine once (loads model/assets) so per-test time stays low."""
    from uniphish.core.engine import default_engine

    default_engine()
    # The URL analyzer lazily loads the brand KB / Unicode tables on first use (several
    # seconds on a cold, busy machine -- longer than the engine's 10 s analyzer budget).
    # Warm it directly so the first scan under test is not a spurious timeout.
    from uniphish.analyzers.url import UrlAnalyzer
    from uniphish.core.analyzer import AnalysisContext, AnalysisOptions
    from uniphish.core.types import Artifact

    UrlAnalyzer().analyze_sync(
        Artifact.from_url(HOMOGLYPH), AnalysisContext(options=AnalysisOptions())
    )


# --------------------------------------------------------------------------- #
# scan: URLs
# --------------------------------------------------------------------------- #
def test_scan_homoglyph_url_is_malicious_with_brand():
    r = run("scan", HOMOGLYPH)
    assert r.exit_code == 0, r.output
    assert "MALICIOUS" in r.stdout
    assert "PayPal" in r.stdout
    assert "Why this verdict" in r.stdout
    assert "MITRE" in r.stdout


def test_scan_defangs_by_default_and_no_defang_restores():
    r = run("scan", COMBOSQUAT)
    assert "hxxps://" in r.stdout
    assert "https://" not in r.stdout
    assert "[.]" in r.stdout
    r2 = run("scan", COMBOSQUAT, "--no-defang")
    assert "https://paypa1-secure-login.test/signin" in r2.stdout.replace("\n", "")


def test_scan_json_is_valid_raw_verdict():
    r = run("scan", HOMOGLYPH, "--json")
    assert r.exit_code == 0, r.output
    data = json.loads(r.stdout)
    assert data["level"] == "malicious"
    assert data["brand"]["brand"] == "paypal"
    assert data["target"] == HOMOGLYPH            # raw, not defanged
    assert {"signals", "indicators", "analyzers", "logit", "risk"} <= set(data)
    assert "ai" not in data


def test_scan_benign_url_prints_safe():
    r = run("scan", BENIGN)
    assert r.exit_code == 0, r.output
    assert "SAFE" in r.stdout
    assert "MALICIOUS" not in r.stdout


def test_scan_fail_on_sets_exit_code():
    assert run("scan", HOMOGLYPH, "--fail-on", "malicious").exit_code == 1
    assert run("scan", HOMOGLYPH, "--fail-on", "suspicious").exit_code == 1
    assert run("scan", BENIGN, "--fail-on", "suspicious").exit_code == 0
    assert run("scan", HOMOGLYPH, "--fail-on", "none").exit_code == 0


def test_scan_explain_lists_evidence():
    r = run("scan", HOMOGLYPH, "--explain")
    assert r.exit_code == 0, r.output
    assert "Why this verdict" in r.stdout


def test_scan_text_message_and_type_override():
    msg = "URGENT: your bank account is suspended, verify now at https://bank-verify.example.test/x"
    r = run("scan", msg, "--json")
    assert r.exit_code == 0, r.output
    assert json.loads(r.stdout)["kind"] == "text"
    r = run("scan", "example.com", "--type", "text", "--json")
    assert json.loads(r.stdout)["kind"] == "text"
    r = run("scan", "example.com", "--json")
    assert json.loads(r.stdout)["kind"] == "url"


def test_scan_ai_without_key_uses_template_fallback():
    r = run("scan", COMBOSQUAT, "--ai")
    assert r.exit_code == 0, r.output
    assert "Analyst narrative" in r.stdout
    assert "template" in r.stdout
    r = run("scan", COMBOSQUAT, "--ai", "--json")
    data = json.loads(r.stdout)
    assert data["ai"]["triage"]["source"] == "template"
    assert data["ai"]["narrative"]


# --------------------------------------------------------------------------- #
# scan: files and stdin
# --------------------------------------------------------------------------- #
def test_scan_eml_file_and_children(tmp_path: Path):
    p = tmp_path / "msg.eml"
    p.write_text(EML, encoding="utf-8")
    r = run("scan", str(p), "--json")
    assert r.exit_code == 0, r.output
    data = json.loads(r.stdout)
    assert data["kind"] == "email"
    assert any(c["kind"] == "url" for c in data["children"])
    assert data["level"] in {"suspicious", "malicious"}
    pretty = run("scan", str(p))
    assert pretty.exit_code == 0, pretty.output
    assert "email" in pretty.stdout


def test_scan_html_file_by_extension_and_by_sniff(tmp_path: Path):
    by_ext = tmp_path / "page.html"
    by_ext.write_text(HTML, encoding="utf-8")
    assert json.loads(run("scan", str(by_ext), "--json").stdout)["kind"] == "page"
    no_ext = tmp_path / "saved_page"
    no_ext.write_text(HTML, encoding="utf-8")
    assert json.loads(run("scan", str(no_ext), "--json").stdout)["kind"] == "page"


def test_scan_binary_and_svg_files_are_file_kind(tmp_path: Path):
    b = tmp_path / "blob.bin"
    b.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    assert json.loads(run("scan", str(b), "--json").stdout)["kind"] == "file"
    s = tmp_path / "doc.svg"
    s.write_text("<svg xmlns='http://www.w3.org/2000/svg'><text>hi</text></svg>")
    assert json.loads(run("scan", str(s), "--json").stdout)["kind"] == "file"


def test_scan_text_file_and_stdin_variants(tmp_path: Path):
    t = tmp_path / "note.txt"
    t.write_text("Your parcel is held, pay the fee today.\n")
    assert json.loads(run("scan", str(t), "--json").stdout)["kind"] == "text"
    r = run("scan", "-", "--json", input=COMBOSQUAT + "\n")
    assert json.loads(r.stdout)["kind"] == "url"
    r = run("scan", "-", "--json", input=EML)
    assert json.loads(r.stdout)["kind"] == "email"
    r = run("scan", "-", "--json", input=HTML)
    assert json.loads(r.stdout)["kind"] == "page"
    r = run("scan", "-", "--type", "text", "--json", input="hello there")
    assert json.loads(r.stdout)["kind"] == "text"


@pytest.mark.parametrize("args", [
    ("scan", "./definitely-missing-file.eml"),
    ("scan", "missing_report.pdf"),
    ("scan", ""),
    ("scan", "   "),
    ("scan", "-"),                              # empty stdin
    ("scan", "x", "--type", "file"),            # not a path
    ("scan", "x", "--type", "bogus"),
])
def test_scan_bad_input_exits_2(args):
    r = run(*args, input="")
    assert r.exit_code == 2, r.output


def test_scan_directory_is_rejected(tmp_path: Path):
    r = run("scan", str(tmp_path))
    assert r.exit_code == 2
    assert "directory" in r.output


def test_scan_oversized_stdin_rejected(monkeypatch):
    monkeypatch.setattr(cli, "MAX_EMAIL_BYTES", 10)
    monkeypatch.setattr(cli, "MAX_FILE_BYTES", 10)
    monkeypatch.setattr(cli, "MAX_PAGE_BYTES", 10)
    monkeypatch.setattr(cli, "MAX_TEXT_CHARS", 1)
    r = run("scan", "-", input="a" * 100)
    assert r.exit_code == 2
    assert "limit" in r.output


def test_terminal_output_cannot_be_hijacked_by_markup_or_escapes():
    nasty = "[bold red]PWNED[/bold red] \x1b[31mred\x1b[0m ‮txt.exe verify now"
    r = run("scan", nasty)
    assert r.exit_code == 0, r.output
    assert "\x1b" not in r.stdout
    assert "‮" not in r.stdout
    assert "[bold red]" in r.stdout.replace("\n", "") or "PWNED" in r.stdout


# --------------------------------------------------------------------------- #
# batch
# --------------------------------------------------------------------------- #
@pytest.fixture
def batch_file(tmp_path: Path) -> Path:
    p = tmp_path / "list.txt"
    p.write_text(f"# comment\n{HOMOGLYPH}\n\n{BENIGN}\n"
                 "=cmd|' /C calc'!A0 verify your account now\n", encoding="utf-8")
    return p


def test_batch_table_summary(batch_file: Path):
    r = run("batch", str(batch_file))
    assert r.exit_code == 0, r.output
    assert "Batch results (3)" in r.stdout
    assert "3 scanned" in r.stdout
    assert "MALICIOUS" in r.stdout and "SAFE" in r.stdout


def test_batch_json_stdout_and_order(batch_file: Path):
    r = run("batch", str(batch_file), "--json")
    assert r.exit_code == 0, r.output
    rows = json.loads(r.stdout)
    assert [x["line"] for x in rows] == [2, 4, 5]
    assert rows[0]["input"] == HOMOGLYPH
    assert rows[0]["verdict"]["level"] == "malicious"
    assert rows[1]["verdict"]["level"] == "benign"
    assert rows[2]["verdict"]["kind"] == "text"


def test_batch_csv_defanged_and_formula_safe(batch_file: Path):
    r = run("batch", str(batch_file), "--csv")
    assert r.exit_code == 0, r.output
    rows = list(csv.DictReader(io.StringIO(r.stdout)))
    assert len(rows) == 3
    assert rows[0]["level"] == "malicious" and rows[0]["brand"] == "PayPal"
    assert rows[0]["input"].startswith("hxxps://")
    assert rows[2]["input"].startswith("'=")           # formula neutralised
    raw = list(csv.DictReader(io.StringIO(run("batch", str(batch_file), "--csv",
                                              "--no-defang").stdout)))
    assert raw[0]["input"].startswith("https://")


def test_batch_output_file_infers_format(batch_file: Path, tmp_path: Path):
    out = tmp_path / "out.csv"
    r = run("batch", str(batch_file), "-o", str(out))
    assert r.exit_code == 0, r.output
    assert "wrote csv" in r.stdout
    assert out.read_text().splitlines()[0].startswith("line,input,kind")
    out2 = tmp_path / "out.json"
    run("batch", str(batch_file), "-o", str(out2))
    assert isinstance(json.loads(out2.read_text()), list)


def test_batch_errors(tmp_path: Path):
    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing\n\n")
    assert run("batch", str(empty)).exit_code == 2
    assert run("batch", str(tmp_path / "missing.txt")).exit_code == 2
    assert run("batch", str(empty), "--json", "--csv").exit_code == 2


def test_batch_never_reads_listed_paths(tmp_path: Path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOPSECRETCONTENT")
    lst = tmp_path / "l.txt"
    lst.write_text(f"{secret}\n")
    r = run("batch", str(lst), "--json")
    assert r.exit_code == 0, r.output
    assert "TOPSECRETCONTENT" not in r.stdout
    assert json.loads(r.stdout)[0]["verdict"]["kind"] == "text"


def test_batch_stdin_and_fail_on():
    r = run("batch", "-", "--fail-on", "malicious", input=HOMOGLYPH + "\n")
    assert r.exit_code == 1
    r = run("batch", "-", "--fail-on", "malicious", input=BENIGN + "\n")
    assert r.exit_code == 0


def test_batch_reports_per_line_failures(monkeypatch, tmp_path: Path):
    from uniphish.core import engine as eng

    real = eng.Engine.analyze

    async def flaky(self, artifact, options=None):
        if "boom" in (artifact.url or ""):
            raise RuntimeError("synthetic failure")
        return await real(self, artifact, options)

    monkeypatch.setattr(eng.Engine, "analyze", flaky)
    p = tmp_path / "l.txt"
    p.write_text("https://boom.example.test/\nhttps://www.python.org/\n")
    r = run("batch", str(p), "--json")
    assert r.exit_code == 0, r.output
    rows = json.loads(r.stdout)
    assert rows[0]["verdict"] is None and "synthetic failure" in rows[0]["error"]
    assert rows[1]["verdict"]["level"] == "benign"
    table = run("batch", str(p))
    assert "ERROR" in table.stdout and "1 error" in table.stdout


# --------------------------------------------------------------------------- #
# export
# --------------------------------------------------------------------------- #
def test_export_stix_is_json_bundle():
    r = run("export", HOMOGLYPH, "--format", "stix")
    assert r.exit_code == 0, r.output
    bundle = json.loads(r.stdout)
    assert bundle["type"] == "bundle"
    assert any(o["type"] == "indicator" for o in bundle["objects"])


def test_export_other_formats():
    misp = json.loads(run("export", HOMOGLYPH, "-f", "misp").stdout)
    assert "Event" in misp
    sigma = list(yaml.safe_load_all(run("export", HOMOGLYPH, "-f", "sigma").stdout))
    assert sigma and "detection" in sigma[0]
    suri = run("export", HOMOGLYPH, "-f", "suricata")
    assert suri.exit_code == 0 and suri.stdout.startswith("alert ")
    yar = run("export", HOMOGLYPH, "-f", "yara")
    assert yar.exit_code == 0 and "rule " in yar.stdout
    ecs = run("export", HOMOGLYPH, "-f", "ecs")
    assert json.loads(ecs.stdout.splitlines()[0])["ecs"]["version"]


def test_export_to_file(tmp_path: Path):
    out = tmp_path / "b.json"
    r = run("export", HOMOGLYPH, "-f", "stix", "-o", str(out))
    assert r.exit_code == 0, r.output
    assert json.loads(out.read_text())["type"] == "bundle"
    assert r.stdout.strip() == ""                       # data went to the file, not stdout


def test_export_benign_has_nothing_to_deploy():
    r = run("export", BENIGN, "--format", "sigma")
    assert r.exit_code == 1
    assert "nothing to export" in r.output
    assert run("export", BENIGN, "--format", "suricata").exit_code == 1
    assert run("export", BENIGN, "--format", "yara").exit_code == 1


def test_export_requires_valid_format_and_input():
    assert run("export", HOMOGLYPH, "--format", "nope").exit_code == 2
    assert run("export", HOMOGLYPH).exit_code == 2
    assert run("export", "./nope.eml", "--format", "stix").exit_code == 2


# --------------------------------------------------------------------------- #
# catalog / version / serve / hunt
# --------------------------------------------------------------------------- #
def test_catalog_table_and_filters():
    r = run("catalog")
    assert r.exit_code == 0, r.output
    assert "brand.homoglyph" in r.stdout
    assert "Signal catalog" in r.stdout
    j = json.loads(run("catalog", "--json", "--analyzer", "url").stdout)
    assert "brand.homoglyph" in j and all(v["analyzer"] == "url" for v in j.values())
    j = json.loads(run("catalog", "--json", "--search", "punycode").stdout)
    assert j and all("punycode" in k or "unycode" in v["title"] for k, v in j.items())
    assert run("catalog", "--search", "zzz-no-such-signal").exit_code == 1


def test_version_command_and_flag():
    import uniphish

    for args in (("version",), ("--version",)):
        r = run(*args)
        assert r.exit_code == 0
        assert uniphish.__version__ in r.stdout


def test_no_args_shows_help():
    r = runner.invoke(cli.app, [], env=ENV)
    assert "scan" in r.output and "batch" in r.output and "export" in r.output


def test_serve_without_server_extra(monkeypatch):
    monkeypatch.setitem(sys.modules, "uvicorn", None)       # forces ImportError
    r = run("serve")
    assert r.exit_code == 1
    assert "uniphish[server]" in r.output


def test_serve_launches_uvicorn(monkeypatch):
    calls: dict = {}
    fake = types.SimpleNamespace(run=lambda target, **kw: calls.update(target=target, **kw))
    monkeypatch.setitem(sys.modules, "uvicorn", fake)
    real_find = cli.importlib.util.find_spec
    monkeypatch.setattr(cli.importlib.util, "find_spec",
                        lambda name, *a: object() if name == "uniphish.server.app"
                        else real_find(name, *a))
    r = run("serve", "--port", "9999", "--reload")
    assert r.exit_code == 0, r.output
    assert calls == {"target": "uniphish.server.app:app", "host": "127.0.0.1", "port": 9999,
                     "reload": True}
    assert "unauthenticated" not in r.output
    r = run("serve", "--host", "0.0.0.0")
    assert "unauthenticated" in r.output
    assert calls["host"] == "0.0.0.0"


def test_serve_rejects_bad_port():
    assert run("serve", "--port", "70000").exit_code == 2


def test_hunt_unavailable(monkeypatch):
    monkeypatch.setitem(sys.modules, "uniphish.hunt.ct", None)
    r = run("hunt", "watch", "--brand", "paypal")
    assert r.exit_code == 1
    assert "not available" in r.output


def test_hunt_delegates_with_arguments(monkeypatch):
    seen: dict = {}
    mod = types.ModuleType("uniphish.hunt.ct")
    mod.main = lambda argv: seen.update(argv=argv) or 0
    monkeypatch.setitem(sys.modules, "uniphish.hunt.ct", mod)
    r = run("hunt", "watch", "--brand", "paypal", "--limit", "5")
    assert r.exit_code == 0, r.output
    assert seen["argv"] == ["watch", "--brand", "paypal", "--limit", "5"]
    mod.main = lambda argv: 3
    assert run("hunt", "x").exit_code == 3


def test_hunt_delegates_to_typer_app(monkeypatch):
    import typer

    sub = typer.Typer()

    @sub.command()
    def go(brand: str = "none") -> None:
        typer.echo(f"hunting {brand}")

    mod = types.ModuleType("uniphish.hunt.ct")
    mod.app = sub
    monkeypatch.setitem(sys.modules, "uniphish.hunt.ct", mod)
    r = run("hunt", "--brand", "paypal")
    assert r.exit_code == 0, r.output
    assert "hunting paypal" in r.stdout


# --------------------------------------------------------------------------- #
# input detection helpers
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("s,expected", [
    ("https://example.com/a?b=c", True),
    ("example.com", True),
    ("www.example.com/path", True),
    ("pаypal.com", True),
    ("javascript:alert(1)", True),
    ("hello world", False),
    ("user@example.com", False),
    ("Hello.", False),
    ("", False),
    ("a" * 9000, False),
])
def test_looks_like_url(s, expected):
    assert cli.looks_like_url(s) is expected


def test_looks_like_email_requires_header_block():
    assert cli.looks_like_email(EML.encode())
    assert not cli.looks_like_email(b"Subject: hi\nthis is a note")   # one header only
    assert not cli.looks_like_email(b"just some text\nwith lines")


def test_looks_like_url_is_fast_on_pathological_input():
    import time

    s = "a." * 3000 + "!"
    t = time.perf_counter()
    cli.looks_like_url(s)
    assert time.perf_counter() - t < 0.5


# --------------------------------------------------------------------------- #
# render helpers
# --------------------------------------------------------------------------- #
def test_defang_and_offsets():
    assert render.defang("http://a.b/c") == "hxxp://a[.]b/c"
    assert render.defang("https://x.y") == "hxxps://x[.]y"
    assert render.defang("ftp://x.y") == "fxp://x[.]y"
    assert render.defang("a@b.c") == "a[@]b[.]c"
    assert render.defang("99.5% sure") == "99.5% sure"
    assert render.defang("ip 10.0.0.1 ok") == "ip 10[.]0[.]0[.]1 ok"
    once = render.defang("https://evil.test/a")
    assert render.defang(once) == once                          # idempotent
    raw = "see http://a.b now"
    out, offs = render.defang_map(raw)
    assert len(offs) == len(raw) + 1 and offs[-1] == len(out)
    assert out[offs[raw.index("b")]] == "b"


def test_sanitize_makes_controls_visible():
    assert render.sanitize("a\x1b[31mb") == "a<U+001B>[31mb"
    assert render.sanitize("x‮y") == "x<U+202E>y"
    assert render.sanitize("ok\n\tfine") == "ok\n\tfine"


def test_safe_text_is_not_markup_and_highlights_spans():
    t = render.safe_text("[link=http://evil.test]click[/link] \x1b[0m", do_defang=False)
    assert "[link=http://evil.test]" in t.plain
    assert "\x1b" not in t.plain
    t = render.safe_text("abcdef", do_defang=False, spans=[(2, 4)])
    styled = [(t.plain[s.start:s.end], str(s.style)) for s in t.spans]
    assert any(txt == "cd" and "red" in st for txt, st in styled)
    t = render.safe_text("aаb", do_defang=False, flag_non_ascii=True)
    assert any("magenta" in str(s.style) for s in t.spans)


def test_gauge_reflects_level():
    from uniphish.core.types import Action, ArtifactKind, Level, Verdict

    v = Verdict(kind=ArtifactKind.URL, target="x", artifact_id="1", risk=0.9, score=90,
                logit=2.2, level=Level.MALICIOUS, action=Action.BLOCK, confidence=0.5)
    g = render.risk_gauge(v)
    assert "MALICIOUS" in g.plain and "90/100" in g.plain
    assert g.plain.count("█") == round(0.9 * 32)
