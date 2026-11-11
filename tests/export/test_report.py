"""Tests for the analyst report generator (HTML / Markdown / PDF) from synthetic verdicts."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from html.parser import HTMLParser

import pytest

from uniphish.core.scoring import PRIOR_LOGIT, apply_contributions
from uniphish.core.types import (
    Action,
    AnalyzerRun,
    ArtifactKind,
    BrandMatch,
    Indicator,
    IndicatorType,
    Level,
    Signal,
    Verdict,
)
from uniphish.export import report as rpt
from uniphish.export.report import (
    build_context,
    defang_text,
    render_report,
    report_markdown,
    to_pdf,
)

URL = "https://login.paypa1-secure.test/signin/verify?id=7"
VOID = {"meta", "link", "br", "hr", "img", "input", "col", "area", "base", "wbr"}


class _Balance(HTMLParser):
    """Strict-ish tag balance checker (HTML5 void elements excepted)."""

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.errors: list[str] = []
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag not in VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}> with stack {self.stack[-3:]}")
            if tag in self.stack:
                while self.stack and self.stack.pop() != tag:
                    pass
        else:
            self.stack.pop()


def parse(html: str) -> _Balance:
    p = _Balance()
    p.feed(html)
    p.close()
    return p


def make(signals=None, *, target=URL, kind=ArtifactKind.URL, level=Level.MALICIOUS,
         children=None, brand=True, indicators=None, **kw) -> Verdict:
    sigs = signals if signals is not None else [
        Signal(id="url.brand.homoglyph", title="Domain imitates PayPal with look-alike digit",
               detail="The digit 1 stands in for the letter l in the host.", weight=4.5,
               category="brand", span=(8, 32), mitre=["T1566.002", "T1656"]),
        Signal(id="kit.aitm.fingerprint", title="AiTM reverse-proxy kit fingerprint",
               weight=7.0, category="kit", mitre=["T1557"]),
        Signal(id="ml.cnn.salient_chars", title="Characters that drove the ML model's score",
               weight=1.5, category="ml",
               evidence={"spans": [{"start": 32, "end": 38, "text": "/signi"}]}),
        Signal(id="rep.top_site", title="Ranked in top sites", weight=-1.2,
               category="reputation"),
    ]
    logit_ = PRIOR_LOGIT + apply_contributions(sigs)
    return Verdict(
        kind=kind, target=target, artifact_id="a" * 24, risk=0.97, score=97, logit=logit_,
        level=level, action=Action.BLOCK, confidence=0.92,
        summary="Malicious (97/100): AiTM kit; impersonates PayPal.",
        brand=BrandMatch(brand="paypal", name="PayPal", technique="homoglyph",
                         confidence=0.91, legit_domains=["paypal.com"],
                         evidence="paypa1 resembles paypal") if brand else None,
        signals=sigs,
        indicators=indicators if indicators is not None else [
            Indicator(type=IndicatorType.URL, value=URL, role="landing", malicious=True),
            Indicator(type=IndicatorType.DOMAIN, value="login.paypa1-secure.test",
                      malicious=True),
            Indicator(type=IndicatorType.IPV4, value="198.51.100.7"),
            Indicator(type=IndicatorType.SHA256, value="ab" * 32, malicious=True),
        ],
        techniques=["homoglyph_domain"],
        analyzers=[AnalyzerRun(name="url", status="ok", duration_ms=3.2, signals=2),
                   AnalyzerRun(name="infra", status="timeout", duration_ms=500.0,
                               error="timed out")],
        children=children or [], meta={"title": "Sign in", "subject": "Your account"},
        duration_ms=41.0, **kw)


def child() -> Verdict:
    c = make(target="https://cdn.evil.test/kit.js", level=Level.SUSPICIOUS, brand=False,
             signals=[Signal(id="page.obfuscated_script", title="Obfuscated script",
                             weight=2.0, category="page")], indicators=[],
             origin="page.script")
    c.score = 60
    return c


def svgs(html: str) -> list[str]:
    return re.findall(r"<svg\b.*?</svg>", html, flags=re.S)


# ----------------------------------------------------------------------------- content
def test_html_contains_core_facts():
    html = render_report(make(children=[child()]))
    assert html.startswith("<!doctype html>")
    assert "97/100" in html and ">97<" in html            # score text + gauge number
    assert "PayPal" in html and "Impersonated brand" in html
    for title in ("Domain imitates PayPal with look-alike digit",
                  "AiTM reverse-proxy kit fingerprint"):
        assert title in html
    assert "url.brand.homoglyph" in html and "kit.aitm.fingerprint" in html
    assert "hxxps://login[.]paypa1-secure[.]test/signin/verify?id=7" in html
    assert "198[.]51[.]100[.]7" in html
    assert "login[.]paypa1-secure[.]test" in html
    assert "homoglyph_domain" in html
    assert "page.script" in html and "cdn[.]evil[.]test/kit[.]js" in html   # child tree
    assert "timed out" in html and "infra" in html                          # analyzer runs


def test_no_live_urls_anywhere():
    html = render_report(make(children=[child()]))
    assert not re.search(r"https?://login\.paypa1", html)
    assert "http://cdn.evil" not in html and "https://cdn.evil" not in html
    # the only anchors are MITRE links
    p = parse(html)
    hrefs = [a.get("href") for t, a in p.tags if t == "a"]
    assert hrefs and all(h.startswith(("https://attack.mitre.org/techniques/",
                                       "https://atlas.mitre.org/techniques/")) for h in hrefs)
    assert "https://attack.mitre.org/techniques/T1566/002" in hrefs
    assert not any(t in ("script", "iframe", "object", "embed", "link", "img", "form")
                   for t, _ in p.tags)


def test_mitre_section_and_atlas_link():
    sig = Signal(id="agent.injection.role_hijack", title="Role hijack", weight=3.5,
                 category="agent", mitre=["AML.T0051.001", "T9999", "javascript:alert(1)"])
    html = render_report(make(signals=[sig]))
    assert "https://atlas.mitre.org/techniques/AML.T0051.001" in html
    hrefs = [a.get("href") for t, a in parse(html).tags if t == "a"]
    assert all(h.startswith("https://") for h in hrefs)
    assert not any("javascript" in h for h in hrefs)
    assert "T9999" in html                                   # unknown id listed, not linked
    assert not [h for h in hrefs if "T9999" in h]


def test_is_well_formed_html_and_svg():
    html = render_report(make(children=[child()]), ai_narrative="Para one.\n\nPara two.")
    p = parse(html)
    assert p.errors == [] and p.stack == []
    found = svgs(html)
    assert len(found) == 2
    for s in found:
        root = ET.fromstring(s)                              # valid XML
        assert root.tag.endswith("svg")
    assert 'role="img"' in found[0]


def test_csp_and_no_external_assets():
    html = render_report(make())
    assert "default-src 'none'" in html
    assert "<script" not in html.lower()
    assert not re.search(r"(?:src|href)=\"(?!https://(?:attack|atlas)\.mitre\.org/)", html)
    assert "@import" not in html and "url(" not in html


def test_waterfall_sums_to_final_logit():
    v = make()
    rows = rpt._waterfall_rows(v)
    assert rows[0][2] == "prior" and rows[-1][2] == "total"
    body = [r[1] for r in rows[:-1]]
    assert sum(body) == pytest.approx(v.logit, abs=0.01)
    assert rows[-1][1] == pytest.approx(v.logit)


def test_waterfall_folds_many_signals_into_other():
    many = [Signal(id=f"url.weak.{i}", title=f"weak {i}", weight=0.3, category=f"c{i}")
            for i in range(30)]
    v = make(signals=many)
    rows = rpt._waterfall_rows(v)
    assert len(rows) == rpt.MAX_WATERFALL + 3
    assert any(r[0] == "Other evidence" for r in rows)
    assert sum(r[1] for r in rows[:-1]) == pytest.approx(v.logit, abs=0.01)
    ET.fromstring(str(rpt.waterfall_svg(v)))


def test_gauge_clamps_and_is_xml():
    for score in (-5, 0, 50, 100, 400):
        root = ET.fromstring(str(rpt.gauge_svg(score, "benign")))
        assert root.tag.endswith("svg")


def test_highlight_spans_and_salient():
    c = build_context(make())
    t = str(c["target"])
    assert '<mark class="hl">' in t
    assert any(r["salient"] for r in c["span_rows"]) and any(
        not r["salient"] for r in c["span_rows"])
    # marked text matches the signal span [8, 32)
    assert any(r["text"] == "login[.]paypa1-secure[.]test" for r in c["span_rows"])


def test_span_out_of_range_and_bad_types_ignored():
    sig = Signal(id="url.x", title="x", weight=2, category="url", span=(900, 990),
                 evidence={"spans": [{"start": "a", "end": 3}, {"start": True, "end": 5},
                                     "junk", {"start": -4, "end": 3}]})
    c = build_context(make(signals=[sig]))
    assert [r["text"] for r in c["span_rows"]] == [defang_text(URL[:3])]


def test_non_ascii_and_invisible_flagged():
    target = "https://pаypal.test/‮login​"
    html = render_report(make(target=target, signals=[]))
    assert '<mark class="na">' in html                       # Cyrillic a
    assert "&lt;U+202E&gt;" in html and "&lt;U+200B&gt;" in html
    assert "‮" not in html and "​" not in html


# ------------------------------------------------------------------------------ XSS
XSS = '<script>alert(1)</script><img src=x onerror=alert(1)>"\'&'


def hostile() -> Verdict:
    sig = Signal(id="url.<b>x</b>", title=XSS, detail=XSS, weight=3, category="<i>c</i>",
                 mitre=[XSS], span=(0, 5), evidence={"spans": [{"start": 0, "end": 2}]})
    return _hostile_verdict(sig)


def _hostile_verdict(sig: Signal) -> Verdict:
    v = make(
        target=XSS + " https://evil.test/a?x=<svg onload=alert(1)>", signals=[sig],
        indicators=[Indicator(type=IndicatorType.URL, value="https://e.test/" + XSS,
                              role=XSS, context=XSS),
                    Indicator(type=IndicatorType.FILENAME, value=XSS)],
        children=[make(target=XSS, kind=ArtifactKind.TEXT, signals=[], indicators=[],
                       origin=XSS, brand=False)])
    v.summary = XSS
    v.meta = {XSS: XSS, "nested": {"a": XSS}}
    v.brand = BrandMatch(brand="b", name=XSS, technique=XSS, confidence=0.5,
                         legit_domains=[XSS], evidence=XSS)
    v.analyzers = [AnalyzerRun(name=XSS, status=XSS, error=XSS)]
    return v


def test_xss_everything_is_escaped():
    html = render_report(hostile(), ai_narrative=XSS, title=XSS)
    assert "<script" not in html.lower()
    p = parse(html)
    tags = {t for t, _ in p.tags}
    assert not tags & {"script", "img", "svg_onload"}
    # no injected element carries an event handler attribute
    assert not any(k.startswith("on") for _, a in p.tags for k in a)
    assert p.errors == [] and p.stack == []
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "onerror=alert(1)" in html                        # present only as inert text
    # svg tags in the page come from our builders only (gauge + waterfall)
    assert [t for t, _ in p.tags].count("svg") == 2
    for s in svgs(html):
        ET.fromstring(s)


def test_xss_title_and_default_title_escaped():
    html = render_report(make(target="</title><script>alert(1)</script>", signals=[]))
    assert "</title><script>" not in html
    assert "<script" not in html.lower()
    assert parse(html).errors == []


def test_xss_in_markdown_is_neutralised():
    md = report_markdown(hostile())
    body = md.replace("\n> ", "\n")                      # drop blockquote markers
    assert not re.search(r"(?<!\\)[<>]", body)           # every angle bracket is escaped
    assert "&lt;" not in md


def test_json_appendix_defanged_and_valid():
    html = render_report(make())
    m = re.search(r"Raw verdict \(JSON\).*?<pre>(.*?)</pre>", html, flags=re.S)
    assert m
    import html as h
    data = json.loads(h.unescape(m.group(1)))
    assert data["score"] == 97 and data["target"].startswith("hxxps://")
    assert "https://login.paypa1" not in m.group(1)


def test_stix_pattern_in_appendix_scheme_defanged():
    html = render_report(make())
    assert "STIX 2.1 pattern" in html
    assert "[url:value" in html and "hxxps://" in html
    assert "'https://login" not in html


def test_benign_verdict_without_extras():
    v = make(signals=[], indicators=[], brand=False, level=Level.BENIGN, kind=ArtifactKind.TEXT,
             target="hello")
    v.risk, v.score, v.action = 0.03, 3, Action.ALLOW
    html = render_report(v)
    assert "No signals were raised" in html and "No indicators were extracted" in html
    assert "STIX 2.1 pattern" not in html
    assert parse(html).errors == []
    assert "Analyst narrative" not in html


def test_ai_narrative_rendered_and_defanged():
    html = render_report(make(), ai_narrative="Visit https://bad.test/x now.\n\nSecond.")
    assert "Analyst narrative" in html and "hxxps://bad[.]test/x" in html
    assert "<p>Second.</p>" in html


def test_custom_title_and_determinism():
    v = make()
    a, b = render_report(v, title="Case 42"), render_report(v, title="Case 42")
    assert a == b and "<title>Case 42</title>" in a


def test_limits_bound_output():
    sigs = [Signal(id=f"url.s{i}", title=f"s{i}", weight=0.1, category="url")
            for i in range(rpt.MAX_SIGNAL_ROWS + 20)]
    inds = [Indicator(type=IndicatorType.DOMAIN, value=f"d{i}.test")
            for i in range(rpt.MAX_IOC_ROWS + 5)]
    c = build_context(make(signals=sigs, indicators=inds))
    assert len(c["signals"]) == rpt.MAX_SIGNAL_ROWS and c["signals_total"] == len(sigs)
    assert len(c["iocs"]) == rpt.MAX_IOC_ROWS and c["iocs_total"] == len(inds)
    deep = make(signals=[], indicators=[], brand=False)
    node = deep
    for _ in range(rpt.MAX_TREE_DEPTH + 3):
        nxt = make(signals=[], indicators=[], brand=False)
        node.children = [nxt]
        node = nxt
    c = build_context(deep)
    assert c["tree_truncated"] and len(c["tree"]) == rpt.MAX_TREE_DEPTH + 1


def test_huge_target_is_truncated():
    c = build_context(make(target="a" * 50_000, signals=[]))
    assert c["target_cut"]


# --------------------------------------------------------------------------- defang
@pytest.mark.parametrize("raw,expected", [
    ("https://a.example.com/x", "hxxps://a[.]example[.]com/x"),
    ("http://1.2.3.4/a", "hxxp://1[.]2[.]3[.]4/a"),
    ("user@example.com", "user[@]example[.]com"),
    ("version 1.5 released.", "version 1.5 released."),
])
def test_defang_text(raw, expected):
    assert defang_text(raw) == expected
    assert defang_text(expected) == expected               # idempotent


def test_defang_bounds_and_whitespace():
    assert defang_text("a\n\t b") == "a b"
    assert defang_text("x" * 1000, 10).endswith("…")
    assert defang_text(None) == ""


# --------------------------------------------------------------------------- markdown
def test_markdown_variant():
    md = report_markdown(make(children=[child()]), ai_narrative="Short note.")
    assert md.startswith("# UniPhish analyst report")
    assert "**97/100**" in md and "MALICIOUS" in md
    assert "PayPal" in md
    assert "Domain imitates PayPal with look-alike digit" in md
    assert "198[.]51[.]100[.]7" in md and "hxxps://login[.]paypa1-secure[.]test" in md
    assert "https://attack.mitre.org/techniques/T1566/002" in md
    assert "| Contribution |" in md and "## Artifact tree" in md
    assert "Short note." in md and "## Analyzer runs" in md
    assert "https://login.paypa1" not in md


def test_markdown_table_cells_cannot_break_out():
    sig = Signal(id="url.x", title="a | b\nc", detail="x|y\n|---|", weight=2, category="url")
    md = report_markdown(make(signals=[sig]))
    row = next(line for line in md.splitlines() if "url.x" in line)
    assert row.count("|") - row.count("\\|") == 7


# ----------------------------------------------------------------------------- PDF
def test_to_pdf_falls_back_to_html(tmp_path, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("no browser")
    monkeypatch.setattr(rpt, "_print_pdf", boom)
    res = to_pdf(make(), tmp_path / "out" / "case.pdf")
    assert not res.is_pdf and res.format == "html"
    assert res.path == tmp_path / "out" / "case.html" and res.path.exists()
    assert "PDF rendering failed" in (res.note or "") and "sandbox" in (res.note or "")
    assert res.path.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_to_pdf_without_playwright(tmp_path, monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name.split(".")[0] == "playwright":
            raise ImportError(name)
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake)
    res = to_pdf(make(), tmp_path / "r.html")
    assert res.format == "html" and res.path == tmp_path / "r.html"
    assert "not installed" in (res.note or "")


def test_to_pdf_success_path_with_stub(tmp_path, monkeypatch):
    def fake(html, out, timeout):
        assert html.startswith("<!doctype html>")
        out.write_bytes(b"%PDF-1.7 stub")
    monkeypatch.setattr(rpt, "_print_pdf", fake)
    pytest.importorskip("playwright")
    res = to_pdf(make(), tmp_path / "ok.pdf")
    assert res.is_pdf and res.note is None and res.path.read_bytes().startswith(b"%PDF")


def test_to_pdf_real_chromium_if_available(tmp_path):
    pytest.importorskip("playwright")
    res = to_pdf(make(children=[child()]), tmp_path / "real.pdf", timeout_s=20)
    if not res.is_pdf:
        pytest.skip(f"headless Chromium unavailable: {res.note}")
    assert res.path.read_bytes().startswith(b"%PDF")


def test_template_missing_error(monkeypatch, tmp_path):
    rpt._env.cache_clear()
    monkeypatch.setattr(rpt, "TEMPLATE_DIR", tmp_path)
    with pytest.raises(rpt.ReportTemplateError):
        render_report(make())
    rpt._env.cache_clear()
