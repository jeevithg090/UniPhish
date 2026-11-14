"""Tests for the phishing-kit signature analyzer (uniphish.analyzers.kits)."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from uniphish.analyzers.kits import (
    FAMILIES,
    MATCHER_KINDS,
    KitAnalyzer,
    KitRuleError,
    check_regex_safe,
    default_signatures,
    load_signatures,
    match_html,
)
from uniphish.core.analyzer import REGISTRY, AnalysisContext, AnalysisOptions
from uniphish.core.mitre import CATALOG
from uniphish.core.types import Artifact, ArtifactKind

FIX = Path(__file__).parent / "fixtures"
EVIL = "https://login.evil.test/"

# fixture -> (page URL, exact set of signature ids that must match)
CASES: dict[str, tuple[str | None, set[str]]] = {
    "aitm_ms_ests.html": (EVIL, {"aitm.ms_ests_config"}),
    "aitm_ms_assets.html": (EVIL, {"aitm.ms_login_assets"}),
    "aitm_google.html": (EVIL, {"aitm.google_accounts_assets"}),
    "clickfix_captcha.html": (None, {"clickfix.captcha_paste", "clickfix.command_staged"}),
    "clickfix_runbox.html": (None, {"clickfix.run_dialog_clipboard"}),
    "clickfix_text_only.html": (None, {"clickfix.run_dialog_text"}),
    "captcha_gate.html": (None, {"captcha.fake_gate"}),
    "bitb.html": (None, {"bitb.fake_window"}),
    "oauth_device.html": (EVIL, {"oauth.device_code_lure"}),
    "oauth_consent.html": (EVIL, {"oauth.consent_clone"}),
    "toad_billing.html": (None, {"toad.billing_callback"}),
    "toad_techsupport.html": (None, {"toad.tech_support"}),
    "drainer_seed.html": (None, {"drainer.seed_phrase_form"}),
    "drainer_approval.html": (None, {"drainer.approval_flow"}),
    "drainer_lure.html": (None, {"drainer.connect_lure"}),
    "generic_telegram.html": (None, {"generic.telegram_exfil"}),
    "generic_discord.html": (None, {"generic.discord_webhook_exfil"}),
    "generic_formhandler.html": ("https://portal.example.com/", {"generic.form_handler_script"}),
    "generic_cloned.html": (None, {"generic.cloned_page_comment"}),
    "generic_devtools.html": (None, {"generic.devtools_block"}),
    "generic_fragment.html": (None, {"generic.victim_email_fragment"}),
    "benign_login.html": ("https://shop.example.com/", set()),
    "benign_docs.html": ("https://docs.example.com/", set()),
    "benign_real_captcha.html": ("https://www.example.com/", set()),
    "benign_wallet_docs.html": ("https://blog.example.com/", set()),
}


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def _ids(html: str, url: str | None) -> set[str]:
    return {m.signature.id for m in match_html(html, url)}


# --------------------------------------------------------------------------- #
# signature file
# --------------------------------------------------------------------------- #
def test_signature_file_loads_and_is_well_formed():
    sigs = default_signatures()
    assert len(sigs) >= 20
    ids = [s.id for s in sigs]
    assert len(ids) == len(set(ids))
    for s in sigs:
        assert s.family in FAMILIES
        assert len(s.name) <= 70
        assert -4.0 <= s.weight <= 8.0
        assert all(m in CATALOG for m in s.mitre)
    assert {s.family for s in sigs} == set(FAMILIES)


def test_every_fixture_is_listed_and_every_signature_is_covered():
    on_disk = {p.name for p in FIX.glob("*.html")}
    assert on_disk == set(CASES)
    covered = set().union(*(ids for _, ids in CASES.values()))
    assert covered == {s.id for s in default_signatures()}


@pytest.mark.parametrize("name", sorted(CASES))
def test_fixture_matches_exactly_its_signatures(name):
    url, expected = CASES[name]
    assert _ids(_read(name), url) == expected


def test_no_default_regex_is_unsafe():
    # load_signatures lints every regex; re-running proves the shipped file passes
    assert load_signatures()


# --------------------------------------------------------------------------- #
# host scoping (AiTM / OAuth must not fire on the genuine service)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "name", ["aitm_ms_ests.html", "aitm_ms_assets.html", "oauth_device.html", "oauth_consent.html"]
)
def test_host_scope_skips_genuine_hosts_and_unknown_urls(name):
    html = _read(name)
    assert _ids(html, "https://login.microsoftonline.com/common/oauth2") == set()
    assert _ids(html, "https://account.live.com/") == set()
    assert _ids(html, None) == set()  # require_url: cannot rule out the real site


def test_aitm_flag_on_lookalike_subdomain_of_other_domain():
    html = _read("aitm_ms_ests.html")
    assert _ids(html, "https://login.microsoftonline.com.evil.test/") == {"aitm.ms_ests_config"}


def test_single_config_key_is_not_enough():
    html = '<html><body><script>var c={"sFTName":"flowToken"};</script></body></html>'
    assert _ids(html, EVIL) == set()


# --------------------------------------------------------------------------- #
# signal contents
# --------------------------------------------------------------------------- #
def test_signal_shape_and_detail():
    (m,) = match_html(_read("clickfix_runbox.html"))
    sig = m.to_signal()
    assert sig.id == "kit.clickfix.run_dialog_clipboard"
    assert sig.category == "kit"
    assert sig.weight == 6.0
    assert "T1204.004" in sig.mitre
    assert "ClickFix" in sig.detail and "clipboard" in sig.detail
    assert sig.evidence["family"] == "clickfix"


def test_clickfix_text_only_is_weaker_than_with_clipboard():
    text_only = {
        m.signature.id: m.signature.weight for m in match_html(_read("clickfix_text_only.html"))
    }
    with_clip = {
        m.signature.id: m.signature.weight for m in match_html(_read("clickfix_runbox.html"))
    }
    assert text_only["clickfix.run_dialog_text"] < with_clip["clickfix.run_dialog_clipboard"]


def test_captcha_gate_not_flagged_when_clipboard_used():
    ids = _ids(_read("clickfix_captcha.html"), None)
    assert "captcha.fake_gate" not in ids  # that is ClickFix, reported as such


# --------------------------------------------------------------------------- #
# analyzer integration
# --------------------------------------------------------------------------- #
def _run(artifact: Artifact):
    ctx = AnalysisContext(options=AnalysisOptions())
    return asyncio.run(KitAnalyzer().analyze(artifact, ctx))


def test_analyzer_registered_and_catalog_declared():
    assert REGISTRY["kits"] is KitAnalyzer
    assert KitAnalyzer.kinds == frozenset({ArtifactKind.PAGE})
    assert KitAnalyzer.stage == 0 and KitAnalyzer.blocking is True
    assert set(KitAnalyzer.signals) == {f"kit.{s.id}" for s in default_signatures()}
    for sid in KitAnalyzer.signals:
        assert sid.startswith("kit.")


def test_analyzer_emits_signals_techniques_meta():
    art = Artifact.from_page(_read("clickfix_captcha.html"))
    res = _run(art)
    got = {s.id for s in res.signals}
    assert got == {"kit.clickfix.captcha_paste", "kit.clickfix.command_staged"}
    assert res.techniques == ["clickfix"]
    assert res.meta["kits"]["matched"] == ["clickfix.captcha_paste", "clickfix.command_staged"]
    assert res.meta["kits"]["signatures_evaluated"] == len(default_signatures())


def test_analyzer_uses_page_url_and_emits_exfil_indicator():
    art = Artifact.from_page(_read("generic_formhandler.html"), url="https://portal.example.com/")
    res = _run(art)
    assert [s.id for s in res.signals] == ["kit.generic.form_handler_script"]
    assert [(i.type.value, i.value, i.role) for i in res.indicators] == [
        ("domain", "collector.evil.test", "exfil-endpoint")
    ]


def test_analyzer_benign_and_empty_pages_produce_nothing():
    assert (
        _run(
            Artifact.from_page(_read("benign_login.html"), url="https://shop.example.com/")
        ).signals
        == []
    )
    assert _run(Artifact.from_page("")).signals == []
    assert _run(Artifact.from_page(b"\xff\xfe\x00garbage<<<")).signals == []


def test_analyzer_reads_favicon_hashes_from_meta():
    rules = [
        {
            "id": "x.fav",
            "name": "fav",
            "family": "generic_kit",
            "severity_weight": 3,
            "all_of": [{"kind": "favicon_mmh3", "hashes": [-123456]}],
        }
    ]
    sigs = load_signatures(rules)
    html = "<html><body>hi</body></html>"
    assert match_html(html, signatures=sigs) == []
    assert [
        m.signature.id for m in match_html(html, favicon_hashes=[-123456], signatures=sigs)
    ] == ["x.fav"]


# --------------------------------------------------------------------------- #
# engine: every matcher kind, plus rule validation
# --------------------------------------------------------------------------- #
def _one(matcher: dict, html: str, url: str | None = None, **extra) -> bool:
    rule = {
        "id": "t.rule",
        "name": "t",
        "family": "generic_kit",
        "severity_weight": 1,
        "all_of": [matcher],
        **extra,
    }
    return bool(match_html(html, url, signatures=load_signatures([rule])))


def test_matcher_kinds_cover_spec():
    assert set(MATCHER_KINDS) == {
        "text_contains",
        "html_regex",
        "form_action_cross_origin",
        "has_clipboard_write",
        "title_regex",
        "resource_host_suffix",
        "meta",
        "favicon_mmh3",
        "script_src_regex",
        "dom_pattern",
    }


def test_text_contains_uses_visible_text_only():
    m = {"kind": "text_contains", "terms": ["Secret   Word"]}
    assert _one(m, "<p>the secret word</p>")
    assert not _one(m, "<script>secret word</script><!-- secret word -->")
    assert not _one({**m, "min": 2, "terms": ["alpha", "beta"]}, "<p>alpha</p>")


def test_html_regex_scopes():
    assert _one({"kind": "html_regex", "pattern": r"<b\s{0,2}id=x"}, "<b  id=x>")
    assert not _one(
        {"kind": "html_regex", "scope": "text", "pattern": "hidden"},
        "<script>hidden</script><p>shown</p>",
    )


def test_title_regex_and_meta_and_script_src():
    assert _one(
        {"kind": "title_regex", "pattern": "^just a moment"}, "<title>Just a moment...</title>"
    )
    assert _one(
        {"kind": "meta", "field": "generator", "contains": "fakekit"},
        '<meta name="generator" content="FakeKit 1.0">',
    )
    assert _one(
        {"kind": "meta", "field": "refresh_offsite", "present": True},
        '<meta http-equiv="refresh" content="0;url=https://other.example/">',
        "https://a.example.com/",
    )
    assert _one(
        {"kind": "script_src_regex", "pattern": r"cdn\.evil\.test/"},
        '<script src="https://cdn.evil.test/a.js"></script>',
    )
    assert not _one(
        {"kind": "script_src_regex", "pattern": r"cdn\.evil\.test/"},
        "<script>var cdn='cdn.evil.test/'</script>",
    )


def test_resource_host_suffix_needs_foreign_page():
    html = '<img src="https://img.assets.test/x.png">'
    m = {"kind": "resource_host_suffix", "suffixes": ["assets.test"]}
    assert _one(m, html, "https://page.example.com/")
    assert not _one(m, html, "https://www.assets.test/")
    assert not _one(m, html, None)


def test_dom_pattern_and_clipboard_matchers():
    assert _one(
        {"kind": "dom_pattern", "selector": "div.a > span", "min": 2},
        "<div class=a><span>1</span><span>2</span></div>",
    )
    assert not _one(
        {"kind": "dom_pattern", "selector": "div.a > span", "min": 3},
        "<div class=a><span>1</span><span>2</span></div>",
    )
    assert _one(
        {"kind": "has_clipboard_write"}, "<script>navigator.clipboard.writeText('x')</script>"
    )


def test_negated_matcher_and_any_of_min():
    rule = {
        "id": "t.neg",
        "name": "t",
        "family": "generic_kit",
        "severity_weight": 1,
        "all_of": [
            {"kind": "text_contains", "terms": ["a"]},
            {"kind": "text_contains", "terms": ["b"], "not": True},
        ],
        "any_of": [
            {"kind": "text_contains", "terms": ["x"]},
            {"kind": "text_contains", "terms": ["y"]},
        ],
        "min_any": 2,
    }
    sigs = load_signatures([rule])
    assert match_html("<p>a x y</p>", signatures=sigs)
    assert not match_html("<p>a x</p>", signatures=sigs)
    assert not match_html("<p>a b x y</p>", signatures=sigs)


@pytest.mark.parametrize(
    "bad",
    [
        {
            "id": "Bad Id",
            "name": "t",
            "family": "generic_kit",
            "severity_weight": 1,
            "all_of": [{"kind": "has_clipboard_write"}],
        },
        {
            "id": "t.a",
            "name": "t",
            "family": "nope",
            "severity_weight": 1,
            "all_of": [{"kind": "has_clipboard_write"}],
        },
        {
            "id": "t.a",
            "name": "t",
            "family": "generic_kit",
            "severity_weight": 99,
            "all_of": [{"kind": "has_clipboard_write"}],
        },
        {
            "id": "t.a",
            "name": "t",
            "family": "generic_kit",
            "severity_weight": 1,
            "mitre": ["T9999"],
            "all_of": [{"kind": "has_clipboard_write"}],
        },
        {"id": "t.a", "name": "t", "family": "generic_kit", "severity_weight": 1},
        {
            "id": "t.a",
            "name": "t",
            "family": "generic_kit",
            "severity_weight": 1,
            "all_of": [{"kind": "wat"}],
        },
        {
            "id": "t.a",
            "name": "t",
            "family": "generic_kit",
            "severity_weight": 1,
            "all_of": [{"kind": "has_clipboard_write", "typo": 1}],
        },
        {
            "id": "t.a",
            "name": "t",
            "family": "generic_kit",
            "severity_weight": 1,
            "all_of": [{"kind": "has_clipboard_write", "not": True}],
        },
        {
            "id": "t.a",
            "name": "t",
            "family": "generic_kit",
            "severity_weight": 1,
            "all_of": [{"kind": "dom_pattern", "selector": "div[["}],
        },
        {
            "id": "t.a",
            "name": "x" * 71,
            "family": "generic_kit",
            "severity_weight": 1,
            "all_of": [{"kind": "has_clipboard_write"}],
        },
        {
            "id": "t.a",
            "name": "t",
            "family": "generic_kit",
            "severity_weight": 1,
            "all_of": [{"kind": "html_regex", "pattern": "(a+)+b"}],
        },
    ],
)
def test_invalid_rules_are_rejected(bad):
    with pytest.raises(KitRuleError):
        load_signatures([bad])


def test_duplicate_ids_rejected():
    r = {
        "id": "t.a",
        "name": "t",
        "family": "generic_kit",
        "severity_weight": 1,
        "all_of": [{"kind": "has_clipboard_write"}],
    }
    with pytest.raises(KitRuleError):
        load_signatures([r, dict(r)])


# --------------------------------------------------------------------------- #
# ReDoS guard
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "pattern",
    [
        r"(a+)+$",
        r"(a*)*",
        r"a.*b",
        r"a.+b",
        r"a{1,}",
        r"(?:a|aa){1,5}",
        r"(a{1,5}){1,5}",
        r"(a)\1",
        r"x{1,5000}",
    ],
)
def test_lint_rejects_dangerous_patterns(pattern):
    with pytest.raises(KitRuleError):
        check_regex_safe(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"a.{0,200}b",
        r"(?:ctrl|cmd)\s{0,3}\+\s{0,3}v\b",
        r"(?:\.exe)?\s{1,3}/c",
        r"[^\n<>]{0,120}?x",
    ],
)
def test_lint_accepts_bounded_patterns(pattern):
    check_regex_safe(pattern)


def test_adversarial_inputs_are_fast():
    sigs = default_signatures()
    seeds = [
        "powershell " * 40_000,
        "navigator.clipboard.writeText(" * 20_000,
        "contextmenu " * 60_000,
        "<div class=url-bar>" * 20_000,
        "a" * 700_000,
        "(555) 010 " * 60_000,
        "win+" * 120_000,
        "<input type=password " * 20_000 + "saved from url=(" * 20_000,
        "<p>" + "verify you are " * 40_000 + "</p>",
    ]
    for seed in seeds:
        start = time.perf_counter()
        match_html(seed, "https://x.evil.test/", signatures=sigs)
        elapsed = time.perf_counter() - start
        assert elapsed < 8.0, f"{seed[:30]!r} took {elapsed:.1f}s"


def test_huge_input_is_bounded():
    html = "<p>x</p>" * 400_000  # ~3.2 MB, over the scan cap
    start = time.perf_counter()
    assert match_html(html) == []
    assert time.perf_counter() - start < 30.0  # dominated by the HTML parser


def test_match_html_never_raises_on_bad_types():
    assert match_html(None) == []  # type: ignore[arg-type]
    assert match_html(b"\x00\xff<html") == []
    assert isinstance(match_html("<html" * 10_000), list)
