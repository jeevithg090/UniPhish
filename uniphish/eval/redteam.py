"""Red-team harness: attack the detector with evasions and report who recovers.

Why this module exists: a benchmark of known attacks (``benchmark.py``) says nothing
about an adversary who *reads the detector's rules* and adapts. This harness takes
malicious items the detector already catches, applies evasion transformations, and
measures

* the **evasion rate** - the share of previously-caught items that slip through - for
  each layer on its own and for the fused engine, and
* the **defense-in-depth recovery** - when one layer is blinded, does another layer (or
  the fusion) still flag the item?

Layers
------
URL suite: ``ml`` (the byte-level CNN alone), ``rules`` (every analyzer except the CNN:
Unicode/IDN policy, brand matching, lexical rules, reputation lists) and ``fusion``
(the product). Injection suite: ``injection_analyzer`` (pattern matching with
de-obfuscation) and ``fusion``; no other analyzer reacts to injection text, so there is no
second layer to recover an evaded item and the suite reports evasion rates only.

Evasions (all applied to synthetic, inert inputs; nothing is fetched or executed):
homoglyph swap, zero-width and bidi insertion, TLD swap, path padding, case
randomisation, percent / double encoding, punycode form, IDEOGRAPHIC FULL STOP host
dots, userinfo decoys; and for the injection detector Unicode-tag smuggling, zero-width
splitting, homoglyph / leet / case obfuscation, base64 / hex wrapping, context padding
and HTML hiding. A no-op ``control`` transformation shows the measurement noise floor.

Honest framing: this is a small, scripted adversary - not an adaptive one. A low
evasion rate here means "these known tricks do not work", never "the detector is
robust". The TLD swap uses ordinary TLD strings inside offline-only synthetic URLs;
nothing is ever resolved.

CLI::

    python -m uniphish.eval.redteam --n 100
"""

from __future__ import annotations

import argparse
import random
import re
import sys
import time
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from uniphish.core.config import get_settings
from uniphish.core.engine import Engine, default_engine
from uniphish.eval import _corpus as C
from uniphish.eval._stats import defang, safe_div
from uniphish.eval.benchmark import (
    SCHEMA_VERSION,
    _environment,
    offline_options,
    save_report,
)
from uniphish.eval.datasets import (
    BRANDS,
    DEFAULT_SEED,
    ArtifactSpec,
    EvalItem,
    load_items,
)

SUITES = ("url", "injection")

LAYERS: dict[str, dict[str, dict[str, Any]]] = {
    "url": {"ml": {"enable": ["ml"]}, "rules": {"disable": ["ml"]}, "fusion": {}},
    "injection": {"injection_analyzer": {"enable": ["injection"]}, "fusion": {}},
}

CAVEATS: tuple[str, ...] = (
    "Scripted, non-adaptive adversary: these are known tricks applied blindly. A low "
    "evasion rate means those tricks fail, not that the detector is robust.",
    "Seeds are synthetic and drawn from the benchmark's own generators, so the seed set is "
    "easier than real-world attacks; evasion rates are measured only on items the "
    "detector caught before the evasion.",
    "Offline only: online evidence (domain age, certificates, live feeds, page content) "
    "that would often recover an evaded URL is deliberately not used.",
    "Small samples: see n_eligible per technique; rates on a handful of items are noisy. "
    "The 'control' row shows the noise floor.",
)

_URL_RE = re.compile(
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*)://(?:(?P<user>[^@/]*)@)?(?P<host>[^/:?#]*)"
    r"(?P<port>:\d+)?(?P<rest>.*)$",
    re.S,
)
_IPLIKE = re.compile(r"^[\d.]+$")
_BIDI_LRI, _BIDI_PDI, _BIDI_RLO = "⁦", "⁩", "‮"
_CYR_LOWER = {k: v for k, v in C._CYR_LOOK.items() if k.islower()}
_PAD_WORDS = (
    "assets",
    "images",
    "wp-content",
    "uploads",
    "2024",
    "05",
    "static",
    "cdn",
    "media",
    "css",
    "fonts",
    "v2",
    "public",
    "files",
    "docs",
    "archive",
)
_PAD_QUERY = (
    "utm_source=newsletter",
    "utm_medium=email",
    "utm_campaign=spring-sale",
    "utm_content=header-link",
    "ref=homepage",
    "lang=en",
    "session=a1b2c3d4e5f6",
    "page=1",
    "sort=newest",
    "view=grid",
)
_FILLER = (
    "The committee met on Tuesday to review the quarterly budget and agreed to publish "
    "the minutes on the shared drive. Volunteers are needed for the spring clean-up. "
)


# --------------------------------------------------------------------------- #
# Types
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Evasion:
    """One evasion technique: ``apply(spec, rng)`` returns a new spec or None (not applicable)."""

    name: str
    description: str
    apply: Callable[[ArtifactSpec, random.Random], ArtifactSpec | None]


def _split(url: str) -> dict[str, str] | None:
    m = _URL_RE.match(url)
    return {k: (v or "") for k, v in m.groupdict().items()} if m else None


def _join(p: dict[str, str]) -> str:
    user = f"{p['user']}@" if p["user"] else ""
    return f"{p['scheme']}://{user}{p['host']}{p['port']}{p['rest']}"


def _url_edit(
    fn: Callable[[dict[str, str], random.Random], bool],
) -> Callable[[ArtifactSpec, random.Random], ArtifactSpec | None]:
    """Lift an in-place URL-part edit into a spec transform (None if it did not apply)."""

    def run(spec: ArtifactSpec, rng: random.Random) -> ArtifactSpec | None:
        if spec.kind != "url":
            return None
        parts = _split(spec.value)
        if not parts or _IPLIKE.match(parts["host"]):
            return None
        if not fn(parts, rng):
            return None
        out = _join(parts)
        return ArtifactSpec("url", out) if out != spec.value else None

    return run


def _brand_label(labels: list[str]) -> int:
    """Index of the label carrying a brand name, else the longest non-TLD label."""
    for i, lab in enumerate(labels[:-1] or labels):
        if any(b in lab.lower() for b in BRANDS):
            return i
    body = labels[:-1] or labels
    return max(range(len(body)), key=lambda i: len(body[i]))


# ---- URL evasions ------------------------------------------------------------
def _ev_homoglyph(p: dict[str, str], rng: random.Random) -> bool:
    labels = p["host"].split(".")
    i = _brand_label(labels)
    pos = [j for j, c in enumerate(labels[i]) if c in _CYR_LOWER]
    if not pos:
        return False
    for j in rng.sample(pos, min(2, len(pos))):
        labels[i] = labels[i][:j] + _CYR_LOWER[labels[i][j]] + labels[i][j + 1 :]
    p["host"] = ".".join(labels)
    return True


def _ev_zero_width(p: dict[str, str], rng: random.Random) -> bool:
    labels = p["host"].split(".")
    i = _brand_label(labels)
    if len(labels[i]) < 3:
        return False
    for _ in range(2):
        j = rng.randrange(1, len(labels[i]))
        labels[i] = labels[i][:j] + rng.choice((C.ZWSP, C.ZWJ, C.WORD_JOINER)) + labels[i][j:]
    p["host"] = ".".join(labels)
    return True


def _ev_bidi(p: dict[str, str], rng: random.Random) -> bool:
    labels = p["host"].split(".")
    i = _brand_label(labels)
    j = rng.randrange(1, max(2, len(labels[i])))
    labels[i] = labels[i][:j] + _BIDI_LRI + labels[i][j:] + _BIDI_PDI
    p["host"] = ".".join(labels)
    p["rest"] = (p["rest"] or "/").replace("/", "/" + _BIDI_RLO, 1)
    return True


def _ev_tld_swap(p: dict[str, str], rng: random.Random) -> bool:
    labels = p["host"].split(".")
    if len(labels) < 2:
        return False
    labels[-1] = rng.choice(("com", "org", "net", "io", "co"))
    p["host"] = ".".join(labels)
    return True


def _ev_path_padding(p: dict[str, str], rng: random.Random) -> bool:
    path, _, query = p["rest"].partition("?")
    path = (
        path.rstrip("/")
        + "/"
        + "/".join(rng.choice(_PAD_WORDS) for _ in range(rng.randrange(6, 10)))
    )
    q = "&".join(rng.sample(_PAD_QUERY, rng.randrange(6, len(_PAD_QUERY))))
    p["rest"] = (
        path
        + "/index.html?"
        + (query + "&" if query else "")
        + q
        + "&token="
        + "".join(rng.choice("0123456789abcdef") for _ in range(48))
    )
    return True


def _ev_case(p: dict[str, str], rng: random.Random) -> bool:
    p["host"] = C.random_case(p["host"], rng)
    p["scheme"] = C.random_case(p["scheme"], rng)
    path, sep, query = p["rest"].partition("?")
    p["rest"] = C.random_case(path, rng) + sep + query
    return True


def _pct_encode_path(path: str, rng: random.Random, *, double: bool) -> str:
    out = []
    for c in path:
        if c.isascii() and c.isalpha() and rng.random() < 0.6:
            out.append(("%25" + f"{ord(c):02X}") if double else f"%{ord(c):02X}")
        else:
            out.append(c)
    return "".join(out)


def _ev_pct(p: dict[str, str], rng: random.Random, *, double: bool = False) -> bool:
    path, sep, query = p["rest"].partition("?")
    if path in ("", "/"):
        path = "/login"
    p["rest"] = _pct_encode_path(path, rng, double=double) + sep + query
    return True


def _ev_punycode(p: dict[str, str], rng: random.Random) -> bool:
    if p["host"].isascii():
        return False
    try:
        p["host"] = p["host"].encode("idna").decode("ascii")
    except UnicodeError:
        return False
    return True


def _ev_fullstop(p: dict[str, str], rng: random.Random) -> bool:
    if "." not in p["host"]:
        return False
    p["host"] = p["host"].replace(".", "。")
    return True


def _ev_userinfo(p: dict[str, str], rng: random.Random) -> bool:
    if p["user"]:
        return False
    p["user"] = "accounts.google.com"
    return True


def _ev_control(p: dict[str, str], rng: random.Random) -> bool:
    p["rest"] = (p["rest"] or "/") + ("&" if "?" in p["rest"] else "?") + "ref=newsletter"
    return True


URL_EVASIONS: tuple[Evasion, ...] = (
    Evasion(
        "control", "No-op (adds ?ref=newsletter): measurement noise floor", _url_edit(_ev_control)
    ),
    Evasion(
        "homoglyph_swap",
        "Swap 1-2 brand letters for Cyrillic look-alikes",
        _url_edit(_ev_homoglyph),
    ),
    Evasion(
        "zero_width_insert",
        "Insert zero-width characters inside the brand label",
        _url_edit(_ev_zero_width),
    ),
    Evasion(
        "bidi_insert",
        "Insert bidi isolate / override controls in host and path",
        _url_edit(_ev_bidi),
    ),
    Evasion(
        "tld_swap", "Replace the TLD with a common, reputable-looking one", _url_edit(_ev_tld_swap)
    ),
    Evasion(
        "path_padding",
        "Pad with a deep benign-looking path and long query",
        _url_edit(_ev_path_padding),
    ),
    Evasion(
        "case_randomization", "Randomise the case of scheme, host and path", _url_edit(_ev_case)
    ),
    Evasion("percent_encoding", "Percent-encode letters of the path", _url_edit(_ev_pct)),
    Evasion(
        "double_percent_encoding",
        "Double percent-encode letters of the path",
        _url_edit(lambda p, r: _ev_pct(p, r, double=True)),
    ),
    Evasion("punycode_host", "Express an IDN host in xn-- form", _url_edit(_ev_punycode)),
    Evasion(
        "ideographic_full_stop",
        "Use U+3002 instead of '.' between host labels",
        _url_edit(_ev_fullstop),
    ),
    Evasion(
        "userinfo_decoy", "Prefix a trusted domain in the userinfo field", _url_edit(_ev_userinfo)
    ),
)


# ---- Text / injection evasions -------------------------------------------------
def _text_edit(
    fn: Callable[[str, random.Random], str | None],
) -> Callable[[ArtifactSpec, random.Random], ArtifactSpec | None]:
    def run(spec: ArtifactSpec, rng: random.Random) -> ArtifactSpec | None:
        if spec.kind != "text":
            return None
        out = fn(spec.value, rng)
        return ArtifactSpec("text", out) if out and out != spec.value else None

    return run


_COVER = "Here is the weather summary for tomorrow: mild with light showers in the afternoon."


def _ev_tag(t: str, rng: random.Random) -> str | None:
    # Tag characters encode ASCII only; skip non-ASCII payloads rather than mangle them.
    return _COVER + C.tag_encode(t) if t.isascii() else None


def _ev_bidi_words(t: str, rng: random.Random) -> str | None:
    return " ".join(_BIDI_LRI + w + _BIDI_PDI for w in t.split(" "))


def _ev_pad(t: str, rng: random.Random) -> str | None:
    return _FILLER * 25 + t + " " + _FILLER * 25


def _page_wrap(style: str) -> Callable[[ArtifactSpec, random.Random], ArtifactSpec | None]:
    def run(spec: ArtifactSpec, rng: random.Random) -> ArtifactSpec | None:
        if spec.kind != "text":
            return None
        frag = {
            "comment": f"<!-- {spec.value} -->",
            "css": f'<div style="display:none">{spec.value}</div>',
            "offscreen": f'<span style="position:absolute;left:-9999px">{spec.value}</span>',
        }[style]
        return ArtifactSpec(
            "page", C.html_page("Community news", body=frag), "https://pages.example/"
        )

    return run


TEXT_EVASIONS: tuple[Evasion, ...] = (
    Evasion(
        "control",
        "No-op (appends a harmless sentence): measurement noise floor",
        _text_edit(lambda t, r: t + " Thank you."),
    ),
    Evasion(
        "tag_smuggling", "Hide the payload as invisible Unicode tag characters", _text_edit(_ev_tag)
    ),
    Evasion(
        "zero_width_split",
        "Split every letter with a zero-width space",
        _text_edit(lambda t, r: C.zero_width_split(t)),
    ),
    Evasion(
        "zero_width_joiner",
        "Split every letter with a zero-width joiner",
        _text_edit(lambda t, r: C.zero_width_split(t, char=C.ZWJ)),
    ),
    Evasion("bidi_insert", "Wrap each word in bidi isolate controls", _text_edit(_ev_bidi_words)),
    Evasion(
        "homoglyph_swap",
        "Replace most Latin letters with Cyrillic look-alikes",
        _text_edit(lambda t, r: C.homoglyph_swap(t, r, rate=0.7)),
    ),
    Evasion("leet_speak", "Leet-speak substitution", _text_edit(lambda t, r: C.leet(t))),
    Evasion("case_randomization", "Randomise letter case", _text_edit(C.random_case)),
    Evasion(
        "base64_wrap",
        "Hide as base64 behind a decode request",
        _text_edit(lambda t, r: C.b64_wrap(t)),
    ),
    Evasion(
        "hex_wrap", "Hide as hex behind a decode request", _text_edit(lambda t, r: C.hex_wrap(t))
    ),
    Evasion("context_padding", "Bury the payload in ~4 KB of benign filler", _text_edit(_ev_pad)),
    Evasion("html_comment", "Move the payload into an HTML comment", _page_wrap("comment")),
    Evasion("html_display_none", "Move the payload into a display:none element", _page_wrap("css")),
    Evasion(
        "html_offscreen",
        "Move the payload off-screen with CSS positioning",
        _page_wrap("offscreen"),
    ),
)

EVASIONS = {"url": URL_EVASIONS, "injection": TEXT_EVASIONS}


# --------------------------------------------------------------------------- #
# Running
# --------------------------------------------------------------------------- #
def _flags(
    engine: Engine, spec: ArtifactSpec, layers: dict[str, dict[str, Any]], warn: float
) -> dict[str, bool]:
    """Layer name -> flagged, for one spec (a failing analysis counts as not flagged)."""
    out: dict[str, bool] = {}
    for name, over in layers.items():
        try:
            v = engine.analyze_sync(spec.to_artifact(), offline_options(**over))
            out[name] = v.risk >= warn
        except Exception:
            out[name] = False
    return out


def _seeds(suite: str, n: int, rng: random.Random, seed: int) -> list[EvalItem]:
    if suite == "url":
        pool = [i for i in load_items("lookalike", seed=seed) if i.spec.kind == "url"]
    else:
        pool = [
            i
            for i in load_items("injection", seed=seed)
            if i.label == 1
            and i.spec.kind == "text"
            and (i.category.startswith("direct_") or i.category == "indirect_text")
        ]
    rng.shuffle(pool)
    return pool[:n]


def _recovery(rows: list[dict[str, bool]], primary: str, secondary: str) -> dict[str, int]:
    """Counts describing how the two single layers and the fusion complement each other."""
    p_miss = [r for r in rows if not r[primary]]
    s_miss = [r for r in rows if not r[secondary]]
    return {
        f"{primary}_missed": len(p_miss),
        f"{secondary}_caught_when_{primary}_missed": sum(r[secondary] for r in p_miss),
        f"fusion_caught_when_{primary}_missed": sum(r["fusion"] for r in p_miss),
        f"{secondary}_missed": len(s_miss),
        f"{primary}_caught_when_{secondary}_missed": sum(r[primary] for r in s_miss),
        f"fusion_caught_when_{secondary}_missed": sum(r["fusion"] for r in s_miss),
        "both_layers_missed": sum(1 for r in rows if not r[primary] and not r[secondary]),
        "fusion_caught_when_both_missed": sum(
            r["fusion"] for r in rows if not r[primary] and not r[secondary]
        ),
        "fusion_lost_despite_a_layer": sum(
            1 for r in rows if (r[primary] or r[secondary]) and not r["fusion"]
        ),
    }


def _visible(s: str) -> str:
    """Escape invisible / control / tag characters so examples are readable and inert."""
    return "".join(
        c
        if unicodedata.category(c) not in ("Cf", "Cc", "Co", "Cn") or c == " "
        else f"\\u{{{ord(c):X}}}"
        for c in s
    )


def _technique_report(rows: list[dict[str, Any]], layer_names: list[str]) -> dict[str, Any]:
    """Aggregate per-variant flag rows (each has ``base``/``after`` dicts) for one technique."""
    n = len(rows)
    detect_after = {ly: safe_div(sum(r["after"][ly] for r in rows), n) for ly in layer_names}
    evasion_rate: dict[str, float | None] = {}
    evaded: dict[str, int] = {}
    caught_before: dict[str, int] = {}
    for ly in layer_names:
        base = [r for r in rows if r["base"][ly]]
        caught_before[ly] = len(base)
        evaded[ly] = sum(not r["after"][ly] for r in base)
        rate = safe_div(evaded[ly], len(base))
        evasion_rate[ly] = None if rate is None else round(rate, 4)
    singles = [x for x in layer_names if x != "fusion"]
    return {
        "n_eligible": n,
        "baseline_detected": caught_before,
        "detect_rate_after": {
            k: None if v is None else round(v, 4) for k, v in detect_after.items()
        },
        "evaded_count": evaded,
        "evasion_rate": evasion_rate,
        "recovery": _recovery([r["after"] for r in rows], singles[0], singles[1])
        if len(singles) == 2
        else None,
        "examples_evaded": [
            _visible(defang(r["variant"]))[:200] for r in rows if not r["after"]["fusion"]
        ][:3],
    }


def run_suite(
    suite: str,
    *,
    n: int = 100,
    seed: int = DEFAULT_SEED,
    techniques: Sequence[str] | None = None,
    engine: Engine | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Run one suite (``url`` or ``injection``) and return its JSON-safe report block."""
    if suite not in SUITES:
        raise ValueError(f"unknown suite {suite!r}; choose from {SUITES}")
    eng = engine or default_engine()
    warn = get_settings().suspicious_threshold
    layers = LAYERS[suite]
    layer_names = list(layers)
    rng = random.Random(seed)
    seeds = _seeds(suite, n, rng, seed)
    # Warm-up (model load etc.) so first-call work is not part of any measurement.
    if seeds:
        _flags(eng, seeds[0].spec, layers, warn)
    baseline: dict[str, dict[str, bool]] = {s.id: _flags(eng, s.spec, layers, warn) for s in seeds}
    eligible = [s for s in seeds if baseline[s.id]["fusion"]]
    evasions = [e for e in EVASIONS[suite] if techniques is None or e.name in techniques]
    out_t: dict[str, Any] = {}
    for ev in evasions:
        erng = random.Random(f"{seed}:{suite}:{ev.name}")
        rows: list[dict[str, Any]] = []
        for s in eligible:
            variant = ev.apply(s.spec, erng)
            if variant is None:
                continue
            rows.append(
                {
                    "id": s.id,
                    "variant": variant.value,
                    "base": baseline[s.id],
                    "after": _flags(eng, variant, layers, warn),
                }
            )
        if progress:
            progress(f"{suite}/{ev.name}: {len(rows)} variants")
        rep = _technique_report(rows, layer_names) if rows else {"n_eligible": 0}
        out_t[ev.name] = {"description": ev.description, **rep}
    return {
        "layers": layer_names,
        "seeds": {
            "requested": n,
            "drawn": len(seeds),
            "baseline_detected_by_fusion": len(eligible),
            "baseline_detected": {ly: sum(baseline[s.id][ly] for s in seeds) for ly in layer_names},
        },
        "techniques": out_t,
        "summary": _suite_summary(out_t, layer_names),
    }


def _suite_summary(techs: dict[str, Any], layer_names: list[str]) -> dict[str, Any]:
    """Pooled evasion rates (excluding the control) and the defence-in-depth headline."""
    real = {k: v for k, v in techs.items() if k != "control" and v.get("n_eligible")}
    pooled: dict[str, float | None] = {}
    for ly in layer_names:
        ev = sum(v["evaded_count"][ly] for v in real.values())
        base = sum(v["baseline_detected"][ly] for v in real.values())
        pooled[ly] = None if not base else round(ev / base, 4)
    worst = sorted(
        (
            (v["evasion_rate"]["fusion"], k)
            for k, v in real.items()
            if v["evasion_rate"]["fusion"] is not None
        ),
        reverse=True,
    )
    singles = [x for x in layer_names if x != "fusion"]
    tot: dict[str, int] = {}
    for v in real.values():
        for k, x in (v["recovery"] or {}).items():
            tot[k] = tot.get(k, 0) + x
    ctrl = techs.get("control", {})
    return {
        "pooled_evasion_rate": pooled,
        "control_evasion_rate": ctrl.get("evasion_rate") if ctrl.get("n_eligible") else None,
        "worst_techniques_for_fusion": [{"technique": k, "evasion_rate": r} for r, k in worst[:5]],
        "fully_evaded_techniques": [k for r, k in worst if r == 1.0],
        "defence_in_depth": None
        if len(singles) != 2
        else {
            k: tot.get(k, 0)
            for k in (
                f"{singles[0]}_missed",
                f"{singles[1]}_caught_when_{singles[0]}_missed",
                f"fusion_caught_when_{singles[0]}_missed",
                f"{singles[1]}_missed",
                f"{singles[0]}_caught_when_{singles[1]}_missed",
                f"fusion_caught_when_{singles[1]}_missed",
                "both_layers_missed",
                "fusion_caught_when_both_missed",
                "fusion_lost_despite_a_layer",
            )
        },
    }


def run_redteam(
    *,
    n: int = 100,
    seed: int = DEFAULT_SEED,
    suites: Sequence[str] = SUITES,
    techniques: Sequence[str] | None = None,
    engine: Engine | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Run the red-team harness and return the full JSON-safe robustness report."""
    t0 = time.perf_counter()
    eng = engine or default_engine()
    blocks = {
        s: run_suite(s, n=n, seed=seed, techniques=techniques, engine=eng, progress=progress)
        for s in suites
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "robustness",
        "name": "robustness",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seed": seed,
        "n_seeds_per_suite": n,
        "environment": _environment([ly for s in suites for ly in LAYERS[s]]),
        "suites": blocks,
        "caveats": list(CAVEATS),
        "run_seconds": round(time.perf_counter() - t0, 2),
    }


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.0f}%"


def to_markdown(report: dict[str, Any], *, heading_level: int = 2) -> str:
    """Render a robustness report as Markdown for ``docs/evaluation.md``."""
    h = "#" * heading_level
    L = [
        f"{h} Red-team robustness",
        "",
        "> **Read this first.** A scripted, non-adaptive adversary applied to items the "
        "detector already catches. A low evasion rate means these known tricks fail; it is "
        "not a proof of robustness. Evasion rate = share of previously-caught items that "
        "are no longer flagged (warn threshold, offline).",
        "",
    ]
    for suite, blk in report["suites"].items():
        layers = blk["layers"]
        sd = blk["seeds"]
        L += [
            f"{h}# {suite} suite",
            "",
            f"Seeds drawn {sd['drawn']}, caught by fusion before evasion "
            f"{sd['baseline_detected_by_fusion']} "
            f"(per layer: {', '.join(f'{k} {v}' for k, v in sd['baseline_detected'].items())}).",
            "",
            "| technique | n | "
            + " | ".join(f"evasion: {ly}" for ly in layers)
            + " | recovered by |",
            "|---|---|" + "---|" * (len(layers) + 1),
        ]
        singles = [x for x in layers if x != "fusion"]
        a, b = (singles + ["", ""])[:2]
        for name, t in blk["techniques"].items():
            if not t.get("n_eligible"):
                L.append(
                    f"| {name} | 0 | " + " | ".join("n/a" for _ in layers) + " | not applicable |"
                )
                continue
            rec = t["recovery"]
            parts = []
            if rec is None:
                pass
            elif rec[f"{a}_missed"]:
                parts.append(
                    f"{a} missed {rec[f'{a}_missed']}: "
                    f"{b} caught {rec[f'{b}_caught_when_{a}_missed']}, "
                    f"fusion {rec[f'fusion_caught_when_{a}_missed']}"
                )
            if rec and rec[f"{b}_missed"]:
                parts.append(
                    f"{b} missed {rec[f'{b}_missed']}: "
                    f"{a} caught {rec[f'{a}_caught_when_{b}_missed']}, "
                    f"fusion {rec[f'fusion_caught_when_{b}_missed']}"
                )
            L.append(
                f"| {name} | {t['n_eligible']} | "
                + " | ".join(_pct(t["evasion_rate"][ly]) for ly in layers)
                + " | "
                + ("; ".join(parts) or ("n/a (single layer)" if rec is None else "no layer missed"))
                + " |"
            )
        s = blk["summary"]
        L += [
            "",
            "Pooled evasion rate (control excluded): "
            + ", ".join(f"{k} {_pct(v)}" for k, v in s["pooled_evasion_rate"].items())
            + "; control (noise floor): "
            + (
                ", ".join(f"{k} {_pct(v)}" for k, v in s["control_evasion_rate"].items())
                if s["control_evasion_rate"]
                else "n/a"
            )
            + ".",
            "",
        ]
        if s["fully_evaded_techniques"]:
            L.append(
                "Techniques that fully evade the fused engine on this seed set: "
                + ", ".join(f"`{t}`" for t in s["fully_evaded_techniques"])
                + "."
            )
        did = s["defence_in_depth"]
        if did:
            L += [
                "",
                "Defence in depth (pooled variant counts): "
                + "; ".join(f"{k.replace('_', ' ')}: {v}" for k, v in did.items())
                + ".",
                "",
            ]
        ex = [
            (k, t["examples_evaded"][0])
            for k, t in blk["techniques"].items()
            if t.get("examples_evaded")
        ]
        if ex:
            L += ["Examples that evaded the fused engine (defanged, max 8):", ""]
            L += [f"- `{k}`: `{v}`" for k, v in ex[:8]]
            L.append("")
    L += [f"{h}# Caveats", ""] + [f"- {c}" for c in report["caveats"]]
    return "\n".join(L) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry: run the harness, write ``results/robustness.json`` (and optional Markdown)."""
    ap = argparse.ArgumentParser(
        prog="python -m uniphish.eval.redteam",
        description="Evasion / robustness testing of the engine.",
    )
    ap.add_argument("--n", type=int, default=100, help="seed items per suite")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--suites", nargs="+", default=list(SUITES), choices=SUITES)
    ap.add_argument("--out-dir", default=None, help="default: $UNIPHISH_RESULTS_DIR or ./results")
    ap.add_argument("--markdown", default=None)
    args = ap.parse_args(argv)
    rep = run_redteam(
        n=args.n, seed=args.seed, suites=args.suites, progress=lambda m: sys.stdout.write(m + "\n")
    )
    path = save_report(rep, args.out_dir, filename="robustness.json")
    sys.stdout.write(f"wrote {path}\n")
    if args.markdown:
        Path(args.markdown).write_text(to_markdown(rep), encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
