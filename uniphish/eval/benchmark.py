"""Benchmark runner: run the real engine over a labelled set and report honestly.

Why this module exists: claims about a detector are only worth the evidence behind
them. This runner pushes every item of a synthetic benchmark (see
:mod:`uniphish.eval.datasets`) through the *same* :class:`~uniphish.core.engine.Engine`
that ships in the product - offline, no network - and reports:

* precision / recall / F1 / accuracy / FPR / FNR / MCC with 95% Wilson intervals, at
  two operating points: **warn** (risk >= suspicious threshold) and **block**
  (risk >= malicious threshold);
* per-category, per-language and per-script breakdowns and the confusion matrix;
* latency (ms/scan, mean / p50 / p95) with one un-timed warm-up scan so model and asset
  loading are not billed to the first sample;
* a calibration view: predicted risk versus observed malicious rate, ECE and Brier,
  both raw and prevalence-adjusted (the engine prior is 12%, benchmarks are ~50%);
* a **false-positive audit** on the legitimate items - the hardest and most important
  number - including which signals cause each false alarm;
* optional layer ablation (ML only / rules only / fusion).

Honest framing (see ``docs/paper_vs_reality.md``): these are small, synthetic sets
whose malicious URLs come from the same transformation families the detector was built
around, so recall is an optimistic ceiling, and the benign set is not a sample of real
traffic. Every report embeds those caveats, the dataset hash, and the precision
projected to realistic base rates. Nothing here fabricates or hides results.

CLI::

    python -m uniphish.eval.benchmark --dataset urls smishing injection email
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import sys
import time
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from uniphish.core import scoring
from uniphish.core.analyzer import AnalysisOptions
from uniphish.core.config import get_settings
from uniphish.core.engine import Engine, default_engine
from uniphish.core.types import ENGINE_VERSION, Level
from uniphish.eval import _stats as S
from uniphish.eval.datasets import (
    DATASET_NAMES,
    DEFAULT_PER_CATEGORY,
    DEFAULT_SEED,
    EvalItem,
    dataset_sha256,
    load_items,
    summarize,
)

log = logging.getLogger("uniphish.eval")

SCHEMA_VERSION = 1
BASE_RATES = (0.5, 0.05, 0.01, 0.001)

CAVEATS: tuple[str, ...] = (
    "Synthetic, small benchmark: results are indicative, not a field estimate. Confidence "
    "intervals are wide for small categories.",
    "The malicious URLs are generated from the same transformation families the detector's "
    "rules were designed around, so recall is an optimistic ceiling for known attack "
    "constructions, not a measure of resistance to novel ones (see the red-team report).",
    "The benign set is hand-built and is NOT a sample of real traffic. Real false-positive "
    "rates depend on the long tail of legitimate sites and must be measured on your own "
    "traffic; 'precision at base rate' shows how fast precision falls when phishing is rare.",
    "All runs are offline: no DNS, RDAP, TLS, reputation-feed or page-fetch evidence is used, "
    "so online-only signals (domain age, certificates, live feeds) are not evaluated.",
    "Malicious hosts use reserved TLDs (.test/.example/.invalid and IDN test TLDs), which "
    "differ from real phishing TLD distributions; TLD-risk behaviour is therefore not "
    "representative.",
    "Per docs/paper_vs_reality.md: we do not claim a general multilingual accuracy advantage "
    "that this data cannot support.",
)

# Layer ablation per dataset: name -> AnalysisOptions field overrides.
DATASET_LAYERS: dict[str, dict[str, dict[str, Any]]] = {
    "urls": {"ml_only": {"enable": ["ml"]}, "rules_only": {"disable": ["ml"]}},
    "lookalike": {"ml_only": {"enable": ["ml"]}, "rules_only": {"disable": ["ml"]}},
    "benign": {"ml_only": {"enable": ["ml"]}, "rules_only": {"disable": ["ml"]}},
    "smishing": {"text_only": {"enable": ["text"]}, "without_text": {"disable": ["text"]}},
    "injection": {
        "injection_only": {"enable": ["injection"]},
        "without_injection": {"disable": ["injection"]},
    },
    "email": {"email_only": {"enable": ["email"]}, "without_email": {"disable": ["email"]}},
}


# --------------------------------------------------------------------------- #
# Running
# --------------------------------------------------------------------------- #
def offline_options(**overrides: Any) -> AnalysisOptions:
    """Safe benchmark options: offline, no fetch/detonation, nothing persisted."""
    base: dict[str, Any] = {
        "online": False,
        "fetch_pages": False,
        "detonate": False,
        "persist": False,
        "explain": False,
        "ai_report": False,
    }
    base.update(overrides)
    return AnalysisOptions.from_dict(base)


def _run_one(engine: Engine, item: EvalItem, options: AnalysisOptions) -> dict[str, Any]:
    """Analyse one item; never raises (errors become fail-open benign results)."""
    t0 = time.perf_counter()
    try:
        v = engine.analyze_sync(item.spec.to_artifact(), options)
    except Exception as e:
        return {
            "id": item.id,
            "category": item.category,
            "label": item.label,
            "kind": item.spec.kind,
            "target": item.spec.target,
            "lang": item.lang,
            "script": item.script,
            "tags": list(item.tags),
            "risk": 0.0,
            "score": 0,
            "logit": scoring.PRIOR_LOGIT,
            "level": Level.BENIGN.value,
            "signals": [],
            "wall_ms": (time.perf_counter() - t0) * 1000.0,
            "engine_ms": 0.0,
            "error": f"{type(e).__name__}: {e}"[:200],
        }
    wall = (time.perf_counter() - t0) * 1000.0
    sigs = sorted(
        v.signals,
        key=lambda s: abs(s.contribution if s.contribution is not None else s.weight),
        reverse=True,
    )[:8]
    return {
        "id": item.id,
        "category": item.category,
        "label": item.label,
        "kind": item.spec.kind,
        "target": item.spec.target,
        "lang": item.lang,
        "script": item.script,
        "tags": list(item.tags),
        "risk": v.risk,
        "score": v.score,
        "logit": v.logit,
        "level": v.level.value,
        "signals": [{"id": s.id, "contribution": s.contribution, "weight": s.weight} for s in sigs],
        "wall_ms": wall,
        "engine_ms": v.duration_ms,
        "error": None,
    }


def run_items(
    items: Sequence[EvalItem],
    *,
    engine: Engine | None = None,
    options: AnalysisOptions | None = None,
    warmup: bool = True,
    progress: Callable[[int, int], None] | None = None,
) -> list[dict[str, Any]]:
    """Run the engine over ``items`` and return one result dict per item (input order).

    An un-timed warm-up scan runs first so lazy model/asset loading is excluded from the
    latency sample.
    """
    eng = engine or default_engine()
    opts = options or offline_options()
    if warmup and items:
        _run_one(eng, items[0], opts)
    out = []
    for i, it in enumerate(items):
        out.append(_run_one(eng, it, opts))
        if progress:
            progress(i + 1, len(items))
    return out


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #
def _flag(results: Sequence[dict[str, Any]], threshold: float) -> list[bool]:
    return [r["risk"] >= threshold for r in results]


def metrics_at(results: Sequence[dict[str, Any]], threshold: float) -> dict[str, Any]:
    """Headline metrics with an item flagged when ``risk >= threshold``."""
    labels = [r["label"] for r in results]
    m = S.rates(S.confusion(labels, _flag(results, threshold)))
    m["threshold"] = threshold
    m["base_rate_projection"] = [
        {"base_rate": b, "precision": S.precision_at_base_rate(m["recall"], m["fpr"], b)}
        for b in BASE_RATES
    ]
    return m


def group_breakdown(
    results: Sequence[dict[str, Any]], key: str, warn: float, block: float
) -> dict[str, dict[str, Any]]:
    """Per-group (category / lang / script) confusion at the warn threshold plus block rate."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for r in results:
        groups.setdefault(str(r[key]), []).append(r)
    out: dict[str, dict[str, Any]] = {}
    for g, rs in sorted(groups.items()):
        labels = [r["label"] for r in rs]
        c = S.confusion(labels, _flag(rs, warn))
        pos = [r for r in rs if r["label"]]
        neg = [r for r in rs if not r["label"]]
        out[g] = {
            "n": len(rs),
            "positives": len(pos),
            "negatives": len(neg),
            **c,
            "recall": S._r(S.safe_div(c["tp"], len(pos))),
            "fpr": S._r(S.safe_div(c["fp"], len(neg))),
            "accuracy": S._r(S.safe_div(c["tp"] + c["tn"], len(rs))),
            "block_rate": S._r(S.safe_div(sum(r["risk"] >= block for r in pos), len(pos)))
            if pos
            else None,
            "mean_score": round(sum(r["score"] for r in rs) / len(rs), 1),
        }
    return out


def tag_breakdown(
    results: Sequence[dict[str, Any]], warn: float, block: float
) -> dict[str, dict[str, Any]]:
    """Metrics for items with versus without each tag (hard, reserved_tld, ambiguous...)."""
    tags = sorted({t for r in results for t in r["tags"]})
    out: dict[str, dict[str, Any]] = {}
    for t in tags:
        keyed = [{**r, "_g": "with" if t in r["tags"] else "without"} for r in results]
        out[t] = group_breakdown(keyed, "_g", warn, block)
    return out


def calibration_view(results: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Raw and prevalence-adjusted calibration (see module docstring for why both)."""
    labels = [r["label"] for r in results]
    raw = S.calibration(labels, [r["risk"] for r in results])
    out: dict[str, Any] = {"raw": raw, "prevalence": None, "prevalence_adjusted": None}
    if labels and 0 < sum(labels) < len(labels):
        prev = sum(labels) / len(labels)
        shift = scoring.logit(prev) - scoring.PRIOR_LOGIT
        adj = [scoring.sigmoid(r["logit"] + shift) for r in results]
        out["prevalence"] = round(prev, 4)
        out["prevalence_adjusted"] = S.calibration(labels, adj)
        out["note"] = (
            "Engine risk is a posterior under a 12% prior; the adjusted view re-bases "
            "the log-odds to this set's prevalence so it can be compared with the "
            "observed rate."
        )
    return out


def false_positive_audit(
    results: Sequence[dict[str, Any]], warn: float, block: float
) -> dict[str, Any]:
    """Audit of the legitimate (label 0) items: who is flagged and which signals did it."""
    neg = [r for r in results if not r["label"]]
    flagged = [r for r in neg if r["risk"] >= warn]
    hard = [r for r in neg if "hard" in r["tags"]]
    easy = [r for r in neg if "hard" not in r["tags"]]
    top_counter: Counter[str] = Counter()
    any_counter: Counter[str] = Counter()
    for r in flagged:
        pos_sigs = [s for s in r["signals"] if (s["contribution"] or s["weight"]) > 0]
        if pos_sigs:
            top_counter[pos_sigs[0]["id"]] += 1
        for s in pos_sigs:
            any_counter[s["id"]] += 1
    n_neg = len(neg)

    def sub(rs: list[dict[str, Any]]) -> dict[str, Any]:
        k = sum(r["risk"] >= warn for r in rs)
        ci = S.wilson_interval(k, len(rs))
        return {
            "n": len(rs),
            "flagged": k,
            "fpr": S._r(S.safe_div(k, len(rs))),
            "ci95": [round(x, 4) for x in ci] if ci else None,
        }

    return {
        "n_benign": n_neg,
        "flagged_warn": len(flagged),
        "blocked": sum(r["risk"] >= block for r in neg),
        "fpr_warn": S._r(S.safe_div(len(flagged), n_neg)),
        "fpr_block": S._r(S.safe_div(sum(r["risk"] >= block for r in neg), n_neg)),
        "ci95": [round(x, 4) for x in (S.wilson_interval(len(flagged), n_neg) or ())] or None,
        "rule_of_three_upper95": S._r(S.rule_of_three(n_neg)) if n_neg and not flagged else None,
        "hard_subset": sub(hard),
        "easy_subset": sub(easy),
        "by_category": {c: v for c, v in group_breakdown(neg, "category", warn, block).items()},
        "top_signal_of_false_positives": dict(top_counter.most_common(10)),
        "signals_in_false_positives": dict(any_counter.most_common(15)),
        "false_positives": [
            {
                "id": r["id"],
                "category": r["category"],
                "target": r["target"],
                "score": r["score"],
                "level": r["level"],
                "signals": [
                    s["id"] for s in r["signals"] if (s["contribution"] or s["weight"]) > 0
                ][:5],
            }
            for r in sorted(flagged, key=lambda r: -r["risk"])
        ],
    }


def _misses(
    results: Sequence[dict[str, Any]], warn: float, limit: int = 40
) -> list[dict[str, Any]]:
    fn = [r for r in results if r["label"] and r["risk"] < warn]
    return [
        {
            "id": r["id"],
            "category": r["category"],
            "target": r["target"],
            "score": r["score"],
            "signals": [s["id"] for s in r["signals"]][:4],
        }
        for r in sorted(fn, key=lambda r: r["risk"])[:limit]
    ]


def summarize_results(results: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Metrics block (operating points, groups, calibration, FP audit, latency)."""
    st = get_settings()
    warn, block = st.suspicious_threshold, st.malicious_threshold
    labels = [r["label"] for r in results]
    lat_wall = [r["wall_ms"] for r in results]
    lat_eng = [r["engine_ms"] for r in results]
    return {
        "operating_points": {
            "warn": metrics_at(results, warn),
            "block": metrics_at(results, block),
        },
        "roc_auc": S.roc_auc(labels, [r["risk"] for r in results]),
        "level_distribution": dict(Counter(r["level"] for r in results)),
        "by_category": group_breakdown(results, "category", warn, block),
        "by_language": group_breakdown(results, "lang", warn, block),
        "by_script": group_breakdown(results, "script", warn, block),
        "by_tag": tag_breakdown(results, warn, block),
        "calibration": calibration_view(results),
        "latency": {
            "wall_ms": S.latency_summary(lat_wall),
            "engine_ms": S.latency_summary(lat_eng),
            "note": "wall_ms includes asyncio loop setup per scan; engine_ms is the "
            "engine's own measurement. Offline, single process.",
        },
        "false_positive_audit": false_positive_audit(results, warn, block),
        "false_negatives": _misses(results, warn),
        "errors": [{"id": r["id"], "error": r["error"]} for r in results if r["error"]],
    }


def _environment(layers: Sequence[str]) -> dict[str, Any]:
    st = get_settings()
    env: dict[str, Any] = {
        "engine_version": ENGINE_VERSION,
        "python": platform.python_version(),
        "platform": platform.platform(terse=True),
        "offline": True,
        "suspicious_threshold": st.suspicious_threshold,
        "malicious_threshold": st.malicious_threshold,
        "prior_logit": scoring.PRIOR_LOGIT,
        "layers_evaluated": list(layers),
    }
    try:
        env["analyzers"] = default_engine().analyzer_names()
    except Exception:
        env["analyzers"] = []
    try:
        from uniphish.url.model import get_model

        info = get_model().info()
        env["model"] = {k: info[k] for k in ("name", "version", "params", "sha256") if k in info}
    except Exception as e:
        env["model"] = {"unavailable": f"{type(e).__name__}"}
    return env


def run_benchmark(
    dataset: str | Sequence[EvalItem],
    *,
    name: str | None = None,
    seed: int = DEFAULT_SEED,
    per_category: int = DEFAULT_PER_CATEGORY,
    limit: int | None = None,
    ablation: bool = False,
    engine: Engine | None = None,
    options: AnalysisOptions | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> dict[str, Any]:
    """Run a benchmark and return a JSON-safe report dict.

    Args:
        dataset: a dataset name from :data:`~uniphish.eval.datasets.DATASET_NAMES` or an
            explicit item list (``name`` then labels the report).
        limit: keep at most ``limit`` items per label, round-robin over categories, for
            quick smoke runs (the full-size run is the CLI).
        ablation: also score single-layer variants (see :data:`DATASET_LAYERS`).
    """
    if isinstance(dataset, str):
        items = load_items(dataset, seed=seed, per_category=per_category)
        ds_name = dataset
    else:
        items, ds_name = list(dataset), name or "custom"
    if limit is not None:
        items = _stratified_head(items, limit)
    if not items:
        raise ValueError("empty dataset")
    eng = engine or default_engine()
    opts = options or offline_options()
    t0 = time.perf_counter()
    results = run_items(items, engine=eng, options=opts, progress=progress)
    layers = DATASET_LAYERS.get(ds_name, {}) if ablation else {}
    ablation_out: dict[str, Any] = {}
    for lname, over in layers.items():
        lres = run_items(items, engine=eng, options=offline_options(**over), warmup=False)
        ablation_out[lname] = {"options": over, **_ablation_summary(lres)}
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "benchmark",
        "name": ds_name,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": {
            **{k: v for k, v in summarize(items).items() if k != "categories"},
            "seed": seed,
            "per_category": per_category,
            "limit": limit,
            "sha256": dataset_sha256(items),
        },
        "environment": _environment(["fusion", *layers]),
        "primary_operating_point": "warn",
        **summarize_results(results),
        "ablation": ablation_out,
        "caveats": list(CAVEATS),
        "run_seconds": round(time.perf_counter() - t0, 2),
    }
    return report


def _stratified_head(items: Sequence[EvalItem], limit: int) -> list[EvalItem]:
    """First ``limit`` items of each label, round-robin over categories (keeps diversity)."""
    out: list[EvalItem] = []
    for label in (1, 0):
        pools: dict[str, list[EvalItem]] = {}
        for it in items:
            if it.label == label:
                pools.setdefault(it.category, []).append(it)
        picked: list[EvalItem] = []
        while len(picked) < limit and any(pools.values()):
            for cat in list(pools):
                if pools[cat] and len(picked) < limit:
                    picked.append(pools[cat].pop(0))
        out.extend(picked)
    return out


def _ablation_summary(results: Sequence[dict[str, Any]]) -> dict[str, Any]:
    st = get_settings()
    m = metrics_at(results, st.suspicious_threshold)
    keep = ("n", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "accuracy", "fpr", "fnr")
    return {
        "warn": {k: m[k] for k in keep},
        "roc_auc": S.roc_auc([r["label"] for r in results], [r["risk"] for r in results]),
    }


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def results_dir(path: str | Path | None = None) -> Path:
    """Output directory: explicit ``path``, ``$UNIPHISH_RESULTS_DIR``, else ``./results``."""
    return Path(path or os.environ.get("UNIPHISH_RESULTS_DIR") or "results")


def save_report(
    report: dict[str, Any], out_dir: str | Path | None = None, filename: str | None = None
) -> Path:
    """Write ``report`` as JSON (default ``results/eval_<name>.json``) and return the path."""
    d = results_dir(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    p = d / (filename or f"eval_{report['name']}.json")
    p.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, sort_keys=False) + "\n", encoding="utf-8"
    )
    return p


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def _ci(ci: Sequence[float] | None) -> str:
    return "n/a" if not ci else f"{ci[0] * 100:.1f}-{ci[1] * 100:.1f}%"


def _cell(s: Any) -> str:
    return S.defang(str(s)).replace("|", "\\|").replace("\n", " ")


def to_markdown(report: dict[str, Any], *, heading_level: int = 2) -> str:
    """Render a benchmark report as Markdown for ``docs/evaluation.md``."""
    h = "#" * heading_level
    ds, env = report["dataset"], report["environment"]
    warn = report["operating_points"]["warn"]
    block = report["operating_points"]["block"]
    L: list[str] = [f"{h} Benchmark: `{report['name']}`", ""]
    L.append(
        f"> **Read this first.** Small synthetic set ({ds['n']} items, {ds['malicious']} "
        f"malicious / {ds['benign']} benign). Numbers are indicative, not field estimates; "
        f"recall on generated look-alikes is an optimistic ceiling and the benign set is "
        f"not real traffic. See the caveats below and `docs/paper_vs_reality.md`."
    )
    L += [
        "",
        f"Dataset sha256 `{ds['sha256'][:16]}`, seed {ds['seed']}, engine "
        f"{env['engine_version']}, thresholds warn >= {env['suspicious_threshold']}, "
        f"block >= {env['malicious_threshold']}, offline.",
        "",
    ]
    L += [
        "| operating point | precision | recall (95% CI) | F1 | accuracy "
        "| FPR (95% CI) | FNR | MCC |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for lab, m in (("warn (suspicious+)", warn), ("block (malicious)", block)):
        L.append(
            f"| {lab} | {_pct(m['precision'])} | {_pct(m['recall'])} ({_ci(m['recall_ci95'])}) | "
            f"{_pct(m['f1'])} | {_pct(m['accuracy'])} | {_pct(m['fpr'])} ({_ci(m['fpr_ci95'])}) | "
            f"{_pct(m['fnr'])} | {m['mcc'] if m['mcc'] is not None else 'n/a'} |"
        )
    L += [
        "",
        f"Confusion at warn: TP {warn['tp']}, FP {warn['fp']}, TN {warn['tn']}, FN {warn['fn']}. "
        f"ROC AUC {report['roc_auc'] if report['roc_auc'] is not None else 'n/a'}.",
        "",
    ]
    L += [
        f"{h}# Precision at realistic base rates",
        "",
        "Precision on a balanced benchmark overstates what users see when phishing is rare "
        "(precision = TPR*b / (TPR*b + FPR*(1-b))).",
        "",
        "| malicious base rate | precision at warn |",
        "|---|---|",
    ]
    for row in warn["base_rate_projection"]:
        L.append(f"| {row['base_rate'] * 100:g}% | {_pct(row['precision'])} |")
    L += [
        "",
        f"{h}# Per category (warn threshold)",
        "",
        "| category | n | pos | neg | recall | FPR | block rate | mean score |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for c, g in report["by_category"].items():
        L.append(
            f"| {c} | {g['n']} | {g['positives']} | {g['negatives']} | {_pct(g['recall'])} | "
            f"{_pct(g['fpr'])} | {_pct(g['block_rate'])} | {g['mean_score']} |"
        )
    langs = report["by_language"]
    if len(langs) > 1:
        L += [
            "",
            f"{h}# Per language (warn threshold)",
            "",
            "| lang | n | recall | FPR |",
            "|---|---|---|---|",
        ]
        for c, g in langs.items():
            L.append(f"| {c} | {g['n']} | {_pct(g['recall'])} | {_pct(g['fpr'])} |")
    if len(report.get("by_tag", {})) and any(
        t in report["by_tag"] for t in ("hard", "reserved_tld")
    ):
        L += [
            "",
            f"{h}# Tagged subsets (warn threshold)",
            "",
            "| tag | subset | n | recall | FPR |",
            "|---|---|---|---|---|",
        ]
        for t, groups in report["by_tag"].items():
            for sub, g in groups.items():
                L.append(f"| {t} | {sub} | {g['n']} | {_pct(g['recall'])} | {_pct(g['fpr'])} |")
    if report.get("ablation"):
        L += [
            "",
            f"{h}# Layer ablation (warn threshold)",
            "",
            "| layer | recall | FPR | F1 | AUC |",
            "|---|---|---|---|---|",
        ]
        L.append(
            f"| fusion (all analyzers) | {_pct(warn['recall'])} | {_pct(warn['fpr'])} | "
            f"{_pct(warn['f1'])} | {report['roc_auc']} |"
        )
        for ln, a in report["ablation"].items():
            w = a["warn"]
            L.append(
                f"| {ln} | {_pct(w['recall'])} | {_pct(w['fpr'])} | {_pct(w['f1'])} "
                f"| {a['roc_auc']} |"
            )
    fp = report["false_positive_audit"]
    L += [
        "",
        f"{h}# False-positive audit (legitimate items)",
        "",
        f"{fp['flagged_warn']} of {fp['n_benign']} benign items flagged at warn "
        f"(FPR {_pct(fp['fpr_warn'])}, 95% CI {_ci(fp['ci95'])}); {fp['blocked']} blocked "
        f"(FPR {_pct(fp['fpr_block'])}). Hard subset: {fp['hard_subset']['flagged']}/"
        f"{fp['hard_subset']['n']}; easy subset: {fp['easy_subset']['flagged']}/"
        f"{fp['easy_subset']['n']}.",
    ]
    if fp["rule_of_three_upper95"] is not None:
        L.append(
            f"Zero false positives still only bounds the true FPR below ~"
            f"{_pct(fp['rule_of_three_upper95'])} (rule of three)."
        )
    if fp["top_signal_of_false_positives"]:
        L += ["", "Leading signal behind each false positive:", ""]
        L += [f"- `{k}`: {v}" for k, v in fp["top_signal_of_false_positives"].items()]
    if fp["false_positives"]:
        L += ["", "| id | target | score | signals |", "|---|---|---|---|"]
        for r in fp["false_positives"][:25]:
            L.append(
                f"| {r['id']} | {_cell(r['target'][:80])} | {r['score']} "
                f"| {', '.join(r['signals'])} |"
            )
        if len(fp["false_positives"]) > 25:
            L.append(f"| ... | {len(fp['false_positives']) - 25} more in the JSON report | | |")
    if report["false_negatives"]:
        L += [
            "",
            f"{h}# Missed malicious items (lowest scores first, max 15)",
            "",
            "| id | target | score |",
            "|---|---|---|",
        ]
        for r in report["false_negatives"][:15]:
            L.append(f"| {r['id']} | {_cell(r['target'][:80])} | {r['score']} |")
    cal = report["calibration"]
    adj = cal.get("prevalence_adjusted") or cal["raw"]
    L += [
        "",
        f"{h}# Calibration",
        "",
        f"Raw ECE {cal['raw']['ece']}, Brier {cal['raw']['brier']}. "
        + (
            f"Prevalence-adjusted (set prevalence {cal['prevalence']}): ECE {adj['ece']}, "
            f"Brier {adj['brier']}."
            if cal.get("prevalence_adjusted")
            else ""
        ),
        "",
        "| predicted risk bin | n | mean predicted | observed malicious rate |",
        "|---|---|---|---|",
    ]
    for b in cal["raw"]["bins"]:
        if b["n"]:
            L.append(
                f"| {b['lo']:.1f}-{b['hi']:.1f} | {b['n']} | {b['mean_predicted']} "
                f"| {b['observed_rate']} |"
            )
    lat = report["latency"]["wall_ms"]
    L += [
        "",
        f"{h}# Latency",
        "",
        f"Per scan, offline, one process: mean {lat['mean']} ms, p50 {lat['p50']} ms, "
        f"p95 {lat['p95']} ms, max {lat['max']} ms (n={lat['n']}).",
        "",
        f"{h}# Caveats",
        "",
    ]
    L += [f"- {c}" for c in report["caveats"]]
    if report["errors"]:
        L += [
            "",
            f"{len(report['errors'])} item(s) raised an error and were counted as benign "
            f"(fail-open): " + ", ".join(e["id"] for e in report["errors"][:10]),
        ]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
DEFAULT_SUITE = ("urls", "smishing", "injection", "email")


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry: run benchmark(s), write ``results/eval_<name>.json``, optionally Markdown."""
    ap = argparse.ArgumentParser(
        prog="python -m uniphish.eval.benchmark",
        description="Benchmark the UniPhish engine on synthetic sets.",
    )
    ap.add_argument("--dataset", nargs="+", default=list(DEFAULT_SUITE), choices=DATASET_NAMES)
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--per-category", type=int, default=DEFAULT_PER_CATEGORY)
    ap.add_argument("--limit", type=int, default=None, help="items per label (smoke runs)")
    ap.add_argument("--no-ablation", action="store_true")
    ap.add_argument("--out-dir", default=None, help="default: $UNIPHISH_RESULTS_DIR or ./results")
    ap.add_argument("--markdown", default=None, help="also write the combined Markdown here")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.WARNING)
    md: list[str] = []
    for name in args.dataset:
        rep = run_benchmark(
            name,
            seed=args.seed,
            per_category=args.per_category,
            limit=args.limit,
            ablation=not args.no_ablation,
        )
        path = save_report(rep, args.out_dir)
        w = rep["operating_points"]["warn"]
        sys.stdout.write(
            f"{name}: n={rep['dataset']['n']} recall={w['recall']} fpr={w['fpr']} "
            f"f1={w['f1']} p95={rep['latency']['wall_ms']['p95']}ms -> {path}\n"
        )
        md.append(to_markdown(rep, heading_level=2))
    if args.markdown:
        Path(args.markdown).write_text("\n".join(md), encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
