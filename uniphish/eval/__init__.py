"""Evaluation and red-team harness for the UniPhish engine.

Why this package exists: it produces the *evidence* behind the detector - labelled
synthetic benchmark sets, an honest metrics report (including a false-positive audit and
latency) and an evasion/red-team harness that shows which layer recovers each attack.

* :mod:`uniphish.eval.datasets` - labelled, reproducible, inert benchmark sets.
* :mod:`uniphish.eval.benchmark` - run the real engine, compute metrics, write
  ``results/eval_*.json`` and Markdown.
* :mod:`uniphish.eval.redteam` - apply evasions, write ``results/robustness.json``.

Run the full-size evaluation from the command line (not part of the unit tests)::

    python -m uniphish.eval.benchmark --dataset urls smishing injection email
    python -m uniphish.eval.redteam --n 100

The public names below are imported lazily so ``import uniphish.eval`` stays cheap.
"""

from __future__ import annotations

import importlib
from typing import Any

_LAZY: dict[str, tuple[str, str]] = {
    "ArtifactSpec": ("uniphish.eval.datasets", "ArtifactSpec"),
    "EvalItem": ("uniphish.eval.datasets", "EvalItem"),
    "DATASET_NAMES": ("uniphish.eval.datasets", "DATASET_NAMES"),
    "load_dataset": ("uniphish.eval.datasets", "load_dataset"),
    "load_items": ("uniphish.eval.datasets", "load_items"),
    "run_benchmark": ("uniphish.eval.benchmark", "run_benchmark"),
    "save_report": ("uniphish.eval.benchmark", "save_report"),
    "benchmark_to_markdown": ("uniphish.eval.benchmark", "to_markdown"),
    "run_redteam": ("uniphish.eval.redteam", "run_redteam"),
    "redteam_to_markdown": ("uniphish.eval.redteam", "to_markdown"),
}

__all__ = sorted(_LAZY)


def __getattr__(name: str) -> Any:
    try:
        module, attr = _LAZY[name]
    except KeyError:
        raise AttributeError(f"module 'uniphish.eval' has no attribute {name!r}") from None
    return getattr(importlib.import_module(module), attr)
