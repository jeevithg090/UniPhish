"""Shared helpers: config loading, seeding, JSON I/O, timing."""

from __future__ import annotations

import json
import os
import random
import time
from contextlib import contextmanager
from typing import Any, Dict

import numpy as np
import yaml


def load_config(path: str = "configs/default.yaml", overrides: Dict[str, Any] | None = None) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    if overrides:
        cfg = _deep_update(cfg, overrides)
    return cfg


def _deep_update(base: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in new.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = _deep_update(base[k], v)
        else:
            base[k] = v
    return base


def set_seed(seed: int = 42) -> None:
    """Seed python, numpy and tensorflow for reproducibility."""
    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)
    try:
        import tensorflow as tf

        tf.random.set_seed(seed)
        tf.keras.utils.set_random_seed(seed)
    except ImportError:
        pass


def save_json(obj: Any, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)


def load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


@contextmanager
def timer(label: str = "elapsed"):
    start = time.perf_counter()
    yield
    print(f"[{label}] {time.perf_counter() - start:.3f}s")
