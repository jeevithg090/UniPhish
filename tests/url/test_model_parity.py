"""Cross-runtime parity: the NumPy forward pass must match the on-device JS model.

``tests/url/parity_runner.js`` runs the canonical ``extension/model.js`` with the
shipped weights over a fixed, diverse URL set and prints each phishing probability as
JSON. This test runs that oracle (skipping cleanly if Node is not installed), then
asserts the pure-NumPy :class:`uniphish.url.model.UrlModel` reproduces every probability
within 1e-4. That 1e-4 budget is the contract the spec sets; in practice the agreement
is ~1e-7 because both runtimes accumulate dot products in float64.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import numpy as np
import pytest

from uniphish.url.model import UrlModel

_RUNNER = Path(__file__).resolve().parent / "parity_runner.js"
_TOL = 1e-4


def _run_node_oracle() -> list[dict]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed; skipping JS<->NumPy parity test")
    if not _RUNNER.is_file():  # pragma: no cover - defensive
        pytest.skip(f"parity runner missing: {_RUNNER}")
    proc = subprocess.run(
        [node, str(_RUNNER)], capture_output=True, text=True, timeout=120, check=False
    )
    if proc.returncode != 0:
        raise AssertionError(f"parity_runner.js failed (exit {proc.returncode}):\n{proc.stderr}")
    data = json.loads(proc.stdout)
    assert isinstance(data, list) and len(data) >= 20, "expected ~25 diverse URLs from the oracle"
    return data


def test_numpy_matches_js_within_tolerance() -> None:
    rows = _run_node_oracle()
    urls = [r["url"] for r in rows]
    js = np.array([r["prob"] for r in rows], dtype=np.float64)

    model = UrlModel()
    got = model.predict(urls).astype(np.float64)

    diff = np.abs(got - js)
    worst = int(diff.argmax())
    assert diff.max() < _TOL, (
        f"max |NumPy - JS| = {diff.max():.2e} exceeds {_TOL:g} at "
        f"{urls[worst]!r} (js={js[worst]:.6f}, numpy={got[worst]:.6f})"
    )


def test_parity_covers_diverse_scripts_and_lengths() -> None:
    """The oracle set must actually exercise the hard cases, or parity is vacuous."""
    rows = _run_node_oracle()
    urls = [r["url"] for r in rows]
    blob = "".join(urls)
    # non-ASCII scripts present
    assert any(ord(c) > 0x3040 for c in blob), "expected CJK/Hangul in the parity set"
    assert any(0x0600 <= ord(c) <= 0x06FF for c in blob), "expected Arabic in the parity set"
    assert any(0x0400 <= ord(c) <= 0x04FF for c in blob), "expected Cyrillic in the parity set"
    assert any(0x0900 <= ord(c) <= 0x097F for c in blob), "expected Devanagari in the parity set"
    # a URL longer than the 600-byte model window (truncation parity)
    assert any(len(u.encode("utf-8")) > 600 for u in urls), "expected a >600-byte URL"
    # a punycode host and an IP host
    assert any("xn--" in u for u in urls)
    assert any("192.168" in u or "0x" in u for u in urls)
