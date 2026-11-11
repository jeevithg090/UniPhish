"""Smoke test: ``import uniphish`` and a trivial scan work with ONLY the core deps.

Why: UniPhish promises a small core install (``pip install uniphish``) with every
heavyweight capability behind an extra (server, mcp, ai, vision, sandbox, yara, office,
intel, bot). If a core code path starts importing one of those unconditionally, the
bare install breaks while the developer environment (which has every extra) stays
green. This test runs a scan in a *subprocess* whose import system refuses every
optional distribution, so such a regression fails here, not on a user's machine.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# Top-level import names of every optional extra in pyproject.toml.
OPTIONAL_IMPORTS = [
    "fastapi",
    "uvicorn",
    "multipart",
    "mcp",
    "anthropic",
    "cv2",
    "PIL",
    "playwright",
    "yara",
    "oletools",
    "pyzipper",
    "stix2",
    "websockets",
    "telegram",
    "tensorflow",
    "sklearn",
    "pandas",
    "matplotlib",
    "optuna",
]

CHILD = textwrap.dedent(
    """
    import importlib.abc, json, socket, sys

    BLOCKED = set(json.loads(sys.argv[1]))

    class Block(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] in BLOCKED:
                raise ModuleNotFoundError(f"No module named {name!r}", name=name)
            return None

    sys.meta_path.insert(0, Block())

    def _deny(*a, **k):
        raise RuntimeError("network access attempted in an offline smoke test")
    socket.getaddrinfo = _deny
    socket.socket.connect = _deny

    import uniphish
    assert uniphish.__version__
    O = dict(timeout_s=300.0, analyzer_timeout_s=200.0)   # cold start can be slow on busy hosts
    out = {}
    v = uniphish.scan_url("https://p\\u0430ypal.com/signin", **O)
    out["url"] = [v.level.value, v.brand.brand if v.brand else None]
    v2 = uniphish.scan_url("https://www.wikipedia.org/wiki/Phishing", **O)
    out["benign"] = v2.level.value
    msg = "Your USPS parcel is held, pay at https://usps-redelivery.example.test/pay now"
    v3 = uniphish.scan_text(msg, **O)
    out["text"] = v3.level.value
    v4 = uniphish.scan_file(b"hello", "a.txt", **O)   # no OpenCV: QR must degrade, not fail
    out["file"] = v4.level.value
    v5 = uniphish.scan_page("<html><body><p>hi</p></body></html>", "https://example.org/", **O)
    out["page"] = v5.level.value
    out["failed"] = [
        (a.name, a.status, a.error) for x in (v, v2, v3, v4, v5) for a in x.analyzers
        if a.status in ("error", "timeout")
    ]
    out["imported_optional"] = sorted(m for m in sys.modules if m.split(".")[0] in BLOCKED)
    print("RESULT" + json.dumps(out))
    """
)


def test_import_is_light() -> None:
    """``import uniphish`` itself pulls in nothing heavy (analyzers load lazily)."""
    code = (
        "import sys, uniphish; "
        "heavy = [m for m in ('numpy', 'httpx', 'fastapi', 'cv2', 'anthropic', 'pydantic') "
        "if m in sys.modules]; print(heavy)"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    assert proc.stdout.strip() == "[]"


def test_version_is_exposed_and_consistent() -> None:
    import uniphish
    from uniphish.core.types import ENGINE_VERSION

    assert uniphish.__version__ == ENGINE_VERSION
    for name in uniphish.__all__:
        assert hasattr(uniphish, name)


def test_trivial_scan_in_process() -> None:
    import uniphish

    v = uniphish.scan_url(
        "https://example.org/", online=False, timeout_s=180, analyzer_timeout_s=120
    )
    assert v.level.value == "benign" and 0 <= v.score <= 100


def test_core_deps_only_scan(tmp_path: Path) -> None:
    """Every scan kind works when every optional extra is un-importable."""
    env = {
        **os.environ,
        "UNIPHISH_DATA_DIR": str(tmp_path / "data"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    env.pop("UNIPHISH_ONLINE", None)
    env.pop("ANTHROPIC_API_KEY", None)
    proc = subprocess.run(
        [sys.executable, "-c", CHILD, json.dumps(OPTIONAL_IMPORTS)],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    line = next(ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT"))
    out = json.loads(line[len("RESULT") :])
    assert out["url"] == ["malicious", "paypal"]
    assert out["benign"] == "benign"
    assert out["text"] in ("suspicious", "malicious")
    assert out["file"] == "benign" and out["page"] == "benign"
    assert out["failed"] == [], out["failed"]
    assert out["imported_optional"] == [], "a core path imported an optional dependency"


@pytest.mark.parametrize(
    "module", ["uniphish.core.engine", "uniphish.core.scoring", "uniphish.core.types"]
)
def test_core_modules_import_without_server_extras(module: str) -> None:
    code = f"import sys; sys.modules['fastapi'] = None; import {module}"
    subprocess.run(
        [sys.executable, "-c", code], cwd=REPO, check=True, capture_output=True, timeout=120
    )
