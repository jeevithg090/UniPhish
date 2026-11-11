"""Registry contract tests: every built-in analyzer is well-formed and discoverable.

Why: the dashboard, docs and ``uniphish catalog`` generate the detection catalog from
``Analyzer.signals`` and the engine discovers analyzers through the ``@register``
registry. A malformed analyzer (no signals declared, duplicate name, unknown kind,
bad stage, a signal id outside the naming scheme) silently degrades all of that, so
the contract is enforced here for whatever is registered, including analyzers added
later by other contributors.
"""

from __future__ import annotations

import importlib
import re

import pytest

import uniphish.analyzers as analyzers_pkg
from uniphish.analyzers import BUILTIN_MODULES, load_builtin_analyzers
from uniphish.core.analyzer import REGISTRY, Analyzer, register, signal_catalog
from uniphish.core.engine import Engine
from uniphish.core.types import Artifact, ArtifactKind, Level

SIGNAL_ID = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")
NAMESPACES = {
    "url",
    "unicode",
    "brand",
    "ml",
    "page",
    "kit",
    "email",
    "auth",
    "social",
    "file",
    "qr",
    "infra",
    "rep",
    "agent",
    "fetch",
}
VALID_STAGES = {0, 10, 20, 30}
# Built-in modules that may legitimately fail to import (none today: every optional
# dependency is handled *inside* its analyzer, so all modules must load).
OPTIONAL_MODULES: set[str] = set()

load_builtin_analyzers()
_ITEMS = sorted(REGISTRY.items())
_IDS = [n for n, _ in _ITEMS]


class TestRegistry:
    def test_every_builtin_module_loads_with_the_full_dependency_set(self) -> None:
        loaded = load_builtin_analyzers()
        missing = [m for m in BUILTIN_MODULES if m not in loaded and m not in OPTIONAL_MODULES]
        assert not missing, f"built-in analyzer modules failed to load: {missing}"

    def test_registry_is_not_empty_and_covers_every_artifact_kind(self) -> None:
        assert len(REGISTRY) >= 10
        covered = {k for cls in REGISTRY.values() for k in cls.kinds}
        assert covered == set(ArtifactKind)

    @pytest.mark.parametrize(("name", "cls"), _ITEMS, ids=_IDS)
    def test_analyzer_declares_a_valid_contract(self, name: str, cls: type[Analyzer]) -> None:
        assert issubclass(cls, Analyzer)
        assert cls.name == name and re.fullmatch(r"[a-z][a-z0-9_]*", name)
        assert isinstance(cls.kinds, frozenset) and cls.kinds
        assert all(isinstance(k, ArtifactKind) for k in cls.kinds)
        assert isinstance(cls.stage, int) and cls.stage in VALID_STAGES, cls.stage
        assert cls.description.strip(), "description is shown in the UI and docs"
        # a blocking analyzer must supply analyze_sync; an async one must override analyze
        if cls.blocking:
            assert cls.analyze_sync is not Analyzer.analyze_sync
        else:
            assert (
                cls.analyze is not Analyzer.analyze or cls.analyze_sync is not Analyzer.analyze_sync
            )
        if cls.requires_detonation:
            assert cls.requires_online, "detonation implies network access"
        if cls.requires_online:
            assert cls.stage >= 10, "online analyzers run after static analysis"
        assert isinstance(cls(), Analyzer), "the engine instantiates analyzers with no arguments"

    @pytest.mark.parametrize(("name", "cls"), _ITEMS, ids=_IDS)
    def test_analyzer_declares_its_signals(self, name: str, cls: type[Analyzer]) -> None:
        assert cls.signals, f"{name} must declare a non-empty signals dict"
        for sid, title in cls.signals.items():
            assert SIGNAL_ID.match(sid), f"{name}: bad signal id {sid!r}"
            assert sid.split(".")[0] in NAMESPACES, f"{name}: {sid!r} outside the namespace list"
            assert isinstance(title, str) and title.strip(), f"{name}: {sid} has no title"
            assert len(title) <= 70, f"{name}: title for {sid} is {len(title)} chars (max 70)"

    def test_analyzer_names_are_unique(self) -> None:
        names = [cls.name for cls in REGISTRY.values()]
        assert len(names) == len(set(names))
        assert all(REGISTRY[k].name == k for k in REGISTRY)

    def test_signal_ids_are_unique_across_analyzers(self) -> None:
        seen: dict[str, str] = {}
        clashes: list[tuple[str, str, str]] = []
        for name, cls in _ITEMS:
            for sid in cls.signals:
                if sid in seen:
                    clashes.append((sid, seen[sid], name))
                seen[sid] = name
        assert not clashes, f"signal ids declared by more than one analyzer: {clashes}"

    def test_signal_catalog_is_non_empty_and_consistent(self) -> None:
        cat = signal_catalog()
        assert len(cat) >= 100
        assert len(cat) == sum(len(cls.signals) for cls in REGISTRY.values())
        for sid, info in cat.items():
            assert info["analyzer"] in REGISTRY
            assert info["title"] == REGISTRY[info["analyzer"]].signals[sid]

    def test_engine_discovers_exactly_the_registry_ordered_by_stage(self) -> None:
        eng = Engine()
        assert set(eng.analyzer_names()) == set(REGISTRY)
        stages = [a.stage for a in eng.analyzers]
        assert stages == sorted(stages)

    def test_register_rejects_malformed_analyzers(self) -> None:
        before = set(REGISTRY)
        with pytest.raises(TypeError):

            @register
            class _NoName(Analyzer):
                kinds = frozenset({ArtifactKind.URL})

        with pytest.raises(TypeError):

            @register
            class _NoKinds(Analyzer):
                name = "no_kinds_test"
                kinds = frozenset()

        assert set(REGISTRY) == before


class TestTolerantLoading:
    """Loading built-ins must survive missing optional dependencies and broken modules."""

    @staticmethod
    def _patch(monkeypatch: pytest.MonkeyPatch, extra: tuple[str, ...], raises: dict) -> None:
        real = importlib.import_module

        def fake(name: str, package: str | None = None):
            if name in raises:
                raise raises[name]
            return real(name, package)

        monkeypatch.setattr(analyzers_pkg, "BUILTIN_MODULES", (*BUILTIN_MODULES[:2], *extra))
        monkeypatch.setattr(analyzers_pkg.importlib, "import_module", fake)

    def test_absent_module_is_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mod = "uniphish.analyzers.not_written_yet"
        err = ModuleNotFoundError(f"No module named {mod!r}", name=mod)
        self._patch(monkeypatch, (mod,), {mod: err})
        ok = analyzers_pkg.load_builtin_analyzers()
        assert mod not in ok and BUILTIN_MODULES[0] in ok

    def test_missing_optional_dependency_is_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mod = "uniphish.analyzers.needs_cv2"
        self._patch(
            monkeypatch, (mod,), {mod: ModuleNotFoundError("No module named 'cv2'", name="cv2")}
        )
        ok = analyzers_pkg.load_builtin_analyzers()
        assert mod not in ok and ok == list(BUILTIN_MODULES[:2])

    def test_module_raising_an_arbitrary_error_does_not_break_loading(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mod = "uniphish.analyzers.explodes"
        self._patch(monkeypatch, (mod, "uniphish.analyzers.url"), {mod: RuntimeError("boom")})
        ok = analyzers_pkg.load_builtin_analyzers()
        assert mod not in ok and "uniphish.analyzers.url" in ok

    def test_engine_still_detects_when_an_optional_analyzer_is_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Dropping an analyzer (a missing optional dependency) degrades gracefully."""
        monkeypatch.delitem(REGISTRY, "file")
        eng = Engine()
        assert "file" not in eng.analyzer_names()
        v = eng.analyze_sync(Artifact.from_url("https://pаypal.com/signin"))
        assert v.level is Level.MALICIOUS
