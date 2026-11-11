"""The analyzer contract and registry.

An analyzer is a small class that inspects one kind of :class:`Artifact` and returns
an :class:`AnalyzerResult`. Analyzers are registered with :func:`register` and
discovered by the engine; adding a detection capability never requires touching the
engine.

    from uniphish.core.analyzer import Analyzer, AnalyzerResult, register
    from uniphish.core.types import ArtifactKind, Signal

    @register
    class ExampleAnalyzer(Analyzer):
        name = "example"
        kinds = frozenset({ArtifactKind.URL})
        signals = {"example.bad_word": "URL contains 'evil'"}

        async def analyze(self, artifact, ctx):
            if "evil" in artifact.url:
                return AnalyzerResult(signals=[Signal(
                    id="example.bad_word", title="Contains 'evil'", weight=1.0,
                    category="url")])
            return AnalyzerResult()

Stages
------
Analyzers run in ascending ``stage`` order; all analyzers of one stage run
concurrently. A later stage can read earlier results for the same artifact through
``ctx.results`` (e.g. the page analyzer reads the URL analyzer's brand match).
Convention: ``0`` = pure/static analysis, ``10`` = enrichment needing earlier
results, ``20`` = network enrichment (DNS, RDAP, TLS, feeds), ``30`` = active
fetching / detonation.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar, TypeVar

from uniphish.core.config import Settings, get_settings
from uniphish.core.types import Artifact, ArtifactKind, BrandMatch, Indicator, Signal

log = logging.getLogger("uniphish.analyzer")

T = TypeVar("T")


@dataclass
class AnalysisOptions:
    """Per-request switches. Defaults are safe: offline, no detonation."""

    online: bool | None = None          # None -> Settings.online
    fetch_pages: bool = False           # statically fetch URL content (requires online)
    detonate: bool = False              # render in a sandboxed headless browser (requires online)
    explain: bool = False               # expensive explanations (e.g. byte saliency)
    ai_report: bool = False             # LLM-written analyst narrative
    max_depth: int = 2                  # child-artifact recursion depth
    max_children: int = 25              # per artifact
    timeout_s: float = 30.0             # whole-analysis budget
    analyzer_timeout_s: float = 10.0    # per analyzer
    enable: frozenset[str] | None = None   # allowlist of analyzer names (None = all)
    disable: frozenset[str] = frozenset()
    persist: bool = True                # let hooks (store) persist the verdict

    def is_online(self, settings: Settings) -> bool:
        return settings.online if self.online is None else self.online

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> AnalysisOptions:
        if not d:
            return cls()
        known = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        for k in ("enable", "disable"):
            if k in known and known[k] is not None:
                known[k] = frozenset(known[k])
        return cls(**known)


@dataclass
class AnalyzerResult:
    """What an analyzer returns. Every field is optional."""

    signals: list[Signal] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    children: list[Artifact] = field(default_factory=list)
    brand: BrandMatch | None = None
    techniques: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)   # merged into Verdict.meta


@dataclass
class AnalysisContext:
    """Everything an analyzer may need besides the artifact itself."""

    options: AnalysisOptions
    settings: Settings = field(default_factory=get_settings)
    depth: int = 0
    parent: Artifact | None = None
    results: dict[str, AnalyzerResult] = field(default_factory=dict)  # earlier stages
    shared: dict[str, Any] = field(default_factory=dict)              # per-artifact memo

    @property
    def online(self) -> bool:
        return self.options.is_online(self.settings)

    def memo(self, key: str, factory: Callable[[], T]) -> T:
        """Compute-once cache shared by analyzers of the same artifact."""
        if key not in self.shared:
            self.shared[key] = factory()
        return self.shared[key]

    async def amemo(self, key: str, factory: Callable[[], Awaitable[T]]) -> T:
        """Async variant of :meth:`memo` (safe under concurrent analyzers)."""
        lock = self.shared.setdefault(f"__lock__{key}", asyncio.Lock())
        async with lock:
            if key not in self.shared:
                self.shared[key] = await factory()
        return self.shared[key]

    def brand(self) -> BrandMatch | None:
        """Best brand match produced by any earlier-stage analyzer."""
        best = None
        for r in self.results.values():
            if r.brand and (best is None or r.brand.confidence > best.confidence):
                best = r.brand
        return best


class Analyzer(ABC):
    """Base class for all analyzers. Subclasses set the ClassVars and implement analyze()."""

    name: ClassVar[str]
    kinds: ClassVar[frozenset[ArtifactKind]]
    stage: ClassVar[int] = 0
    requires_online: ClassVar[bool] = False
    requires_detonation: ClassVar[bool] = False
    blocking: ClassVar[bool] = False         # True -> analyze_sync() runs in a worker thread
    description: ClassVar[str] = ""
    signals: ClassVar[dict[str, str]] = {}   # catalog: signal id -> title (for docs / UI)

    def applies(self, artifact: Artifact, ctx: AnalysisContext) -> bool:
        """Cheap pre-check; return False to skip this artifact."""
        return True

    async def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        """Inspect ``artifact`` and return evidence. Must not raise for bad input.

        Override this for I/O-bound (async) analyzers. Pure/CPU-bound analyzers may
        instead override :meth:`analyze_sync`; with ``blocking = True`` the engine
        runs it in a worker thread so it never stalls the event loop.
        """
        if self.blocking:
            return await asyncio.to_thread(self.analyze_sync, artifact, ctx)
        return self.analyze_sync(artifact, ctx)

    def analyze_sync(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        """Synchronous implementation hook (see :meth:`analyze`)."""
        raise NotImplementedError(f"{type(self).__name__} must implement analyze or analyze_sync")


REGISTRY: dict[str, type[Analyzer]] = {}

A = TypeVar("A", bound=type[Analyzer])


def register(cls: A) -> A:
    """Class decorator adding an analyzer to the global registry."""
    if not getattr(cls, "name", None):
        raise TypeError(f"{cls.__name__} must define a non-empty 'name'")
    if not getattr(cls, "kinds", None):
        raise TypeError(f"{cls.__name__} must define 'kinds'")
    if cls.name in REGISTRY and REGISTRY[cls.name] is not cls:
        log.debug("analyzer %s re-registered by %s", cls.name, cls.__qualname__)
    REGISTRY[cls.name] = cls
    return cls


def signal_catalog() -> dict[str, dict[str, str]]:
    """All signal ids declared by registered analyzers -> {title, analyzer}."""
    out: dict[str, dict[str, str]] = {}
    for name, cls in sorted(REGISTRY.items()):
        for sid, title in cls.signals.items():
            out[sid] = {"title": title, "analyzer": name}
    return out
