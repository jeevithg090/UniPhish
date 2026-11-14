"""The analysis engine: artifact -> analyzers (staged, concurrent) -> fused Verdict.

    from uniphish.core.engine import Engine
    from uniphish.core.types import Artifact

    engine = Engine()
    verdict = engine.analyze_sync(Artifact.from_url("https://pаypal.com/login"))
    print(verdict.level, verdict.score, verdict.summary)

Guarantees
----------
* **Fault isolation** — an analyzer that raises or times out is recorded in
  ``Verdict.analyzers`` and never breaks the verdict.
* **Bounded work** — global time budget, per-analyzer timeout, recursion depth,
  per-artifact child cap and cycle detection (an email linking to a page that links
  back is analysed once).
* **Explainability** — the verdict's log-odds equals PRIOR + Σ signal contributions.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from uniphish.core import events, mitre, scoring
from uniphish.core.analyzer import (
    REGISTRY,
    AnalysisContext,
    AnalysisOptions,
    Analyzer,
    AnalyzerResult,
)
from uniphish.core.config import Settings, get_settings
from uniphish.core.types import (
    AnalyzerRun,
    Artifact,
    ArtifactKind,
    BrandMatch,
    Indicator,
    Level,
    Signal,
    Verdict,
)

log = logging.getLogger("uniphish.engine")

Hook = Callable[[Verdict, Artifact, AnalysisOptions], Awaitable[None] | None]


@dataclass
class _Run:
    deadline: float
    visited: set[str] = field(default_factory=set)
    child_sem: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(8))

    def remaining(self) -> float:
        return self.deadline - time.monotonic()


class Engine:
    """Orchestrates analyzers. Thread-safe to share; cheap to construct."""

    def __init__(
        self,
        settings: Settings | None = None,
        analyzers: Iterable[Analyzer] | None = None,
        hooks: Iterable[Hook] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        if analyzers is None:
            from uniphish.analyzers import load_builtin_analyzers

            load_builtin_analyzers()
            analyzers = [cls() for cls in REGISTRY.values()]
        self.analyzers: list[Analyzer] = sorted(analyzers, key=lambda a: (a.stage, a.name))
        self.hooks: list[Hook] = list(hooks or [])

    # ------------------------------------------------------------------ API #
    def add_hook(self, hook: Hook) -> None:
        """Register a callback run after every *top-level* verdict (e.g. persistence)."""
        self.hooks.append(hook)

    def analyzer_names(self) -> list[str]:
        return [a.name for a in self.analyzers]

    def warm_up(self) -> None:
        """Eagerly load heavy, cached data (brand KB, Unicode tables, reference lists,
        the CNN weights) so the cost is paid once here instead of inside the first
        analysis, where it could exceed a per-analyzer time budget. Best-effort: every
        loader is optional and failures are ignored."""
        warmers: list[tuple[str, Callable[[], Any]]] = []

        def _add(mod: str, fn_name: str, *args: Any) -> None:
            def _call() -> Any:
                import importlib

                return getattr(importlib.import_module(mod), fn_name)(*args)

            warmers.append((f"{mod}.{fn_name}", _call))

        _add("uniphish.url.brandkb", "get_kb")
        _add("uniphish.url.confusables", "brand_skeleton", "warmup")
        _add("uniphish.url.scripts", "restriction_level", "warmup")
        _add("uniphish.assets.lists", "find_lures", "login verify account")
        _add("uniphish.assets.lists", "tld_risk", "com")
        _add("uniphish.url.model", "get_model")
        for label, fn in warmers:
            try:
                fn()
            except Exception as e:  # optional dep / missing asset -> skip
                log.debug("warm_up skipped %s: %s", label, e)

    async def analyze(self, artifact: Artifact, options: AnalysisOptions | None = None) -> Verdict:
        opts = options or AnalysisOptions()
        run = _Run(deadline=time.monotonic() + opts.timeout_s)
        verdict = await self._analyze(artifact, opts, run, depth=0, parent=None)
        await self._run_hooks(verdict, artifact, opts)
        events.publish("verdict", _event_payload(verdict))
        return verdict

    def analyze_sync(self, artifact: Artifact, options: AnalysisOptions | None = None) -> Verdict:
        """Blocking wrapper usable from sync code, even inside a running event loop."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.analyze(artifact, options))
        box: dict[str, Any] = {}

        def _worker() -> None:
            try:
                box["v"] = asyncio.run(self.analyze(artifact, options))
            except BaseException as e:  # pragma: no cover - re-raised below
                box["e"] = e

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t.join()
        if "e" in box:
            raise box["e"]
        return box["v"]

    # convenience ---------------------------------------------------------- #
    async def analyze_url(self, url: str, **opts: Any) -> Verdict:
        return await self.analyze(Artifact.from_url(url), AnalysisOptions.from_dict(opts))

    async def analyze_text(self, text: str, **opts: Any) -> Verdict:
        return await self.analyze(Artifact.from_text(text), AnalysisOptions.from_dict(opts))

    async def analyze_email(self, raw: bytes | str, **opts: Any) -> Verdict:
        return await self.analyze(Artifact.from_email(raw), AnalysisOptions.from_dict(opts))

    async def analyze_page(self, html: str | bytes, url: str | None = None, **opts: Any) -> Verdict:
        return await self.analyze(Artifact.from_page(html, url), AnalysisOptions.from_dict(opts))

    async def analyze_file(self, data: bytes, filename: str | None = None, **opts: Any) -> Verdict:
        return await self.analyze(
            Artifact.from_file(data, filename), AnalysisOptions.from_dict(opts)
        )

    # ------------------------------------------------------------ internals #
    def _select(self, artifact: Artifact, ctx: AnalysisContext) -> list[Analyzer]:
        o = ctx.options
        out = []
        for a in self.analyzers:
            if artifact.kind not in a.kinds:
                continue
            if o.enable is not None and a.name not in o.enable:
                continue
            if a.name in o.disable:
                continue
            if a.requires_online and not ctx.online:
                continue
            if a.requires_detonation and not (o.detonate and ctx.online):
                continue
            out.append(a)
        return out

    async def _run_one(
        self, a: Analyzer, artifact: Artifact, ctx: AnalysisContext, run: _Run
    ) -> tuple[AnalyzerResult | None, AnalyzerRun]:
        budget = min(ctx.options.analyzer_timeout_s, run.remaining())
        if budget <= 0:
            return None, AnalyzerRun(name=a.name, status="skipped", error="time budget exhausted")
        t0 = time.perf_counter()
        try:
            if not a.applies(artifact, ctx):
                return None, AnalyzerRun(name=a.name, status="skipped")
            res = await asyncio.wait_for(a.analyze(artifact, ctx), timeout=budget)
            ms = (time.perf_counter() - t0) * 1000
            res = res or AnalyzerResult()
            for s in res.signals:
                s.analyzer = s.analyzer or a.name
            return res, AnalyzerRun(
                name=a.name, status="ok", duration_ms=round(ms, 2), signals=len(res.signals)
            )
        except asyncio.TimeoutError:
            ms = (time.perf_counter() - t0) * 1000
            return None, AnalyzerRun(
                name=a.name,
                status="timeout",
                duration_ms=round(ms, 2),
                error=f"exceeded {budget:.1f}s",
            )
        except Exception as e:  # fault isolation: one analyzer never breaks a verdict
            ms = (time.perf_counter() - t0) * 1000
            log.exception("analyzer %s failed on %s", a.name, artifact.id)
            return None, AnalyzerRun(
                name=a.name,
                status="error",
                duration_ms=round(ms, 2),
                error=f"{type(e).__name__}: {e}"[:300],
            )

    async def _analyze(
        self,
        artifact: Artifact,
        opts: AnalysisOptions,
        run: _Run,
        depth: int,
        parent: Artifact | None,
    ) -> Verdict:
        t0 = time.perf_counter()
        run.visited.add(artifact.id)
        ctx = AnalysisContext(options=opts, settings=self.settings, depth=depth, parent=parent)
        selected = self._select(artifact, ctx)
        runs: list[AnalyzerRun] = []
        for stage in sorted({a.stage for a in selected}):
            batch = [a for a in selected if a.stage == stage]
            outcomes = await asyncio.gather(*(self._run_one(a, artifact, ctx, run) for a in batch))
            for a, (res, ar) in zip(batch, outcomes, strict=True):
                runs.append(ar)
                if res is not None:
                    ctx.results[a.name] = res

        signals: list[Signal] = []
        indicators: dict[tuple[str, str], Indicator] = {}
        children: list[Artifact] = []
        techniques: list[str] = []
        meta: dict[str, Any] = {}
        brand: BrandMatch | None = None
        for res in ctx.results.values():
            signals.extend(res.signals)
            for ind in res.indicators:
                indicators.setdefault(ind.key(), ind)
            children.extend(res.children)
            techniques.extend(res.techniques)
            meta.update(res.meta)
            if res.brand and (brand is None or res.brand.confidence > brand.confidence):
                brand = res.brand

        # ---- children (links, attachments, QR payloads, redirects) -------- #
        child_verdicts: list[Verdict] = []
        if depth < opts.max_depth and children:
            uniq: list[Artifact] = []
            for c in children:
                if c.id in run.visited or any(c.id == u.id for u in uniq):
                    continue
                uniq.append(c)
            dropped = max(0, len(uniq) - opts.max_children)
            if dropped:
                meta["children_dropped"] = dropped
            uniq = uniq[: opts.max_children]
            for c in uniq:
                run.visited.add(c.id)
                c.parent_id = c.parent_id or artifact.id

            async def _child(c: Artifact) -> Verdict | None:
                if run.remaining() <= 0:
                    return None
                async with run.child_sem:
                    return await self._analyze(c, opts, run, depth + 1, artifact)

            child_verdicts = [v for v in await asyncio.gather(*(_child(c) for c in uniq)) if v]
            for cv in child_verdicts:
                w = scoring.child_weight(cv)
                if w > 0:
                    signals.append(
                        Signal(
                            id=f"engine.child.{cv.kind.value}",
                            title=f"Contains {cv.level.value} {cv.kind.value}"
                            + (f" ({cv.origin})" if cv.origin else ""),
                            detail=f"{cv.target[:200]} — {cv.summary}",
                            weight=w,
                            category="child",
                            analyzer="engine",
                            evidence={"child_id": cv.id, "child_score": cv.score},
                            mitre=sorted({m.id for m in cv.mitre})[:6],
                        )
                    )
                if (
                    brand is None
                    and cv.brand
                    and not cv.brand.official
                    and cv.level is not Level.BENIGN
                ):
                    brand = cv.brand
                techniques.extend(t for t in cv.techniques if cv.level is not Level.BENIGN)

        fused = scoring.fuse(signals, self.settings)
        signals.sort(key=lambda s: abs(s.contribution or 0.0), reverse=True)
        mitre_ids = {m for s in signals if (s.contribution or 0) > 0 for m in s.mitre}
        for cv in child_verdicts:
            if cv.level is not Level.BENIGN:
                mitre_ids.update(m.id for m in cv.mitre)

        verdict = Verdict(
            kind=artifact.kind,
            target=artifact.label,
            artifact_id=artifact.id,
            origin=artifact.origin,
            signals=signals,
            indicators=list(indicators.values()),
            brand=brand,
            techniques=list(dict.fromkeys(techniques)),
            mitre=mitre.resolve_many(mitre_ids),
            children=child_verdicts,
            analyzers=runs,
            meta=meta,
            duration_ms=round((time.perf_counter() - t0) * 1000, 2),
            **fused,
        )
        verdict.summary = scoring.summarize(verdict)
        return verdict

    async def _run_hooks(self, verdict: Verdict, artifact: Artifact, opts: AnalysisOptions) -> None:
        for hook in self.hooks:
            try:
                r = hook(verdict, artifact, opts)
                if asyncio.iscoroutine(r):
                    await r
            except Exception:
                log.exception("verdict hook %r failed", hook)


def _event_payload(v: Verdict) -> dict[str, Any]:
    return {
        "id": v.id,
        "kind": v.kind.value,
        "target": v.target,
        "score": v.score,
        "level": v.level.value,
        "summary": v.summary,
        "brand": v.brand.name if v.brand else None,
        "techniques": v.techniques[:5],
    }


_default: Engine | None = None
_default_lock = threading.Lock()


def default_engine(*, warm: bool = True) -> Engine:
    """Process-wide engine with all built-in analyzers (lazy, warmed once)."""
    global _default
    with _default_lock:
        if _default is None:
            eng = Engine()
            if warm:
                eng.warm_up()
            _default = eng
        return _default


__all__ = ["Engine", "default_engine", "ArtifactKind"]
