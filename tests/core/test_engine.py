"""Contract tests for the core engine, scoring and data model."""

from __future__ import annotations

import asyncio

import pytest

from uniphish.core import scoring
from uniphish.core.analyzer import AnalysisOptions, Analyzer, AnalyzerResult
from uniphish.core.engine import Engine
from uniphish.core.types import (
    Artifact,
    ArtifactKind,
    ArtifactTooLarge,
    Indicator,
    IndicatorType,
    Level,
    Severity,
    Signal,
)


def _sig(sid, w, cat="test", **kw):
    return Signal(id=sid, title=sid, weight=w, category=cat, **kw)


class Fixed(Analyzer):
    name = "fixed"
    kinds = frozenset({ArtifactKind.URL, ArtifactKind.TEXT})

    def __init__(self, signals=(), children=(), stage=0, name=None):
        self._signals = list(signals)
        self._children = list(children)
        type(self).stage = stage
        if name:
            self.name = name

    async def analyze(self, artifact, ctx):
        return AnalyzerResult(signals=[s.model_copy() for s in self._signals],
                              children=list(self._children),
                              indicators=[Indicator(type=IndicatorType.URL,
                                                    value=artifact.url or "x")])


class Boom(Analyzer):
    name = "boom"
    kinds = frozenset({ArtifactKind.URL})

    async def analyze(self, artifact, ctx):
        raise RuntimeError("kaboom")


class Slow(Analyzer):
    name = "slow"
    kinds = frozenset({ArtifactKind.URL})

    async def analyze(self, artifact, ctx):
        await asyncio.sleep(5)
        return AnalyzerResult()


class SyncBlocking(Analyzer):
    name = "sync"
    kinds = frozenset({ArtifactKind.URL})
    blocking = True

    def analyze_sync(self, artifact, ctx):
        return AnalyzerResult(signals=[_sig("sync.hit", 1.0)])


def test_no_signals_is_benign():
    v = Engine(analyzers=[]).analyze_sync(Artifact.from_url("https://example.com/"))
    assert v.level is Level.BENIGN and v.score == round(100 * scoring.sigmoid(scoring.PRIOR_LOGIT))


def test_strong_signal_is_malicious_and_decomposes():
    eng = Engine(analyzers=[Fixed([_sig("a", 4.5, "brand"), _sig("b", 1.0, "url")])])
    v = eng.analyze_sync(Artifact.from_url("https://x.test/"))
    assert v.level is Level.MALICIOUS
    total = scoring.PRIOR_LOGIT + sum(s.contribution for s in v.signals)
    assert abs(total - v.logit) < 1e-3          # exact decomposition
    assert v.signals[0].id == "a"               # sorted by |contribution|
    assert v.signals[0].severity is Severity.CRITICAL


def test_correlated_evidence_is_damped():
    many_weak = [_sig(f"w{i}", 1.0, "url") for i in range(6)]
    v = Engine(analyzers=[Fixed(many_weak)]).analyze_sync(Artifact.from_url("https://x.test/"))
    assert sum(s.contribution for s in v.signals) < 2.3   # geometric series < 1/(1-0.55)


def test_benign_evidence_lowers_risk():
    v = Engine(analyzers=[Fixed([_sig("ml", 2.0, "ml"), _sig("top", -3.0, "reputation")])]) \
        .analyze_sync(Artifact.from_url("https://x.test/"))
    assert v.level is Level.BENIGN


def test_faulty_and_slow_analyzers_are_isolated():
    eng = Engine(analyzers=[Boom(), Slow(), Fixed([_sig("ok", 1.0)])])
    v = eng.analyze_sync(Artifact.from_url("https://x.test/"),
                         AnalysisOptions(analyzer_timeout_s=0.2))
    status = {r.name: r.status for r in v.analyzers}
    assert status["boom"] == "error" and status["slow"] == "timeout" and status["fixed"] == "ok"
    assert any(s.id == "ok" for s in v.signals)


def test_blocking_analyzer_runs_in_thread():
    v = Engine(analyzers=[SyncBlocking()]).analyze_sync(Artifact.from_url("https://x.test/"))
    assert [s.id for s in v.signals] == ["sync.hit"]


def test_children_propagate_and_cycles_stop():
    bad_child = Artifact.from_url("https://child.test/")

    class Parent(Analyzer):
        name = "parent"
        kinds = frozenset({ArtifactKind.TEXT})

        async def analyze(self, artifact, ctx):
            return AnalyzerResult(children=[bad_child, bad_child])

    class ChildAn(Analyzer):
        name = "child"
        kinds = frozenset({ArtifactKind.URL})

        async def analyze(self, artifact, ctx):
            # links back to itself -> must not recurse forever
            return AnalyzerResult(signals=[_sig("evil", 5.0, "brand")], children=[bad_child])

    v = Engine(analyzers=[Parent(), ChildAn()]).analyze_sync(Artifact.from_text("hello"))
    assert len(v.children) == 1                      # deduplicated
    assert v.children[0].level is Level.MALICIOUS
    assert v.level is Level.MALICIOUS                # inherited via engine.child.url
    assert any(s.id == "engine.child.url" for s in v.signals)


def test_enable_disable_and_online_gating():
    class Net(Analyzer):
        name = "net"
        kinds = frozenset({ArtifactKind.URL})
        requires_online = True

        async def analyze(self, artifact, ctx):
            return AnalyzerResult(signals=[_sig("net", 1.0)])

    eng = Engine(analyzers=[Net(), Fixed([_sig("f", 1.0)])])
    off = eng.analyze_sync(Artifact.from_url("https://x.test/"))
    assert {r.name for r in off.analyzers} == {"fixed"}
    on = eng.analyze_sync(Artifact.from_url("https://x.test/"), AnalysisOptions(online=True))
    assert {r.name for r in on.analyzers} == {"fixed", "net"}
    only = eng.analyze_sync(Artifact.from_url("https://x.test/"),
                            AnalysisOptions(online=True, disable=frozenset({"net"})))
    assert {r.name for r in only.analyzers} == {"fixed"}


def test_size_limits():
    with pytest.raises(ArtifactTooLarge):
        Artifact.from_url("https://x.test/" + "a" * 9000)
    with pytest.raises(ValueError):
        Artifact.from_url("   ")


def test_artifact_id_is_stable():
    assert Artifact.from_url("https://a.test/").id == Artifact.from_url("https://a.test/").id
    assert Artifact.from_url("https://a.test/").id != Artifact.from_url("https://b.test/").id


def test_verdict_json_roundtrip():
    v = Engine(analyzers=[Fixed([_sig("a", 2.0)])]).analyze_sync(Artifact.from_url("https://x.test/"))
    from uniphish.core.types import Verdict

    again = Verdict.model_validate_json(v.model_dump_json())
    assert again.score == v.score and again.signals[0].id == "a"


async def test_analyze_inside_running_loop():
    eng = Engine(analyzers=[Fixed([_sig("a", 1.0)])])
    v = await eng.analyze(Artifact.from_url("https://x.test/"))
    assert v.signals and eng.analyze_sync(Artifact.from_url("https://y.test/")).signals
