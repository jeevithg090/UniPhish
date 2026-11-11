"""Core contracts: data model, analyzer protocol, engine, scoring, config, events."""

from uniphish.core.analyzer import (
    AnalysisContext,
    AnalysisOptions,
    Analyzer,
    AnalyzerResult,
    register,
)
from uniphish.core.types import (
    Action,
    Artifact,
    ArtifactKind,
    BrandMatch,
    Indicator,
    IndicatorType,
    Level,
    Severity,
    Signal,
    Verdict,
)

__all__ = [
    "Action", "AnalysisContext", "AnalysisOptions", "Analyzer", "AnalyzerResult", "Artifact",
    "ArtifactKind", "BrandMatch", "Indicator", "IndicatorType", "Level", "Severity", "Signal",
    "Verdict", "register",
]
