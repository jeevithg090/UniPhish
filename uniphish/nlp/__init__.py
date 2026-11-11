"""Natural-language heuristics for UniPhish (lexical, deterministic, dependency-free).

from uniphish.nlp import analyze_text, detect_otp_request, detect_phone_number
result = analyze_text("Urgent: verify your account within 24 hours")
"""

from __future__ import annotations

from uniphish.nlp.social_engineering import (
    MAX_TEXT_CHARS,
    TACTICS,
    SEResult,
    TacticHit,
    analyze_text,
    detect_otp_request,
    detect_phone_number,
    lexicon_stats,
)

__all__ = [
    "MAX_TEXT_CHARS",
    "TACTICS",
    "SEResult",
    "TacticHit",
    "analyze_text",
    "detect_otp_request",
    "detect_phone_number",
    "lexicon_stats",
]
