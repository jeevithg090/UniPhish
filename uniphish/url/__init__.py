"""URL intelligence: parsing, Unicode/IDN security, brand impersonation and the
byte-level CNN runtime.

This package is the analytical heart of UniPhish. It is deliberately free of heavy
dependencies (no TensorFlow) so the whole platform runs anywhere:

* :mod:`uniphish.url.parse` — a hostile-input-hardened URL parser (WHATWG-ish host
  handling, IDNA, IPv4 obfuscation, public-suffix awareness) and URL extraction.
* :mod:`uniphish.url.confusables` — UTS #39 confusable skeletons and domain-squatting
  folds used for homoglyph/typo brand matching.
* :mod:`uniphish.url.scripts` — Unicode script resolution, restriction levels and the
  invisible/bidi/tag-smuggling character detectors.
* :mod:`uniphish.url.idn_policy` — Chromium-style IDN spoof assessment.
* :mod:`uniphish.url.brandkb` — the brand knowledge base (who gets phished, which
  domains are legitimately theirs).
* :mod:`uniphish.url.model` / :mod:`uniphish.url.saliency` — a pure-NumPy forward pass
  of the original UniPhish CNN, plus occlusion saliency.
"""

from __future__ import annotations

from uniphish.url.confusables import (
    are_confusable,
    ascii_fold,
    brand_skeleton,
    confusable_chars_in,
    lookalikes_of,
    skeleton,
)
from uniphish.url.idn_policy import IdnAssessment, assess_host
from uniphish.url.parse import (
    ParsedURL,
    defang,
    extract_urls,
    host_is_under,
    normalize_url,
    parse_url,
    refang,
    same_site,
)
from uniphish.url.scripts import (
    RestrictionLevel,
    decode_tag_chars,
    find_bidi_controls,
    find_invisible,
    is_mixed_script,
    restriction_level,
)

__all__ = [
    "IdnAssessment",
    "ParsedURL",
    "RestrictionLevel",
    "are_confusable",
    "ascii_fold",
    "assess_host",
    "brand_skeleton",
    "confusable_chars_in",
    "decode_tag_chars",
    "defang",
    "extract_urls",
    "find_bidi_controls",
    "find_invisible",
    "host_is_under",
    "is_mixed_script",
    "lookalikes_of",
    "normalize_url",
    "parse_url",
    "refang",
    "restriction_level",
    "same_site",
    "skeleton",
]
