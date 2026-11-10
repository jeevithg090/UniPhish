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

__all__ = [
    "ParsedURL",
    "defang",
    "extract_urls",
    "host_is_under",
    "normalize_url",
    "parse_url",
    "refang",
    "same_site",
]
