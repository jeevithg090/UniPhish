# Spec: STIX 2.1 / TAXII / MISP export
OWN: uniphish/export/__init__.py, uniphish/export/stix.py, uniphish/export/misp.py,
tests/export/test_stix.py, tests/export/test_misp.py.

PURPOSE: turn a Verdict into machine-readable CTI any SIEM/TIP/ISAC can ingest. Prefer
the stix2 library if present; also provide a dependency-free dict builder fallback.

stix.py: to_stix_bundle(verdict) -> dict (STIX 2.1 JSON): an Indicator (STIX pattern over
the observables — url/domain/ip/file-hash), Observed-Data/SCOs, Attack-Pattern objects
from verdict.mitre (ATT&CK + ATLAS, with external_references to the technique URL),
Relationships (indicator 'indicates' attack-pattern), plus optional Identity (UniPhish)
and Malware-Analysis-ish note. Deterministic ids (uuid5 over the observable so re-runs are
stable — pass a namespace; do NOT use random/time in a way that breaks determinism — a
created timestamp may be supplied by the caller or omitted). stix_pattern(indicator)
helper. bundle_many(verdicts). Validate against the stix2 lib when available.

misp.py: to_misp_event(verdict) -> dict (MISP event JSON: Event with Attributes typed
url/domain/ip-dst/sha256/email-src, tags incl. mitre ATT&CK galaxy
'misp-galaxy:mitre-attack-pattern=..."', threat level, analysis, info line; objects for
url + file). to_misp_feed(verdicts).

TESTS: bundle has an Indicator with a valid pattern + attack-pattern + relationship for a
homoglyph verdict; ATLAS technique maps for a prompt-injection verdict; deterministic ids;
MISP attributes + galaxy tags present; JSON serialisable. Build synthetic Verdicts
directly (don't run the engine) to keep tests fast and offline.
