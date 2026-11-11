# Spec: integration tests, CI, packaging polish
OWN: tests/integration/test_end_to_end.py, tests/integration/test_registry.py,
tests/test_smoke.py, .github/workflows/ci.yml, Makefile (rewrite for v2), MANIFEST.in,
docs/dev/testing.md. Do NOT change library code; if you find a real bug, document it in
your known_issues + integrator_requests precisely (file:line, failing case) rather than
editing another owner's file.

tests/integration: drive the PUBLIC API (uniphish.scan_url/scan_text/scan_email/scan_page/
scan_file and core.engine.default_engine) end to end with the FULL analyzer set loaded
(offline): a homoglyph URL -> malicious + right brand + MITRE + IOCs; a benign popular URL
-> benign (false-positive guard); a synthetic phishing email with a malicious link +
attachment -> malicious parent with child verdicts + indicators; a smishing text; a
prompt-injection text/page -> AgentGuard/injection signals + ATLAS; a legit IDN + a LOTS-
hosted-benign page -> not over-flagged. Assert the verdict decomposition identity
(logit == prior + sum contributions) holds on real multi-analyzer verdicts. test_registry:
every registered analyzer declares its signals dict, has unique name, valid kinds/stage;
signal_catalog is non-empty; loading built-ins is tolerant of missing optional deps.
test_smoke: `import uniphish` + a trivial scan works with ONLY the core deps.
ci.yml: GitHub Actions — matrix py3.10/3.11/3.12 on ubuntu: install '.[dev]' (+ playwright
install chromium only where needed, allow-fail), ruff check, pytest (offline, exclude -m
network and -m slow), build the sdist/wheel; a separate job building web/ (node) if present
and uploading the dashboard; cache pip. Green-badge friendly. Makefile: setup/test/lint/
serve/scan/eval/hunt/web/docker targets for v2. MANIFEST.in includes assets + static +
templates.
TESTS: your integration tests pass offline with the full engine. Report the exact counts.
