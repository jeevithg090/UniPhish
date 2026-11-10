# Spec: analyst report generator (HTML/PDF-ready)
OWN: uniphish/export/report.py, uniphish/server/templates/report.html.j2 (Jinja2),
tests/export/test_report.py. Depends on core.types.Verdict, export.stix (optional),
ai.analyst (optional), jinja2.

render_report(verdict, *, ai_narrative=None, title=None) -> str (a self-contained HTML
analyst report: header with verdict/level/score gauge (inline SVG), impersonated brand,
the signal contribution waterfall (inline SVG bars), highlighted URL/text with salient
spans, IOC table (defanged, with a copy-friendly plain list), MITRE ATT&CK/ATLAS section
with technique links, the child-artifact tree, per-analyzer run table, optional AI
narrative, and an appendix with the raw JSON + STIX pattern). No external assets/JS (works
offline, embeddable); all CSS inline; XSS-safe (escape all artifact-derived text; defang
all URLs so nothing is clickable-dangerous). A to_pdf(verdict, path) that uses a headless
browser (playwright) if available, else writes the HTML and notes PDF needs the extra.
report_markdown(verdict) -> str for a ticketing-friendly text version.
TESTS: HTML contains the score, brand, each top signal, IOCs (defanged), MITRE links, and
is well-formed; artifact text with an HTML-injection attempt is escaped (no raw <script>);
markdown variant present. Build synthetic Verdicts; offline.
