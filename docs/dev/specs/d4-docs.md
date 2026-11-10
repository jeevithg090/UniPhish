# Spec: documentation + README (the storefront)
OWN: README.md (full rewrite), docs/architecture.md, docs/api.md, docs/agentguard.md,
docs/detections.md (generated catalog), docs/quickstart.md, docs/threat-model.md,
CONTRIBUTING.md, SECURITY.md, docs/dev/README.md. Do NOT change code; you may run the CLI /
import the package to GENERATE content (e.g. the signal catalog, an example verdict). Read
the whole repo (core, analyzers, specs in docs/dev/specs, server, agent, hunt, export) to
describe what actually exists — verify claims against the code; do not overclaim.

README.md: a top-tier open-source security project front page — one-line positioning (an
open-source, AI-native anti-phishing platform: multilingual detection for URLs, pages,
emails, files & QR codes, for humans AND AI agents), a crisp 'why this exists' (the market
gap: on-device/explainable/multilingual + protecting AI agents), a feature matrix, an
architecture diagram (ASCII/mermaid of Artifact->analyzers->fusion->Verdict + surfaces),
a 60-second quickstart (pip install -e '.[all]'; python -c scan; uniphish scan; uniphish
serve; MCP; extension), real example outputs (use defanged samples; you may run the engine
to capture a real verdict), the explainability/log-odds fusion story, the MITRE ATT&CK +
ATLAS coverage, the detection-as-code exports, the AgentGuard section, the honest
'paper vs reality' + evaluation/limitations section (link docs/paper_vs_reality.md), a
responsible-use/defensive statement, install extras table, and links to the deep docs.
Keep the credibility that honesty buys — cite what's measured, flag what's heuristic.
docs/detections.md: generate from core.analyzer.signal_catalog (after importing analyzers).
Make it skimmable, accurate, and genuinely impressive. No build/test to run; prose + a
couple of generated snippets.
