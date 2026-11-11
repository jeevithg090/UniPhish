# Developer notes

Internal documentation for people building UniPhish. If you only want to use it, start at
the [README](../../README.md) and the [quickstart](../quickstart.md). If you want to
contribute, read [CONTRIBUTING.md](../../CONTRIBUTING.md) first.

## How UniPhish 2 was built

UniPhish 2 was built **spec-first and in parallel**. A shared contract defined the product,
the package layout, file ownership, coding standards and the analyzer API; each area then
had a one-page spec that named the exact files its builder owned and what the module had to
provide. Builders could only edit files they owned and had to describe any needed change in
shared files as an integrator request. This is why the codebase has uniform conventions
(module docstring explaining *why*, typed public API, data in assets, offline tests) and why
module boundaries are clean.

| Document | What it is |
|---|---|
| [build-contract.md](build-contract.md) | The shared contract: product, layout and ownership, environment, coding standards, how to write an analyzer, signal conventions and weight scale. **Read this before touching code.** |
| [specs/](specs/) | One spec per module, listed below. They describe intent and ownership; the code and tests are the source of truth for behaviour. A spec can lag the implementation, so when they disagree, trust the code and fix the spec. |

## Module specs

**Wave A, foundations**

| Spec | Module |
|---|---|
| [a1-unicode](specs/a1-unicode.md) | Unicode security core: confusables, scripts, IDN policy |
| [a2-brandkb](specs/a2-brandkb.md) | brand knowledge base |
| [a3-threatdata](specs/a3-threatdata.md) | reference data (TLD risk, LOTS, shorteners, lures, top sites) and typed accessors |
| [a4-model](specs/a4-model.md) | TensorFlow-free runtime for the byte-level CNN |
| [a5-net](specs/a5-net.md) | SSRF-proof network gateway and caches |
| [a6-emailparse](specs/a6-emailparse.md) | hostile-input email parsing and authentication analysis |
| [a7-htmlparse](specs/a7-htmlparse.md) | HTML structural parsing |
| [a8-store](specs/a8-store.md) | SQLite persistence |
| [a9-nlp](specs/a9-nlp.md) | multilingual social-engineering lexical model |
| [a10-filestatic](specs/a10-filestatic.md) | static file analysis and QR decoding |
| [a11-lexical](specs/a11-lexical.md) | URL lexical features and attack-technique classification |
| [a12-stix](specs/a12-stix.md) | STIX 2.1, TAXII and MISP export |
| [a13-dac](specs/a13-dac.md) | Sigma, Suricata, YARA and ECS export |
| [a14-aianalyst](specs/a14-aianalyst.md) | optional LLM analyst |

**Wave B, analyzers**

| Spec | Analyzer |
|---|---|
| [b1-url-analyzer](specs/b1-url-analyzer.md) | `url` |
| [b2-ml-analyzer](specs/b2-ml-analyzer.md) | `ml` |
| [b3-page-analyzer](specs/b3-page-analyzer.md) | `page` |
| [b4-kits](specs/b4-kits.md) | `kits` (AiTM, ClickFix, BitB signatures) |
| [b5-injection](specs/b5-injection.md) | `injection` (AgentGuard detection core) |
| [b6-text](specs/b6-text.md) | `text` |
| [b7-email-analyzer](specs/b7-email-analyzer.md) | `email` |
| [b8-file-analyzer](specs/b8-file-analyzer.md) | `file` (+ QR) |
| [b9-reputation](specs/b9-reputation.md) | `reputation` |
| [b10-infra](specs/b10-infra.md) | `infra` (online) |
| [b11-fetch](specs/b11-fetch.md) | `fetch`, `detonate` (active, online) |

**Wave C, surfaces and operations**

| Spec | Surface |
|---|---|
| [c1-api](specs/c1-api.md) | FastAPI server |
| [c2-web](specs/c2-web.md) | SOC console |
| [c3-cli](specs/c3-cli.md) | CLI |
| [c4-mcp](specs/c4-mcp.md) | AgentGuard and MCP server |
| [c5-extension](specs/c5-extension.md) | MV3 browser extension |
| [c6-bot](specs/c6-bot.md) | Telegram bot |
| [c7-ct](specs/c7-ct.md) | Certificate Transparency hunter |
| [c8-hunt](specs/c8-hunt.md) | permutation engine and brand watch |
| [c9-integrations](specs/c9-integrations.md) | mailbox and SIEM sinks |
| [c10-eval](specs/c10-eval.md) | evaluation and red-team harness |

**Wave D, polish**

| Spec | Deliverable |
|---|---|
| [d1-report](specs/d1-report.md) | analyst report generator |
| [d2-corpus](specs/d2-corpus.md) | labelled sample corpus (`examples/corpus/`) |
| [d3-feeds](specs/d3-feeds.md) | threat-feed ingestion and connectors |
| [d4-docs](specs/d4-docs.md) | this documentation set |
| [d5-ci](specs/d5-ci.md) | integration tests, CI, packaging |

## Repository layout

```text
uniphish/core/        types, analyzer base + registry, engine, scoring, config, mitre, events, net, cache
uniphish/url/         parse, confusables, scripts, idn_policy, brandkb, brands, lexical, techniques, model, saliency
uniphish/analyzers/   one module per analyzer; BUILTIN_MODULES in __init__.py controls what loads
uniphish/{page,mail,files,nlp,intel}/   parsers and enrichment
uniphish/{agent,hunt,export,integrations,ai,store,eval,server,cli}/
uniphish/assets/      YAML/JSON/binary data (+ README with provenance)
web/  extension/  bot/  examples/corpus/  scripts/  tests/<area>/  docs/
uniphish/*.py (top level), api/, data/, scripts/make_report.py ...   legacy 1.x TensorFlow research stack
```

The legacy 1.x modules (`model.py`, `train.py`, `evaluate.py`, `brands.py`, `reasons.py`,
`enrich.py`, `infer.py`, `api/server.py`, ...) remain for reproducing the original paper
results and are superseded by the new layout. They need the `train` extra and are not imported
by the runtime engine.

## Everyday workflow

```bash
pip install -e '.[dev]'
python -m pytest tests/<area> -q            # network blocked by tests/conftest.py, per-test data dir
ruff check <files>
python scripts/smoke_platform.py            # whole-platform canonical cases
uniphish catalog                            # confirm your signal is declared
```

Working conventions inherited from the contract:

* Modules own their files; shared spine files (`core/`, `analyzers/__init__.py`,
  `pyproject.toml`) change only through a deliberate, reviewed edit.
* Every signal is declared in its analyzer's `signals` dict; docs and the console are
  generated from that.
* Tests do not touch the network and use temporary data directories.
* Never commit real phishing content; fixtures are synthetic and inert.

## Regenerating generated artifacts

| Artifact | Command | Notes |
|---|---|---|
| [docs/detections.md](../detections.md) | regenerate from `uniphish.core.analyzer.signal_catalog()` after `load_builtin_analyzers()` | grouped by analyzer; counts in the header must equal `len(signal_catalog())` |
| Unicode tables (`uniphish/assets/unicode/`) | `python -I scripts/gen_unicode_data.py --download --out uniphish/assets/unicode` (or `--src <dir>`) | pinned Unicode version is reported by `uniphish.url.confusables.unicode_version()` |
| Extension data (`extension/data/`) | `python extension/tools/build_data.py` (`--check` verifies freshness) | generated from the canonical assets; never hand-edit |
| Extension icons | `python extension/tools/make_icons.py` | |
| SOC console bundle (`uniphish/server/static/`) | `cd web && npm ci && npm run build` | type-checks then builds |
| Benchmark and red-team results | `python -m uniphish.eval.benchmark --dataset urls smishing injection email` and `python -m uniphish.eval.redteam --n 100` | writes `results/eval_*.json`, `results/robustness.json`; update [docs/evaluation.md](../evaluation.md) when numbers change |
| Legacy model figures | `python -m scripts.make_report` | legacy TensorFlow stack |

## Known issues worth knowing before you start

Mirrors the README and [threat model](../threat-model.md#known-gaps); fix them if you can.

* First-scan cold start can time out the `url` analyzer (brand YAML parsed with the
  pure-Python loader).
* The ML signal can warn alone and over-fires on ordinary URLs; the extension already
  prevents this, the Python engine does not.
* `uniphish hunt` cannot find an entry point in `uniphish.hunt.ct`.
* TAXII and legacy `/scan` and `/stix` routes are outside API-key auth.
* The top-level `Makefile` still targets the legacy 1.x pipeline.

## Writing documentation

* Verify every claim against the code or a command you ran; prefer measured numbers and cite
  where they come from.
* Flag heuristics as heuristics (hand-set weights, curated lists, judgement-calibrated
  priors) and keep known gaps visible.
* Use defanged or reserved-domain examples only.
