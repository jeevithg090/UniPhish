# Testing, CI and packaging

How the UniPhish 2 test-suite is organised, what CI runs, and what to do when something
is red. Everything here is **offline**: `tests/conftest.py` makes any DNS lookup or
non-loopback socket connect raise, so a test can never depend on the internet (or send a
request to a real phishing host). Opt in per test with `@pytest.mark.network` (those are
deselected unless you pass `-m network`).

## Quick reference

```bash
make setup              # .venv + `pip install -e '.[dev]'` (uses uv when installed)
make test               # fast offline suite  (== what CI runs)
make test-integration   # tests/integration + tests/test_smoke.py only
make lint               # ruff check + ruff format --check (whole tree)
make fix                # ruff --fix + ruff format
make web-lint           # Biome lint + format check for web/
make check              # lint + test
make build              # sdist + wheel into dist/
make verify-dist        # build, then assert the wheel ships assets/model/templates
make web                # npm ci && npm run build  -> uniphish/server/static
make help               # everything else (serve, scan, export, eval, redteam, hunt, docker ...)
```

Run a single area: `./.venv/bin/python -m pytest tests/url -q`.

## Layout

| Path | What it proves |
| --- | --- |
| `tests/<area>/` | Unit tests for one package (`url`, `page`, `mail`, `files`, `nlp`, `intel`, `agent`, `hunt`, `export`, `store`, `server`, `cli`, `bot`, `eval`, ...). No `__init__.py`; pytest runs with `--import-mode=importlib`. |
| `tests/integration/test_end_to_end.py` | The public API (`uniphish.scan_*`, `core.engine.default_engine`) with the **full** analyzer set: detection quality, false-positive guards, child verdicts, IOCs, MITRE, AgentGuard, and the fusion identities. |
| `tests/integration/test_registry.py` | Analyzer contract: unique names, valid kinds/stage, every signal id declared, namespaced, titled and unique; tolerant loading of built-ins. |
| `tests/test_smoke.py` | `import uniphish` is light, and every scan kind works when **every optional extra is un-importable** (subprocess with a poisoned import hook). |
| `extension/test/` | `node --test` suite for the on-device extension engine. |
| `web/src/**/*.test.*` | `vitest` suite for the SOC console. |

### What the end-to-end tests assert

* A Cyrillic-homoglyph URL is `malicious`, names the right brand with technique
  `homoglyph`, maps to MITRE `T1566.002`, and yields the punycode URL/domain as IOCs.
  Greek and Cyrillic variants for other brands are covered.
* Popular benign sites, official brand hosts (`paypal.com`, `microsoft.com`, `github.com`),
  single-script IDNs (`münchen.de`, Japanese) and harmless pages on
  living-off-trusted-sites hosting (`*.pages.dev`, `*.web.app`, `sites.google.com`) are **not**
  flagged, and the hosting gets no reputation credit.
* A synthetic phishing email (spoofed display name, failing SPF/DMARC, look-alike link,
  script-bearing SVG) is `malicious`, with child verdicts for the link and the attachment
  (and the attachment's embedded redirect one level deeper), IOCs from every level, and
  the children's risk propagated into the parent.
* Smishing text, prompt-injection text and a page with hidden injection raise
  `agent.injection.*` signals with MITRE ATLAS ids; `AgentGuard` blocks them and allows
  benign content.
* **Fusion identities** on every node of real multi-analyzer verdicts:
  `logit == clamp(prior + sum(signal.contribution))`, `risk == sigmoid(logit)`,
  `score == round(100 * risk)`, `level` matches the thresholds, damping never amplifies a
  weight, and re-fusing a verdict's own signals reproduces its score and level.
* Every emitted signal id is declared in some analyzer's `signals` catalog.

## Writing tests

* Offline only. Mock `uniphish.core.net`, use `httpx.MockTransport` / `respx`, or inject
  resolvers. Never fetch a real URL.
* Fixtures contain **indicators, not payloads**: reserved domains (`.test`, `.example`,
  `.invalid`, `example.com`) and obviously inert strings. See the build contract.
* Cold start is slow: the first scan loads the brand knowledge base and Unicode tables
  (seconds on a loaded machine). Integration tests warm these once per module and pass
  generous `timeout_s` / `analyzer_timeout_s`; copy that pattern for any test that
  runs the full engine, otherwise the default 10 s analyzer budget can cause a flaky
  `timeout` status on a busy runner.
* Use Hypothesis for parsers and normalisers; keep a file under ~2 s where you can.
* Mark long tests `@pytest.mark.slow` and network tests `@pytest.mark.network`.

## CI (`.github/workflows/ci.yml`)

| Job | Runs |
| --- | --- |
| `lint` | `ruff check .` and `ruff format --check .` with a pinned ruff (same as `make lint`). |
| `test` | Matrix Python 3.10 / 3.11 / 3.12 on Ubuntu: `pip install -e '.[dev]'` (pip cache on), optional Playwright Chromium on 3.12 (allowed to fail), then `pytest -m "not network and not slow"`. |
| `package` | After lint + test: `python -m build`, `twine check`, assert the wheel contains the assets/model/templates, install the wheel into a **clean venv with core deps only** and scan a homoglyph URL, upload `dist/`. |
| `web` | If `web/package-lock.json` exists: `npm ci`, `npm run lint` (Biome), `npm run build` (tsc + vite), `npm test`, upload the built dashboard artifact. |
| `extension` | `node --test` for the extension. |

The workflow needs no secrets and requests read-only permissions, so it is safe on forks.
Concurrent runs on the same ref cancel each other.

## Packaging

* `pyproject.toml` `[tool.setuptools.package-data]` and `MANIFEST.in` both list the data
  trees (`uniphish/assets`, `uniphish/server/static`, `uniphish/server/templates`,
  `py.typed`), so a directory one forgets is still shipped by the other. `make verify-dist`
  and the CI `package` job fail if the wheel is missing any of them.
* The dashboard is built into `uniphish/server/static` by `make web`; build it **before**
  `make build` when releasing, otherwise the wheel carries whatever static build is checked
  in.
* `make docker` builds from `dist/` only (stdin Dockerfile), so `.venv` and `node_modules`
  never enter the build context. There is no committed Dockerfile yet.

## Lint scope

`make lint` and CI lint and format-check the whole Python tree. `legacy/`, `web/`,
`extension/` and the built dashboard are excluded in `[tool.ruff]`; `scripts/` relaxes the
security (`S`) rules. The web console uses Biome
(`web/biome.json`).

## Known gaps (as of this writing)

* `uniphish hunt` fails with `uniphish.hunt.ct exposes neither 'app' nor 'main'`:
  `uniphish/cli/main.py` delegates to a CLI entry point that `uniphish/hunt/ct.py` does not
  define. `make hunt` therefore drives `CTHunter` through the library instead.
* Cold-start cost: `assets.load_yaml` uses PyYAML's pure-Python loader, so loading
  `brands.yaml` takes ~4 s on an idle laptop and over 10 s under load, which can exceed the
  default per-analyzer budget on the first scan of a process (`email` analyzer timeout on a
  fresh interpreter). Using `yaml.CSafeLoader` when available removes most of it.
* ML signal on official hosts: `ml.cnn.phishing` fires (+4.0) on some official-brand URLs
  (for example `https://www.paypal.com/signin`); legitimacy evidence still keeps the verdict
  benign (score ~27) but the margin is thin.
