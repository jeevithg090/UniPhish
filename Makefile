# UniPhish 2 -- developer entry points.
#
#   make setup      create .venv and install the package with every extra + dev tools
#   make test       fast offline test-suite (what CI runs)
#   make check      lint + test
#   make help       list all targets
#
# Everything defaults to the project virtualenv; override with `make PY=python3 ...`.

PY      ?= ./.venv/bin/python
RUFF    ?= ./.venv/bin/ruff
PYTEST   = $(PY) -m pytest
HOST    ?= 127.0.0.1
PORT    ?= 8080
IMAGE   ?= uniphish:2

.DEFAULT_GOAL := help
.PHONY: help setup test test-all test-integration test-smoke test-cov lint fix check \
	fmt serve scan batch export catalog eval redteam hunt web web-install web-test web-lint \
	extension-test \
	build verify-dist docker clean distclean train-data train

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "; printf "UniPhish 2 targets\n\n"} \
		/^[a-zA-Z0-9_-]+:.*## / {printf "  \033[1m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf "\nVariables: PY, HOST, PORT, IMAGE, INPUT (scan/export), TYPE, FORMAT, N (redteam)\n"

# ----------------------------------------------------------------------------- setup
setup: ## Create .venv and install '.[dev]' (all extras + test/lint tools); uses uv when present
	@if command -v uv >/dev/null 2>&1; then \
		uv venv --python 3.12 .venv 2>/dev/null || uv venv .venv; \
		uv pip install --python $(PY) -e '.[dev]'; \
	else \
		python3 -m venv .venv && $(PY) -m pip install -U pip && $(PY) -m pip install -e '.[dev]'; \
	fi
	@echo "Optional: $(PY) -m playwright install chromium   (sandbox detonation)"

# ------------------------------------------------------------------------------ tests
test: ## Fast offline test-suite (no network, no slow tests)
	$(PYTEST) -m "not network and not slow"

test-all: ## Everything including slow tests (still offline)
	$(PYTEST) -m "not network"

test-integration: ## End-to-end + registry + smoke tests with the full analyzer set
	$(PYTEST) tests/integration tests/test_smoke.py

test-smoke: ## Core-dependencies-only import + scan check
	$(PYTEST) tests/test_smoke.py

test-cov: ## Test-suite with a coverage report (needs: pip install pytest-cov)
	$(PYTEST) -m "not network and not slow" --cov=uniphish --cov-report=term-missing:skip-covered

# ------------------------------------------------------------------------------- lint
lint: ## ruff lint + format check (see [tool.ruff] in pyproject.toml)
	$(RUFF) check .
	$(RUFF) format --check .

fix: ## ruff check --fix, then ruff format
	$(RUFF) check --fix .
	$(RUFF) format .

fmt: ## ruff format
	$(RUFF) format .

check: lint test ## Lint + test

# ----------------------------------------------------------------------- run / use it
serve: ## Run the API + SOC console on http://$(HOST):$(PORT)
	$(PY) -m uniphish.cli.main serve --host $(HOST) --port $(PORT)

INPUT ?= https://www.example.com/login
TYPE  ?= auto
scan: ## Scan one input: make scan INPUT='https://pаypal.com' [TYPE=url|text|email|page|file]
	$(PY) -m uniphish.cli.main scan "$(INPUT)" --type $(TYPE)

batch: ## Scan a file of inputs (one per line): make batch INPUT=urls.txt
	$(PY) -m uniphish.cli.main batch "$(INPUT)"

FORMAT ?= stix
export: ## Export a verdict as detection-as-code: make export INPUT=... FORMAT=stix|misp|sigma|suricata|yara|ecs
	$(PY) -m uniphish.cli.main export "$(INPUT)" --format $(FORMAT)

catalog: ## Print the detection catalog (every signal every analyzer can emit)
	$(PY) -m uniphish.cli.main catalog

eval: ## Reproduce the benchmark (writes results/eval_*.json and docs/evaluation.md inputs)
	$(PY) -m uniphish.eval.benchmark --dataset urls smishing injection email

N ?= 100
redteam: ## Adversarial robustness run (writes results/robustness.json)
	$(PY) -m uniphish.eval.redteam --n $(N)

define HUNT_PY
import asyncio
from uniphish.hunt import CTHunter
hunter = CTHunter(publish=False)
asyncio.run(hunter.run(source="sample"))
for k, v in vars(hunter.stats).items():
    print(f"{k:>18}: {v}")
endef
export HUNT_PY

hunt: ## Replay the bundled synthetic CT sample through the hunter (offline)
	$(PY) -c "$$HUNT_PY"

# --------------------------------------------------------------------------------- web
web-install: ## Install the web console dependencies (reproducible: npm ci)
	cd web && npm ci

web: web-install ## Build the SOC console into uniphish/server/static
	cd web && npm run build

web-test: ## Type-check and unit-test the web console
	cd web && npm run typecheck && npm test

web-lint: ## Lint + format-check the web console (Biome)
	cd web && npm run lint

extension-test: ## Test the browser extension's on-device engine (node --test)
	cd extension && npm test

# ------------------------------------------------------------------------- packaging
build: ## Build sdist + wheel into dist/ (needs: uv, or `pip install build`)
	rm -rf dist
	@if command -v uv >/dev/null 2>&1; then uv build; else $(PY) -m build; fi

define VERIFY_PY
import glob, sys, zipfile
wheel = sorted(glob.glob("dist/*.whl"))[-1]
names = zipfile.ZipFile(wheel).namelist()
need = ["uniphish/py.typed", "uniphish/assets/brands.yaml", "uniphish/assets/unicode/",
        "uniphish/assets/model/", "uniphish/server/templates/", "uniphish/server/static/index.html"]
missing = [n for n in need if not any(x.startswith(n) or x == n for x in names)]
print(wheel, len(names), "files")
sys.exit("wheel is missing: " + ", ".join(missing) if missing else 0)
endef
export VERIFY_PY

verify-dist: build ## Check the built wheel ships its data files (assets, templates, dashboard)
	$(PY) -c "$$VERIFY_PY"

define DOCKERFILE
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 UNIPHISH_DATA_DIR=/data
COPY *.whl /wheels/
RUN W="$$(ls /wheels/uniphish-*.whl)" && pip install "$$W[server,vision,yara,office,intel]" \
    && useradd -m uniphish && mkdir /data && chown uniphish /data
USER uniphish
VOLUME /data
EXPOSE 8080
CMD ["uniphish", "serve", "--host", "0.0.0.0", "--port", "8080"]
endef
export DOCKERFILE

docker: build ## Build a slim container image (context = dist/, so .venv/node_modules never enter it)
	@command -v docker >/dev/null 2>&1 || { echo "docker is not installed"; exit 1; }
	@printf '%s\n' "$$DOCKERFILE" | docker build -t $(IMAGE) -f - dist
	@echo "Run: docker run --rm -p 8080:8080 -v uniphish-data:/data $(IMAGE)"

# --------------------------------------------------------------- legacy training stack
# The v1 paper-reproduction pipeline now lives under legacy/ (see legacy/README.md) and
# needs the 'train' extra / TensorFlow. Run from that directory.
train-data: ## (v1 model training) build the small demo dataset -- needs the 'train' extra
	cd legacy && $(abspath $(PY)) -m data.build_dataset --small

train: ## (v1 model training) adversarial training -- needs the 'train' extra / TensorFlow
	cd legacy && TF_CPP_MIN_LOG_LEVEL=3 $(abspath $(PY)) -m train

# ----------------------------------------------------------------------------- clean
clean: ## Remove caches, bytecode and build output
	rm -rf build dist .pytest_cache .ruff_cache .hypothesis htmlcov .coverage
	find . -path ./.venv -prune -o -path ./web/node_modules -prune -o -type d -name __pycache__ -print0 | xargs -0 rm -rf

distclean: clean ## clean + remove the virtualenv and node_modules
	rm -rf .venv web/node_modules extension/node_modules
