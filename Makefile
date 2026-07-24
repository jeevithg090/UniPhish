.PHONY: help setup test data data-full train train-noadv eval infer figures clean

PY := ./.venv/bin/python

help:
	@echo "UniPhish — reproducible pipeline"
	@echo "  make setup       create venv + install deps"
	@echo "  make test        run unit tests"
	@echo "  make data        build small demo dataset (data/processed/)"
	@echo "  make data-full   build full-scale dataset (40k/family)"
	@echo "  make train       adversarial training"
	@echo "  make train-noadv ablation: no adversarial training"
	@echo "  make eval        evaluate + write results/results.json"
	@echo "  make infer URL=... score a single URL"
	@echo "  make figures     regenerate paper figures from results.json"

setup:
	python3 -m venv .venv && $(PY) -m pip install -U pip && $(PY) -m pip install -r requirements.txt

test:
	TF_CPP_MIN_LOG_LEVEL=3 $(PY) -m pytest

data:
	$(PY) -m data.build_dataset --small

data-full:
	$(PY) -m data.build_dataset --per-family 40000 --include-real

train:
	TF_CPP_MIN_LOG_LEVEL=3 $(PY) -m uniphish.train

train-noadv:
	TF_CPP_MIN_LOG_LEVEL=3 $(PY) -m uniphish.train --no-adv

eval:
	TF_CPP_MIN_LOG_LEVEL=3 $(PY) -m uniphish.evaluate

infer:
	TF_CPP_MIN_LOG_LEVEL=3 $(PY) -m uniphish.infer "$(URL)"

clean:
	rm -rf artifacts results/*.json data/processed/*.csv __pycache__ */__pycache__
