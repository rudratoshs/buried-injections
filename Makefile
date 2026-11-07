.PHONY: bench bench-agentdojo bench-windows bench-payloads bench-budget bench-action bench-register test test-fast setup setup-test-venv

# Everything runs in a local Python 3.12 venv (llm-guard does not build on 3.14).
# Without `make setup`, `PY` falls back to the pytest-only test venv below.
PY := $(or $(wildcard .venv/bin/python),.cache/test-venv/bin/python)

setup:
	python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt

bench:
	$(PY) bench/run.py --dataset sample

bench-agentdojo:
	$(PY) bench/run.py --dataset agentdojo

# Attack text scored on its own, no surrounding context (~1 min on CPU).
bench-payloads:
	$(PY) bench/payloads.py

# Catch rate when each detector may wrongly block at most 2% of normal traffic (~20 min on CPU).
bench-budget:
	$(PY) bench/at_budget.py

# Input scope x window size table (~15 min on CPU).
bench-windows:
	$(PY) bench/windows.py

# Action-level metric (#9): simulated AgentDojo banking agent, deterministic evaluator.
# Reuses the saved detector scores from bench-budget, so no model download (~5 s).
bench-action:
	$(PY) bench/action_level.py

# Same injection as a command and as a polite request, scored alone (~1 min on CPU).
# The 2% budget column reuses the thresholds saved by bench-budget.
bench-register:
	$(PY) bench/register.py

# --- test-only venv (pytest alone; no torch, no model download) ------------
# `make test` runs in the venv from `make setup` when it exists. Otherwise it
# builds a tiny one under .cache/test-venv, so the pure-Python evaluator,
# register and gateway tests run on a fresh checkout without the ~5 GB setup.
# Needs no python3.12: the venv uses whatever python3 is on PATH, and the test
# requirements are installed by the system pip into the venv's site-packages
# (no ensurepip, which Debian/Ubuntu images without python3-venv lack).
tests: test

PY_TEST := $(or $(wildcard .venv/bin/python),.cache/test-venv/bin/python)

test: setup-test-venv
	$(PY_TEST) -m pytest -q $(or $(TESTS),tests)

test-fast: test

setup-test-venv:
	@if ! .cache/test-venv/bin/python -c 'import pytest' 2>/dev/null; then \
		echo "Creating .cache/test-venv (pytest only)"; \
		rm -rf .cache/test-venv; mkdir -p .cache/test-venv; \
		python3 -m venv --without-pip .cache/test-venv || exit 1; \
		SP=$$(.cache/test-venv/bin/python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])'); \
		for pkg in $$(grep -v '^#' requirements-test.txt | grep -v '^$$'); do \
			python3 -m pip install --quiet --disable-pip-version-check --target "$$SP" "$$pkg" || \
				{ echo "installing $$pkg failed"; exit 1; }; \
		done; \
		.cache/test-venv/bin/python -c 'import pytest' || { echo "test venv setup failed"; exit 1; }; \
	fi
