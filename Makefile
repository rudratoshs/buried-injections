.PHONY: bench bench-agentdojo bench-windows bench-payloads bench-budget bench-action bench-register test setup

# Everything runs in a local Python 3.12 venv (llm-guard does not build on 3.14).
PY := .venv/bin/python

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

test:
	$(PY) -m pytest -q tests
