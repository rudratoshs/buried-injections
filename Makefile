.PHONY: bench bench-agentdojo bench-windows bench-payloads setup

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

# Input scope x window size table (~15 min on CPU).
bench-windows:
	$(PY) bench/windows.py
