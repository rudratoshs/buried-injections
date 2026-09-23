.PHONY: bench bench-agentdojo bench-windows setup

# Everything runs in a local venv (Homebrew's Python is externally managed).
PY := .venv/bin/python

setup:
	python3 -m venv .venv && .venv/bin/pip install agentdojo transformers torch

bench:
	$(PY) bench/run.py --dataset sample

bench-agentdojo:
	$(PY) bench/run.py --dataset agentdojo

# The README's context-dilution table (~15 min on CPU).
bench-windows:
	$(PY) bench/windows.py
