"""
windows.py -- the input scope x window size experiment behind the README table.

Scores every AgentDojo case with Prompt Guard 2 under two input scopes
(task prompt + tool output, or tool output only) and three window sizes,
to show the low catch rate does not depend on how cases are built.

Usage:
    python bench/windows.py        # ~15 min on CPU
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datasets import agentdojo_texts
from detectors import PromptGuard2Detector

WINDOWS = [510, 128, 64]


class Text:
    """Minimal stand-in for a ToolCall: the detector only reads as_text()."""

    def __init__(self, text):
        self.text = text

    def as_text(self):
        return self.text


def main():
    detector = PromptGuard2Detector()   # model loads once, reused for every config
    rows = []

    print(f"\n{'what the model reads':<28}{'window':<8}{'caught':<16}{'false pos':<12}")
    print("-" * 64)
    for include_prompt in (True, False):
        scope = "task prompt + tool output" if include_prompt else "tool output only"
        cases = list(agentdojo_texts(include_prompt))
        attacks = [Text(t) for label, t in cases if label == "attack"]
        benign = [Text(t) for label, t in cases if label == "benign"]

        for window in WINDOWS:
            detector.WINDOW, detector.STRIDE = window, window * 3 // 4
            caught = sum(detector.check(c) for c in attacks)
            false_blocks = sum(detector.check(c) for c in benign)
            print(f"{scope:<28}{window:<8}{f'{caught}/{len(attacks)}':<16}"
                  f"{f'{false_blocks}/{len(benign)}':<12}", flush=True)
            rows.append({
                "scope": scope, "window": window,
                "attacks_caught": caught, "attacks_total": len(attacks),
                "false_blocks": false_blocks, "benign_total": len(benign),
            })

    out_path = os.path.join(os.path.dirname(__file__), "results", "windows.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(rows, f, indent=2)
    print(f"\nSaved: {out_path}\n")


if __name__ == "__main__":
    main()
