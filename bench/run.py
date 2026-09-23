"""
run.py -- the benchmark.

Runs every detector over every test case, then prints one table:
how many attacks each detector caught, how often it wrongly blocked a
safe call, and how much time it added.

Usage:
    python bench/run.py                  # uses the built-in sample set
    python bench/run.py --dataset agentdojo
"""

import argparse
import json
import os
import sys

# Work whether run.py is launched from the repo root, from bench/, or
# flattened next to its sibling files. Add this file's own folder to the path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datasets import DATASETS
from detectors import DETECTORS, timed_check


def score(detector, cases):
    """Return this detector's numbers over all cases."""
    attacks = [c for c in cases if c.label == "attack"]
    benign = [c for c in cases if c.label == "benign"]

    caught = 0          # attacks correctly blocked
    false_blocks = 0    # benign wrongly blocked
    times = []

    for c in attacks:
        blocked, ms = timed_check(detector, c)
        times.append(ms)
        if blocked:
            caught += 1

    for c in benign:
        blocked, ms = timed_check(detector, c)
        times.append(ms)
        if blocked:
            false_blocks += 1

    times.sort()
    p50 = times[len(times) // 2] if times else 0.0

    return {
        "detector": detector.name,
        "attacks_total": len(attacks),
        "attacks_caught": caught,
        "detection_rate": caught / len(attacks) if attacks else 0.0,
        "benign_total": len(benign),
        "false_blocks": false_blocks,
        "false_positive_rate": false_blocks / len(benign) if benign else 0.0,
        "p50_ms": round(p50, 3),
    }


def print_table(rows):
    header = f"{'detector':<18}{'caught':<16}{'false pos':<18}{'p50 ms':<8}"
    print("\n" + header)
    print("-" * len(header))
    for r in rows:
        caught = f"{r['attacks_caught']}/{r['attacks_total']} ({r['detection_rate']:.0%})"
        fp = f"{r['false_blocks']}/{r['benign_total']} ({r['false_positive_rate']:.0%})"
        print(f"{r['detector']:<18}{caught:<16}{fp:<18}{r['p50_ms']:<8}")
    print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="sample", choices=list(DATASETS))
    args = parser.parse_args()

    cases = DATASETS[args.dataset]()
    rows = [score(d, cases) for d in DETECTORS]

    print(f"\nDataset: {args.dataset}  ({len(cases)} cases)")
    print_table(rows)

    out_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{args.dataset}.json")
    with open(out_path, "w") as f:
        json.dump(rows, f, indent=2)
    print(f"Saved: {out_path}\n")


if __name__ == "__main__":
    main()