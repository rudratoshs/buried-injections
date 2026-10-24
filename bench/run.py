"""
run.py -- the benchmark.

Runs every detector over every test case, then prints one table:
how many attacks each detector caught, how often it wrongly blocked a
safe call, and how much time it added.

Usage:
    python bench/run.py                  # uses the built-in sample set
    python bench/run.py --dataset agentdojo
    python bench/run.py --dataset agentdojo --template novel_wrapper
    python bench/run.py --dataset agentdojo --template all   # per-template table
    python bench/run.py --detector regex-baseline   # run one detector only
    python bench/run.py --list-detectors            # show detector names
"""

import argparse
import json
import os
import sys

# Work whether run.py is launched from the repo root, from bench/, or
# flattened next to its sibling files. Add this file's own folder to the path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datasets import DATASETS, TEMPLATE_NAMES
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


def count_caught(detector, attacks):
    """How many attacks this detector blocks, and the per-call times."""
    caught, times = 0, []
    for c in attacks:
        blocked, ms = timed_check(detector, c)
        times.append(ms)
        if blocked:
            caught += 1
    return caught, times


def score_per_template(detectors, template_cases, benign):
    """Catch rate per (template, detector), plus one shared benign/FP row.

    `template_cases` is {template_name: [attack ToolCalls]}; `benign` is the
    (template-independent) benign set, scored once per detector. This is what
    makes the memorisation-vs-generalisation gap explicit: a template-matching
    detector scores high on `standard` and lower on the re-worded templates.
    """
    per_template = {}   # template -> [row per detector]
    for name, attacks in template_cases.items():
        rows = []
        for d in detectors:
            caught, times = count_caught(d, attacks)
            times.sort()
            rows.append({
                "detector": d.name,
                "attacks_total": len(attacks),
                "attacks_caught": caught,
                "detection_rate": caught / len(attacks) if attacks else 0.0,
                "p50_ms": round(times[len(times) // 2], 3) if times else 0.0,
            })
        per_template[name] = rows

    benign_rows = []
    for d in detectors:
        false_blocks, _ = count_caught(d, benign)
        benign_rows.append({
            "detector": d.name,
            "benign_total": len(benign),
            "false_blocks": false_blocks,
            "false_positive_rate": false_blocks / len(benign) if benign else 0.0,
        })
    return per_template, benign_rows


def print_table(rows):
    header = f"{'detector':<26}{'caught':<16}{'false pos':<18}{'p50 ms':<8}"
    print("\n" + header)
    print("-" * len(header))
    for r in rows:
        caught = f"{r['attacks_caught']}/{r['attacks_total']} ({r['detection_rate']:.0%})"
        fp = f"{r['false_blocks']}/{r['benign_total']} ({r['false_positive_rate']:.0%})"
        print(f"{r['detector']:<26}{caught:<16}{fp:<18}{r['p50_ms']:<8}")
    print()


def print_template_tables(detectors, per_template, benign_rows):
    """One column per detector: catch rate per template, then shared FP."""
    names = [d.name for d in detectors]
    col = max(18, max((len(n) for n in names), default=0) + 2)
    print("\nCatch rate per template (attacks caught / total):\n")
    header = f"{'template':<16}" + "".join(f"{n:<{col}}" for n in names)
    print(header)
    print("-" * len(header))
    for template, rows in per_template.items():
        by_name = {r["detector"]: r for r in rows}
        line = f"{template:<16}"
        for n in names:
            r = by_name[n]
            cell = f"{r['attacks_caught']}/{r['attacks_total']} ({r['detection_rate']:.0%})"
            line += f"{cell:<{col}}"
        print(line)

    print("\nFalse positives on the benign set (template-independent):\n")
    header = f"{'detector':<26}{'false pos':<18}"
    print(header)
    print("-" * len(header))
    for r in benign_rows:
        fp = f"{r['false_blocks']}/{r['benign_total']} ({r['false_positive_rate']:.0%})"
        print(f"{r['detector']:<26}{fp:<18}")
    print()


def build_cases(dataset, template):
    """Load a dataset; `template` only applies to the templated agentdojo set."""
    if dataset == "agentdojo":
        return DATASETS[dataset](template=template)
    return DATASETS[dataset]()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="sample", choices=list(DATASETS))
    parser.add_argument("--template", default="standard",
                        choices=TEMPLATE_NAMES + ["all"],
                        help="attack-delivery template for the agentdojo dataset "
                             "(default: standard = important_instructions; "
                             "'all' runs every template and prints a per-template "
                             "catch-rate table)")
    parser.add_argument("--detector", default=None,
                        help="run only this detector (see --list-detectors)")
    parser.add_argument("--list-detectors", action="store_true",
                        help="print detector names and exit")
    args = parser.parse_args()

    if args.list_detectors:
        for d in DETECTORS:
            print(d.name)
        return

    detectors = DETECTORS
    if args.detector:
        detectors = [d for d in DETECTORS if d.name == args.detector]
        if not detectors:
            available = ", ".join(d.name for d in DETECTORS)
            parser.error("unknown detector %r (available: %s)"
                         % (args.detector, available))

    out_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(out_dir, exist_ok=True)

    # --- per-template mode: only meaningful for the templated agentdojo set ---
    if args.template == "all":
        if args.dataset != "agentdojo":
            parser.error("--template all only applies to --dataset agentdojo")
        template_attacks = {}
        benign = None
        for name in TEMPLATE_NAMES:
            cases = build_cases("agentdojo", name)
            template_attacks[name] = [c for c in cases if c.label == "attack"]
            if benign is None:   # identical across templates; keep the first
                benign = [c for c in cases if c.label == "benign"]

        per_template, benign_rows = score_per_template(detectors, template_attacks, benign)

        total = sum(len(a) for a in template_attacks.values())
        print(f"\nDataset: agentdojo  (templates: {len(TEMPLATE_NAMES)}, "
              f"{total} attacks total, {len(benign)} benign)")
        print_template_tables(detectors, per_template, benign_rows)

        payload = {"per_template": per_template, "benign": benign_rows}
        stem = "agentdojo.templates" if not args.detector \
            else f"agentdojo.templates.{args.detector}"
        out_path = os.path.join(out_dir, f"{stem}.json")
        with open(out_path, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"Saved: {out_path}\n")
        return

    # --- single-template mode (default: standard, i.e. unchanged behaviour) ---
    cases = build_cases(args.dataset, args.template)
    rows = [score(d, cases) for d in detectors]

    label = args.dataset
    if args.dataset == "agentdojo" and args.template != "standard":
        label = f"{args.dataset} [{args.template}]"
    print(f"\nDataset: {label}  ({len(cases)} cases)")
    print_table(rows)

    stem = args.dataset if not args.detector else f"{args.dataset}.{args.detector}"
    if args.dataset == "agentdojo" and args.template != "standard":
        stem = f"{stem}.{args.template}"
    out_path = os.path.join(out_dir, f"{stem}.json")
    with open(out_path, "w") as f:
        json.dump(rows, f, indent=2)
    print(f"Saved: {out_path}\n")


if __name__ == "__main__":
    main()