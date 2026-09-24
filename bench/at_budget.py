"""
at_budget.py -- how many attacks each detector catches when it may wrongly block
at most a fixed share of normal traffic (default 2%).

A detector that blocks lots of normal traffic gets switched off, and then it
catches nothing. So instead of each detector's default threshold, this picks
the threshold at which it wrongly blocks no more than the budget, and counts
the attacks it still catches there.

The threshold is checked two ways:
  in-sample     picked on all normal cases, measured on the same cases;
  cross-domain  picked on normal cases from 3 of AgentDojo's 4 suites, then
                measured on the 4th suite it has never seen (rotated through
                all four). This is the number to trust.

Usage:
    python bench/at_budget.py              # 2% budget, ~20 min on CPU
    python bench/at_budget.py --reuse      # recompute from saved scores
    python bench/at_budget.py --budget 0.05
"""

import argparse
import json
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datasets import AGENTDOJO_VERSION, load_agentdojo
from detectors import DETECTORS, HFClassifier, LLMGuardDetector, RegexDetector


def caught_at_budget(attack_scores, benign_scores, budget):
    """Attacks caught at the lowest threshold that keeps false alarms within budget."""
    allowed = math.floor(budget * len(benign_scores))       # e.g. 2% of 97 -> 1
    ranked = sorted(benign_scores, reverse=True)
    threshold = ranked[allowed] if allowed < len(ranked) else float("-inf")
    # Block only scores strictly above the (allowed+1)-th highest benign score.
    caught = sum(s > threshold for s in attack_scores)
    false_alarms = sum(s > threshold for s in benign_scores)
    return caught, false_alarms, threshold


def suite_sizes():
    """(benign, attack) case counts per suite, in the order load_agentdojo() yields them."""
    from agentdojo.task_suite.load_suites import get_suites
    return [(len(x.user_tasks), len(x.user_tasks) * len(x.injection_tasks))
            for x in get_suites(AGENTDOJO_VERSION).values()]


def cross_domain(attack_scores, benign_scores, budget, sizes):
    """Pick the threshold on 3 suites' normal cases, measure on the 4th; rotate."""
    def split(scores, counts):
        out, i = [], 0
        for n in counts:
            out.append(scores[i:i + n])
            i += n
        return out
    B = split(benign_scores, [b for b, _ in sizes])
    A = split(attack_scores, [a for _, a in sizes])
    caught = false_alarms = 0
    for held_out in range(len(sizes)):
        calib = [s for j, part in enumerate(B) if j != held_out for s in part]
        _, _, threshold = caught_at_budget([], calib, budget)
        caught += sum(s > threshold for s in A[held_out])
        false_alarms += sum(s > threshold for s in B[held_out])
    return caught, false_alarms


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=float, default=0.02)
    ap.add_argument("--reuse", action="store_true", help="recompute from the saved scores")
    args = ap.parse_args()
    out = os.path.join(os.path.dirname(__file__), "results", f"at_budget_{round(args.budget * 100)}pct.json")
    sizes = suite_sizes()

    if args.reuse:
        rows = json.load(open(out))
        for r in rows:
            for stale in ("attacks_caught", "false_alarms"):     # field names from an earlier version
                r.pop(stale, None)
            r.update(summarise(r["attack_scores"], r["benign_scores"], args.budget, sizes))
        report(rows, args.budget, out)
        return

    cases = load_agentdojo()
    attacks = [c for c in cases if c.label == "attack"]
    benign = [c for c in cases if c.label == "benign"]
    rows = []

    for d in DETECTORS:
        if isinstance(d, RegexDetector):
            a = [float(d.check(c)) for c in attacks]
            b = [float(d.check(c)) for c in benign]
        elif isinstance(d, HFClassifier):
            a = [d.score(c.as_text()) for c in attacks]
            b = [d.score(c.as_text()) for c in benign]
        elif isinstance(d, LLMGuardDetector):
            continue    # same model as protectai-deberta-v2; only its default threshold differs
        else:
            continue
        print(f"scored {d.name}", flush=True)
        rows.append({"detector": d.name, "budget": args.budget, "attack_scores": a, "benign_scores": b,
                     **summarise(a, b, args.budget, sizes)})
    report(rows, args.budget, out)


def summarise(a, b, budget, sizes):
    caught, fa, threshold = caught_at_budget(a, b, budget)
    cd_caught, cd_fa = cross_domain(a, b, budget, sizes)
    return {"attacks_total": len(a), "benign_total": len(b), "threshold": threshold,
            "in_sample_caught": caught, "in_sample_false_alarms": fa,
            "cross_domain_caught": cd_caught, "cross_domain_false_alarms": cd_fa}


def report(rows, budget, out):
    print(f"\nbudget: at most {budget:.0%} of normal traffic wrongly blocked\n")
    print(f"{'detector':<26}{'caught (unseen suite)':<24}{'false alarms (unseen)':<24}{'threshold':<10}")
    print("-" * 84)
    for r in rows:
        n_a, n_b = r["attacks_total"], r["benign_total"]
        c, f = r["cross_domain_caught"], r["cross_domain_false_alarms"]
        print(f"{r['detector']:<26}{f'{c}/{n_a} ({c / n_a:.0%})':<24}{f'{f}/{n_b} ({f / n_b:.0%})':<24}{r['threshold']:.4g}")
    with open(out, "w") as fh:
        json.dump(rows, fh, indent=1)
    print(f"\nSaved: {out}\n")


if __name__ == "__main__":
    main()
