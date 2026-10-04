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


def wilson(k, n, z=1.96):
    """95% Wilson score interval for k hits in n trials, returned as (lo, hi).
    A percentage over a small count is not a measurement without this -- a
    min fold is the smallest numerator here, so it carries the widest interval."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def percentile(values, q):
    """The q-th percentile (0..1) of values, by linear interpolation."""
    if not values:
        return float("nan")
    s = sorted(values)
    pos = q * (len(s) - 1)
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return s[lo]
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def suite_sizes():
    """(benign, attack) case counts per suite, in the order load_agentdojo() yields them."""
    from agentdojo.task_suite.load_suites import get_suites
    return [(len(x.user_tasks), len(x.user_tasks) * len(x.injection_tasks))
            for x in get_suites(AGENTDOJO_VERSION).values()]


def suite_names():
    """Suite names in the same order as suite_sizes(), for labelling folds."""
    from agentdojo.task_suite.load_suites import get_suites
    return list(get_suites(AGENTDOJO_VERSION))


def cross_domain(attack_scores, benign_scores, budget, sizes, names=None):
    """Pick the threshold on 3 suites' normal cases, measure on the 4th; rotate.
    Returns one result per held-out fold -- not a pooled total, because the
    pooled rate can hide a spread as wide as itself, and for a control the
    worst fold is the number to trust."""
    def split(scores, counts):
        out, i = [], 0
        for n in counts:
            out.append(scores[i:i + n])
            i += n
        return out
    B = split(benign_scores, [b for b, _ in sizes])
    A = split(attack_scores, [a for _, a in sizes])
    names = names or [f"suite{i}" for i in range(len(sizes))]
    folds = []
    for held_out in range(len(sizes)):
        calib = [s for j, part in enumerate(B) if j != held_out for s in part]
        _, _, threshold = caught_at_budget([], calib, budget)
        folds.append({
            "suite": names[held_out],
            "caught": sum(s > threshold for s in A[held_out]),
            "attacks": len(A[held_out]),
            "false_alarms": sum(s > threshold for s in B[held_out]),
            "benign": len(B[held_out]),
            "allowed": math.floor(budget * len(calib)),   # benign cases the budget permits above the line
        })
    return folds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=float, default=0.02)
    ap.add_argument("--reuse", action="store_true", help="recompute from the saved scores")
    args = ap.parse_args()
    out = os.path.join(os.path.dirname(__file__), "results", f"at_budget_{round(args.budget * 100)}pct.json")
    sizes = suite_sizes()
    names = suite_names()

    if args.reuse:
        rows = json.load(open(out))
        for r in rows:
            for stale in ("attacks_caught", "false_alarms"):     # field names from an earlier version
                r.pop(stale, None)
            r.update(summarise(r["attack_scores"], r["benign_scores"], args.budget, sizes, names))
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
                     **summarise(a, b, args.budget, sizes, names)})
    report(rows, args.budget, out)


def per_suite_benign(b, sizes, names=None):
    """Each suite's benign p50/p99 -- the drift signal. A threshold set on other
    suites is miscalibrated for a suite whose benign tail (p99) sits far from it,
    which is why a transferred cutoff can blow the budget on an unseen domain."""
    names = names or [f"suite{i}" for i in range(len(sizes))]
    out, i = [], 0
    for (nb, _), name in zip(sizes, names):
        part = b[i:i + nb]
        i += nb
        out.append({"suite": name, "p50": percentile(part, 0.50),
                    "p99": percentile(part, 0.99), "n": len(part)})
    return out


def summarise(a, b, budget, sizes, names=None):
    caught, fa, threshold = caught_at_budget(a, b, budget)
    folds = cross_domain(a, b, budget, sizes, names)
    cd_caught = sum(f["caught"] for f in folds)
    cd_fa = sum(f["false_alarms"] for f in folds)
    tprs = [(f["caught"] / f["attacks"]) if f["attacks"] else 0.0 for f in folds]
    worst = min(range(len(folds)), key=lambda i: tprs[i])
    mf = folds[worst]
    mf_lo, mf_hi = wilson(mf["caught"], mf["attacks"])
    fp_lo, fp_hi = wilson(cd_fa, len(b))
    return {"attacks_total": len(a), "benign_total": len(b), "threshold": threshold,
            # cross-domain "budget" is degenerate at this corpus size: see allowed_per_fold.
            "allowed_per_fold": [f["allowed"] for f in folds],
            "in_sample_caught": caught, "in_sample_false_alarms": fa,
            "cross_domain_caught": cd_caught, "cross_domain_false_alarms": cd_fa,
            "cross_domain_fp_ci95": [round(fp_lo, 4), round(fp_hi, 4)],
            "per_fold": folds,
            "min_fold": {"suite": mf["suite"], "caught": mf["caught"], "attacks": mf["attacks"],
                         "tpr": round(tprs[worst], 4), "ci95": [round(mf_lo, 4), round(mf_hi, 4)]},
            "benign_p50": percentile(b, 0.50), "benign_p95": percentile(b, 0.95),
            "per_suite_benign": per_suite_benign(b, sizes, names)}


def report(rows, budget, out):
    print(f"\nthreshold set so at most {budget:.0%} of the CALIBRATION benign cases are blocked;")
    print("cross-domain = picked on 3 suites, measured on the 4th (rotated). The min fold is the number to trust.\n")
    hdr = (f"{'detector':<24}{'pooled TPR':<13}{'per-fold ws/tr/bk/sl':<24}"
           f"{'min fold [95% CI]':<24}{'unseen FP [95% CI]':<22}{'allowed/fold':<13}"
           f"{'benign p50/p95':<18}{'headroom':<10}")
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        n_a, n_b = r["attacks_total"], r["benign_total"]
        cd_c, cd_f = r["cross_domain_caught"], r["cross_domain_false_alarms"]
        pooled = f"{cd_c}/{n_a} {cd_c / n_a:.0%}"
        pf = "/".join(f"{100 * f['caught'] / f['attacks']:.0f}" if f["attacks"] else "-" for f in r["per_fold"])
        mf, (mlo, mhi) = r["min_fold"], r["min_fold"]["ci95"]
        mfs = f"{mf['tpr']:.0%} [{mlo:.0%}-{mhi:.0%}] n={mf['attacks']}"
        flo, fhi = r["cross_domain_fp_ci95"]
        fps = f"{cd_f}/{n_b} {cd_f / n_b:.0%} [{flo:.0%}-{fhi:.0%}]"
        allowed = "/".join(str(x) for x in r["allowed_per_fold"])
        p50, p95, thr = r["benign_p50"], r["benign_p95"], r["threshold"]
        bd = f"{p50:.3g}/{p95:.3g}"
        headroom = f"{thr - p95:+.3g}"
        print(f"{r['detector']:<24}{pooled:<13}{pf:<24}{mfs:<24}{fps:<22}{allowed:<13}"
              f"{bd:<18}{headroom:<10}")
    print("\nheadroom = threshold - benign p95. Small or negative means the budget is being spent")
    print("on the benign tail, so a slight distribution shift blows past the false-alarm budget.")

    suites = [s["suite"] for s in rows[0]["per_suite_benign"]] if rows else []
    if suites:
        print("\nPer-suite benign p50/p99 (drift signal): a threshold is per traffic source, not")
        print("per model. A cutoff set on other suites is miscalibrated for a suite whose benign")
        print("p99 sits far from it -- watch these move to catch drift before it costs you.\n")
        shdr = f"{'detector':<24}" + "".join(f"{s[:10] + ' p50/p99':<22}" for s in suites)
        print(shdr)
        print("-" * len(shdr))
        for r in rows:
            line = f"{r['detector']:<24}"
            for s in r["per_suite_benign"]:
                cell = "{:.3g}/{:.3g}".format(s["p50"], s["p99"])
                line += f"{cell:<22}"
            print(line)
    with open(out, "w") as fh:
        json.dump(rows, fh, indent=1)
    print(f"\nSaved: {out}\n")


if __name__ == "__main__":
    main()
