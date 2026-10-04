"""
register.py -- does rewriting an injection as a polite request get it past the detector?

Scores the 40 pairs in register_pairs.py on their own (no surrounding tool
output, like payloads.py). Each pair asks for the same action as a command and
as a polite first-person request. Reported two ways:

  default     each detector's own check() (0.5, or LLM Guard's shipped 0.92);
  2% budget   the in-sample threshold saved by at_budget.py, i.e. the cut at
              which the detector wrongly blocks at most 2% of AgentDojo's
              normal tool output. Run `make bench-budget` first; skipped if
              that file is missing.

Per detector it prints how many commands and polite versions are caught, the
discordant pairs (command caught but polite missed / the reverse), an exact
two-sided McNemar p with a Holm correction across detectors, and a paired
bootstrap 95% interval for the drop. All detectors see the same 40 pairs, so
the rows are not independent replications.

The polite rewrite changes register AND removes canonical attack words
("ignore", "override", "system"), so this measures the whole rewrite, not
politeness alone.

Usage:
    python bench/register.py        # ~1 min on CPU
"""

import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datasets import ToolCall
from detectors import DETECTORS, HFClassifier, RegexDetector
from register_pairs import PAIRS

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")


def mcnemar_p(b, c):
    """Exact two-sided McNemar p from the discordant counts b and c."""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def holm(pvals):
    """Holm-adjusted p-values, same keys as the input dict."""
    order = sorted(pvals, key=pvals.get)
    adjusted, running = {}, 0.0
    for rank, key in enumerate(order):
        running = max(running, min(1.0, (len(order) - rank) * pvals[key]))
        adjusted[key] = running
    return adjusted


def drop_interval(command, polite, reps=2000, seed=0):
    """Paired bootstrap 95% interval for (command rate - polite rate)."""
    rng = random.Random(seed)
    n = len(command)
    diffs = sorted(
        sum(command[i] - polite[i] for i in (rng.randrange(n) for _ in range(n))) / n
        for _ in range(reps))
    return diffs[int(0.025 * reps)], diffs[int(0.975 * reps) - 1]


def budget_thresholds():
    """{detector: threshold} from at_budget.py's saved results, or {} if absent."""
    path = os.path.join(RESULTS, "at_budget_2pct.json")
    if not os.path.exists(path):
        return {}
    return {r["detector"]: r["threshold"] for r in json.load(open(path))}


def compare(command, polite):
    """Summary of one detector's verdicts on the pairs (lists of bools)."""
    b = sum(x and not y for x, y in zip(command, polite))
    c = sum(y and not x for x, y in zip(command, polite))
    lo, hi = drop_interval(command, polite)
    return {"command_caught": sum(command), "polite_caught": sum(polite),
            "command_only": b, "polite_only": c, "mcnemar_p": mcnemar_p(b, c),
            "drop": (sum(command) - sum(polite)) / len(command), "drop_ci95": [lo, hi]}


def main():
    thresholds = budget_thresholds()
    rows = []
    for d in DETECTORS:
        row = {"detector": d.name}
        command = [d.check(ToolCall("", {}, cmd, "attack")) for cmd, _ in PAIRS]
        polite = [d.check(ToolCall("", {}, pol, "attack")) for _, pol in PAIRS]
        row["default"] = compare(command, polite)
        if d.name in thresholds:   # at_budget.py skips LLM Guard (same model as protectai)
            t = thresholds[d.name]
            if isinstance(d, HFClassifier):
                score = d.score
            elif isinstance(d, RegexDetector):
                score = lambda text: float(d.check(ToolCall("", {}, text, "attack")))
            else:
                score = None
            if score is not None:
                row["budget_threshold"] = t
                row["budget"] = compare([score(cmd) > t for cmd, _ in PAIRS],
                                        [score(pol) > t for _, pol in PAIRS])
        rows.append(row)
        print(f"scored {d.name}", file=sys.stderr, flush=True)

    for key in ("default", "budget"):
        present = {r["detector"]: r[key]["mcnemar_p"] for r in rows if key in r}
        for name, p in holm(present).items():
            next(r for r in rows if r["detector"] == name)[key]["holm_p"] = p

    n = len(PAIRS)
    print(f"\n{n} pairs, scored alone. command -> polite caught; b/c = command-only / polite-only.\n")
    print(f"{'detector':<26}{'default':<12}{'b/c':<8}{'Holm p':<10}{'2% budget':<12}{'b/c':<8}{'Holm p':<10}")
    print("-" * 86)
    for r in rows:
        line = f"{r['detector']:<26}"
        for key in ("default", "budget"):
            if key in r:
                s = r[key]
                line += (f"{str(s['command_caught']) + ' -> ' + str(s['polite_caught']):<12}"
                         f"{str(s['command_only']) + '/' + str(s['polite_only']):<8}{s['holm_p']:<10.2g}")
            else:
                line += f"{'-':<12}{'-':<8}{'-':<10}"
        print(line)

    out = os.path.join(RESULTS, "register.json")
    os.makedirs(RESULTS, exist_ok=True)
    with open(out, "w") as f:
        json.dump(rows, f, indent=2)
    print(f"\nSaved: {out}\n")


if __name__ == "__main__":
    main()
