"""
plot.py -- the leaderboard as a picture.

One point per detector: false-positive rate on the x axis, catch rate on the
y axis. The top-left corner is where a detector wants to be (catches every
attack, blocks no safe traffic). A dotted line marks the 2% false-alarm budget
used by at_budget.py, so you can see at a glance which detectors stay inside
it at their default threshold.

Reads the rows that run.py saves (bench/results/<dataset>.json) and writes a
PNG next to them. Needs matplotlib; no models are loaded.

Usage:
    python bench/plot.py                       # bench/results/agentdojo.json -> agentdojo.png
    python bench/plot.py --dataset sample      # any file run.py produced
    python bench/plot.py --results path.json --out path.png
"""

import argparse
import json
import os
import sys

import matplotlib

matplotlib.use("Agg")           # headless; must come before pyplot is imported
import matplotlib.pyplot as plt  # noqa: E402

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
REQUIRED = ("detector", "detection_rate", "false_positive_rate")
BUDGET = 0.02                   # the false-alarm budget used by at_budget.py


def load_rows(path):
    """Rows saved by run.py. Fails loudly on any other results file."""
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, list) or not data:
        raise ValueError(f"{path}: expected a non-empty list of detector rows "
                         "(the file run.py writes); per-template and payload "
                         "results are not supported")
    for row in data:
        missing = [k for k in REQUIRED if k not in row]
        if missing:
            raise ValueError(f"{path}: row {row.get('detector')!r} lacks {missing}")
    return data


def group_labels(rows, digits=1):
    """Detectors that land on the same point share one label.

    Returns {(x_pct, y_pct): [detector names]} with x/y rounded to `digits`
    so e.g. two detectors that both flag everything are annotated once.
    """
    groups = {}
    for r in rows:
        key = (round(100 * r["false_positive_rate"], digits),
               round(100 * r["detection_rate"], digits))
        groups.setdefault(key, []).append(r["detector"])
    return groups


def place_labels(groups, radius=6.0, step=11):
    """Decide where each group's label goes so neighbours do not overlap.

    Points closer than `radius` (in percentage points, either axis) form a
    cluster; labels inside a cluster are stacked upwards, `step` points apart.
    Returns [(point, text, dx, dy, ha)] in offset-points coordinates.
    """
    placed = []
    clusters = []        # [(anchor_x, anchor_y, lines_used)]
    for (x, y), names in sorted(groups.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        for c in clusters:
            if abs(c[0] - x) < radius and abs(c[1] - y) < radius:
                break
        else:
            c = [x, y, 0]
            clusters.append(c)
        dx = -8 if x > 85 else 8
        ha = "right" if dx < 0 else "left"
        dy = -12 if y > 95 else 8 + step * c[2]
        c[2] += len(names)
        placed.append(((x, y), "\n".join(names), dx, dy, ha))
    return placed


def make_plot(rows, title):
    fig, ax = plt.subplots(figsize=(7.5, 6))
    xs = [100 * r["false_positive_rate"] for r in rows]
    ys = [100 * r["detection_rate"] for r in rows]
    ax.scatter(xs, ys, s=60, zorder=3)

    for point, text, dx, dy, ha in place_labels(group_labels(rows)):
        ax.annotate(text, point, xytext=(dx, dy), textcoords="offset points",
                    fontsize=8, ha=ha, va="bottom")

    ax.axvline(100 * BUDGET, linestyle=":", linewidth=1, color="grey", zorder=1)
    ax.text(100 * BUDGET + 1.0, 78, f"{BUDGET:.0%} false-alarm budget",
            fontsize=8, color="grey", rotation=90, va="center")

    ax.set_xlim(-3, 103)
    ax.set_ylim(-3, 103)
    ax.set_xlabel("False positives: safe tool outputs blocked (%)  -  lower is better")
    ax.set_ylabel("Catch rate: attacks blocked (%)  -  higher is better")
    ax.set_title(title)
    ax.grid(True, linewidth=0.4, alpha=0.5, zorder=0)
    fig.tight_layout()
    return fig


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="agentdojo",
                        help="results file stem under bench/results/ (default: agentdojo)")
    parser.add_argument("--results", default=None,
                        help="explicit results JSON (overrides --dataset)")
    parser.add_argument("--out", default=None,
                        help="output PNG (default: same stem as the results file)")
    args = parser.parse_args()

    results = args.results or os.path.join(RESULTS, f"{args.dataset}.json")
    if not os.path.exists(results):
        sys.exit(f"{results} not found; run `python bench/run.py --dataset "
                 f"{args.dataset}` first")
    out = args.out or os.path.splitext(results)[0] + ".png"

    rows = load_rows(results)
    n_attacks = rows[0].get("attacks_total")
    n_benign = rows[0].get("benign_total")
    stem = os.path.splitext(os.path.basename(results))[0]
    title = f"Catch rate vs false-positive rate: {stem}"
    if n_attacks and n_benign:
        title += f" ({n_attacks} attacks, {n_benign} benign)"

    fig = make_plot(rows, title)
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"Saved: {out}")


if __name__ == "__main__":
    main()
