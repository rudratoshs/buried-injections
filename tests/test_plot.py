"""Tests for the leaderboard scatter plot (bench/plot.py). Run: python -m pytest -q tests

Needs matplotlib (in requirements.txt) and the saved results; no models are loaded.
Skipped if matplotlib is not installed.
"""

import os
import sys

import pytest

pytest.importorskip("matplotlib")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bench"))

from plot import RESULTS, group_labels, load_rows, make_plot  # noqa: E402

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def test_load_rows_reads_what_run_py_saves():
    rows = load_rows(os.path.join(RESULTS, "agentdojo.json"))
    assert len(rows) == 10
    for r in rows:
        assert 0.0 <= r["detection_rate"] <= 1.0
        assert 0.0 <= r["false_positive_rate"] <= 1.0


def test_load_rows_rejects_other_result_shapes(tmp_path):
    bad = tmp_path / "payloads.json"
    bad.write_text('[{"detector": "x", "agentdojo_blocked": 1}]')
    with pytest.raises(ValueError, match="lacks"):
        load_rows(str(bad))

    templated = tmp_path / "agentdojo.templates.json"
    templated.write_text('{"per_template": {}, "benign": []}')
    with pytest.raises(ValueError, match="expected a non-empty list"):
        load_rows(str(templated))


def test_overlapping_detectors_share_one_label():
    rows = [
        {"detector": "a", "detection_rate": 1.0, "false_positive_rate": 0.98},
        {"detector": "b", "detection_rate": 1.0, "false_positive_rate": 0.98},
        {"detector": "c", "detection_rate": 0.0, "false_positive_rate": 0.0},
    ]
    groups = group_labels(rows)
    assert groups == {(98.0, 100.0): ["a", "b"], (0.0, 0.0): ["c"]}


def test_make_plot_writes_a_png(tmp_path):
    rows = load_rows(os.path.join(RESULTS, "sample.json"))
    out = tmp_path / "sample.png"
    fig = make_plot(rows, "sample")
    fig.savefig(str(out), dpi=72)
    assert out.read_bytes()[:8] == PNG_MAGIC
