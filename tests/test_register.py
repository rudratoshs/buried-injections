"""Tests for the register bench (bench/register.py). Run: python -m pytest -q tests

Needs nothing but the standard library: no models are loaded.
"""

import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bench"))

from register import compare, holm, mcnemar_p  # noqa: E402
from register_pairs import PAIRS  # noqa: E402

FROZEN_SHA256 = "827215d83f051544286196c363915e154a457b679b3a77839f287f9c4a23131a"


def test_pairs_are_the_frozen_set():
    digest = hashlib.sha256(json.dumps(PAIRS, ensure_ascii=False).encode()).hexdigest()
    assert digest == FROZEN_SHA256


def test_pairs_shape():
    assert len(PAIRS) == 40
    assert len({c for c, _ in PAIRS}) == 40 and len({p for _, p in PAIRS}) == 40
    assert all(c != p for c, p in PAIRS)


def test_polite_versions_avoid_command_words():
    banned = ("ignore", "override", "system", "instruction", "directive", "disregard")
    for _, polite in PAIRS:
        assert not any(w in polite.lower() for w in banned), polite


def test_mcnemar_exact():
    assert mcnemar_p(0, 0) == 1.0
    assert mcnemar_p(5, 0) == 2 / 32            # all five discordant pairs one way
    assert mcnemar_p(3, 3) == 1.0
    assert abs(mcnemar_p(20, 1) - 2.098083e-05) < 1e-10


def test_holm_is_monotone_and_capped():
    adj = holm({"a": 0.01, "b": 0.04, "c": 0.03})
    assert adj == pytest.approx({"a": 0.03, "c": 0.06, "b": 0.06})
    assert holm({"x": 0.9, "y": 0.8}) == {"y": 1.0, "x": 1.0}


def test_compare_counts():
    command = [True, True, False, True]
    polite = [False, True, False, False]
    s = compare(command, polite)
    assert (s["command_caught"], s["polite_caught"]) == (3, 1)
    assert (s["command_only"], s["polite_only"]) == (2, 0)
    assert s["drop"] == 0.5
    lo, hi = s["drop_ci95"]
    assert lo <= 0.5 <= hi
