# Contributing to buried-injections

Thanks for wanting to help. This benchmark gets more useful every time someone
adds a detector, an attack, or a fix — so contributions are genuinely welcome,
and small ones are perfect.

## The most useful thing you can add: a detector

The whole point of this repo is to compare prompt-injection detectors on
realistic attacks. Adding one is usually a **one-line change**.

Any Hugging Face text classifier:

```python
# in bench/detectors/__init__.py
HFClassifier("my-detector", "org/model-id")   # class 1 = injection
```

Anything else — an API-based detector, a heuristic, your own model — is a small
class with a `name` and a `check(call) -> bool` (`True` = block).

Then run:

```bash
make bench-agentdojo
make bench-payloads
```

…and open a PR with the numbers. I'll add your detector to the leaderboard.

## Other good contributions

- **A new attack template.** Every AgentDojo attack here uses one wrapper
  (`important_instructions`). More templates would make the benchmark stronger —
  this is a known limitation, see the README caveats.
- **A bug in the harness or scoring.** If a number looks wrong, please open an
  issue with the case; correctness matters more than any result.
- **Docs and clarity fixes.** If something was confusing to run, it'll confuse
  the next person too.

## Ground rules

- Every number must be reproducible. If you change scoring, say so in the PR.
- Keep it honest. This repo reports what detectors *miss*; findings that make a
  detector look bad are just as welcome as ones that make it look good.
- API-only detectors (needing a key) are welcome as PRs, but they're kept out of
  the default run so anyone can reproduce every number for free.

## Running it locally

```bash
make setup   # Python 3.12 venv + requirements
make bench   # 16-case smoke test (fast)
```

Open an issue if you get stuck — I'd rather fix the setup than have you fight it.
