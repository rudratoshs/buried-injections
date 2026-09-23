"""
Detectors decide whether a tool call should be BLOCKED or ALLOWED.

Every detector is just a class with one method:

    check(call) -> bool     # True = block it, False = allow it

To add your own detector, copy `RegexDetector` below, rename it,
put your logic inside check(), and add it to DETECTORS at the bottom.
"""

import re
import time


class RegexDetector:
    """Baseline: block a call if any dangerous pattern shows up in it.

    Deliberately simple. This is the floor every real detector must beat.
    """

    name = "regex-baseline"

    # Patterns that suggest an injection or a dangerous action.
    PATTERNS = [
        r"ignore (all |the )?previous instructions",
        r"disregard (your|all) (instructions|rules)",
        r"### *system",
        r"### *important",
        r"\brm\s+-rf\b",
        r"\bexec\s*\(",                 # code exec() call, not the exec tool name
        r"/\.ssh/",
        r"169\.254\.169\.254",          # cloud metadata endpoint (AWS/GCP/Azure)
        r"metadata\.google\.internal",
        r"\.aws/credentials",
        r"send .* to (http|https)://",
        r"curl .+ \| .*sh",
        r"AKIA[0-9A-Z]{16}",           # AWS access key format
    ]

    def __init__(self):
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.PATTERNS]

    def check(self, call) -> bool:
        text = call.as_text()
        return any(rx.search(text) for rx in self._compiled)


class PromptGuard2Detector:
    """Meta's Llama Prompt Guard 2 (86M) injection/jailbreak classifier.

    Two classes: 0 = BENIGN, 1 = MALICIOUS (v1's "JAILBREAK" class is gone).

    MODEL_ID points at a public community copy of the weights so no login
    is needed. The official repo is gated: request access at
    https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M, run
    `.venv/bin/hf auth login`, then switch MODEL_ID to it.

    The model reads 512 tokens at a time, and injections usually sit at the
    END of a tool output, so long text is scored in overlapping windows and
    the call is blocked if any window is malicious.
    """

    name = "prompt-guard-2"
    MODEL_ID = "gravitee-io/Llama-Prompt-Guard-2-86M-onnx"
    THRESHOLD = 0.5   # block if P(malicious) >= this in any window
    WINDOW = 510      # 512 minus the two special tokens
    STRIDE = 384      # windows overlap so an injection can't straddle a cut

    def __init__(self):
        self._model = None   # lazy load so the file imports without torch

    def _load(self):
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        self._tok = AutoTokenizer.from_pretrained(self.MODEL_ID)
        self._model = AutoModelForSequenceClassification.from_pretrained(self.MODEL_ID).eval()

    def check(self, call) -> bool:
        import torch
        if self._model is None:
            self._load()
        ids = self._tok(call.as_text(), add_special_tokens=False)["input_ids"]
        starts = range(0, max(len(ids) - self.WINDOW, 0) + self.STRIDE, self.STRIDE)
        cls, sep = self._tok.cls_token_id, self._tok.sep_token_id
        windows = [[cls, *ids[s:s + self.WINDOW], sep] for s in starts]
        batch = self._tok.pad({"input_ids": windows}, return_tensors="pt")
        with torch.no_grad():
            p_malicious = self._model(**batch).logits.softmax(-1)[:, 1]
        return p_malicious.max().item() >= self.THRESHOLD


def timed_check(detector, call):
    """Run a detector on one call, returning (blocked, milliseconds)."""
    start = time.perf_counter()
    blocked = detector.check(call)
    ms = (time.perf_counter() - start) * 1000.0
    return blocked, ms


# The detectors the benchmark will run and compare.
# Add or remove entries here.
DETECTORS = [
    RegexDetector(),
    PromptGuard2Detector(),
]
