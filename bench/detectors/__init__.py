"""
Detectors decide whether a tool call should be BLOCKED or ALLOWED.

Every detector is just a class with one method:

    check(call) -> bool     # True = block it, False = allow it

To add your own detector, copy `RegexDetector` below, rename it,
put your logic inside check(), and add it to DETECTORS at the bottom.
"""

import os
import re
import time

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")


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


class HFClassifier:
    """Any Hugging Face text classifier whose class 1 means injection/malicious.

    Models read 512 tokens at a time, and injections usually sit at the END
    of a tool output, so long text is scored in overlapping windows and the
    call is blocked if any window is malicious. Weights are loaded from
    safetensors only (no pickle), and everything runs on CPU so latency is
    comparable across detectors.
    """

    THRESHOLD = 0.5   # block if P(malicious) >= this in any window
    WINDOW = 510      # 512 minus the two special tokens
    STRIDE = 384      # windows overlap so an injection can't straddle a cut

    def __init__(self, name, model_id, tokenizer_id=None):
        self.name, self.MODEL_ID = name, model_id
        self.TOKENIZER_ID = tokenizer_id   # sentencepiece tokenizer to use instead
        self._model = None   # lazy load so the file imports without torch

    def _load(self):
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        if self.TOKENIZER_ID:
            self._tok = AutoTokenizer.from_pretrained(self.TOKENIZER_ID, use_fast=False)
        else:
            self._tok = AutoTokenizer.from_pretrained(self.MODEL_ID)
        self._model = AutoModelForSequenceClassification.from_pretrained(
            self.MODEL_ID, use_safetensors=True).eval()

    def score(self, text) -> float:
        """Highest P(malicious) over all windows of the text."""
        import torch
        if self._model is None:
            self._load()
        ids = self._tok(text, add_special_tokens=False)["input_ids"]
        starts = range(0, max(len(ids) - self.WINDOW, 0) + self.STRIDE, self.STRIDE)
        cls, sep = self._tok.cls_token_id, self._tok.sep_token_id
        windows = [[cls, *ids[s:s + self.WINDOW], sep] for s in starts]
        batch = self._tok.pad({"input_ids": windows}, return_tensors="pt")
        with torch.no_grad():
            return self._model(**batch).logits.softmax(-1)[:, 1].max().item()

    def check(self, call) -> bool:
        return self.score(call.as_text()) >= self.THRESHOLD


class PromptGuard2Detector(HFClassifier):
    """Meta's Llama Prompt Guard 2 (86M). Classes: 0 = BENIGN, 1 = MALICIOUS.

    MODEL_ID points at a public community copy of the weights so no login
    is needed. The official repo is gated: request access at
    https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M, run
    `.venv/bin/hf auth login`, then switch MODEL_ID to it.

    Tokenizer: with transformers 4.x the copy's tokenizer.json loads wrongly
    (word boundaries dropped: "Send a transaction" -> "Sendatransaction").
    Prompt Guard 2 86M is built on mDeBERTa-v3-base, whose original
    sentencepiece tokenizer gives identical ids to the copy under
    transformers 5 on every benchmark text, so that is used instead.
    """

    def __init__(self):
        super().__init__("prompt-guard-2-86m", "gravitee-io/Llama-Prompt-Guard-2-86M-onnx",
                         tokenizer_id="microsoft/mdeberta-v3-base")


class LLMGuardDetector:
    """Protect AI's LLM Guard PromptInjection scanner, as shipped.

    Uses the library's defaults (ProtectAI deberta-v3 v2 model, threshold
    0.92, full-text match), pinned to CPU like every other detector.
    """

    name = "llm-guard"

    def __init__(self):
        self._scanner = None

    def check(self, call) -> bool:
        if self._scanner is None:
            import dataclasses
            import torch
            from llm_guard.input_scanners import PromptInjection
            from llm_guard.input_scanners.prompt_injection import V2_MODEL
            model = dataclasses.replace(V2_MODEL, pipeline_kwargs={
                **V2_MODEL.pipeline_kwargs, "device": torch.device("cpu")})
            self._scanner = PromptInjection(model=model)
        _, is_valid, _ = self._scanner.scan(call.as_text())
        return not is_valid


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
    HFClassifier("prompt-guard-2-22m", "gravitee-io/Llama-Prompt-Guard-2-22M-onnx",
                 tokenizer_id="microsoft/deberta-v3-xsmall"),   # same tokenizer fix as 86M
    HFClassifier("protectai-deberta-v2", "protectai/deberta-v3-base-prompt-injection-v2"),
    LLMGuardDetector(),
    HFClassifier("deepset-deberta", "deepset/deberta-v3-base-injection"),
    HFClassifier("fmops-distilbert", "fmops/distilbert-prompt-injection"),
    HFClassifier("testsavant-defender", "testsavantai/prompt-injection-defender-base-v0"),
    HFClassifier("preamble-defense", "PreambleAI/prompt-injection-defense"),
    HFClassifier("jailbreak-detector-large", "madhurjindal/Jailbreak-Detector-Large"),
]
