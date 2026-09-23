<div align="center">

# 🛡️ buried-injections

### How well do open-source detectors catch *realistic* AI agent attacks?

![Python](https://img.shields.io/badge/python-3.14-3776AB?logo=python&logoColor=white)
![Dataset](https://img.shields.io/badge/dataset-AgentDojo%20v1-8A2BE2)
![Attacks](https://img.shields.io/badge/attacks-629-critical)
![Benign](https://img.shields.io/badge/benign-97-success)
![Model](https://img.shields.io/badge/model-Prompt%20Guard%202%2086M-0467DF?logo=meta&logoColor=white)

</div>

---

## 🎯 TL;DR

On **629 real [AgentDojo](https://github.com/ethz-spylab/agentdojo) injection attacks**:

> 🔴 **Regex catches 0%**
> 🔴 **Meta's Prompt Guard 2 catches ~1%**

This is **not a bug in the harness** ✅ (it was checked). It's what happens when you
stop testing detectors on the attack string alone and start testing them the
way a firewall actually sees traffic: 🕵️ **the injection buried inside ordinary tool output.**

---

## 📊 Results

`make bench-agentdojo` · 629 attack cases + 97 benign cases

| Detector | 🎯 Caught | ⚠️ False positives | ⏱️ p50 latency |
|---|---|---|---|
| 🔤 `regex-baseline` | **0 / 629** (0%) | 0 / 97 (0%) | 0.057 ms |
| 🤖 `prompt-guard-2` | **6 / 629** (1%) | 0 / 97 (0%) | 167.7 ms |

- 🎯 **Caught** — attacks correctly blocked *(higher is better)*
- ⚠️ **False positives** — safe calls wrongly blocked *(lower is better)*
- ⏱️ **p50 latency** — median time added per call *(Prompt Guard 2 on CPU)*

> [!NOTE]
> 🧩 **Model used:** the public community copy
> [`gravitee-io/Llama-Prompt-Guard-2-86M-onnx`](https://huggingface.co/gravitee-io/Llama-Prompt-Guard-2-86M-onnx)
> of Meta's gated model, so no access request is needed. The benchmark loads its
> `model.safetensors` weights through `transformers`, not the ONNX files.
> Numbers may shift slightly with Meta's official
> [`meta-llama/Llama-Prompt-Guard-2-86M`](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M);
> the 0–3% conclusion does not.

---

## 🔬 Why the classifier misses: context dilution

| 🧪 Test | 📈 P(malicious) |
|---|---|
| AgentDojo attack text **on its own** | **0.996** 🚨 blocked |
| Same attack **after a normal tool output** | usually **< 0.05** 😶 allowed |

Prompt Guard 2 spots the attack instantly in isolation. Put it **after** a
normal tool output — 🧾 a bill, 📧 an email, ⭐ a product review — and the model
calls the whole thing safe. The benign context **dilutes the signal**.

This held across every configuration tested (`make bench-windows`, ~15 min on CPU):

| 👀 What the model reads | 🪟 Window | 🎯 Caught | ⚠️ Wrongly blocked |
|---|---|---|---|
| task prompt + tool output | 510 *(default)* | 10 / 629 | 0 / 97 |
| task prompt + tool output | 128 | 6 / 629 | 0 / 97 |
| task prompt + tool output | 64 | 16 / 629 | 0 / 97 |
| 🔧 **tool output only** | 510 | **0 / 629** | 0 / 97 |
| 🔧 **tool output only** | 128 | **0 / 629** | 0 / 97 |
| 🔧 **tool output only** | 64 | 18 / 629 (3%) | 0 / 97 |

> [!IMPORTANT]
> 🔧 The **"tool output only"** rows matter most. That's closest to how a gateway
> scans in practice — and it's the **weakest** case. Smaller windows help only
> marginally ✂️: they chop the ~100-token attack into fragments that each look harmless.

<sub>ℹ️ The main results table shows 6/629 rather than 10/629 for the default
configuration because the harness prefixes each case with its tool name,
`agent_task`. Small wording changes move the count by a few cases; none move
it above 3%.</sub>

---

## 🧭 Scope: what this does and does not test

✅ **Does** — text-level detection. Can a detector, reading the text an agent
sees, flag an injection attack without wrongly flagging benign requests?

❌ **Does not:**

- 🤖 **Run a live agent.** It doesn't measure whether the attack actually
  *succeeds* against a model — that needs an LLM and API costs.
- 📜 **Test policy / allowlist enforcement.** Prompt Guard 2 only flags *prompt
  injections*, so it lets plainly dangerous calls through. On the built-in sample it allows:
  - 💣 `rm -rf /`
  - 🔑 reading `~/.ssh/id_rsa` and `~/.aws/credentials`
  - ☁️ the cloud metadata endpoint `169.254.169.254`
  - 📥 `curl … | sh`

  None of those are injections, so a classifier won't flag them. A real firewall
  needs a policy layer for that, and it isn't benchmarked here.

> [!TIP]
> 💡 **Takeaway for anyone building an agent firewall:** detection classifiers are
> weak on realistic, context-embedded attacks, so **policy-based enforcement**
> (allow / deny / approve per tool and argument) matters **more, not less**.

---

## 🚀 Run it

```bash
make setup            # 📦 creates .venv, installs transformers + torch + agentdojo
make bench            # 🧪 16-case built-in sample
make bench-agentdojo  # 📊 the real 629-case AgentDojo result (~2.5 min on CPU)
make bench-windows    # 🔬 the context-dilution window table (~15 min on CPU)
```

⬇️ The first run downloads the Prompt Guard 2 weights (~300 MB).

🔐 **Using Meta's official model instead:** request access at the Hugging Face
link above, run `.venv/bin/hf auth login`, then change `MODEL_ID` in
`bench/detectors/__init__.py`.

---

## 🗂️ Files

| 📄 File | 🛠️ Role |
|---|---|
| `bench/run.py` | Runs every detector over every case, prints + saves the table |
| `bench/datasets/__init__.py` | Test cases: 16-case sample + AgentDojo loader (629 + 97) |
| `bench/detectors/__init__.py` | Detectors: regex baseline + Prompt Guard 2 |
| `bench/windows.py` | Context-dilution experiment: input scope × window size |
| `bench/results/` | Generated tables (JSON) |

---

## ➕ Add your own detector

1. 📋 Copy a class in `bench/detectors/__init__.py`
2. ✍️ Implement `check(call) -> bool` (`True` = block)
3. 📌 Add it to `DETECTORS`
4. 🔁 Re-run `make bench-agentdojo` to see it in the table

---

## ⚠️ Caveats

- 🧪 Results are from **one model copy on one dataset**. They show a *pattern*
  (detectors fail on context-embedded attacks), not a universal constant.
- 📚 AgentDojo is one benchmark. A fuller picture would add InjecAgent, AgentDyn,
  and a live-agent evaluation.
- 🚦 The 16-case sample is a **smoke test**, not a result. Only the AgentDojo
  numbers are meaningful.
