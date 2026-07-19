# How Guardana works — the whole product, from A to Z

This is the map of the entire product: what it is, why it exists, how the engine
works, how extensions plug in, and how the pieces fit the way you run AI. Read it
top to bottom and you will understand Guardana end to end — the concept, not just
the code. Every other doc drills into one box on this map.

---

## 1. The one-sentence version

**Guardana is one rule engine that verifies the security of AI you host or build
yourself — the model's *files* and *build pipeline*, and the served model's
*behaviour* — and it runs the same way on a laptop, in CI, and next to a live
model.**

Two things make it different from a general code scanner:

1. **It is dedicated to AI/LLM risk, and only that.** There are excellent generic
   tools for SQL injection, secrets, and CVEs. Guardana does not compete with
   them. It knows about pickle opcodes in a `.pt` file, `trust_remote_code`, Keras
   `Lambda` layers, MCP tool poisoning, dataset loading scripts, system-prompt
   leakage, jailbreaks, excessive tool-use agency, and denial-of-wallet — the
   threats that only exist because the thing you ship is a model.
2. **It treats *"did the attack actually succeed, and how sure are we?"* as a
   first-class question.** Most dynamic AI scanners grade a model's answer with a
   keyword regex and misjudge the outcome a large fraction of the time. Guardana
   makes grading a swappable, versioned component (the **Evaluator**) that reports
   a confidence, so a result you can't trust is labelled as such instead of
   quietly passing.

---

## 2. The mental model (four ideas)

Hold these four ideas and everything else follows.

**a) One engine, five abstractions.** The engine knows almost nothing about
specific threats. It knows how to *discover* checks, *run* them against a *thing*,
and *grade* the result. All the actual security knowledge lives in small,
pluggable pieces. There are exactly five kinds of piece — Target, Rule,
Evaluator, Finding, Profile — and everything you might add is one of them.

**b) Two layers: build vs runtime.** Every check secures one of two things:

- **Build** — *how the model is made*: its files, weights, dependencies, source
  code, and training data. These checks are static: they read artifacts, need no
  network, and run on your machine, in CI, or on the training server.
- **Runtime** — *how the served model behaves*: prompt injection, jailbreaks,
  system-prompt leakage, secret-leaking output, excessive tool use, unbounded
  output. These checks are dynamic: they exercise a live endpoint and grade what
  comes back.

This split is a first-class concept in the code — `RuleMeta.surface` — and
`guardana rules` groups its output by it.

**c) Three ways to run it, one engine underneath.** `scan` (build layer, static),
`probe` (runtime layer, one-shot), and `monitor` (runtime layer, on a loop next
to a served model). Same rules, same findings, same report — three entry points.
The command *is* the layer selector: `scan` runs the build rules, `probe` and
`monitor` the runtime ones.

**d) A finding is a finding.** However a check was written (YAML or Python) and
whatever it looked at (a file or a live model), the result is one normalized
shape with a severity, a standards tag (OWASP/MITRE/NIST), evidence, and — for
dynamic checks — a graded verdict with a confidence. One shape means one report
format, one policy gate, one collector.

---

## 3. The engine, box by box

The engine lives in `guardana-core`. Here is each abstraction and how a single
run flows through them.

### Target — the thing under test
A uniform interface over *what you are checking*, so a rule never hard-codes
whether it is reading a file or talking to a model.

- `ArtifactTarget` walks a directory and hands rules its files (models, manifests,
  source), skipping `.git`, `.venv`, `node_modules`, and the like.
- `EndpointTarget` is a live chat endpoint; it exposes `chat(messages)` and, when
  the transport supports it, `offer_tools(messages, tools)` for tool-calling —
  and it hides which wire protocol is in use (`--provider openai|ollama|tgi`).

A target advertises **capabilities** (`READ_FILES`, `CHAT`, `PLANT_SYSTEM_PROMPT`,
`CALL_TOOLS`). A rule declares which capabilities it needs, and the runner
*skips* a rule the target can't satisfy — never crashes, and records the skip.

### Rule — what to look for
A single check. Two ways to author one, **same contract**:

- **Declarative YAML** — "send these prompts, grade with this evaluator", or a
  multi-turn `steps:` scenario. No code.
- **Python plugin** — for logic YAML can't express (parsing a pickle, walking an
  AST, reading a model config, driving a tool-calling probe).

A rule carries `RuleMeta`: its id, severity, which layer it belongs to (its
`surface`, derived automatically — artifact ⇒ build, endpoint ⇒ runtime), its
standards taxonomy, and the capabilities it needs.

### Evaluator — did it succeed, and how sure are we
This is the differentiator. An evaluator turns a model's reply into a **Verdict**:
`outcome` (pass / fail / **inconclusive**), a `confidence`, a `rationale`, and the
id of the evaluator that judged it. Grading is swappable without touching the
rule. Shipped evaluators:

- `keyword` — cheap refusal-marker matching, honestly low confidence.
- `canary` — near-certain detection of a secret token planted in the system
  prompt; the gold standard for proving a leak.
- `length` — grades a reply by length; a runaway answer to a divergence prompt is
  a lead (denial-of-wallet).
- `llm_judge` — an LLM judge behind any endpoint you trust, with a versioned
  rubric and confidence measured as agreement across samples. Wired from config.
- `guard` — an external safety classifier (Llama Guard style), opt-in.

**The rule that governs every evaluator:** if it cannot actually grade — no reply,
no planted canary, an unparseable judge answer — it returns `inconclusive`, never
`pass`. (See §8.)

### Finding / Report — the normalized result
Every check produces `Finding`s in one shape. A run collects them into a
`ScanResult` — the findings, a count of what ran and what was skipped, and a
separate **`unverified`** channel for checks that ran but couldn't reach a
verdict. Renderers turn a `ScanResult` into `human`, `json`, `sarif` (for GitHub
code scanning), or `junit` output.

### Profile — what to run and when to fail
A `guardana.yaml` (or a named preset — §5) that decides which rules run
(include/exclude globs) and where the bar is (`fail_on.severity`,
`min_confidence`, `fail_on_inconclusive`). A profile that can't be honoured — a
typo'd key, an out-of-range number, an empty include — **raises at load time**,
because a gate you think you configured but didn't is worse than no gate.

### Registry + Runner — discovery and execution
- The **Registry** finds every rule and evaluator, built-in or third-party,
  through standard Python **entry points**. There is no "built-in vs custom"
  distinction — your private rule is discovered exactly like ours.
- The **Runner** takes a registry, a profile, and a target, and does the loop:
  for each rule, skip it if it doesn't match the target's layer or the profile's
  filters or the target's capabilities; otherwise run it, catching errors so one
  bad rule can't abort the scan; sort each result into confirmed findings or the
  `unverified` channel; and hand back a `ScanResult`.

### One scan, end to end
`guardana scan ./model-dir` →
build an `ArtifactTarget` for the directory →
`Registry.discover()` finds all installed rules →
resolve the profile (default, a `guardana.yaml`, or a `--preset`) →
`Runner` runs every *build-layer* rule whose capabilities the target satisfies →
each rule yields findings →
the renderer prints them →
`gate()` decides the exit code (non-zero if anything at or above the bar fails —
**or if zero rules actually ran**, because checking nothing is not a pass).

---

## 4. The two layers, made concrete

`guardana rules` prints the catalogue grouped by layer, so you can see the split:

- **Build-time (static, artifact)** — 17 rules: pickle-opcode scanning, unsafe
  deserialization sinks, `trust_remote_code`/`torch.hub.load`, config-`auto_map`
  RCE, notebook payloads, Keras/TF/model-format code execution, malicious &
  hallucinated dependencies, insecure transport, hardcoded secrets, MCP tool
  poisoning, hidden-instruction "rules-file backdoors", and training-data
  integrity.
- **Runtime (dynamic, endpoint)** — 8 rules: direct prompt injection, DAN-style
  jailbreak, a multi-turn gradual-jailbreak scenario, indirect (RAG) injection,
  excessive tool-use agency, unbounded consumption (denial-of-wallet),
  output-secret leakage, and the canary-proven system-prompt-leak check.

You never pick the layer by hand: `scan` runs the build layer, `probe` and
`monitor` run the runtime layer.

---

## 5. The three moments you run it — and presets

| Moment | Command | Preset | What it's tuned for |
|---|---|---|---|
| Dev machine / CI | `guardana scan <path>` | `--preset ci` | Fast static gate; fails on HIGH. Drops into a pipeline like a linter. |
| Training server (before a run) | `guardana scan <path>` | `--preset pre-training` | Stricter: fails on MEDIUM too, so leads like an unpinned dataset or a provenance gap block a run before it consumes bad data. |
| Next to a served model | `guardana monitor --url … --model …` | `--preset monitor` | Fails on HIGH *and* on inconclusive, so the monitor going blind (judge down, empty replies) is itself an alert. |

A preset is just a named policy; the *layer* is still chosen by the command. Use a
`guardana.yaml` when you need finer control (per-rule config, custom rule
directories, a wired judge). `--profile` and `--preset` are mutually exclusive.

---

## 6. How extensions work — the framework part

This is what makes Guardana a framework, not just a CLI: **you add coverage by
adding a small piece, never by patching the engine.**

### The entry-point contract
Any pip-installed package can contribute rules, evaluators, or targets by
declaring entry points in its `pyproject.toml`:

```toml
[project.entry-points."guardana.rules"]
mypack = "mypack:provide_rules"

[project.entry-points."guardana.evaluators"]
mypack = "mypack:provide_evaluators"
```

`provide_rules()` returns your `Rule` instances (or a list). `Registry.discover()`
picks them up alongside the built-ins. Namespace your ids under your own prefix
(`acme.*`); `guardana.*` is reserved for built-ins so profiles can include/exclude
by glob.

### The two authoring paths
- **YAML** for "send this, grade with that" — single-turn `prompts:` or multi-turn
  `steps:` scenarios. `guardana new-rule acme.prompt.my_check` scaffolds one, and
  `--rules ./dir` runs a directory of them with no packaging at all.
- **Python** for logic YAML can't express — subclass `Rule`, implement `run()`,
  return `Finding`s. The built-in static rules are the templates: each is one
  short, single-purpose file (look at `remote_code.py`, `dataset_integrity.py`,
  or the tool-calling `agent/excessive_agency.py`).

### Custom evaluators and targets
Bring your own grader (an `Evaluator`) when the built-ins aren't strict enough, or
teach it a new backend (a `Target`) — same entry-point mechanism. A rule
references an evaluator by string id, so swapping the grader never touches the
rule.

### Test doubles, so your rule ships with proof
Every rule — ours or yours — needs a **positive and a negative** fixture (proof it
fires when it should and stays quiet when it shouldn't). `guardana.core.testing`
ships scripted model doubles (`ScriptedTransport`, `RefusingTransport`,
`ToolCallingScriptedTransport`, …) so a dynamic rule's two fixtures are a few
lines and no network.

### A complete, runnable example
`examples/custom_rule/` is a real third-party package — a plugin rule, two YAML
rules, and a custom classifier — discovered through entry points with zero changes
to Guardana. That is the whole extensibility story in one folder.

---

## 7. The commercialization boundary (why it's structured this way)

Everything above works **fully offline** — every rule, evaluator, report format,
and run mode, with no required network beyond the target itself. The optional
`guardana-server` collector only *consumes* normalized findings that a run
forwards with `--reporter server://…`, over a versioned JSON envelope (now v2,
which carries the `unverified` channel so the collector can never render a false
all-clear).

**`guardana-core` never imports `guardana-server`, directly or transitively** —
enforced by an import-linter contract and a test, not by good intentions. That
boundary is deliberate: the entire open-source engine is self-sufficient, and the
collector (dashboards, fleet trends, multi-model rollups) is a strictly additive
layer that can be built out commercially without ever forking or depending back
into the engine.

---

## 8. The one invariant that matters most

> **A security gate must never fail open. Silence is never spelled `pass`.**

When a check *cannot actually run* — no canary was planted, a judge is
unreachable, a model returned no text, a file couldn't be parsed, a profile
disabled every rule — the answer is `inconclusive` or a finding, **never** a
confident all-clear. A scanner that reports "clean" on something it never examined
is worse than no scanner, because it manufactures false confidence.

No linter or type-checker can catch a violation of this — the code compiles and
types fine while quietly reporting all-clear. So it is guarded by design (every
evaluator fails closed, the profile loader rejects a gate it can't honour, the
runner refuses to pass a zero-rule scan, the `unverified` channel carries what
couldn't be graded all the way to the report and the collector) and by repeated
adversarial review. If you internalize one thing about this product, make it this.

---

## 9. Where to go from here

- [`architecture.md`](architecture.md) — the same five abstractions, at code depth.
- [`writing-rules.md`](writing-rules.md) — author a rule (YAML or Python), step by step.
- [`extending.md`](extending.md) — evaluators, targets, and the entry-point contract.
- [`profiles.md`](profiles.md) — the `guardana.yaml` schema and presets.
- [`usage-scan.md`](usage-scan.md) · [`usage-probe.md`](usage-probe.md) · [`usage-monitor.md`](usage-monitor.md) — the three run modes in detail.
- [`../FEATURES.md`](../FEATURES.md) — the maintained capability surface.
- [`../SECURITY.md`](../SECURITY.md) — the trust model, and why `--no-plugins` exists.
