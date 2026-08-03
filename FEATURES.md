# Guardana — features

What ships out of the box and what you can achieve with it, in one maintained
place. [`CHANGELOG.md`](CHANGELOG.md) is the history; this file is the current
capability surface. It is updated with every user-visible feature change, and
a test (`test_features_doc.py`) pins it to the rule/evaluator registry so the
two cannot silently drift.

## Product maturity

FEATURES describes **what ships today**. Anything not here is a plan, and plans
live in [`ROADMAP.md`](ROADMAP.md).

| Component | Maturity |
|---|---|
| Engine + built-in rules | beta |
| `scan` / `probe` / `monitor` / `diff` | beta |
| Collector (`guardana-server`) | **experimental** — in-memory, unauthenticated, local evaluation only |
| Extension API | unstable by design until 1.0 |

Full detail, including what is deliberately not covered:
[`docs/product-status.md`](docs/product-status.md).

## Out of the box

### Four things you do with one engine

| Mode | Command | What it gives you |
|---|---|---|
| **Static scan** | `guardana scan <path>` | Offline, no-network, deterministic supply-chain checks over a repo or model directory. Exit code `1` on a gate failure — drops into CI like a linter. |
| **Live probe** | `guardana probe --url … --model …` | One-shot dynamic run against a live endpoint: injection, jailbreaks (single- and multi-turn), system-prompt leakage, output-secret checks — every finding graded by an Evaluator with an explicit confidence. Rules run concurrently (`--concurrency`, default 4) with rate-limit backoff, and results stay in rule order so two runs match. |
| **MCP server** | `guardana probe --mcp <url>` | Examines a **live** MCP server's tool manifest: hidden instructions in tool descriptions, and drift from the manifest you approved (`--write-mcp-pin` to approve, `--mcp-pin` to compare). Streamable HTTP needs no permission; an stdio server is *started* by Guardana, so it takes an explicit `--allow-exec`. |
| **Monitor** | `guardana monitor --url … --model …` | Long-running sampling observer next to a served model; alerts on gate failure, on a check that could not run, and on any cycle that is *worse* than the first one by the same definition `diff` uses — including a check that can no longer grade what it used to. Plants a fresh random canary every cycle. |

Scan takes a **per-finding baseline** (`--write-baseline` to snapshot, `--baseline`
to apply): accept today's findings with a reason so a blocking gate can go live on
an existing repo, while a new finding still fails — waived findings stay reported
(`WAIVED` / `waived` / SARIF `suppressions`), never silently dropped. Waivers are
matched by rule + file + description, so they survive unrelated line shifts. Scan a
single file or a whole directory; a single-file target never walks nothing.

**Drops into CI in one step:** the official **GitHub Action**
(`guardana/guardana@vX.Y.Z`) scans and uploads SARIF to code scanning, and a
**pre-commit** hook installs straight from PyPI — see
[`docs/integrations.md`](docs/integrations.md).

### The re-test gate: is this worse than last time? (`guardana diff`)

A fourth command sits **on top of** the three above rather than beside them — it
runs no rules. > **What `monitor` is, precisely.** It performs **scheduled synthetic security
> checks** against a configured target. It does **not** passively inspect
> production user traffic and does **not** sit inline in the request path.

Save a run with `--output` on `scan`/`probe` (a versioned JSON
document, not just output: it records the tool version, the target, the profile,
and **which** rules ran with a digest of each), then hand two of them to
`guardana diff`. It fails the build on deterioration: a new problem, a problem
finally proven, a rising severity, a check that **went blind**, or a rule that
stopped running. Exit `1` on a regression, exit `2` when the two runs cannot
honestly be compared — never a quiet `0`.

Comparison works on a check's *state* rather than a finding count, because a live
model answers differently every run and a gate that tripped on tallies would be
switched off. A waiver reports as a changed waiver, never as a fix; a run made
with a narrower profile reports its missing rules as lost coverage, never as
findings that went away. See [`docs/usage-diff.md`](docs/usage-diff.md).

Plus `guardana rules` (list everything installed, incl. your own, **grouped by
security layer**, filterable with `--surface build|runtime`, and able to include
a custom pack with `--rules <dir>` so you can confirm it parses), `guardana init`
(starter policy file), `guardana new-rule` (scaffold a custom rule), and
`--format human|json|sarif|junit` everywhere a result is printed.

Every rule belongs to one of two **layers**, derived from what it inspects:
**build** (static, artifact — how the model is made; run by `scan`) and
**runtime** (dynamic, endpoint — how it behaves; run by `probe`/`monitor`). This
is the semantic split between securing the build process and securing the served
model, made visible.

### Policy presets for the three moments (`--preset`)

`--preset ci` (fail on HIGH — dev & CI), `--preset pre-training` (stricter, fail
on MEDIUM so leads block a training run), `--preset monitor` (fail on HIGH and on
inconclusive). A preset tunes only the failure bar; the command still picks the
layer. Mutually exclusive with `--profile`.

### Built-in rules, mapped to the frameworks auditors speak

**Counts and the full catalog are generated from the installed registry, never
typed by hand:** [rule summary](docs/generated/rule-summary.md) ·
[full catalog](docs/generated/rule-catalog.md) ·
[evaluators](docs/generated/evaluator-catalog.md) ·
[taxonomy coverage](docs/generated/taxonomy-coverage.md). A count in prose drifts;
these do not.

Every finding carries typed **OWASP LLM Top 10 (2025)**, **OWASP Top 10 for
Agentic Applications (ASI01–ASI10, 2026 edition)**, **OWASP ML Top 10 (2023)**,
**MITRE ATLAS v5.6.0** — including the agentic techniques (`AML.T0080` context
poisoning, `AML.T0110` tool poisoning, `AML.T0053` tool invocation,
`AML.T0109` rug pull) — and **NIST AI 100-2e2025** references.

| Rule | Severity | What it catches |
|---|---|---|
| `guardana.supply_chain.pickle_opcode` | CRITICAL | Pickle payloads (incl. inside `.pt`) importing non-allowlisted callables — arbitrary code on `load()`. |
| `guardana.supply_chain.dependency_risk` | HIGH | Unsafe deserialization sinks in source: the pickle family (`pickle`/`joblib`/`dill`/`pandas.read_pickle`), `torch.load` without `weights_only=True`, `yaml.load` with an unsafe `Loader` (value-aware, keyword or positional), `numpy.load` with `allow_pickle`. |
| `guardana.supply_chain.remote_code` | HIGH | `trust_remote_code=True` on a transformers/datasets load, and `torch.hub.load(...)` (runs a remote repo's `hubconf.py`) — arbitrary code from a Hub repo at load time (today's most common model-download RCE). |
| `guardana.supply_chain.remote_code_config` | CRITICAL/HIGH/MED | A model `config.json` that asks for code to run on load. `auto_map`/`custom_pipelines` point at custom Python run under `trust_remote_code=True` (HIGH when the module ships alongside) — the artifact form of the RCE the `.py` scan can't see. **`_attn_implementation_internal` naming a Hub repo is CRITICAL: the kernel-dispatch path ignores `trust_remote_code=False`, so the "safe mode" does not stop it (CVE-2026-4372, transformers 4.56–5.2.x with `kernels`; fixed in 5.3.0).** Matched by key name, never by value shape — `_name_or_path` looks identical and appears in most real configs. |
| `guardana.supply_chain.notebook_payload` | HIGH | Dangerous sinks inside Jupyter `.ipynb` code cells — `eval`/`exec`/`os.system`/`shell=True`, and `!curl … \| sh` shell escapes; an unparseable cell is surfaced, never silently skipped. |
| `guardana.training.dataset_integrity` | MED/LOW | Training-data hygiene: a Hugging Face dataset loading script (code runs on load) and unpinned `load_dataset(...)` (a swappable, poisonable source). |
| `guardana.supply_chain.code_execution` | HIGH | Dynamic code / shell sinks in source: builtin `eval`/`exec`, `os.system`, `subprocess(..., shell=True)` — distinguishing `df.eval(...)` (a method) from the dangerous builtin. |
| `guardana.supply_chain.insecure_transport` | HIGH/MED | TLS verification disabled (`verify=False` → MITM) and model/dataset fetched over plaintext `http://` (a lead; localhost excluded). |
| `guardana.supply_chain.keras_lambda` | HIGH | Keras `Lambda` layer — arbitrary Python that runs on `load_model`. `.keras` is parsed structurally; legacy `.h5`/`.hdf5` is matched on the exact `"class_name": "Lambda"` marker and is a **firm** finding, because `load_model` silently ignores `safe_mode` for that format (CVE-2025-9905) — a layer merely *named* "Lambda" is not flagged. Escalates when the body references `os`/`subprocess`/…. A model whose config could not be read is reported as *not scanned*. CVE-2025-1550/9905. |
| `guardana.supply_chain.saved_model_ops` | MEDIUM | TensorFlow SavedModel `ReadFile`/`WriteFile` graph operators — load-time filesystem read/overwrite (lead; JFrog TFLOW-MALOPS). |
| `guardana.supply_chain.malicious_dependency` | HIGH/MED | **Advisory-backed**, from a bundled offline **AI/ML-only** dataset (never a general CVE feed — that is an explicit non-goal). Two channels: a **compromised release** (`ultralytics` 8.3.41–46, `lightning` 2.6.2/2.6.3, the `torchtriton` dependency-confusion name) — the one signal that catches a *legitimate* package which was poisoned — and a **vulnerable loader**, a library whose flaw is what arms an artifact this same scan finds (`transformers` <5.3.0 ↔ the kernel-injection config, `llama-cpp-python`/`sglang` ↔ a poisoned chat template, `torch` <2.6 ↔ a pickle, `keras` <3.11.3 ↔ an `.h5` Lambda). Only *exact* pins are matched, so a range constraint never manufactures a version. Every entry carries a public reference; a malformed dataset fails loudly at load. Bring your own with `MaliciousDependencyRule(advisories=…)`. Plus install-time network fetch in `setup.py`. |
| `guardana.supply_chain.model_format` | HIGH/INFO | XXE in PMML/XML model files, and safetensors container integrity (a well-formed safetensors file is never flagged). Format-specific depth belongs to the rule that owns the format — `keras_lambda`, `chat_template` — so one artifact never yields two findings about one fact. |
| `guardana.supply_chain.chat_template` | CRITICAL/HIGH | **Chat-template SSTI.** The Jinja template that ships *inside* a model runs the moment the model is used — a gadget in it is code execution with no inference and no `trust_remote_code`. Read as a parsed value (not a byte window) from all four carriers: GGUF `tokenizer.chat_template`, `tokenizer_config.json` (string *and* named-list form), a standalone `chat_template.jinja`, and `chat_template.json`. Catches dunder chains, the `\|attr` sandbox escape (CVE-2025-27516), `lipsum`/`cycler` gadget entry points, shell/`os` sinks, and template inclusion (HIGH). An unreadable template is reported as *not scanned*, never as clean. CVE-2024-34359, CVE-2026-5760. |
| `guardana.supply_chain.onnx_graph` | HIGH/MED | **ONNX, which pickle scanners skip entirely** (ModelScan covers H5/pickle/SavedModel only). Walks the graph structure straight off disk — a multi-GB model costs kilobytes of reading. Flags an operator **domain outside the standard set** (the runtime must register a native operator library to run the model — machine code at inference), an **`external_data` path** that climbs out of the model directory or is absolute (an arbitrary file-read primitive — HIGH, firm), and **`metadata_props`** carrying invisible smuggling characters or executable-looking payloads. A graph it cannot walk, or could not finish walking, is reported as *not scanned*. |
| `guardana.supply_chain.hallucinated_package` | MEDIUM | Imports of unknown packages — slopsquat *leads*, at honest lead-level confidence. |
| `guardana.supply_chain.provenance` | MEDIUM | Unpinned model downloads and missing licenses (leads). |
| `guardana.supply_chain.hardcoded_secret` | HIGH | Current-era keys — `sk-proj-`/`sk-ant-api03-` (OpenAI/Anthropic), GitHub token forms, private-key headers — across Python, config, **and** web/systems source (`.ts`/`.js`/`.go`/`.java`/`.rs`/`.tf`/…). Opt-in `entropy: true` mode also catches provider-less secrets (a DB password, a shared JWT key). |
| `guardana.output.secrets` | HIGH | A live model leaking secret-shaped strings in its replies to benign probes. |
| `guardana.prompt.mcp_tool_poisoning` | HIGH/MED | Hidden instructions in an MCP tool manifest — invisible Unicode, instruction-override phrases, base64 payloads in tool descriptions (indirect prompt injection). |
| `guardana.prompt.hidden_instructions` | HIGH | Invisible instruction-smuggling characters (bidi overrides, the Unicode Tags block, zero-width) in agent rule files (`.cursorrules`), Markdown model cards, **and a safetensors `__metadata__` block** — the one free-text channel in the format everyone picks *because* it cannot carry code, and one that hubs render and agents read back. The "Rules File Backdoor" mechanism. Concealment, not imperative prose, is the signal. |
| `guardana.prompt.injection.ignore_previous` | HIGH | Direct instruction-override injection. |
| `guardana.prompt.jailbreak.dan_style` | HIGH | Persona-override / encoding-smuggling jailbreaks. |
| `guardana.scenario.gradual_jailbreak` | HIGH | **Multi-turn** escalation the single prompts miss — a scripted conversation graded per step and as a whole. |
| `guardana.scenario.indirect_injection` | HIGH | Indirect (RAG) prompt injection: a poisoned "retrieved document" tells the model to reveal its secret token; a canary leak proves it obeyed. |
| `guardana.agent.excessive_tool_use` | HIGH | Excessive agency: offered a benign calculator alongside shell/delete/email tools for a trivial task, the model reaches for a destructive one — graded on the tool calls it actually made, deterministic like a canary. |
| `guardana.agent.tool_result_injection` | CRITICAL | **Confused deputy over a whole agent run.** The model is asked to summarise a document; the *tool result* it reads carries an instruction to forward that document elsewhere. Graded on the run, not the reply: every step looks permissible and the run still ends somewhere nobody approved. If the model never opened the document the payload was never delivered, and the verdict is `inconclusive` — not a model that behaved. |
| `guardana.agent.credential_exfiltration` | CRITICAL | A marker planted fresh in the agent's context reappearing in an **outgoing tool argument**. The same standard as a canary-proven system-prompt leak, applied to an action instead of a reply — a match is proof, not an opinion. |
| `guardana.agent.tool_argument_scope` | HIGH | The task names one file; the model passes a glob, a parent directory or a traversal. The call is permitted, the blast radius is not, and nothing in the reply text would show it. |
| `guardana.agent.memory_poisoning` | CRITICAL | **ASI06 with a session boundary.** A note saved in one conversation comes back in the next, and the agent treats it as its own prior context. Guardana writes in session one and grades session two, started clean — only the store crosses the boundary, so this is memory poisoning rather than an instruction the model can still see. If the agent never read its memory back, the verdict is `inconclusive`. |
| `guardana.agent.mcp_server_manifest` | CRITICAL/HIGH | **A live MCP server's tool manifest.** A tool description is fed to the agent's model as trusted context, so an instruction hidden in one is indirect prompt injection with an audience of one. Reading it from the *running* server is what catches a description changed after it was approved — a **rug pull** (`AML.T0109`), which a file scan cannot see. Pin the approved manifest with `--write-mcp-pin`; without a pin, drift is reported `inconclusive`, never as a clean server. |
| `guardana.prompt.unbounded_consumption` | MEDIUM | Denial-of-wallet: a divergence ("repeat forever") prompt whose reply runs on with no server-side cap (lead-level, graded by reply length). |
| `guardana.prompt.system_prompt_leak.canary` | CRITICAL | System-prompt disclosure, proven by a fresh random canary planted per run — unfakeable, unambiguous evidence. |

The `pickle_opcode` rule also **unzips ZIP-based `.pt` archives and scans every
member regardless of extension** (a payload hidden under a non-`.pkl` name
cannot slip past), reports a dangerous global found **before** a
deliberately-broken tail as CRITICAL rather than a silent skip, and flags a
7z-compressed model it cannot decompress instead of passing it clean.

### Evaluators — "did the attack succeed, and how sure are we"

The core differentiator: grading is a first-class, swappable, versioned
component, never a regex bolted onto a probe.

- **`keyword`** — cheap refusal-marker matching, honestly low confidence.
- **`canary`** — near-certain detection of a planted marker.
- **`tool_call`** — grades a whole **agent run** by what it did: tools it must
  not invoke, a planted marker leaving through a tool argument, arguments wider
  than the task, and `delivered_by` — the tool whose *result* carries the
  payload, without which "it did not misbehave" would be reported about a model
  that never received the injection at all. Deterministic, so the first slice of
  agent coverage needs no judge.
- **`length`** — grades a reply by length; a runaway answer to a divergence
  prompt is a lead (for `unbounded_consumption`). Honestly low-confidence.
- **`llm_judge`** — an LLM judge behind any OpenAI-compatible endpoint (a
  local vLLM/Ollama keeps it fully offline), wired from `guardana.yaml`.
  Versioned rubric stamped into every finding (`llm_judge@2025.1`);
  confidence measured as agreement across `min_agreement` samples;
  unparseable output fails closed.
- **`guard`** — optional external safety classifier (Llama Guard / Granite
  Guardian style), opt-in only and conservatively scored.

**Measure the judge, do not trust it.** `guardana calibrate` grades a corpus whose
outcomes are already known — canaries and tool calls settle them without a human —
and reports accuracy, Brier score and **expected calibration error**, the number
that catches a judge which is no better than a coin flip and says it is sure every
time. A starter corpus ships with Guardana and stays open source: a starter corpus
is a security capability, and no capability is withheld from the OSS build. All
three numbers are `None` — printed as `—` — when nothing was graded, so a
measurement that never happened cannot read as a perfect one, and the command
exits non-zero rather than letting that pass. Record what it measured under
`evaluators.llm_judge.calibration` and the judge reports a **calibrated**
confidence, capped by the accuracy it was actually observed at; with no
measurement it says so in every rationale instead of leaving you to assume. A
calibration is bound to the versioned rubric it was made for (`llm_judge@2025.1`),
so a changed rubric cannot inherit an older number.

**One rule ships opted-out**: `guardana.agent.goal_hijack` (ASI01) is judge-graded,
and no built-in uses a judge — an unconfigured evaluator is an error under the
default policy, so shipping it enabled would turn every judge-less probe red.
Enable it with `--rules` pointed at the package's `catalog/optional/`.

Every evaluator fails closed: a check that cannot actually grade returns
`inconclusive`, surfaced on a dedicated **unverified** channel in all four
output formats — never a silent all-clear. `fail_on_inconclusive: true`
makes unverified checks fail the gate.

### Measured confidence, not asserted confidence

Every dynamic finding carries a confidence — and `guardana.core.calibration`
is how you check whether that number means anything. `calibrate(evaluator,
samples)` grades a labelled corpus and reports the **Brier score** (how good the
predictions are overall) and the **expected calibration error** (when the judge
says it is 90% sure, is it right 90% of the time?). ECE is the sharper of the
two: a judge can be no better than a coin flip while claiming certainty every
time, and accuracy hides exactly that.

Labelling the corpus costs nothing, because the deterministic graders already
produce ground truth: a planted canary appearing verbatim in a reply is a fact,
not an opinion, and so is the list of tools a model actually called. Label a set
with those, ask the judge the same questions, and you have a measured error rate
with nobody hand-labelling a row.

The report refuses to flatter: an evaluator that returned `inconclusive` is
counted and excluded rather than scored as a prediction it never made, a corpus
below the minimum sample count is reported as unreliable with the reason, and an
empty corpus raises instead of returning a perfect-looking zero. A report is tied
to the *versioned* evaluator id (`llm_judge@2025.1`), so a changed rubric cannot
inherit an older measurement.

### Three channels, because "no findings" has three meanings

A clean report can mean three different things, and conflating them is how a
scanner lies. Guardana keeps them apart end to end — in every output format and
in the collector envelope:

| Channel | Meaning |
|---|---|
| **findings** | a check ran and found something |
| **unverified** | a check ran and honestly could not reach a verdict |
| **errors** | a check **never ran** — a plugin that failed to import, a rule file that would not load, a rule that raised |

A fourth channel answers a different question: **observations** is what the run
*saw* — models and their formats, dependency manifests, datasets, notebooks —
so "what is deployed here" and "what changed since the last run" don't require
walking the target again. It is taken from the target rather than from the rules,
so narrowing a profile can never quietly shrink the component list, and a
component that could not be read is listed as unread instead of dropped. It
carries no compliance vocabulary: mapping these facts onto CycloneDX or an audit
template is an extension's job, never the engine's.

The third is the one that used to be invisible. A rule that crashed landed in
`rules_skipped` next to "this target has no files for that rule", so a CRITICAL
check blowing up looked exactly like a check that did not apply — and the build
stayed green. It now has its own channel and **fails the gate by default**
(`fail_on_error`), one broken rule never stops the rest of the scan, and one
broken plugin never takes rule discovery down with it.

### A saved run is evidence, not a screenshot (`guardana run`)

`--output run.json` writes a **run manifest** alongside the findings: what was
examined and under which configuration, by which software, at what cost, and how
it was gated — with UTC timestamps and algorithm-qualified digests throughout.
`guardana run inspect` reads it back without re-running anything.

Three properties are the point:

**Unknown is never zero.** A value nobody measured prints as `not recorded`, and
serializes as `null`. A file scan that genuinely sends zero requests and a run
from a version that never counted are different facts, and only one of them lets
a team budget the next run. The same rule holds inside a single number: when some
requests report token counts and others do not, the manifest carries the sum
*and* `requests_missing_token_counts`, so a partial bill is labelled partial.

**The verdict is stored, never re-derived.** `result_summary.gate` is written by
the engine as `pass`, `fail` or `indeterminate`. A consumer that recomputed it
from the counts would eventually compute it differently — and the divergence
would surface as a green build.

**The fingerprint says what it covers.** `target.fingerprint_inputs` lists the
fields the digest was computed from, so nobody mistakes a digest of a declared
endpoint for a digest of model weights.

The schema is published as [`schemas/run-v2.schema.json`](schemas/run-v2.schema.json)
with its major version in its identifier, and a test validates what Guardana
writes against it. Runs written by 0.6 are migrated forward in memory when read,
so upgrading does not strand the evidence you already have — and what the older
schema never recorded stays an explicit unknown rather than becoming a default.

### "Why did it do that" (`guardana doctor`, `guardana config explain`)

`doctor` reports what this installation actually is: distribution versions and
whether they agree, which plugins loaded and which failed to import, whether
third-party rules are installed, and which settings weaken the gate. It **contacts
nothing** — a diagnostic that costs money or appears in production logs is one
people avoid running.

`config explain` prints the settings in force rather than the ones somebody typed.
Most of a gate is defaults, and a default nobody can see is a default nobody
checked.

### Accepted risk that expires (`guardana baseline`)

A waiver is the one place Guardana deliberately does not fail on a finding, so it
is kept temporary and visible. Each one carries a reason, an approver and an
expiry — and **an expired waiver stops waiving**: the finding comes back and the
gate goes red again.

`guardana baseline verify` names the waivers that lapsed and the ones still
carrying generated placeholder text, so a red gate is traceable to an acceptance
running out rather than looking like new breakage. `update` only removes waivers
for findings that are fixed; it never adds one on your behalf.

### Safe mode that still checks things (`--plugins`)

Importing a plugin is trusting it. The old `--no-plugins` refused everything
including Guardana's own rules, which made the safe mode the empty mode — and an
empty scan is a control people turn off.

`--plugins builtins` loads the reviewed distributions and discovers nothing else;
`--plugins allowlist --allow-plugin acme-rules` adds the ones you name. Trust goes
by **distribution name**, because an entry point can call itself anything. A
plugin that is refused lands in the `errors` channel, which fails the gate by
default — a pack you installed and this run declined to load is coverage you think
you have.

### Every rule says how far it reaches (`--safety`, `--allow-destructive`)

A rule declares whether it only reads, sends prompts, or could make the target
act; a run declares what it permits. `--safety passive` sends nothing at all — a
zero-cost check of the wiring that is visibly empty rather than quietly green.

`--allow-destructive` is a **separate switch**, not a fourth level, so raising the
impact ceiling can never reach a destructive rule by accident. Nothing shipped is
destructive, and a test keeps it that way.

A rule refused for safety appears in `rules_skipped` with the reason and the flag
that would permit it — a coverage gap you can see, never a silent drop.

### Evidence is redacted by default, at one seam (`privacy:`)

The most sensitive text in a deployment is exactly what a security finding quotes.
Until 0.7 that was handled by convention — rules were careful — which held while
every rule was ours and does not survive an extension API.

Now one redactor sits between findings and every output: the renderers, the
collector envelope, and baseline files. It is applied by the renderer factory
rather than by each renderer, so a format added next year is covered without its
author knowing the policy exists.

Three things keep it honest. **Secrets go even at `full`** — that mode means "keep
the model's words", not "store a live key", and since 0.7.1 no setting offers the
other reading: `redact_secrets: false` is refused at load time. **Redaction is
never silent**: a finding says its evidence was changed, and truncation says so
too. **Placeholders are hashed and labelled**, so the same secret redacts
identically across runs — which keeps a baseline waiver matching — and the label
says which kind of key it was, which is what tells you what to rotate.

A test enumerates every registered renderer from the registry and asserts a
crafted credential cannot pass through any of them, per path rather than once.
That enumeration is why `monitor` was the leak it was until 0.7.1: it emitted a
layer *above* the renderers, where nothing was enumerating anything. All three
emitting commands now redact from the profile before anything leaves them.

### Ask the target what it can actually do (`guardana target inspect`)

"OpenAI-compatible" is a claim about a URL shape. A gateway can accept a tools
array and never call anything; a proxy can drop the system message. Both turn a
rule into a check that runs and proves nothing — which reads as a pass.

Inspection probes each capability with one small request and reports **supported**,
**unsupported**, or **unknown**, keeping the third apart from the second on
purpose. Anything the target declared and no probe confirmed is listed as such,
and the rules that become unrunnable are named rather than counted.

Every skipped rule in a run now carries the reason and the missing capability, so
"this never applied" and "this provider cannot do it" stop looking alike.
`fail_on.fail_on_skipped` turns the second into an `indeterminate` verdict for
teams paying for coverage they expect to get.

### Know the cost before the run (`guardana plan`, `budgets:`)

Probing a hosted model costs money. `guardana plan probe` states the upper bound
**without sending a request**: which rules would run, which would be skipped, and
at most how many requests they would send. Every rule declares its own ceiling,
and a gate measures each shipped rule against its declaration — so the number is a
claim somebody checks, not a promise.

A rule that declares no cost is **named**, never counted as free, and a plan
containing one never claims to fit a budget.

`budgets:` sets the ceiling for real: requests, input and output tokens, wall
time. It is checked before each request rather than after each rule, so a ceiling
of 200 means 200. Three properties keep it from becoming an excuse:

- a run that hits its ceiling **keeps what it already found**, and says it stopped;
- it exits `6` and **never passes the gate**, whatever its partial findings say;
- `guardana diff` **refuses to read the missing findings as an improvement**.

A budget nothing can enforce — a token ceiling on a transport that reports no
tokens — is refused before the first request, with exit `3`. A ceiling the user
believes in and nothing watches is worse than no ceiling.

### Policy gates (`guardana.yaml`)

Include/exclude rules by glob (`guardana.*` vs `acme.*`), set the failure bar
(`fail_on.severity`, `fail_on.min_confidence`, `fail_on_inconclusive`), point
at custom rule directories, configure the judge/guard. A profile that can't be
honoured — a typo'd key, an out-of-range confidence, an empty include —
**raises at load time** instead of silently weakening the gate.

### Endpoint providers

`--provider openai` (default — vLLM, llamafile, Ollama's `/v1`, LM Studio…),
`--provider ollama` (native `/api/chat`), `--provider tgi` (HF TGI
`/generate`). Unknown provider = loud error.

Or map a **guarded product endpoint** with `--adapter <file>`: a body template
(`{{prompt}}`/`{{system}}`, or `{{messages}}` for the full multi-turn transcript),
`${ENV}`-expanded headers, and a dotted `response_path` to the reply — so the probe
exercises your gateway and guardrails, not just the bare model. Fail-closed (no
`{{prompt}}`/`{{messages}}` slot, or a response path that isn't text, is an error);
a multi-turn scenario's escalation is folded in, never dropped. Public API:
`HttpAdapterTransport` / `AdapterConfig`.

### A framework, not just a CLI

- **Declarative YAML rules** — single-turn `prompts:` or multi-turn `steps:`
  scenarios; load from a plain directory (`--rules`, `rules.paths`) with no
  packaging, or bundle in a package.
- **Four entry-point groups** — `guardana.rules`, `guardana.evaluators`,
  `guardana.targets`, `guardana.taxonomies` — discovered identically for
  built-ins and third-party packages; namespace by id, override built-ins, or go
  YAML-only with `--no-plugins`.
- **Map rules to your own framework.** Mapping is mandatory for a rule, so the
  framework list is open: register `TaxonomyRef`s through `guardana.taxonomies`
  and a YAML rule can name them (`taxonomy: [ACME-14]`) beside `LLM01`. Because
  registration goes through an installed package rather than a string in a rule
  file, an unknown id in `taxonomy:` still fails at load. Redefining a known
  short id is refused: overriding a rule changes what you check, overriding
  `LLM01` changes what a report claims to an auditor.
- **Evaluators declare the `expect:` fields they read** (`Evaluator.expects`), so
  a third-party evaluator is configurable from YAML exactly like a built-in —
  and a misspelled field for *that* evaluator is an error, not a rule that looks
  configured and grades nothing.
- **Canary planting is a contract, not a list of known classes**
  (`Rule.with_canary`). Any rule shape — ours or yours — takes part in the fresh
  per-run token; a rule that grades by canary and refuses one is rejected at
  registration rather than silently passing every model.
- **One shared read per file, not one per rule** (`guardana.core.source`):
  `ArtifactTarget.python_source(path)` returns a `PythonSource` — text, parsed
  tree, and nodes grouped by type in source order — read, parsed and walked
  **once per scan** and cached under a memory budget. Your rule asks for
  `source.nodes(ast.Call)` instead of walking the tree itself, and costs the scan
  nothing extra. On this repo that took a scan from 1.27 s to 0.36 s while
  reporting identical findings; a cost gate counts the operations so a regression
  fails the build. A file the scan is *prevented* from reading (too large,
  unopenable) lands in `errors` rather than vanishing — padding a malicious
  loader past the read limit buys no silence.
- **Public model-format readers** (`guardana.core.formats`, documented in
  [`docs/model-formats.md`](docs/model-formats.md)): `read_gguf_metadata`,
  `read_safetensors_header`, `read_onnx_summary`. Bounded, offline,
  deterministic, and fail-closed — sizes claimed *inside* a file are checked
  before anything is allocated, a non-regular file is refused rather than
  opened, and anything unparseable raises `FormatError` instead of reading as
  "clean". They return data and never a verdict, which is the whole point: your
  pack brings the threat knowledge, the engine brings the binary parsing. Adding
  a reader for a new format is a module with one function.
- **Test doubles included** (`guardana.core.testing`): `ScriptedTransport`,
  `RefusingTransport`, `EchoingTransport`, `ToolCallingScriptedTransport`,
  `FailingTransport` — a positive and negative fixture for your dynamic rule is
  a few lines, no network. Plus artifact builders `build_gguf`,
  `build_safetensors`, `build_onnx`, so a crafted *malicious* fixture for a
  static rule is a dict literal in a test instead of a binary in your repo.
- **Embeddable engine** — drive `Registry` + `Runner` from your own code and
  skip the CLI entirely.
- A complete runnable third-party package: [`examples/custom_rule/`](examples/custom_rule/).

### Optional central collector + dashboard

> **Maturity: experimental.** In-memory storage, no authentication — local
> evaluation only. Persistence, API keys, project isolation, finding lifecycle and
> audit log are the v0.7 milestone.

Any run forwards normalized findings with `--reporter server://…` (versioned
JSON envelope). The collector (`guardana-server`) is strictly additive and
separately deployed — the engine never depends on it, enforced by an
import-linter contract and a test. It ships an **opt-in monitoring dashboard**
(`create_app(dashboard=True)` or `GUARDANA_DASHBOARD=1`, off by default): a
single self-contained page — no build step, works offline — showing severity and
per-source/per-rule breakdowns, an activity-over-time trend, a prominent
**unverified** counter, and a recent-findings list where each entry shows a
**human-readable rule name** and expands to its description, evidence, and graded
verdict (from a bundled `catalog/en.json`). Read-only; the no-auth posture is
unchanged (do not expose to an untrusted network).

## What you can achieve

**Gate a repo in CI.** `guardana scan .` exits `1` on a HIGH finding;
`--format sarif` feeds GitHub code scanning — with a repo-relative URI,
`region.startLine`, `partialFingerprints`, and a populated `driver.rules[]` — so
alerts annotate the exact source line on a PR.

**Vet a model file before you load it.** Download a `.pt`/`.pkl`/GGUF from a
hub, `guardana scan ./downloads` — pickle-borne code execution is caught
before the first `torch.load`.

**Probe your endpoint before it ships.** `guardana probe --url
http://localhost:8000 --model my-model --system-prompt-file prod-prompt.txt`
runs injection/jailbreak/leak checks against the real configuration and
reports graded, confidence-carrying findings.

**Keep watch in production.** `guardana monitor … --interval 300 --reporter
server://…` as a systemd unit or sidecar: every cycle re-probes (fresh
canary included) and alerts on regressions — a behavioural drift tripwire.

**Ship your organization's own rule pack.** `guardana new-rule
acme.prompt.our_policy`, iterate with `--rules ./team-rules`, then package it
behind the `guardana.rules` entry point — private or upstreamed, same
contract.

**Bring your own judge.** Point `evaluators.llm_judge` at any
OpenAI-compatible model you trust; rules don't change when the grader does.

**Script the attack that takes three turns.** A YAML scenario (`steps:`)
expresses gradual escalation declaratively — no Python, graded per turn and
across the whole conversation.

**Aggregate a fleet.** Many agents, one collector, one `/trend` — self-hosted
today, and the foundation a managed cloud builds on without touching the engine.
