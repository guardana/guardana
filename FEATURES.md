# Guardana — features

What ships out of the box and what you can achieve with it, in one maintained
place. [`CHANGELOG.md`](CHANGELOG.md) is the history; this file is the current
capability surface. It is updated with every user-visible feature change, and
a test (`test_features_doc.py`) pins it to the rule/evaluator registry so the
two cannot silently drift.

## Out of the box

### Three ways to run one engine

| Mode | Command | What it gives you |
|---|---|---|
| **Static scan** | `guardana scan <path>` | Offline, no-network, deterministic supply-chain checks over a repo or model directory. Exit code `1` on a gate failure — drops into CI like a linter. |
| **Live probe** | `guardana probe --url … --model …` | One-shot dynamic run against a live endpoint: injection, jailbreaks (single- and multi-turn), system-prompt leakage, output-secret checks — every finding graded by an Evaluator with an explicit confidence. |
| **Monitor** | `guardana monitor --url … --model …` | Long-running sampling observer next to a served model; alerts on gate failure, a finding-count rise over its baseline, or a rise in *unverified* checks (a model whose safety checks go blind is itself the alert). Plants a fresh random canary every cycle. |

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

### 27 built-in rules, mapped to the frameworks auditors speak

Every finding carries typed OWASP LLM Top 10 / MITRE ATLAS / NIST references.

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
- **`length`** — grades a reply by length; a runaway answer to a divergence
  prompt is a lead (for `unbounded_consumption`). Honestly low-confidence.
- **`llm_judge`** — an LLM judge behind any OpenAI-compatible endpoint (a
  local vLLM/Ollama keeps it fully offline), wired from `guardana.yaml`.
  Versioned rubric stamped into every finding (`llm_judge@2025.1`);
  confidence measured as agreement across `min_agreement` samples;
  unparseable output fails closed.
- **`guard`** — optional external safety classifier (Llama Guard / Granite
  Guardian style), opt-in only and conservatively scored.

Every evaluator fails closed: a check that cannot actually grade returns
`inconclusive`, surfaced on a dedicated **unverified** channel in all four
output formats — never a silent all-clear. `fail_on_inconclusive: true`
makes unverified checks fail the gate.

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
- **Three entry-point groups** — `guardana.rules`, `guardana.evaluators`,
  `guardana.targets` — discovered identically for built-ins and third-party
  packages; namespace by id, override built-ins, or go YAML-only with
  `--no-plugins`.
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
