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
(`WAIVED` / `waived` / SARIF `suppressions`), never silently dropped.

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

### 25 built-in rules, mapped to the frameworks auditors speak

Every finding carries typed OWASP LLM Top 10 / MITRE ATLAS / NIST references.

| Rule | Severity | What it catches |
|---|---|---|
| `guardana.supply_chain.pickle_opcode` | CRITICAL | Pickle payloads (incl. inside `.pt`) importing non-allowlisted callables — arbitrary code on `load()`. |
| `guardana.supply_chain.dependency_risk` | HIGH | Unsafe deserialization sinks in source: the pickle family (`pickle`/`joblib`/`dill`/`pandas.read_pickle`), `torch.load` without `weights_only=True`, `yaml.load` with an unsafe `Loader` (value-aware, keyword or positional), `numpy.load` with `allow_pickle`. |
| `guardana.supply_chain.remote_code` | HIGH | `trust_remote_code=True` on a transformers/datasets load, and `torch.hub.load(...)` (runs a remote repo's `hubconf.py`) — arbitrary code from a Hub repo at load time (today's most common model-download RCE). |
| `guardana.supply_chain.remote_code_config` | HIGH/MED | A model `config.json` whose `auto_map`/`custom_pipelines` points at custom Python run on a `trust_remote_code=True` load — the artifact form of the RCE the `.py` scan can't see; HIGH when the module ships alongside. |
| `guardana.supply_chain.notebook_payload` | HIGH | Dangerous sinks inside Jupyter `.ipynb` code cells — `eval`/`exec`/`os.system`/`shell=True`, and `!curl … \| sh` shell escapes; an unparseable cell is surfaced, never silently skipped. |
| `guardana.training.dataset_integrity` | MED/LOW | Training-data hygiene: a Hugging Face dataset loading script (code runs on load) and unpinned `load_dataset(...)` (a swappable, poisonable source). |
| `guardana.supply_chain.code_execution` | HIGH | Dynamic code / shell sinks in source: builtin `eval`/`exec`, `os.system`, `subprocess(..., shell=True)` — distinguishing `df.eval(...)` (a method) from the dangerous builtin. |
| `guardana.supply_chain.insecure_transport` | HIGH/MED | TLS verification disabled (`verify=False` → MITM) and model/dataset fetched over plaintext `http://` (a lead; localhost excluded). |
| `guardana.supply_chain.keras_lambda` | HIGH/MED | Keras `Lambda` layer — arbitrary Python that runs on `load_model` (`.keras` parsed structurally, legacy `.h5` bytes-scanned); escalates when it references `os`/`subprocess`/…. CVE-2025-1550/9905. |
| `guardana.supply_chain.saved_model_ops` | MEDIUM | TensorFlow SavedModel `ReadFile`/`WriteFile` graph operators — load-time filesystem read/overwrite (lead; JFrog TFLOW-MALOPS). |
| `guardana.supply_chain.malicious_dependency` | HIGH/MED | Known-malicious package releases (curated blocklist, e.g. the `ultralytics` compromise) in manifests, plus install-time network fetch in `setup.py`. |
| `guardana.supply_chain.model_format` | HIGH | Model files in formats that can carry code; a well-formed safetensors file is never flagged. |
| `guardana.supply_chain.hallucinated_package` | MEDIUM | Imports of unknown packages — slopsquat *leads*, at honest lead-level confidence. |
| `guardana.supply_chain.provenance` | MEDIUM | Unpinned model downloads and missing licenses (leads). |
| `guardana.supply_chain.hardcoded_secret` | HIGH | Current-era keys — `sk-proj-`/`sk-ant-api03-` (OpenAI/Anthropic), GitHub token forms, private-key headers — across Python, config, **and** web/systems source (`.ts`/`.js`/`.go`/`.java`/`.rs`/`.tf`/…). Opt-in `entropy: true` mode also catches provider-less secrets (a DB password, a shared JWT key). |
| `guardana.output.secrets` | HIGH | A live model leaking secret-shaped strings in its replies to benign probes. |
| `guardana.prompt.mcp_tool_poisoning` | HIGH/MED | Hidden instructions in an MCP tool manifest — invisible Unicode, instruction-override phrases, base64 payloads in tool descriptions (indirect prompt injection). |
| `guardana.prompt.hidden_instructions` | HIGH | Invisible instruction-smuggling characters (bidi overrides, the Unicode Tags block, zero-width) in agent rule files (`.cursorrules`) and Markdown model cards — the "Rules File Backdoor". Concealment, not imperative prose, is the signal. |
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

### A framework, not just a CLI

- **Declarative YAML rules** — single-turn `prompts:` or multi-turn `steps:`
  scenarios; load from a plain directory (`--rules`, `rules.paths`) with no
  packaging, or bundle in a package.
- **Three entry-point groups** — `guardana.rules`, `guardana.evaluators`,
  `guardana.targets` — discovered identically for built-ins and third-party
  packages; namespace by id, override built-ins, or go YAML-only with
  `--no-plugins`.
- **Test doubles included** (`guardana.core.testing`): `ScriptedTransport`,
  `RefusingTransport`, `EchoingTransport`, `ToolCallingScriptedTransport`,
  `FailingTransport` — a positive and negative fixture for your dynamic rule is
  a few lines, no network.
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
`--format sarif` feeds GitHub code scanning so findings annotate PRs.

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
