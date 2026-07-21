# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3] - 2026-07-21

### Added

- **Configurable scan scope** (`rules.paths_exclude` globs in `guardana.yaml`, and
  a `.guardanaignore` file at the scan root): skip large non-code trees (`data/`,
  `archive/`, model dirs) for speed and less noise. Both are matched against each
  path relative to the scan root.
- **The Marketplace Action follows a moving `v0.1` tag.** `scripts/release.py` now
  points the `vMAJOR.MINOR` tag at each release, so `guardana/guardana@v0.1` always
  resolves to the latest patch — no manual step per release. The release workflow
  triggers on full `v*.*.*` tags only, so moving a two-part tag never re-triggers a
  publish.

### Changed

- **`hallucinated_package` wording is clearer.** An import that is neither a known
  package nor a declared dependency now reads "isn't a known package or a declared
  dependency — declare it in requirements/pyproject, or verify it exists on PyPI",
  instead of the more alarming slopsquat framing (offline, the rule can't tell an
  undeclared-but-real package from a nonexistent one).

## [0.1.2] - 2026-07-21

Field-hardening from a second deep-test of the packages on a real ML codebase.

### Added

- **Official GitHub Action** (`guardana/guardana@v0.1.2`) and a documented
  **pre-commit** integration ([`docs/integrations.md`](docs/integrations.md)): a
  one-step CI job that scans and uploads SARIF to code scanning, and a local hook
  that installs `guardana-cli` from PyPI.
- **`guardana scan <file>`** now scans a single file, not only a directory —
  previously a single-file target walked nothing and reported a clean bill (a
  fail-open on `guardana scan suspicious.pkl`).

### Changed

- **SARIF is now valid for GitHub code scanning.** The line number goes in
  `region.startLine` (not glued onto the artifact URI), the URI is repo-relative
  (not an absolute checkout path), each result carries `partialFingerprints` and a
  `ruleIndex`, and `tool.driver.rules[]` lists the rules — so alerts attach to the
  source line instead of a non-existent path.
- **Static sinks are alias-aware.** `import pandas as pd; pd.read_pickle(...)`,
  `import numpy as np; np.load(..., allow_pickle=True)`, `import torch as t;
  t.load(...)`, and `import os as o; o.system(...)` are now caught — the dominant
  idiom, previously missed.
- **`hallucinated_package` reads the target repo's declared dependencies**
  (`requirements*.txt`, `pyproject.toml`), so a real in-requirements package
  (`jsonlines`, `langdetect`, `PyPDF2`, …) is not flagged under an isolated install
  where it isn't importable in Guardana's own environment.
- **Baseline waivers survive line shifts.** A finding's fingerprint is now rule +
  file + description (no line number), so an unrelated edit above a waived finding
  no longer un-waives it — while a genuinely different finding still fails the gate.
- **Entropy mode skips structured public values** — a UUID, a hex digest
  (md5/sha1/sha256), a model id / slash-path, or base64 of printable text is no
  longer flagged as a provider-less secret.
- **Multi-turn scenarios are no longer neutered through `--adapter`.** A body can
  carry a `{{messages}}` slot for the full transcript, and otherwise every turn is
  folded into `{{prompt}}` as a labelled transcript — the escalation context a
  scenario is *about* is never silently dropped to the last turn.
- **`hardcoded_secret` also scans `.vue`/`.svelte`** (frontend single-file
  components that embed JS/TS).
- **`dependency_risk` precision:** `torch.load(..., weights_only=False)` says so
  (not "without weights_only=True"); `yaml.load(..., Loader=FullLoader)` is a
  MEDIUM note that names the loader (materially safer than `Loader`/`UnsafeLoader`).
- **A 4xx from a probed endpoint** is reported distinctly ("rejected the request —
  check the auth header / body") from an unreachable host.

### Fixed

- `scripts/release.py` now recognizes a bare `## [Unreleased]` changelog heading,
  so a release after the first no longer fails to find the section to roll.

## [0.1.1] - 2026-07-21

Production-hardening from the first real-world use of the packages.

### Added

- **Per-finding baseline** (`guardana scan --baseline <file>` /
  `--write-baseline <file>`): accept today's findings on an existing repo with a
  reason so a blocking gate can be turned on without fixing the whole backlog,
  while a *new* finding (a different rule+location fingerprint) still fails.
  Waived findings are never silently dropped — they are reported in a `waived`
  channel in every format (a `WAIVED` line in human output, a `waived` array in
  JSON, native `suppressions` in SARIF). A malformed baseline is a hard error,
  never a silent waive-nothing or waive-everything.
- **Custom endpoint adapter** (`guardana probe --adapter <file>`): probe a
  *guarded product endpoint* with its own request/response schema, not just the
  raw OpenAI/Ollama/TGI wire — so the probe exercises the guardrails in front of
  the model, not only the bare model. The adapter file maps a body template (with
  a `{{prompt}}` slot and optional `{{system}}`), static/`${ENV}`-expanded headers,
  and a dotted `response_path` to the reply text. New public API
  `guardana.core.target.HttpAdapterTransport` / `AdapterConfig`. Fail-closed: a
  body with no `{{prompt}}` slot, or a response path that does not resolve to
  text, is an error — never a blank exchange graded as a clean pass. A planted
  system prompt with no `{{system}}` slot is folded into the prompt, never dropped.

### Changed

- **`hardcoded_secret` gains an opt-in entropy mode** (`rule_config` →
  `guardana.supply_chain.hardcoded_secret.entropy: true`): in addition to the
  high-precision prefix-anchored keys, it flags a high-entropy value assigned to a
  secret-named variable (`db_password`, `jwt_secret`, …) — the provider-less
  secrets that carry no recognizable prefix. Off by default because generic
  entropy matching is false-positive-prone; placeholders and config-shaped names
  are filtered out.

## [0.1.0] - 2026-07-20

### Added

- **Rule engine** (`guardana-core`): `Target` / `Rule` / `Evaluator` /
  `Finding` / `Profile` abstractions, plus a `Registry` for discovery and a
  `Runner` for execution. The whole public API is re-exported from
  `guardana.core` (`Rule`, `RuleMeta`, `Target`, `Evaluator`, `Finding`,
  `Registry`, `Runner`, `Severity`, ...), so plugin code needs one import
  line.
- **25 built-in rules** (`guardana-rules`):
  - 19 Python plugins — 17 static artifact-kind checks (`pickle_opcode`,
    `dependency_risk`, `remote_code`, `remote_code_config`, `notebook_payload`,
    `code_execution`, `insecure_transport`, `keras_lambda`, `saved_model_ops`,
    `malicious_dependency`, `model_format`, `hallucinated_package`, `provenance`,
    `hardcoded_secret`, `mcp_tool_poisoning`, `hidden_instructions`,
    `training.dataset_integrity`) plus 2 dynamic endpoint-kind checks
    (`output.secrets`, `agent.excessive_tool_use`).
  - 4 declarative single-turn YAML endpoint rules:
    `prompt.injection.ignore_previous`, `prompt.jailbreak.dan_style`,
    `prompt.system_prompt_leak.canary`, `prompt.unbounded_consumption`.
  - 2 declarative multi-turn scenarios: `scenario.gradual_jailbreak`,
    `scenario.indirect_injection`.
  - `supply_chain.remote_code` flags `trust_remote_code=True` on a
    transformers/datasets load — arbitrary code from a Hub repo executes at
    load time, the most common RCE vector for a downloaded model.
  - `supply_chain.code_execution` flags dynamic-code / shell sinks in source
    (builtin `eval`/`exec`, `os.system`, `subprocess(..., shell=True)`),
    distinguishing the dangerous builtins from same-named methods
    (`df.eval(...)`).
  - `supply_chain.insecure_transport` flags disabled TLS verification
    (`verify=False`) and model/dataset fetches over plaintext `http://`
    (a lead; localhost excluded).
  - `supply_chain.dependency_risk` now also covers the pickle-family wrappers
    `joblib.load`, `dill.load`/`dill.loads`, and `pandas.read_pickle`
    alongside the existing `pickle`/`torch.load`/`yaml.load`/`numpy.load`
    sinks.
  - `supply_chain.keras_lambda` flags a Keras `Lambda` layer — arbitrary
    Python that runs on `load_model`, no inference needed. `.keras` archives
    are parsed structurally and escalated when the layer references a
    non-Keras module (`os`, `subprocess`, …); legacy `.h5`/`.hdf5` are
    bytes-scanned as a lead. CVE-2025-1550, CVE-2025-9905, CVE-2024-3660.
  - `supply_chain.saved_model_ops` flags TensorFlow SavedModel
    `ReadFile`/`WriteFile` graph operators — load-time filesystem read/
    overwrite — via a bytes-scan of `saved_model.pb` (lead; JFrog
    TFLOW-MALOPS).
  - `supply_chain.malicious_dependency` flags known-malicious package
    releases in dependency manifests via a curated blocklist (e.g. the
    `ultralytics` 8.3.41/42/45/46 compromise) and install-time network
    fetches in `setup.py`.
  - `prompt.mcp_tool_poisoning` flags hidden instructions in an MCP tool
    manifest — invisible/format Unicode, instruction-override phrases, and
    base64 payload blobs in tool descriptions (indirect prompt injection).
  - `supply_chain.remote_code_config` flags a model `config.json` whose
    `auto_map`/`custom_pipelines` points at custom Python executed on a
    `trust_remote_code=True` load — the on-disk artifact of the RCE the
    `.py`-only `remote_code` scan cannot see; HIGH when the referenced module
    ships alongside, a MEDIUM lead otherwise.
  - `supply_chain.notebook_payload` scans Jupyter `.ipynb` code cells (a format
    the `.py` scanners never open) for the shared code-execution sinks and for
    `!curl … | sh` shell escapes; a cell whose Python cannot be parsed is
    surfaced as a lead, never silently skipped.
  - `supply_chain.remote_code` now also flags `torch.hub.load(...)`, which
    downloads a GitHub repo and runs its `hubconf.py` at load time.
  - `prompt.hidden_instructions` flags invisible instruction-smuggling
    characters (bidirectional overrides, the Unicode Tags block, zero-width
    space) in agent rule files (`.cursorrules`, `.windsurfrules`) and Markdown
    model cards — the "Rules File Backdoor" (Pillar Security, 2025). The signal
    is concealment, not imperative language, so a plain rules file is not
    flagged. The hidden-character vocabulary is shared with `mcp_tool_poisoning`.
  - `training.dataset_integrity` flags two deterministic training-data hygiene
    gaps that make poisoning possible: a Hugging Face dataset loading script
    (code runs on load) at MEDIUM, and an unpinned `load_dataset(...)` with no
    `revision=` (a swappable source) at LOW. First rule to map OWASP LLM04
    (Data & Model Poisoning) / ML02.
  - `scenario.indirect_injection` — indirect / RAG prompt injection: a poisoned
    "retrieved document" instructs the model to reveal its secret token; a
    canary leak proves it obeyed. First rule to map OWASP LLM08.
  - `agent.excessive_tool_use` — offered a benign calculator alongside
    shell/delete/email tools for a trivial arithmetic task, a model that reaches
    for a destructive one is flagged. Graded deterministically on the tool calls
    it actually made (not its text), so it is near-certain like a canary. First
    rule to map OWASP LLM06; needs the new tool-calling target capability.
  - `prompt.unbounded_consumption` — a divergence ("repeat forever") probe whose
    reply runs on with no server-side cap (denial-of-wallet). Graded by the new
    `length` evaluator as a lead. First rule to map OWASP LLM10.
- **Tool-calling endpoint target**: `EndpointTarget.offer_tools(...)` and the
  optional `ToolCallingTransport` (implemented by the OpenAI transport; `ollama`
  and `tgi` are unaffected) let a rule offer tools and observe the model's
  `tool_calls`, gated by the new `CALL_TOOLS` capability. This is the "observe
  more than a text reply" unlock that enables the excessive-agency check.
- **`length` evaluator** — grades a reply by length; a runaway answer to a
  divergence prompt is a lead. Fails closed (`inconclusive`) on no reply.
  - `supply_chain.pickle_opcode` hardened: it now unzips ZIP-based `.pt`
    archives and scans **every member regardless of extension**
    (CVE-2025-1889), reports a dangerous global seen **before** a
    deliberately-broken stream tail as CRITICAL instead of a silent LOW
    "unscanned", and flags a 7z-compressed model it cannot decompress
    (the nullifAI evasion) rather than passing it clean.
- **`Exchange` conversation primitive** (`guardana.core.exchange`): every
  evaluator grades a full exchange (prompt(s) + reply(s) + transcript), not a
  bare string. An exchange with no reply text is graded `inconclusive` by
  every built-in evaluator — fail-closed by construction.
- **Declarative multi-turn scenarios**: a YAML rule with `steps:` drives a
  whole conversation — the full history is replayed each turn by default,
  or `stateful: true` sends only the new message to a server that keeps
  session state — with an `expect:` per step and/or for the conversation as
  a whole. A scenario with no `expect` anywhere is a load error — an
  ungraded scenario would pass everything.
- **Named endpoint providers**: `--provider openai|ollama|tgi` on `probe` and
  `monitor`. The default `openai` transport covers any OpenAI-compatible
  server (vLLM, llamafile, Ollama's `/v1`); `ollama` speaks the native
  `/api/chat`, `tgi` speaks Hugging Face TGI's `/generate`. An unknown
  provider fails loudly.
- **`llm_judge` wired from config**: an `evaluators.llm_judge:` block in
  `guardana.yaml` (`endpoint`, `model`, optional `api_key_env`,
  `prompt_version`, `min_agreement`) builds the judge as an ordinary
  endpoint — a local vLLM/Ollama gives fully offline grading. The judging
  prompt is versioned and stamped into the finding
  (`evaluator_id: llm_judge@2025.1`); confidence is the agreement fraction
  across `min_agreement` samples instead of a flat constant; a reply with no
  parseable verdict fails closed at reduced confidence. Without the config
  block, a rule that names `llm_judge` is skipped *visibly* — never silently
  passed.
- **Optional `guard` evaluator**: grades a reply with an external safety
  classifier (Llama Guard / Granite Guardian style) via an
  `evaluators.guard:` block. Opt-in only, at conservative confidence — a
  guard used as an always-on all-clear would fail open. An unrecognized guard
  reply is `inconclusive`, never a pass.
- **`unverified` findings channel**: a dynamic check that ran but could not
  reach a verdict (unreachable judge, empty model reply) lands in
  `ScanResult.unverified` and is rendered distinctly in all four formats
  (human `? [UNVERIFIED]`, JSON `unverified`, SARIF `level: note` +
  `kind: review`, JUnit `<skipped>`). `fail_on.fail_on_inconclusive: true`
  makes unverified checks fail the gate.
- **Lead-confidence static findings**: probabilistic supply-chain signals
  (possible slopsquat imports, unpinned model downloads, missing license) now
  carry an explicit low-confidence "lead" verdict, while deterministic
  detections (pickle opcodes, secrets) stay verdict-free and certain.
- **`guardana` CLI** (`guardana-cli`): `scan`, `probe`, `monitor`, `init`,
  `rules`, and `new-rule` commands, plus `--version`.
- **Security layers (`Surface`)**: every rule belongs to the **build** layer
  (static, artifact — how the model is made) or the **runtime** layer (dynamic,
  endpoint — how it behaves), derived from what it inspects. `guardana rules`
  groups its output by layer and takes `--surface build|runtime`. The command
  already picks the layer: `scan` runs build rules, `probe`/`monitor` runtime.
- **Named policy presets (`--preset`)** on `scan`/`probe`/`monitor`, for the
  three moments you run Guardana: `ci` (fail on HIGH), `pre-training` (stricter,
  fail on MEDIUM so leads block a training run), and `monitor` (fail on HIGH and
  on inconclusive). Mutually exclusive with `--profile`.
- **A-Z product guide** (`docs/how-it-works.md`): the whole product end to
  end — concept, engine, the two layers, the three run modes, and how extensions
  plug in.
- **Custom rule directories**: the repeatable `--rules PATH` flag on `scan`,
  `probe`, and `monitor`, and `rules.paths: [...]` in `guardana.yaml`, load
  declarative YAML rules straight off disk — no packaging. A malformed rule
  file is a warning, never an abort.
- **`guardana new-rule <id> [--evaluator keyword|canary] [--dir PATH]`**:
  scaffolds a ready-to-edit YAML rule for the `--rules` workflow.
- **Monitor plants a canary**: each `guardana monitor` cycle runs the same
  probe `guardana probe` runs, planting a fresh random canary in a dedicated
  system prompt — so the CRITICAL system-prompt-leak rule runs every cycle
  instead of being skipped. `monitor` also takes `--system-prompt-file`,
  same as `probe`.
- **Reporters** (`guardana-report`): human, SARIF, JSON, and JUnit output.
- **Taxonomy mappings**: every built-in rule tagged against OWASP LLM Top 10,
  MITRE ATLAS, and NIST.
- **Plugin extension model**: rules, evaluators, and targets can be added via
  YAML (no code) or Python entry points (`guardana.rules`,
  `guardana.evaluators`, `guardana.targets`), discovered identically for
  built-in and third-party packages. `guardana scan --no-plugins` disables
  entry-point discovery entirely.
- **`guardana.core.testing`**: transport test doubles (`ScriptedTransport`,
  `RefusingTransport`, `EchoingTransport`, `ToolCallingScriptedTransport`,
  `FailingTransport`) so a dynamic rule's positive and negative fixtures run
  against a scripted model with no network.
- **Versioned collector envelope**: the reporter POSTs a versioned envelope
  (`schema_version`, currently `2` — it carries `findings` and the `unverified`
  channel alongside `source`/`summary`), and `guardana-server` validates
  every submission with Pydantic — a malformed POST or an unsupported
  `schema_version` gets `422` instead of poisoning `/findings` and `/trend`.
- **Optional `guardana-server` collector**: ingests normalized `Finding`s from
  many agents for a list/trend view, kept behind the core↔server boundary
  (`guardana-core` never imports `guardana-server`).
- **Opt-in monitoring dashboard** (`guardana-server`): off by default; enabled
  with `create_app(dashboard=True)` or `GUARDANA_DASHBOARD=1`. A single
  self-contained HTML page (no build step, works offline) served at `GET /`,
  backed by an aggregated `GET /stats` — severity, per-source and per-rule
  breakdowns, an activity-over-time trend, a prominent `unverified` counter, and
  a recent-findings list. Each finding shows a **human-readable rule name** with
  an expandable detail (what the rule catches, the evidence, the graded verdict,
  and the standards tags), served from a bundled `catalog/en.json` (`GET
  /catalog`) that a test pins to the rule registry so it can't drift; custom
  rules fall back to the finding's own title. The findings list scrolls in its
  own bounded box so the page height stays stable as findings accumulate.
  Read-only and unauthenticated (same posture as the collector); the store gained
  timestamped `records()` for the time-series, and `Store.list()` was renamed to
  `Store.submissions()`.
- **Tooling hardening**: curated ruff ruleset including bandit (`S`) and
  public-API docstrings (`D`); `mypy --strict` across the whole repo, tests
  included; pytest branch-coverage gate (`fail_under = 90`) in CI; an
  import-linter contract enforcing that the engine never depends on the
  collector; pre-commit hooks with conventional-commit message enforcement
  and `detect-private-key` (plus pre-push mypy / import-linter / pytest /
  dogfood-scan gates); dependency audit (`uv audit`) in CI. CI dogfoods
  Guardana against its own source (`guardana scan packages`) on every push.

### Changed

- **`hallucinated_package` no longer floods real ML repos with false positives.**
  It now folds in the top-level import names of every distribution installed in
  the scanning environment (`importlib.metadata.packages_distributions()`) and
  ships a much larger curated allowlist that covers import names differing from
  their PyPI distribution (`bs4`→beautifulsoup4, `jwt`→PyJWT, `cv2`→opencv-python,
  `psycopg2`, `sentence_transformers`, `prometheus_client`, …). This only removes
  noise: a package that is importable demonstrably exists, so a non-existent
  (hallucinated) one can never appear in either set — the check is not weakened.
- **`hardcoded_secret` now scans web/systems source files**, not just Python and
  config. Added `.ts`/`.tsx`/`.js`/`.jsx`/`.mjs`/`.cjs`/`.go`/`.rb`/`.java`/`.kt`/
  `.rs`/`.php`/`.cs`/`.tf`/`.tfvars`/`.gradle`/`.xml` (and `.bash`/`.zsh`): a
  served model is fronted by a Node/Go/Java gateway as often as a Python one, and
  a secret there leaks just the same.
- **`guardana rules --rules <dir>`** now includes custom YAML rule packs in the
  listing (the same repeatable flag `scan`/`probe` accept), so you can confirm a
  pack parses and is discovered without launching a probe; unloadable files are
  warned about, never silently dropped.

### Security

Findings from the pre-release code audit. Guardana has not
been released, so none of these ever reached a user — but each one would have
weakened the guarantee the tool exists to make.

- **A profile that silently disabled every rule.** `include: "guardana.*"` — a
  string where a list belongs, which YAML accepts without complaint — was
  exploded into single-character globs that match no rule id. A scan would run
  **zero rules and exit 0** on a repository containing a malicious pickle. A
  profile that cannot be honoured now raises at load time instead of quietly
  becoming a weaker one; the same applies to a typo'd key or an unknown
  severity.
- **`dependency_risk` missed the dangerous form of `yaml.load`.** It flagged
  only calls with no `Loader=` (which modern PyYAML rejects anyway) while
  `yaml.load(data, Loader=yaml.UnsafeLoader)` — the actual RCE vector — passed
  clean. The loader's *value* is now inspected, whether it is passed by keyword
  or positionally.
- **`guardana monitor` ran a weaker rule set than `guardana probe`.** It never
  planted a system prompt, so the CRITICAL system-prompt-leak rule was skipped
  for an unmet capability on every cycle. It now runs the same probe.
- **A malformed POST could take down the collector's `/trend`** for every
  client until restart. Submissions are validated; the store is bounded.
- **A rule could crash a whole scan.** An unreadable directory raised
  `PermissionError` (not a `RuleError`) out of `hallucinated_package`. Rules
  now degrade to "skipped" instead of aborting the run.
- **Type-narrowing `assert`s in six rules** would have vanished under
  `python -O`, letting a rule run against a target it cannot handle.
- Outbound URLs are restricted to `http`/`https`, and evaluator confidences are
  validated to `[0, 1]` so a third-party evaluator cannot distort a policy gate.

A second, adversarial review pass (reviewers instructed to assume the first pass
was overconfident) found more of the same "silence spelled as pass" class:

- **A profile could disable its own gate two more ways.** `min_confidence: .nan`
  (or any value outside `[0, 1]`) silently made the confidence gate unfailable;
  an empty or null `include:` matched no rule at all. Both now raise at load.
- **The secret scanner missed every current LLM key format.** `sk-proj-`
  (OpenAI's default since 2024), `sk-ant-api03-` (Anthropic), and `sk-svcacct-`
  all slipped past the old `sk-[A-Za-z0-9]{20,}` pattern — the single most
  likely secret in an AI repo. Added those plus the `gho_`/`ghu_`/`ghs_`/`ghr_`
  GitHub token forms and the `ENCRYPTED`/`DSA`/`PGP` private-key headers.
- **Two evaluators reported a confident "pass" on checks that never ran.** A
  canary rule with no planted canary, and an `llm_judge` reply it couldn't
  parse, both used to read as all-clear. The canary case is now rejected at
  load; the judge now fails closed on unparseable output and recognizes real
  verdict formats (`**FAIL**`, `FAIL - …`).
- **A model reply of `content: null`** (a refusal or tool-call) became the
  literal string `"None"` and was graded as a clean pass. It is now rejected as
  having no text to evaluate.
- **A crafted repo could hang or OOM the scanner.** A FIFO or a `/dev/zero`
  symlink named `*.py` reports `st_size == 0`, sailed past the size check, and
  read forever. The reader now skips non-regular files and bounds the read
  itself rather than trusting `stat()`; the scan bound was also raised so real
  generated sources are scanned, not silently skipped.
- **A malformed YAML rule crashed the whole scan** (raw `TypeError` /
  `AttributeError` out of load), and a scalar `prompts:` string exploded into
  single-character prompts. Rule loading now validates every field and reports a
  bad file instead of aborting.
- **The long-running monitor died on the first transient blip** and blamed the
  wrong host; a dead collector took it down too. It now survives transient
  endpoint failures per-cycle and only exits when the endpoint never worked.
- **The collector could be crashed or exhausted.** Concurrent reads during
  ingest raised "deque mutated during iteration" and 500'd `/trend`; an
  unbounded body could store millions of findings; an omitted `schema_version`
  was guessed as v1. The store is now lock-guarded, the envelope is
  length-bounded, `/findings` is paginated, and `schema_version` is required.
- Duplicate rule ids (from overlapping `--rules` / `rules.paths`) ran twice —
  doubled findings and doubled probe calls against a live model. The registry
  now de-dupes by id, last-wins (which also lets a custom rule override a
  built-in).
- **A YAML rule silently dropped `inconclusive` verdicts.** The evaluation
  loop kept only `fail` outcomes, so a check that *could not run* (no reply
  to grade, an unreachable judge) read as a clean pass — the exact
  fail-open this project exists to prevent. Inconclusive verdicts are now
  surfaced on the dedicated `unverified` channel in every output format.

A third adversarial pass (same instruction: assume the previous passes were
overconfident) found that green gates still hid live fail-opens of the same
class:

- **A scan that ran zero rules exited 0 with a green "No findings".** The
  earlier fix rejected the `include:`-scalar *input* that produced the
  zero-rules state, but never guarded the resulting *state*: `exclude: ["*"]`,
  an `include:` glob matching no id, and `--no-plugins` with no `--rules` each
  still reported a confident all-clear on a malicious repo. `gate()` now fails
  when `rules_run == 0` (nothing was verified, so it cannot pass), and the human
  renderer refuses to print "No findings" when nothing ran.
- **The collector envelope dropped the entire `unverified` channel.** The
  human/JSON/SARIF/JUnit renderers surface checks that could not be graded, but
  the reporter serialized only `findings` — so a model whose CRITICAL checks
  could not run was forwarded to the fleet dashboard as `findings: []`, a false
  all-clear at the collector boundary. The envelope now carries `unverified`
  (and a summary count); `schema_version` bumped to 2 and the collector stores
  and retains it.
- **The pickle scanner silently skipped ZIP members it could not read.** A
  member that raised `RuntimeError` (an encrypted member) aborted the whole
  scan; a member that was itself a nested archive was passed clean. Both now
  become a visible "unscanned" finding — without flooding ordinary `.pt` tensor
  storages with noise, which is why only nested-archive magics are flagged.
- **`malicious_dependency` missed every multi-line lockfile.** The known-bad
  release check required name and version on one line, so `poetry.lock`,
  `uv.lock`, and `pdm.lock` — the files that authoritatively pin a resolved
  dependency — never matched. It now parses the `[[package]]` block form, and a
  longer release sharing a bad prefix (`8.3.410` vs `8.3.41`) no longer false-positives.
- **The monitor never alerted when its own checks stopped grading.** A served
  model whose judge went down or whose replies came back empty kept `findings`
  at 0 while `unverified` climbed, and under the default policy no alert ever
  fired — the monitor going blind looked identical to a healthy model. It now
  baselines and alerts on a rising `unverified` count too.
- **A `canary` rule could be authored so its marker was never planted.** The
  schema forced `expect.canary` but not `requires: [plant_system_prompt]`, so a
  canary rule (single-turn or scenario) could run against a target where the
  canary was never set and pass everything. That combination is now a load-time
  error, and the probe plants a fresh canary for multi-turn scenarios too, not
  only single-turn rules.
- **The keyword evaluator treated compliant openers as refusals.** `"as an ai"`
  and `"i'm sorry"` open harmful compliances (`"As an AI, here's how to…"`) at
  least as often as refusals, so they graded compliance as a PASS. Removed; a
  genuine apologetic refusal still matches a hard refusal phrase, and the bias
  now errs toward surfacing a reply, not hiding it.
- **`insecure_transport` missed an uppercase `HTTP://` scheme.** The plaintext
  check was case-sensitive; the scheme is now matched case-insensitively.
