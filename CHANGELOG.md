# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **The prose beside the moving Action pin stayed on 0.3 through 0.5.0.** The pin
  itself was rewritten to `@v0.5`, and the sentence next to it in `README.md` and
  `docs/integrations.md` went on telling readers the tag points at "the latest
  0.3.x" — the automation moved the tag and left its explanation, one line over.
  Both are now rewritten in the same pass as every other version marker, and the
  release-tooling test pins them to the released version, so the next release
  cannot repeat it a third time.

## [0.5.0] - 2026-07-29

### Added

- **Guardana grades an agent run, not just a reply.** `offer_tools` answered one
  question — which tool did the model reach for first — and the interesting
  agentic failures are not there. A confused deputy needs a tool *result* to
  carry the injection; over-broad arguments need a task that justified a narrow
  one; nothing about either shows up in the reply text. `guardana.core.trajectory`
  drives the loop: Guardana plays the harness, offers tools, hands back what a
  `ToolDouble` says, and never executes anything. `Trajectory` hangs off
  `Exchange` rather than replacing it, so `Evaluator.evaluate` keeps its shape and
  all five existing evaluators grade a run unchanged.
- **Memory and context poisoning (ASI06, `AML.T0080`/`AML.T0080.000`).** What
  separates an agent from a chat is that a note written in one conversation comes
  back in the next and the model treats it as its own prior context. A YAML rule
  can now declare `memory: read`/`memory: write` tools and a `then:` task that
  runs in a **fresh session** against the same store: Guardana writes in the
  first, grades the second, and only the store crosses the boundary — otherwise
  the check would be proving a single-turn injection the model can still see. The
  store is built per run, never at parse time, so one target's notes cannot reach
  the next target's probe. If the agent never read its memory back, the verdict is
  `inconclusive`.
- **Four agent rules**, all graded on facts about the run rather than on an
  opinion about it: `agent.tool_result_injection` (confused deputy, ASI01/ASI02,
  `AML.T0053`/`AML.T0086`), `agent.credential_exfiltration` (a planted marker
  leaving through a tool argument, ASI03/`AML.T0098`) and
  `agent.tool_argument_scope` (a glob where the task named one file, ASI02/
  `AML.T0101`) and `agent.memory_poisoning` (ASI06). **31 built-in rules.**

  Rules that drive two sessions cost twice their `max_steps`, which the probe
  cost gate caught the moment the first one landed. `TrajectoryRule.budget` states
  the real number, because a cost that is only true per session is not one anyone
  can plan a probe around.
- **A live MCP server is a target** (`guardana probe --mcp <url>`, ASI04). A tool
  description is fed to the agent's model as trusted context, so an instruction
  hidden in one is indirect prompt injection with an audience of one — and reading
  it from the *running* server is what catches a description changed after it was
  approved, which a file scan cannot see. Approve a manifest with
  `--write-mcp-pin`, compare with `--mcp-pin`, and a divergence is a **rug pull**
  (`AML.T0109`). Without a pin, drift is reported `inconclusive`, never as a clean
  server: "nothing changed" and "we have no idea whether anything changed" are
  different answers. The client is JSON-RPC on the standard library — **no new
  dependency**. Streamable HTTP talks to something already running; an stdio
  server is *started* by Guardana, which is the only place the engine executes the
  thing it examines, so it takes an explicit `--allow-exec`. **32 built-in rules.**
- **A `tool_call` evaluator** with four criteria — `forbidden_tools`,
  `canary_in_arguments`, `forbidden_argument_values` and `delivered_by`. The last
  is what keeps the check honest: it names the tool whose result carries the
  payload, and if the model never called it the injection never arrived, so the
  verdict is `inconclusive` rather than a model that looks robust for having
  ignored the document. A rule that configures no criterion at all grades
  `inconclusive` too.
- **Bounds on a run, and each one ends it as `inconclusive`.** Steps (6 by
  default, 12 ceiling), tool calls answered per step (8), tool-result and history
  bytes (1 MiB / 8 MiB), and a 120 s deadline. The history is **never trimmed to
  fit** — the span that would be dropped is exactly the one carrying the payload,
  so trimming deletes the evidence and then reports clean. A verdict that can no
  longer change stops the run, which is correctness and cost in one move.
  `test_probe_cost.py` pins all of it by counting model calls, the way
  `test_scan_cost.py` counts parses.
- **`ChatMessage` learned the `tool` role** (plus `tool_calls` and
  `tool_call_id`, and `ToolCall.id`, which the wire format returns and the parser
  used to drop). `Exchange.transcript` now renders tool calls and results
  explicitly: they live in fields rather than in `content`, so a content-only
  transcript showed a tool-calling turn as an empty line and hid the half that
  matters — from the judge and from the human reading the evidence alike.
- **`guardana calibrate`** — the plumbing that turns the calibration measurement
  into a routine. It grades a JSONL corpus of labelled samples and reports
  accuracy, Brier and ECE; a **starter corpus ships with Guardana**, generated
  from the project's own scripted doubles, and stays open source because a starter
  corpus is a security capability. A corpus line it cannot use is an error, never
  a skipped sample: a corpus quietly one row shorter measures something other than
  what its author meant and the number still looks like a calibration. An
  unreliable measurement exits non-zero, because "we measured nothing" must not
  read as "we measured, and it was fine".
- **`llm_judge` reports a calibrated confidence**, capped by the accuracy it was
  measured at — agreement between samples of one judge measures consistency, not
  correctness, and a judge can agree with itself every time and still be wrong.
  With no measurement recorded it reports raw agreement *and says so in the
  rationale*. A calibration is bound to the versioned rubric it was made for, so a
  changed rubric cannot inherit an older number.
- **A judge-graded ASI01 goal-hijack rule, shipped opted-out** in
  `catalog/optional/`. Whether an agent abandoned its goal is semantic and no
  deterministic grader settles it — but no built-in rule uses `llm_judge`, and an
  unconfigured evaluator is an error under the default policy, so enabling it by
  default would turn every judge-less `probe` red.
- **The OWASP Top 10 for Agentic Applications (ASI01–ASI10) and the agentic MITRE
  ATLAS techniques.** `guardana.core.taxonomy` is now a package, and rules carry
  the references they had already earned: `AML.T0080` (AI Agent Context
  Poisoning) and its `Memory` sub-technique, `AML.T0110` (AI Agent Tool
  Poisoning), `AML.T0053` (Tool Invocation), `AML.T0086` (Exfiltration via Tool
  Invocation), `AML.T0109` (Supply Chain Rug Pull), `AML.T0011.002`/`AML.T0104`
  (poisoned agent tool, used and published). The ASI edition label is **2026**
  though publication was December 2025 — the same convention `OWASP-LLM-2025`
  follows, that edition having shipped in 2024.
- **A fourth entry-point group, `guardana.taxonomies`.** Mapping every rule to a
  public framework is mandatory here, so the framework list could not stay
  closed: a company mapping to its own control catalogue registers `TaxonomyRef`s
  and writes `taxonomy: [ACME-14]` in YAML beside `LLM01`. Registration happens
  through an installed package rather than a string in a rule file, so an unknown
  id in `taxonomy:` is still a load error. Redefining a known short id is refused
  — overriding a *rule* changes what you check, overriding `LLM01` changes what a
  report claims to an auditor, for the built-in rules too.
- **Evaluators declare the `expect:` fields they read** (`Evaluator.expects`), and
  `Expectation` carries evaluator-specific fields alongside the two the engine
  handles itself. `expect:` accepted exactly `canary` and `goal` before, so a
  third-party evaluator could never be configured from YAML at all — strictness
  with no seam. The strictness is unchanged: a field the named evaluator does not
  read is an error, at load for the evaluators core ships and in the `errors`
  channel for a plugin's, which is the first moment the plugin exists.

### Changed

- **`CalibrationReport.brier`, `.expected_calibration_error` and `.accuracy` are
  now `float | None`.** They returned `0.0` when nothing was graded — a flawless
  score for a measurement that never happened, with `is_reliable` the only thing
  between a reader and it. Anyone reaching for `report.brier` without checking
  first saw perfect calibration where there had been none. The roadmap named two
  of the three; `accuracy` lied in exactly the same way. A public API change, made
  now because 0.5 is still before the compatibility promise 1.0 makes.

### Fixed

- **A dynamic YAML rule must now declare `requires: [chat]`.** Every built-in
  already did, but nothing enforced it — harmless while one endpoint-kind target
  existed, and a trap the moment a second one did: a rule without it would be
  planned against an MCP server, find no chat interface, return nothing, and be
  counted as a rule that ran and found nothing wrong. For the same reason the five
  `if not isinstance(target, EndpointTarget): return` guards now raise instead of
  returning quietly; capabilities already guarantee compatibility, so reaching one
  means the contract broke, and that belongs in `errors`.
- **Security: a rule shape the engine did not recognise never got its canary
  planted.** The probe resolved a rule's canary through
  `isinstance(rule, YamlRule | ScenarioRule)`; anything else was routed to the
  pass where nothing is planted, so `CanaryEvaluator` looked for a marker that
  was never there and reported a confident `pass` — a fully leaking model graded
  clean. That had already shipped once for `ScenarioRule`, and it applied to
  *every* third-party rule class until now. Planting is a contract on `Rule`
  (`with_canary`), and a rule that grades by canary while refusing to take one is
  rejected at registration.
- **The `[0.4.0]` changelog heading was deleted by the release-notes fix that
  followed it**, leaving the whole 0.4.0 section under `[Unreleased]` — where the
  next release would have rolled it into 0.5.0 and left 0.4.0 with no notes.
- **Three documented versions sat on 0.3 through the 0.4.0 release.** The landing
  page header, the security policy's supported-versions line, and the README's
  roadmap table all still said 0.3 — the same staleness the Action-pin automation
  was added to prevent, one file over, because only the pins were automated.
  `scripts/bump_version.py` now rewrites these markers in the same pass and
  refuses the bump if any of them has been reworded away, and a test pins all
  three to the released version. The delivered v0.4 section is out of
  `ROADMAP.md`, where shipped work does not belong.

## [0.4.0] - 2026-07-27

### Fixed

- **Security: a Python file too large to read vanished from the scan.** The new
  shared read returned "no tree" for an oversized file exactly as it does for one
  that is not valid Python, so padding a malicious loader past the 16 MiB limit
  removed it from every static rule and nothing in the report said so. Reading is
  now three outcomes, not two: a file the scan was *prevented* from examining
  (too large, unopenable, not a regular file) is recorded and surfaces in
  `errors`, which fails the gate; a file that simply is not runnable Python stays
  quiet, because a rule looking for Python constructs genuinely has nothing to
  find there.
- **Security: an unreadable component was inventoried as though it had been
  examined.** The size probe used `stat()`, which succeeds on a file whose
  contents cannot be opened, so a `model.onnx` with no read permission appeared
  with a size while every rule had skipped it. It is now opened, and a component
  that cannot be is marked `read: failed`. The test that was meant to pin this
  asserted `read == "failed" or "size_bytes" in attributes` — a second disjunct
  that is always true, so it passed either way. Fixed too.
- **Ctrl-C and an unreachable endpoint end a concurrent probe again.**
  `ThreadPoolExecutor` workers are non-daemon and CPython joins them at
  interpreter exit, so a probe printed `could not reach endpoint`, returned, and
  then sat there while every in-flight rule finished — up to the socket timeout
  times the retry count, per request. The pool is now hand-rolled from daemon
  threads, and once the endpoint is known to be down no further rule is started
  against it.
- **`Retry-After: nan` no longer wrecks a probe.** `float("nan")` parses without
  raising and survives both `max` and `min` (every NaN comparison is false), and
  `time.sleep(nan)` raises — so a rate limit was reported as "check could not
  run" for every rule that touched the endpoint. Non-finite values now fall back
  to the exponential backoff.
- **`observations` paths are relativized with the findings.** A report mixed
  repo-relative finding paths with absolute component paths, so the run-to-run
  diff the channel exists for called every component changed as soon as the
  checkout moved, and an uploaded report carried the checkout path that the
  findings beside it were deliberately scrubbed of.
- **`PythonSource.nodes()` really is in document order.** The index was built
  from `ast.walk`, which is breadth-first, so a module-level call came back
  before an earlier one nested in a function — while the docstring and
  `docs/writing-rules.md` promised source order to rule authors. Nodes are now
  sorted by position.
- **A failed source read is cached even once the cache budget is spent**, so the
  "every rule sees the same answer" guarantee no longer depends on how much
  Python the target contains.
- **`bump_version.py` validates before it writes.** A docs file that had lost its
  Action pin aborted the run *after* the five pyprojects and `__version__` were
  already rewritten, leaving a half-bumped tree with a stale `uv.lock`.

### Added

- **`probe` and `monitor` run rules concurrently** (`--concurrency`, default 4).
  Dynamic rules spend nearly all their time waiting on a model, so overlapping
  them is the biggest wall-clock win available. Results are collected in rule
  order whatever finishes first, so two runs of the same probe produce the same
  report and a CI diff stays signal. Artifact scanning stays sequential on
  purpose: it is local, already linear-cost, and a pool there would cost
  determinism for little gain. `Runner` defaults to sequential so embedding
  Guardana never silently opens N connections to someone's model. Measured
  against a stubbed endpoint with the 8 shipped runtime rules: **1.91 s → 0.69 s
  at the default 4** (2.8×), and 0.36 s at 8 — the ratio holds at real model
  latency, since the run is almost entirely waiting.
- **Rate limits are retried instead of ending the probe.** `429` and the
  transient `5xx` statuses get capped exponential backoff that honours
  `Retry-After` — bounded to 30 s, so a server answering `Retry-After: 86400`
  cannot park a scan for a day. Retries are bounded and a failure that survives
  them is raised, never turned into a silent "no reply". A sustained 429 now
  names `--concurrency` rather than repeating the generic 4xx advice to check an
  auth header that is working fine.
- **`ScanResult.observations` — what the scan saw, beside what it found.**
  `guardana.core.observation` and `guardana.core.inventory` record the components
  a run encountered: models with their format and size, dependency manifests,
  datasets, notebooks. Rules produce findings, which is a record of *problems* and
  the wrong shape for "what is deployed here" or "what changed since last run".
  The inventory is taken from the target, not from the rules — otherwise
  excluding a rule would quietly shrink the component list — and a component that
  could not be read is listed as unread rather than dropped. It carries no
  regulatory vocabulary at all: mapping these facts onto CycloneDX or an audit
  template belongs to an extension package, so no external calendar ages the
  engine. Surfaced in the JSON renderer and counted in the human summary.

- **`guardana.core.source` — read a Python file once, not once per rule.**
  `read_python_source()` returns a `PythonSource`: the text, the parsed tree, and
  the tree's nodes grouped by type, built with a single walk. It returns data and
  never a verdict, the same split `guardana.core.formats` draws for model files.
  `ArtifactTarget.python_source()` caches it for the life of one scan, under a
  memory budget — trees measure ~9.3× the size of their source, so past the
  budget the cache stops growing instead of growing unbounded. A file that cannot
  be read or parsed caches as `None` too, deliberately: a retried failure would
  let two rules disagree about the same scan and make the report depend on rule
  ordering. `ArtifactTarget` also lists the tree once and filters per call
  instead of walking it for every rule.

  Measured on this repository (452 files, 19 build-time rules): tree walks 26 →
  2, file opens 2025 → 462, `ast.parse` 1477 → 213, engine run 1090 ms → 175 ms,
  and `guardana scan packages` end to end 1.27 s → 0.36 s. The deliberately
  vulnerable demo fixture still reports the same 12 findings — faster, not
  shallower.

  This is a security property, not a comfort: a scan nobody waits for is one that
  gets switched off, and a switched-off scanner fails open at a level no rule can
  defend. A **cost gate** (`test_scan_cost.py`) now pins it by counting
  operations rather than seconds, so it behaves the same on a loaded CI runner as
  on a laptop — and it is verified to fail when the sharing is removed (42 parses
  instead of 6 on the same fixture).

### Fixed

- **The documented GitHub Action pin pointed two releases back.** The README, the
  integrations guide and the landing page all told users to pin
  `guardana/guardana@v0.1` while 0.3.0 was current. That is worse than a broken
  link — the workflow still runs, just without the fail-closed fixes 0.2 and 0.3
  shipped. The pins now name the current series, and `scripts/bump_version.py`
  rewrites them in lockstep with the package versions, failing loudly if a
  documented file stops carrying one and deliberately leaving a pre-release alone
  (`release.py` does not move the stable tag for one either). A test pins the
  documented pins to the released version, so the two cannot drift again.

- **The agent auto-format hook was never actually shipped.** `CLAUDE.md` and the
  hook's own docstring both said it was checked in so every agent gets it, while
  `.gitignore` excluded all of `.claude/`. The hook now lives in
  `scripts/ruff_on_edit.py` — inside the tree `mypy --strict .` walks, since it
  skips dot-directories — and `.claude/settings.json` is tracked alongside it.
  Only machine-local state (`settings.local.json`) stays ignored.

### Changed

- **`probe` and `monitor` now default to 4 concurrent requests, not 1.** An
  existing cron against a metered endpoint quadruples its request rate on upgrade
  with no config change; pass `--concurrency 1` to keep the old behaviour. The
  library default stays sequential (`DEFAULT_ENDPOINT_CONCURRENCY = 1`), so
  embedding the engine never opens connections you did not ask for.
- **Seven product principles are now project law** (`CLAUDE.md`,
  restated for humans in `CONTRIBUTING.md`): no regulation or vendor name as
  logic in the engine, cost that grows with the target rather than the rule
  count, offline with no account, a fixed commercial boundary (engine and
  built-in rules stay open source — only hosting and curated content may ever be
  paid), a public-framework mapping on every rule, a justified dependency
  surface, and no real data in fixtures. A change that breaks one is wrong
  regardless of how it tests.
- **The roadmap is rewritten around the engine instead of around a regulation.**
  0.4 makes scan cost linear (one tree walk instead of 26, one file read instead
  of 4.8, one AST parse instead of 7, bounded concurrency in `probe`, and a
  benchmark that gates regressions); 0.5 makes agents a first-class target
  (OWASP ASI01–ASI10, the new MITRE ATLAS agentic techniques, trajectory
  grading, memory poisoning, live MCP supply chain); 0.6 adds run-to-run
  regression (`guardana diff`) and multilingual corpora; 1.0 freezes the
  extension API. The compliance evidence pack (CycloneDX ML-BOM) moves out of the
  engine into a separate extension package — the EU AI Act's high-risk duties
  were deferred to December 2027, and an engine that encodes a legal calendar
  ages with it.

## [0.3.0] - 2026-07-26

### Fixed

- **Security: the `errors` channel was dropped on three of the four paths that
  carry a result.** `ScanResult` gained a defaulted sixth field, and every place
  that rebuilt the dataclass field by field silently lost it — so `guardana probe`,
  `guardana monitor` and any `scan --baseline` run still printed `✓ No findings.`
  and exited 0 when a CRITICAL check had crashed. Fixed at the root: `ScanResult`
  now owns a `merged()` constructor, `apply_baseline` uses `dataclasses.replace`,
  and `_sub_registry` carries the source registry's load failures. A future
  channel cannot go missing the same way.
- **Security: `--write-baseline` never reported or gated checks that could not
  run**, so a team could commit a baseline missing whatever a crashed rule would
  have found. It now names each one and exits non-zero on them — while still never
  gating on the findings it is snapshotting, which is the point of the flag.
- **Security: a run-time `RuleLoadError` was a silent skip** while the identical
  error at load time failed the gate. Both are now recorded: the check did not
  run, and where it failed does not change that.
- **Security: the collector's read paths ignored `errors`.** `/stats` never
  aggregated them and the dashboard neither tiled nor listed them, so an agent
  whose checks were all crashing rendered as a clean one — the failure the v3
  envelope was added to prevent, one layer further out.
- **Security: the monitor had no `errors` alert condition**, so with
  `fail_on_error: false` a monitored model whose rules had started raising ran
  silently for days. It is baselined like `unverified`, of which it is the
  strictly worse sibling.
- **Security: calibration inverted every verdict at or below half confidence.**
  The prediction was re-derived from the probability instead of carrying the
  evaluator's stated outcome, so `LengthEvaluator` — which passes at exactly 0.5
  — measured as 0% accurate while grading every sample correctly. The module that
  exists to audit judges was publishing inverted numbers about them. The
  abstention caveat also now fires at half the corpus, as its docstring promised,
  instead of only above 50% of the *graded* subset.
- **A rule-local `OSError` no longer reports a healthy endpoint as down.** The
  re-raise is narrowed to connection failures (`URLError`/`EndpointError`); a rule
  that merely opens a missing local file is recorded instead of abandoning the run.
- **A provider returning the wrong type can no longer poison discovery.**
  `_absorb` validates before registering, so a provider returning a mapping (which
  iterates to strings) can no longer make the *next*, healthy entry point fail —
  isolation no longer depends on entry-point ordering.
- **`guardana rules` reports packs that failed to import**, and the human renderer
  no longer prints the `✓` all-clear next to a `! [ERROR]` line.
- **A rejected envelope is no longer swallowed as an outage.** A v3 agent posting
  to a not-yet-upgraded v2 collector gets a distinct message naming the schema
  mismatch, instead of one indistinguishable from an unreachable host.

### Added

- **`guardana.core.calibration` — the confidence, measured.** The project's
  central claim is that other scanners misjudge whether an attack succeeded and
  Guardana reports an honest confidence instead. That confidence was agreement
  across samples: a reasonable proxy, but an assertion, which is the same thing
  everyone else offers. `calibrate(evaluator, samples)` now measures it against
  known-correct labels and reports **Brier** and **expected calibration error**.
  ECE is the one that bites: an evaluator can be no better than a coin flip while
  claiming certainty every time, and accuracy alone will not show it.
  Building the labelled corpus needs no human: the deterministic graders already
  produce ground truth — a planted canary appearing verbatim is a fact, and so is
  the list of tools a model actually called. The report refuses to flatter, too —
  `inconclusive` verdicts are counted and excluded rather than scored as
  predictions nobody made, a corpus under `MIN_RELIABLE_SAMPLES` is returned as
  unreliable *with the reason*, and an empty corpus raises instead of returning a
  zero that reads like a perfect score. A report is keyed to the versioned
  evaluator id, so a changed rubric cannot inherit an old measurement.

### Fixed

- **Security: the engine could report a green build on a check that never ran.**
  A rule that raised landed in `rules_skipped` — the same bucket as "this target
  cannot satisfy that rule's capabilities", a normal and expected outcome — and
  `gate()` only failed when *zero* rules ran. So a CRITICAL rule crashing on a
  crafted artifact left 26 others running, `rules_run > 0`, and the build green.
  Reproduced against 0.2.0 before the fix. Checks that could not run now have
  their own `errors` channel and **fail the gate by default**.
- **Security: one broken plugin took the whole tool down.** `Registry.discover()`
  called `ep.load()()` with no isolation, so a single third-party entry point that
  failed to import — a pack pinned to a library you do not have, a typo in a
  provider — raised out of discovery and left the user with *no rules at all*,
  built-ins included. That got sharper the moment 0.2.0 published
  `guardana.core.formats` and started inviting third-party packs. Each entry point
  is now isolated; a broken one is recorded and the rest still load.
- **Security: a third-party rule with an ordinary bug aborted the scan.** The
  runner caught only `RuleError`, so a plugin raising `ValueError` (or anything
  else) ended the run. Every `Exception` is caught per rule now — and
  `BaseException` deliberately is not, so Ctrl-C and `SystemExit` still stop the
  scan. Findings a rule already yielded before dying are kept.
- **Security: a custom rule that would not load was only a stderr warning.**
  `CLAUDE.md` requires a YAML typo to raise at load time, because a gate you think
  you configured but do not have is worse than no gate — but `load_yaml_rule_dirs`
  downgraded exactly that to a warning and carried on green. It now feeds the same
  `errors` channel.

### Added

- **The `errors` channel, everywhere.** "No findings" had three meanings and only
  two were distinguishable. A *finding* is "a check ran and found something",
  *unverified* is "a check ran and could not tell", and an **error** is "a check
  never ran". The third is now first-class in `ScanResult`, in all four renderers
  (human, JSON, JUnit `<error>` rather than `<failure>`, SARIF
  `toolExecutionNotifications` with `executionSuccessful: false`), and in the
  collector envelope.
- **`fail_on_error` in `guardana.yaml`** (default **`true`**). The opposite
  default to `fail_on_inconclusive`, on purpose: `inconclusive` is a verdict — the
  check ran and honestly could not tell — while an error means it never happened.
  Set `false` if you would rather ship than fix the broken check.

### Changed

- **`rules_skipped` means one thing again:** the target cannot satisfy the rule's
  capabilities. A rule that raised no longer hides there. A rule whose *evaluator
  was never configured* is still a skip, not an error — that is a configuration
  state, not a defect.
- **Collector envelope `schema_version` 2 → 3**, carrying `errors` and its count.
  The collector accepts **both** 2 and 3, so a fleet can upgrade one agent at a
  time; a v2 agent simply reports no errors, which is honest, because a v2 agent
  could not observe them.
- **An unreachable endpoint still exits 2, not 1.** Connection failures against an
  endpoint target propagate rather than being swallowed into `errors`: every rule
  would fail identically, so it is a fact about the run, reported once at the top
  with its own exit code. The same exception from an artifact rule *is* rule-local
  and is recorded.

## [0.2.0] - 2026-07-26

### Added

- **Public model-format readers — `guardana.core.formats`.** Bounded, offline,
  deterministic, fail-closed readers for GGUF metadata and safetensors headers.
  They return data and no verdicts, so a third-party pack can ship threat
  knowledge without first writing a binary parser. Sizes claimed *inside* a file
  are checked against an explicit `Limits` before anything is allocated, so a
  crafted artifact costs a `FormatError`, not the scan. `guardana.core.testing`
  gains `build_gguf` / `build_safetensors`, so a crafted fixture is a dict
  literal in a test rather than a malicious binary in the repo.
- **New rule `guardana.supply_chain.chat_template` (CRITICAL/HIGH).** A model's
  chat template is Jinja source that ships inside the artifact and renders the
  moment the model is used — a gadget in it executes code with no inference and
  no `trust_remote_code` (CVE-2024-34359 in llama-cpp-python; CVE-2026-5760 in
  SGLang's rerank path, 2026). The rule reads the template as a *parsed value*
  from every carrier it can hide in: GGUF `tokenizer.chat_template`,
  `tokenizer_config.json` (both the string and the named-list form),
  `chat_template.json`, and the standalone `chat_template.jinja` that
  transformers has written by default since 4.47. It flags dunder chains, the
  `|attr` sandbox escape (CVE-2025-27516 — the escape from the very sandbox
  `transformers` renders templates in), `lipsum`/`cycler` gadget entry points,
  shell/`os` sinks, and template inclusion (HIGH). A template it cannot read is
  reported as *not scanned*, never as clean.

- **`remote_code_config` covers kernel-dispatch config injection (CVE-2026-4372).**
  A `config.json` whose private `_attn_implementation_internal` field names a Hub
  repository gets that repository downloaded and imported on load — and the kernel
  path never consults `trust_remote_code`, so `trust_remote_code=False` does not
  stop it. That is CRITICAL, and it is matched by key name rather than by value
  shape, because `_name_or_path` carries an identical-looking `owner/repo` string
  in most real configs. A kernel requested through the documented
  `attn_implementation` field is reported the way `trust_remote_code=True` is: a
  lead. Affects transformers 4.56.0–5.2.x with `kernels` installed; fixed in 5.3.0.

- **`hidden_instructions` reads safetensors `__metadata__`.** safetensors is the
  format people choose precisely because it cannot carry code, which makes its one
  free-text channel the natural hiding place for a directive in an artifact
  reviewers treat as inert — and hubs render it while agents read it back. Same
  contract as the rest of the rule: concealment is the signal, not prose.

- **New rule `guardana.supply_chain.onnx_graph` (HIGH/MEDIUM).** ONNX carries no
  pickle, which is why scanners skip it — ModelScan covers H5, pickle and
  SavedModel only. Three of its structural features are worth reading, and the
  rule reads all three: an operator **domain outside the standard set** (the
  runtime has to register a native operator library, i.e. machine code, before
  the model will run), an **`external_data` location** that climbs out of the
  model directory or is absolute (an arbitrary file-read primitive — firm HIGH),
  and **`metadata_props`** carrying invisible smuggling characters or an
  executable-looking payload. The graph is walked straight off disk with a
  dependency-free streaming protobuf reader that seeks past tensor payloads, so a
  multi-gigabyte model costs kilobytes of reading. A graph it cannot walk — or
  could not finish walking — is reported as *not scanned*.
  `guardana.core.testing.build_onnx` builds the fixtures.

- **`malicious_dependency` is advisory-backed.** A bundled, offline, **AI/ML-only**
  dataset replaces the one-package blocklist. It is deliberately not a general CVE
  feed — that stays a non-goal — because an entry only earns its place by closing
  the loop between an artifact this scan already finds and the code that would run
  it. Two channels: a **compromised release** (`ultralytics` 8.3.41–46, `lightning`
  2.6.2/2.6.3, the `torchtriton` dependency-confusion name), which is the only
  signal that catches a *legitimate* package that was poisoned; and a **vulnerable
  loader** — `transformers` <5.3.0 for the kernel-injection config, `llama-cpp-python`
  and `sglang` for a poisoned chat template, `torch` <2.6 for a pickle, `keras`
  <3.11.3 for an `.h5` Lambda — reported as a lead, because it matters only once
  something poisoned reaches it. Only *exact* pins are matched (a range constraint
  pins nothing, and guessing would manufacture findings). Every entry carries a
  public reference, a malformed dataset raises at load rather than scanning as
  empty, and `MaliciousDependencyRule(advisories=…)` takes your own.
- **A worked extension example on the new primitives.**
  [`docs/model-formats.md`](docs/model-formats.md) documents the reader contract,
  and `examples/custom_rule` gains a second plugin rule that inspects a GGUF model
  and is *entirely* policy — the binary parsing comes from the engine.

### Changed

- **The legacy `.h5` Keras Lambda finding is firm, not a lead.** It is matched on
  the exact `"class_name": "Lambda"` marker instead of the bare word, so a layer a
  user merely *named* "Lambda" is no longer reported as code execution — and since
  `load_model` silently ignores `safe_mode` for `.h5` (CVE-2025-9905), a declared
  Lambda there *will* run, which is a verdict rather than a hedge. A `.keras` file
  that is not a readable archive falls back to the byte marker and, failing that,
  is reported as *not scanned*.
- **`model_format` no longer inspects Keras or GGUF files.** Those formats belong
  to `keras_lambda` and `chat_template`; previously a single `.h5` Lambda produced
  two findings at two different severities.

### Fixed

- **Security: a crafted repository could stall a scan indefinitely.** Every binary
  scanner (`pickle_opcode`, `keras_lambda`, `model_format`, `saved_model_ops`,
  `hardcoded_secret`) opened files directly, so a FIFO named `model.pkl` blocked
  the read until a writer appeared — forever, in CI. All of them now go through one
  guarded bounded reader, and the file is reported as *not scanned* rather than
  skipped in silence. The same guard covers `guardana.core.formats`.
- **Security: scanning a real checkpoint could exhaust memory.** `pickle_opcode`
  read whole files with `path.read_bytes()`, so a multi-GB `.pt` — or a symlink to
  `/dev/zero` — took the scan down with it. Zip containers are now streamed from
  disk instead of held in memory, and a *raw* pickle is capped at 512 MiB and
  reported as not fully scanned beyond that.
- **Security: a chat-template payload could hide past the scanner.**
  `model_format` looked for a Jinja gadget only within 4 KiB of the literal
  `chat_template`, so a gadget appended to the end of a real 8 KiB template
  scanned clean — verified against the shipping rule before the fix. The
  template value is now graded in full, whatever its length.
- **Security: the same window produced findings out of thin air.** Because the
  scan covered a byte window rather than a value, a code model's vocabulary
  (which contains tokens like `__init__`) was reported as a HIGH chat-template
  gadget on a model carrying no chat template at all.
- **One fact, one finding.** `model_format` no longer inspects `.gguf`;
  ownership sits with `chat_template`, so a single poisoned template can no
  longer produce two findings at two severities.

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
