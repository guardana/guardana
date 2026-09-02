---
title: "The 0.22 audit"
nav_order: 25
summary: "what a review of the released 0.22.0 found about the extension surface, which seams are closed on purpose and which by accident, and the six-cycle program that follows from it"
status: accepted
---

# The 0.22 audit: how open the engine really is, and what to open next

**Status:** accepted · **Written:** 2026-09-02 · **Subject:** the released 0.22.0 at `8e2cd76`

A review of the released build with one question in front of it: **can a team
that is not this repository build its own security layer on top of Guardana —
its own checks, graders, targets, datasets and outputs — without patching the
engine, and get the same honest verdict the built-ins get?** The answer is "for
rules and evaluators, yes; for everything else, only from Python", and the
findings below are why. Kept as a design document because the *pattern* in them
decides the next six increments, and because the two real defects passed every
gate this repository has.

## Method, and its limits

Static reading of the engine, the CLI, the rule packs and the documentation, then
running the commands the documentation tells an extension author to run and
reading what they printed. Three things were verified by execution rather than
by reading, and each is marked below. The review did not run a live model, a
live MCP server or the collector; nothing here is a claim about those paths.

## What is genuinely open today

Worth stating first, because the gaps below are narrow beside it:

- Four entry-point groups (`guardana.rules`, `guardana.evaluators`,
  `guardana.targets`, `guardana.taxonomies`), every one exercised by
  `examples/custom_rule`, loaded transactionally, with id conflicts refused and
  the `guardana.*` namespace enforced.
- Capability protocols: a target that inherits nothing of Guardana's runs the
  built-in artifact rules, and `assert_target_conforms` checks both directions.
- Declarative rules in three shapes, fixtures with the three-state outcome,
  `rule test`, `pack validate`, `pack lock`, an `extension_api` version, a plugin
  trust policy, test doubles, model-format readers, `assert_secure`.
- The assessment channel with a stable case identity, and a diff that refuses an
  incomparable pair.

Nothing in the program below replaces any of that. It fills the seams around it.

## Defects — the two that were verified by running

**1. The reference third-party target fails the contract the same release made
true.** `examples/custom_rule/src/acme_rules/prompt_library_target.py` declares
`Capability.READ_FILES` and implements none of `FileReader`. Run through the
conformance kit the release shipped:

```console
$ uv run --isolated --no-cache --with ./packages/guardana-core \
    --with ./packages/guardana-rules --with ./examples/custom_rule python check.py
unmet_surfaces: ('read_files (needs FileReader)',)
assert_target_conforms RAISED: TargetContractError AcmePromptLibraryTarget does not
satisfy the target contract:
  declares read_files (needs FileReader) but does not implement it
```

Any `Runner.run` over that target records a capability error, and with the default
`fail_on_error: true` the run is `indeterminate`. The example's own tests never run
the `Runner` over the target and never call the conformance kit, so the one
package that stands in for every third party's was never held to the contract the
documentation tells third parties to copy. 0.22.0 rewrote thirty-five
`isinstance` checks in the engine and the rule packs and did not revisit the
example, which is precisely the seam the example exists to exercise.

**2. The documented inner loop for a third party exits `indeterminate` on the
documentation's own example.** `docs/usage-rule-test.md` opens with
`guardana rule test 'acme.*'`. No rule in `examples/custom_rule` declares a fixture —
not the two YAML rules (no `fixtures:` block) and not the three plugin rules (no
`fixtures()` override) — so the command reports five gaps and exits `2`. The verdict
is correct. The example is what is wrong: it demonstrates the part of the contract
that says silence is not proof by being silent.

Both are fixed in the first cycle, and the fix carries its own gate: the isolated
example suite runs the `Runner` over the target, calls `assert_target_conforms`,
and proves every example rule through `verify_rules`.

## Defects — found by reading, confirmed by output

**3. `plan scan` prices a file scan as unknown.** Every one of the twenty built-in
artifact rules inherits `estimated_requests = None`, so the plan for a scan that
sends nothing prints:

```text
requests: at least 19, at most 0 — plus 19 of unknown cost
```

An artifact target has nothing to send a request to — the manifest already states
that a file scan's `requests: 0` is a measurement — so `None` here is the wrong
kind of honesty, and "at least 19, at most 0" is a sentence with no reading. The
default becomes `0` for `TargetKind.ARTIFACT` and stays `None` for everything
else, where the answer genuinely depends on the rule.

**4. Plugin trust is not one policy.** `scan`, `probe`, `monitor`, `analyze-trace`,
`rule test` and `pack *` resolve `--plugins` through `resolve_trust`. `baseline`
hard-codes `all`, `import-observations` hard-codes `disabled`, `target inspect`
and `calibrate` call a bare `Registry.discover()`, and `plan probe` passes a
literal `True`. A security control that a user sets on one command and not on the
next is a control they believe they have. Every command that discovers gets the
same two flags, from the same resolver, with the same test. Cycle 0's own static
gate — which scans every file in `guardana.cli` for the bare call or the hard-coded
literal instead of trusting a rereading — found two more than this list did,
`guardana rules` and `guardana taxonomy`, which is the reading-versus-running
argument this audit makes everywhere else, demonstrated on its own defect.

**5. Fixtures in YAML exist for one of the three YAML shapes.** `fixtures:` is
accepted on a `prompts:` rule and rejected on `steps:` and `task:` rules. The
seven built-in scenario and trajectory rules are therefore unsampled, and a third
party writing the shapes the documentation calls the interesting ones cannot
sample theirs either.

**6. Prose that the build no longer agrees with.** `SECURITY.md` lists three
entry-point groups of four; `FEATURES.md` still invites a pack to "override
built-ins", which 0.22.0 made a refused conflict; `--no-plugins` is documented as
the safe mode in `SECURITY.md` and implemented as a deprecated alias wired on two
commands; `GullibleAgentTransport`, `FIXED_RUN_TIME`, `fake_jwt`, `fake_llm_key` and
`fake_secrets` are exported and documented nowhere; and `CLAUDE.md` says scan cost
is "pinned by a benchmark" when what exists — correctly — is two operation-count
gates that count tree walks, parses and transport calls, which mean the same thing
on a laptop and a loaded runner. The last one is fixed by changing the sentence,
not by adding a wall-clock benchmark; see "Rejected" below.

## The closed seams, sorted by intent

Every place an extension author would reach and find a literal instead of a
lookup. The second column is the decision, and the reasoning for each "stays
closed" is as important as the reasoning for each "opens".

| Seam | Today | Decision |
|---|---|---|
| CLI target construction | literal `ArtifactTarget(...)`, `build_endpoint(...)`, `TraceTarget(...)` in nine places; `registry.targets()` never consumed by a command | **opens** — [`target-locators.md`](target-locators.md) |
| `--format` and renderers | closed `OutputFormat` enum over a hard-coded dict | **opens** — [`output-plugins.md`](output-plugins.md) |
| `--reporter` | `server://` only | **opens** — same document |
| Provider transports | `openai`, `ollama`, `tgi` | **stays closed**; a custom wire protocol is a custom target with a scheme, which the first row makes selectable. A second registry for the same thing one layer down is two ways to do one job |
| `Capability` | closed enum, by design | **opens, last** — [`namespaced-extension-ids.md`](namespaced-extension-ids.md), because the typo-becomes-silent-skip argument has to be answered before the list is opened |
| `AssertionKind` | closed enum plus four dispatch tables | **opens, last** — same document |
| Attack technique | absent; a vulnerability crossed with an encoding is a new rule | **opens** — [`attack-techniques.md`](attack-techniques.md) |
| Numeric assessors, suites, datasets | the `Assessment` shape carries them; nothing produces them | **opens** — [`quality-suites.md`](quality-suites.md), [`paired-regression-statistics.md`](paired-regression-statistics.md) |
| Presets | three, hard-coded | **stays closed**; a preset is a named policy and a `guardana.yaml` already expresses any policy. A preset registry would be a second profile format |
| `guardana.yaml` keys | frozensets, unknown key refused | **stays closed**; the refusal is the feature. Extensions get `rule_config:` and `evaluators:`, which are free-form by design |
| CLI commands | imperative list in `main.py` | **stays closed**; a plugin that adds verbs to a security tool is a plugin that can add `guardana wipe`. Four verbs is a product decision |
| `TargetKind` | three values | **stays closed**; a verb selects a kind, and a fourth kind is a fifth verb |
| Collector `Store` | `create_app(store=...)` | **stays closed**; the collector deliberately has no plugin loader, and it never imports the engine |
| `observe()` dispatch | `isinstance` over two protocols | **stays closed for now**; a custom target produces no inventory, which is an absence the manifest shows, not a false claim. Revisited when a design partner's target needs it |

## The program that follows

Six cycles, ordered by dependency and by what a real team hits first. The
implementation plans are working documents outside the public tree; this is the
public commitment and the order.

| Cycle | Delivers | Why here |
|---|---|---|
| 0 — truth *(done)* | the six defects above closed with gates; a layers contract in import-linter; CodeQL; coverage floors for the areas that had none | cheap, and every one of them is something a third party hits in their first hour |
| 1 — author tooling | target locators; renderer and reporter plugins; YAML fixtures for all three shapes; `guardana new-pack`; a capability manifest generated from code | a suite against *your* system needs your system to be a target the CLI can build; the rest is the difference between an afternoon and a week for a pack author |
| 2 — quality suites | versioned datasets, suites as rules, measurement on `Verdict`, deterministic and judged assessors, a suite gate that refuses below a sample size | Horizon 1's outcome, on the channel 0.22.0 shipped |
| 3 — paired statistics | `diff` and `monitor` answer "worse" over a paired sample with a minimum effect and an exact test, or say they cannot | Horizon 1's exit criteria |
| 4 — techniques | a `Technique` extension point and four deterministic transforms | coverage as a product of two small sets rather than a sum of large ones, and a seam the freeze must see |
| 5 — namespaced ids | capabilities and assertion kinds a pack can declare, resolved at load, typos still refused | the last two extension points 1.0 criterion 8 names |

What moves on the roadmap: `TargetFactory` from "deferred" to cycle 1; the
technique from "designed before 1.0" to cycle 4 with a design; the capability
descriptor and custom assertion kinds from "its own design" to cycle 5 with one;
CodeQL from P1 to cycle 0. Assessments in the collector stay after cycle 3,
because the suite and dataset shapes have to settle first — the reason
0.22.0 already gave. Nothing in Horizons 2 and 3 moves.

### One rule for the extension API number across the program

`extension_api` moves when a pack *can need* something an older build lacks, and
every move is additive: the build advertises the set of API versions it
implements, a pack names the one it was written against, and the check becomes
"does the pack's range contain any version this build implements". A pack
declaring `>=1,<2` today loads on every build this program produces. Cycle 1
advertises `2` (locators, output plugins, fixtures for every YAML shape), cycle 4
advertises `3` (techniques), cycle 5 advertises `4` (namespaced ids). Cycles 0, 2
and 3 add nothing a pack implements, so they add no number. The pack manifest's
own `schema_version` moves separately, once per cycle that adds a `provides` list,
and older manifests migrate forward in memory as they do now.

## Rejected

**A `--plugin-file path.py` for script-style extensions.** The request behind it is
real — a team's first rule is a file, not a package — and the answer is
`guardana new-pack`, which turns a name into an installable package with the four
entry points, a manifest, three fixtures and a conforming target in one command. A
second way to load Python into a security scanner, from a path on the command
line, is a second trust decision with its own edge cases in a tool whose plugin
policy exists to have exactly one.

**A wall-clock benchmark as a gate.** Time on a shared runner is noise, and a
gate that fails on noise is a gate people learn to re-run. The operation-count
gates measure the property principle 2 actually names — cost grows with the
target, not with the rule count — and they cannot be made green by a faster
machine. The sentence in `CLAUDE.md` changes to say what is pinned.

**Mutation testing as a gate.** The project already inverts every test by hand,
and a mutation run over the engine takes longer than the whole suite. It may be
worth running on a schedule as advice; it is not worth blocking a merge on.

**A fifth verb for suites.** A suite is a rule whose cases come from a dataset,
and `probe` already runs rules against an endpoint under a budget, a plan, a
policy and a manifest. A `guardana suite run` would be `probe` with a narrower
help text and a second pipeline to keep honest.

**Opening presets and profile keys to plugins.** See the table. A profile that
refuses a key it does not know is the reason a typo is a load error and not a
gate nobody configured.

**A public extension registry.** Unchanged from the roadmap: meaningful once a pack
has a manifest, a range, a lock and a trust model — the first three exist now, and
the fourth still does not.

## What this audit does not change

The four verbs. The engine knowing no vendor and no regulation. Offline by
default and no account. The fail-closed direction of every refusal named here:
each cycle adds outcomes an extension can produce, and none of them is a new way
to pass.

## See also

- [`extension-author-tooling.md`](extension-author-tooling.md) — the fixtures, manifest and lock this builds on
- [`capability-protocols.md`](capability-protocols.md) — why a target's declaration and its surface must agree
- [`assessment-channel.md`](assessment-channel.md) — the measurement record the suites fill
- [`audit-0.21.md`](audit-0.21.md) — the previous audit, and the pattern both share
