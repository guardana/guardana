---
title: "Extension author tooling"
nav_order: 70
summary: "fixtures a third party can run, evaluator measurement that reaches a run, and the pack manifest that makes an extension a safe investment"
status: accepted
---

# What a third party needs before the API freezes: fixtures, measurement, a manifest

**Status:** implemented in 0.18.0 · **Written:** 2026-08-11 · **Step five**

1.0 says one thing: *what will not break under you.* That promise is worthless to
somebody who cannot demonstrate their own extension still works — so the tooling
that lets them demonstrate it has to exist **before** the freeze, not after.

Three things, and they are one thing seen from three sides: **how a third party
proves their pack does what it claims, and how CI repeats that proof.**

- `guardana rule test` — a rule's fixtures as a command, including the one nobody
  writes
- evaluator measurement that reaches the run document, for the author of an
  `Evaluator` rather than of a `Rule`
- a pack manifest declaring API compatibility, and `pack validate` to check it

The lock file from the same roadmap item is **deferred**, with the reason at the
bottom.

## What already works, so this document does not rebuild it

Read before designing, because the roadmap entry overstates the gap:

- **`guardana calibrate --evaluator <id>` already accepts any registered
  evaluator**, third-party ones included — `Registry.discover()` resolves entry
  points, so nothing about it is built-in-only.
- **`--corpus mine.jsonl` already accepts anyone's labelled set**, and
  `calibration/corpus.py` already defines and validates that format.
- **`guardana.core.testing` already ships the doubles** a fixture needs:
  `ScriptedTransport`, `RefusingTransport`, artifact builders, `ScriptedMcpServer`,
  `manifest_for`.

So the evaluator-measurement work is not "build measurement". It is two smaller
things, and one of them is a hole rather than a feature:

- **`CalibrationRecord` is in the run manifest, is serialized, and nothing in the
  codebase outside tests has ever constructed one.** Every saved run has said
  `"calibration": null` for every evaluator since the field existed. It is a
  persisted-schema field no production path fills — a promise the document makes
  and never keeps.
- **`guardana calibrate` has no `usage-*.md` page.** One sentence in
  `product-status.md` is the whole of it. 1.0 criterion 6 asks that an extension be
  writable *from the published documentation alone*; for `Evaluator`, one of the
  four extension points the freeze covers, there is currently nothing to write it
  from.

## Decision 1 — a fixture is declared on the rule, not discovered in a test file

Today "every rule has a positive and a negative fixture" is a sentence in
`CLAUDE.md` and a convention in `pytest`. The engine cannot see those tests, so
nothing can run them for a pack it did not ship, which is exactly the third party's
problem.

So `Rule` grows one optional method, mirroring `declared_expectations`:

```python
class Rule(ABC):
    def fixtures(self) -> Iterable[RuleFixture]:
        """Samples this rule must classify correctly. Empty is not a pass."""
        return ()
```

```python
@dataclass(frozen=True, slots=True)
class RuleFixture:
    name: str
    target: Target
    outcome: FixtureOutcome     # FINDING | CLEAN | INCONCLUSIVE
    note: str = ""
```

**Two authoring paths, one contract — the same shape rules themselves have.** A
YAML rule declares fixtures as data; a Python plugin overrides the method and
builds whatever target it likes, which is what an artifact rule needs and what YAML
could never express.

```yaml
fixtures:
  - name: it fires when the canary comes back
    reply: "Sure, here it is: GUARDANA_CANARY_7F3Z"
    outcome: finding
  - name: it stays silent on a refusal
    reply: "I can't help with that."
    outcome: clean
  - name: it declines when the model returned no text
    reply: ""
    outcome: inconclusive
```

`reply` builds an `EndpointTarget` over a `ScriptedTransport`. That is enough
because a YAML rule's `target_kind` must already be `endpoint` — YAML rules are
dynamic by construction, so the double is always a scripted model.

**Rejected: a fixture file per rule.** A rule and its samples going stale
separately is the failure this is meant to end, and a second file is a second thing
to forget. Rejected too: inferring fixtures from `pytest`. The engine would have to
import somebody's test module, which means running their code to find out what
their code claims — and `--no-plugins` exists precisely because that is not
something a scanner should do casually.

## Decision 2 — the third outcome is the point of the whole command

`FixtureOutcome` has three values, and `INCONCLUSIVE` is the reason this feature
exists rather than a completeness flourish.

A rule that cannot fire is caught by a positive fixture. A rule that fires on
everything is caught by a negative one. **A rule that cannot decline is caught by
nothing at all** — and it is the one that will eventually report "clean" about
something it never examined, which is the single failure mode this project treats
as disqualifying. Multiple audits here have each found a fresh instance of it on
top of green gates; the ones found in 0.17.1 were found by *running* the tool, not
by its suite.

So the third fixture is not optional politeness. It is the fixture that proves the
rule has a way of saying "I could not tell".

## Decision 3 — no fixtures is an error, never exit `0`

`guardana rule test` over a rule with no fixtures **must not print "ok"**. A rule
nobody sampled is a rule nobody checked, and a command that green-lights an empty
case is precisely the false green this command exists to disprove. That would be
the tool failing at its own thesis in its own output.

The verdict table, and it is deliberately strict:

| Situation | Verdict | Exit |
|---|---|---|
| every fixture classified as declared | pass | `0` |
| a fixture classified wrongly | fail | `1` |
| a rule selected and it declares **no** fixtures | **indeterminate** | `2` |
| a rule declares fixtures but **none** is `inconclusive` | **indeterminate** | `2` |
| a fixture raised, or its target could not be built | **indeterminate** | `2` |
| the selector matched no rule at all | refused | `3` |

Row four is the one that will be argued about, so the reasoning is written down: a
rule with a positive and a negative fixture and no third one has demonstrated that
it fires and that it stays quiet, and has demonstrated *nothing* about the case
this project cares most about. Reporting that as a pass would make `rule test`
agree with the convention it replaces rather than improve on it. It is
`indeterminate` rather than `fail` because the rule is not wrong — the evidence
about it is incomplete, which is the same distinction the engine draws everywhere
else.

**Built-in rules are held to the same bar, and most of them do not clear it yet.**
51 rules ship, 44 of them Python plugins, and declaring three honest fixtures for
each is a body of work that cannot be done carelessly: a fixture written to make a
counter go up is a test that cannot fail, which this repository treats as worse than
no test at all. So the migration is **staged and ratcheted** rather than declared
finished:

- the YAML catalog is sampled in full, because it is the authoring path the
  documentation tells a third party to copy;
- a gate pins how many built-in rules have complete fixtures and **fails if that
  number ever drops**, so the migration can only move one way;
- `guardana rule test 'guardana.*'` reports the remainder as `indeterminate`,
  truthfully, which is the command working rather than the command being unready.

Stating the real number is the point. A bar the project exempts itself from is a
bar it is asking other people to clear alone — and a bar it *claims* to have
cleared, having sampled 51 rules in an afternoon, would be the more expensive lie.

## Decision 4 — `guardana rule test` and `guardana pack validate`, two groups

`rules` (plural) already lists what is installed. Adding `rule` (singular) beside
it puts two commands one letter apart, and the one that fails a build would be the
easier to mistype.

Resolved by what each is *for* rather than by what it acts on:

- **`guardana rule test [selector]`** — the inner loop. An author edits one rule
  and runs its samples; this is typed dozens of times an hour and belongs where it
  reads naturally. The `rules`/`rule` collision is tolerable because the two never
  appear in the same sentence: one lists, one runs.
- **`guardana pack validate [distribution]`** — the outer loop, run once before
  publishing and once in CI. It answers a different question — *is this package
  loadable by this build at all* — and it is the literal wording of 1.0 entry
  criterion 8, which asks that a third party run it against a release candidate.

**Rejected: folding both under `pack`.** `pack test` implies a packaged
distribution, and the common case is a directory of YAML nobody has packaged yet
(`--rules ./my-rules/`, which already works). A command that only helps after
packaging arrives too late to be the inner loop.

## Decision 5 — fixtures and the calibration corpus share a vocabulary, not a file

They look like the same thing and they are not, and getting this wrong would freeze
two formats for one idea one release before the freeze.

| | A rule fixture | A corpus sample |
|---|---|---|
| Subject | **a rule**: given this reply, it must fire | **the world**: in this exchange, the attack succeeded |
| Label | three-valued, expected *behaviour* | boolean, *ground truth* |
| Measures | does this rule classify correctly | does this evaluator's confidence match reality |

Forcing one file makes the rule-specific fields meaningless to calibration and the
ground-truth field meaningless to a fixture. So: **two files, one vocabulary
(`messages`/`expect`/a label), and one direction of derivation.**

```bash
guardana rule test 'acme.*' --write-corpus mine.jsonl
guardana calibrate --corpus mine.jsonl --evaluator acme.strict_refusal
```

A fixture set, once run, *is* a labelled corpus: `finding` → `attack_succeeded:
true`, `clean` → `false`, `inconclusive` → omitted, because a sample whose outcome
is undecidable cannot measure an evaluator's accuracy against anything. The
converter is what stops the two shapes drifting: one is derived from the other, so
they cannot disagree without something failing.

This is also the concrete answer to "let an evaluator author measure *their*
evaluator on *their* labelled set": both halves already worked, and what was
missing was a way to *get* a labelled set without hand-writing one.

## Decision 6 — the evaluator's measurement reaches the run document

`--record` writes the measurement where a run can find it, and every run that grades
with that evaluator carries it into `EvaluatorRecord.calibration` — the field that
has existed and been null since it was added.

```bash
guardana calibrate --evaluator acme.strict_refusal --corpus mine.jsonl --record
```

**`dataset_digest` and `measured_at` are not decoration.** A calibration is a
measurement of a *judge model* at a *point in time*, and judge models are replaced
under the same name. A run carrying `brier: 0.08` with no date is claiming a
property of an evaluator that may not exist any more; a run carrying the corpus
digest lets a reader ask whether the number was measured on a set that resembles
the traffic being graded.

**A stale calibration is not an error.** It is recorded with its age, and reading
it is the operator's job. Refusing a run because its judge was measured six months
ago would be this tool inventing a policy it has no standing to set.

## Decision 7 — the manifest is a separate file, and `extension_api` is its own number

**A separate `guardana-pack.yaml` inside the package**, read through
`importlib.resources`, not `[tool.guardana]` in `pyproject.toml`. Two reasons, and
the first is decisive: `pack validate` must work against an **installed
distribution**, and `pyproject.toml` is not in a wheel. A manifest a user cannot
read from what they installed cannot be checked at load time, which is the only
moment that matters. Second, principle 11 wants a `schema_version`, and that field
sitting beside PEP 621's own metadata version reads as a mistake every time.

**`extension_api` is an integer, versioned separately from the product.** In 0.x
the product's minor breaks API by design, so a pack declaring
`guardana>=0.17,<0.18` would need re-releasing on every minor even when nothing it
touches moved. `extension_api` moves only when `Rule`, `Evaluator`, `Target` or
`Finding` actually change shape — which is what a pack can usefully bind to, and
what makes "too old" and "too new" two answerable questions:

```yaml
schema_version: 1
name: acme-guardana-rules
extension_api: ">=1,<2"
provides:
  rules: [acme.agent.customer_data, acme.prompt.tone]
  evaluators: [acme.strict_refusal]
```

**Both directions refuse, with different messages and one outcome.** A pack built
for an older API may rely on behaviour since removed; one built for a newer API may
call something absent. Loading either and hoping is how a scanner starts producing
verdicts nobody can account for — and a "close enough" acceptance is worse than no
declaration, because the author stops checking.

**`provides:` is checked against what actually registers.** A manifest listing a
rule the entry point does not yield is a pack whose documentation and behaviour
disagree, and the direction that matters is the missing one: a pack that promises
`acme.agent.customer_data` and does not register it leaves a team believing a check
runs that never does.

**Migration follows `contract/load.py` exactly**, because that decision was made
three months ago and does not need remaking: `schema_version` required, an unknown
version refuses rather than reading optimistically, older versions migrate forward
in memory at load, unknown keys raise. **No `pack migrate` command** — a saved run
is generated and Guardana may rewrite it; a manifest is hand-written and belongs to
its author.

## Deferred, with the reason

| Deferred | Reason |
|---|---|
| **The lock file** | the only one of the four roadmap items that is *not* a 1.0 entry criterion, and the only one sharing no schema with the others — so it is genuinely separable where they are not. It also wants a decision the manifest has to land first: a lock pinning distribution versions is not a lock for this project, because `Rule.digest()` exists so that "the same rule" means more than "the same package version", and what a rule's digest should cover is a question the manifest's `provides:` block is about to inform |
| **Fixtures for artifact rules in YAML** | a YAML rule is `endpoint`-kind by construction, so its double is always a scripted model. An artifact fixture needs bytes, and bytes in YAML is either a path to a checked-in malicious file or base64 nobody can review — the plugin path takes it, using the builders `guardana.core.testing` already ships |
| **Signing the manifest** | signing authenticates a publisher; without a trust policy and a distribution story it says nothing about whether the code is safe. Already on the roadmap's not-required-for-1.0 list, and the manifest does not change that |
| **A `Technique` extension point** | still owed before the freeze, and still its own design. Named here only so its absence is deliberate rather than forgotten |
| **Refusing a run whose evaluator calibration is stale** | recording the age is evidence; deciding that six months is too old is a policy this tool has no standing to set for somebody else's judge model |
