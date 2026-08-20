---
name: add-a-rule
description: Add security coverage to Guardana the way this repository requires — as a rule, evaluator or target, never by patching the engine — with the fixtures, the framework mapping and the documentation that make it shippable. Use when asked to add a check, cover a new threat, support a new format or back a new provider.
---

# Adding coverage

The engine knows almost nothing about specific threats. It knows how to discover
rules, run them against targets, and evaluate outcomes. **All domain knowledge
lives in rules, evaluators and targets — never in the engine.** A change that
teaches `guardana-core` about a threat, a vendor, a file format or a regulation
is the wrong change, however small.

## Pick the path

**YAML** is the default, for anything expressible as "send this prompt, grade it
with this evaluator". No code. Drop it in `packages/guardana-rules/src/guardana/
rules/catalog/`; `uv run guardana new-rule acme.prompt.my_check` scaffolds one.
`steps:` instead of `prompts:` makes it a multi-turn `ScenarioRule`.

**A Python plugin** is for logic YAML cannot express — a parser, a stateful
probe, an artifact format. Same `Rule` contract, registered through the
`guardana.rules` entry point.

**An evaluator** when the *judgement* is what is new, not the stimulus. One short
file, registered through `guardana.evaluators`. A rule names it by string, so
swapping graders never touches a rule.

**A target** when the *thing under test* is new. Declare `capabilities()` **and**
implement the matching protocol from `guardana.core.target.protocols` — both
halves, then prove it with `guardana.testing.assert_target_conforms`.

## Non-negotiables

**A framework mapping, or it does not ship.** Every rule maps to OWASP LLM /
OWASP ASI / MITRE ATLAS / NIST. The mapping is what makes a finding answerable in
somebody else's audit. Use the full reference form (`LLM07:2025`), never a bare
id.

**A positive fixture and a negative one.** The positive proves the rule fires;
the negative proves it stays quiet. Dynamic rules get both in three lines with
`guardana.core.testing`'s scripted transports and no network. A rule with only a
positive fixture is a rule nobody has shown to be quiet, and `guardana rule test`
reports it as `indeterminate` rather than green — truthfully.

**Never a confident all-clear on something unexamined.** If the rule cannot run —
no canary was planted, a judge's reply is unparseable, the model returned no text
— the verdict is `inconclusive` or a finding. In this codebase, silence is never
spelled `pass`. No linter can catch this; only an adversarial reader can.

**Cost grows with the target, not with the rule count.** A new rule must not add
a tree walk, a re-read or a re-parse of something already read this run. Ask
through `target.python_source(path)` and `target.iter_files(suffixes)`; both
cache.

**Declare impact and cost.** `impact`, `destructive` and `estimated_requests` are
how a policy selects and a budget bounds. `estimated_requests` is an upper bound:
spending less is fine, spending more is a defect, and a gate measures every
shipped rule against its own declaration.

**Namespace it.** `guardana.*` is reserved for built-ins and is now *enforced* —
an installed distribution registering one is refused at load time.

**Record what you measured, if you graded something.** A rule that sends a prompt
and judges a reply calls `ctx.record(from_verdict(...))` for every case, passes
included. Without the passes there is no denominator. A rule that only reads a
file records nothing — "I looked and found nothing" is not a measurement.

## Then the documentation, in the same commit

`CHANGELOG.md` (why, not only what), `FEATURES.md` if the capability surface
moved, the relevant `docs/` page, and `uv run python scripts/generate_docs.py` —
never edit `docs/generated/` by hand. The landing page states a rule count; a
test pins it to the registry, so it will tell you.

## Verify it the way the project verifies things

Run the gate (`full-gate` skill), and then **run the documented command against a
real target and read what it wrote**. A fake OpenAI-compatible endpoint is three
lines of `http.server`. More real defects in this repository have been found that
way than by any test.
