# `acme-guardana-rules` — a third-party Guardana extension

A **complete, runnable** example of the "extend Guardana in your own repo"
story: a separate pip-installable distribution, owned by a fictional company
*Acme*, that adds security checks under its own `acme.*` namespace **without
forking or patching Guardana**. Everything here is discovered through the same
public entry points the built-ins use — there is no built-in-vs-custom
distinction at the registry level.

**All four entry-point groups are registered here, and that is deliberate.** A
documented group nothing registers is a seam nobody has run: `guardana.targets`
sat in the contract from 0.1 with no example behind it, so `pack validate`
shipped in 0.18.0 accusing every pack that had a target of not registering one,
and there was nothing installed anywhere that could notice. `guardana.taxonomies`
was in the same state until 0.19.0.

`AcmePromptLibraryTarget` implements the surface it declares, and the tests prove
it: `tests/test_prompt_library_target.py` runs `guardana.testing.assert_target_conforms`
against it, then drives a real `Runner` over it and checks that the built-in
artifact rules — not just Acme's own — actually ran. A target that only declared
`READ_FILES` without a `FileReader` behind it used to pass every test in this
package, because none of them ran the `Runner`; this is the one that would have
caught it.

## What it ships

| File | What it demonstrates |
|---|---|
| `src/acme_rules/hardcoded_secret.py` | A **Python plugin rule** (`acme.supply_chain.hardcoded_key`) — logic YAML can't express. Its `fixtures()` samples a live key, a vault reference, and a config path nobody can read (a dangling symlink), so all three outcomes — finding, clean, inconclusive — are proven. |
| `src/acme_rules/approved_model.py` | A rule that **inspects a model file** (`acme.supply_chain.approved_model`) — and is entirely policy, because the GGUF parsing comes from the public [`guardana.core.formats`](../../docs/model-formats.md) readers. Its `fixtures()` method builds three samples with `guardana.core.testing.build_gguf` — an unapproved organization, an approved one, and bytes that are not a GGUF file at all — so no binary is checked in and the inconclusive case is proven, not assumed. |
| `src/acme_rules/catalog/customer_data.yaml` | A YAML rule for an invariant **no public framework knows about** (`acme.agent.customer_data`) — this assistant serves one customer at a time. Its `fixtures:` block samples a leak, a clean refusal, and an empty reply. |
| `src/acme_rules/catalog/overreach.yaml` | A **declarative YAML rule** (`acme.prompt.overreach`) graded with Guardana's built-in `keyword` evaluator. Its `fixtures:` block samples a claimed order, a deferred one, and an empty reply. |
| `src/acme_rules/catalog/refusal.yaml` | A YAML rule (`acme.prompt.data_exfiltration`) graded with Acme's **own** evaluator — referenced by id, resolved from the registry at run time — and mapped to Acme's **own** control `ACME-14` beside its OWASP entries. Its `fixtures:` block samples a hedged refusal, a clean one, and an empty reply. |
| `src/acme_rules/refusal_classifier.py` | A **custom `Evaluator`** (`acme.strict_refusal`) — bring-your-own "did the attack succeed, and how sure are we" grader. |
| `src/acme_rules/prompt_library_target.py` | A **custom `Target`** (`guardana.targets`) — Acme's own prompt library as a thing rules can be pointed at. |
| `src/acme_rules/controls.py` | A **custom framework** (`guardana.taxonomies`) — Acme's control catalogue, which is what makes `taxonomy: [ACME-14]` resolve instead of failing to load. |
| `src/acme_rules/guardana-pack.yaml` | The **pack manifest**, hand-written and checked by `guardana pack validate` against what the entry points really register. |
| `pyproject.toml` | The **entry-point contract** that makes all of the above discoverable. |
| `tests/` | Ordinary unit and integration tests — discovery, the pack manifest, the target's own conformance — plus `test_every_rule_is_sampled.py`, which asserts that `guardana rule test 'acme.*'` itself passes. CI runs these. |

**The fixture law lives in the rules themselves, not in `tests/`.** Every rule above
declares its own samples — `fixtures:` in a YAML rule, `fixtures()` on a plugin
class — and `guardana rule test 'acme.*'` runs them without a network call, which
is what makes the law checkable for a rule this repository never saw: a third
party's fixtures live in *their* pack. Positive and negative are not enough on
their own; every rule here also proves it can decline (`outcome: inconclusive`)
— an empty reply, a config file nobody can read, five bytes that are not a GGUF
file — because a rule that cannot say "I could not tell" is a rule that will
eventually report clean about something it never examined.

## Try it

From the repo root, install the example alongside Guardana and list the rules —
Acme's `acme.*` rules appear right next to the built-ins:

```bash
uv pip install -e examples/custom_rule
uv run guardana rules | grep acme
```

You should see `acme.supply_chain.hardcoded_key`, `acme.supply_chain.approved_model`,
`acme.agent.customer_data`, `acme.prompt.overreach` and `acme.prompt.data_exfiltration`
in the listing, and `ACME-14` beside the built-in frameworks in `guardana taxonomy`.

Run every rule's own fixtures — the fixture law, as a command, sending nothing
anywhere:

```bash
uv run guardana rule test 'acme.*'
```

```
5 rule(s); 15 fixture(s) passed, 0 failed, 0 could not run. 0 rule(s) not fully sampled.
```

Or run its `pytest` suite directly:

```bash
uv run pytest examples/custom_rule/tests
```

## Use it as a template

Copy this directory, rename `acme_rules` → `yourorg_rules`, change the `acme.*`
ids and the `name` in `pyproject.toml`, and you have a private rule pack you can
keep internal or publish. The contract is identical either way. Full walkthrough:
[`docs/writing-rules.md`](../../docs/writing-rules.md) and
[`docs/extending.md`](../../docs/extending.md).
