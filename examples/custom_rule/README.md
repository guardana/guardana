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

## What it ships

| File | What it demonstrates |
|---|---|
| `src/acme_rules/hardcoded_secret.py` | A **Python plugin rule** (`acme.supply_chain.hardcoded_key`) — logic YAML can't express. |
| `src/acme_rules/approved_model.py` | A rule that **inspects a model file** (`acme.supply_chain.approved_model`) — and is entirely policy, because the GGUF parsing comes from the public [`guardana.core.formats`](../../docs/model-formats.md) readers. Its fixtures are built with `guardana.core.testing.build_gguf`, so no binary is checked in. |
| `src/acme_rules/catalog/customer_data.yaml` | A YAML rule for an invariant **no public framework knows about** (`acme.agent.customer_data`) — this assistant serves one customer at a time. |
| `src/acme_rules/catalog/overreach.yaml` | A **declarative YAML rule** (`acme.prompt.overreach`) graded with Guardana's built-in `keyword` evaluator. |
| `src/acme_rules/catalog/refusal.yaml` | A YAML rule (`acme.prompt.data_exfiltration`) graded with Acme's **own** evaluator — referenced by id, resolved from the registry at run time — and mapped to Acme's **own** control `ACME-14` beside its OWASP entries. |
| `src/acme_rules/refusal_classifier.py` | A **custom `Evaluator`** (`acme.strict_refusal`) — bring-your-own "did the attack succeed, and how sure are we" grader. |
| `src/acme_rules/prompt_library_target.py` | A **custom `Target`** (`guardana.targets`) — Acme's own prompt library as a thing rules can be pointed at. |
| `src/acme_rules/controls.py` | A **custom framework** (`guardana.taxonomies`) — Acme's control catalogue, which is what makes `taxonomy: [ACME-14]` resolve instead of failing to load. |
| `src/acme_rules/guardana-pack.yaml` | The **pack manifest**, hand-written and checked by `guardana pack validate` against what the entry points really register. |
| `pyproject.toml` | The **entry-point contract** that makes all of the above discoverable. |
| `tests/` | The **fixture law** in practice — positive *and* negative fixtures, no network (uses `guardana.core.testing` doubles). CI runs these. |

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
Run its tests directly:

```bash
uv run pytest examples/custom_rule/tests
```

## Use it as a template

Copy this directory, rename `acme_rules` → `yourorg_rules`, change the `acme.*`
ids and the `name` in `pyproject.toml`, and you have a private rule pack you can
keep internal or publish. The contract is identical either way. Full walkthrough:
[`docs/writing-rules.md`](../../docs/writing-rules.md) and
[`docs/extending.md`](../../docs/extending.md).
