# `acme-guardana-rules` — a third-party Guardana extension

A **complete, runnable** example of the "extend Guardana in your own repo"
story: a separate pip-installable distribution, owned by a fictional company
*Acme*, that adds security checks under its own `acme.*` namespace **without
forking or patching Guardana**. Everything here is discovered through the same
public entry points (`guardana.rules`, `guardana.evaluators`) the built-ins use
— there is no built-in-vs-custom distinction at the registry level.

## What it ships

| File | What it demonstrates |
|---|---|
| `src/acme_rules/hardcoded_secret.py` | A **Python plugin rule** (`acme.artifact.hardcoded_key`) — logic YAML can't express. |
| `src/acme_rules/catalog/overreach.yaml` | A **declarative YAML rule** graded with Guardana's built-in `keyword` evaluator. |
| `src/acme_rules/catalog/refusal.yaml` | A YAML rule graded with Acme's **own** evaluator — referenced by id, resolved from the registry at run time. |
| `src/acme_rules/refusal_classifier.py` | A **custom `Evaluator`** (`acme.strict_refusal`) — bring-your-own "did the attack succeed, and how sure are we" grader. |
| `pyproject.toml` | The **entry-point contract** that makes all of the above discoverable. |
| `tests/` | The **fixture law** in practice — positive *and* negative fixtures, no network (uses `guardana.core.testing` doubles). CI runs these. |

## Try it

From the repo root, install the example alongside Guardana and list the rules —
Acme's `acme.*` rules appear right next to the built-ins:

```bash
uv pip install -e examples/custom_rule
uv run guardana rules | grep acme
```

You should see `acme.artifact.hardcoded_key`, `acme.prompt.overreach`, and
`acme.prompt.refusal` in the listing. Run its tests directly:

```bash
uv run pytest examples/custom_rule/tests
```

## Use it as a template

Copy this directory, rename `acme_rules` → `yourorg_rules`, change the `acme.*`
ids and the `name` in `pyproject.toml`, and you have a private rule pack you can
keep internal or publish. The contract is identical either way. Full walkthrough:
[`docs/writing-rules.md`](../../docs/writing-rules.md) and
[`docs/extending.md`](../../docs/extending.md).
