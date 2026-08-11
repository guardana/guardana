# `guardana pack validate` — can this build load your pack, and does it do what it says

1.0 promises that `Rule`, `Evaluator` and `Target` will not break under you. A
promise is only worth something if you can check whether *this* build keeps it for
*your* package — so a pack declares what it needs and what it provides, and this
command answers both questions.

```bash
guardana pack validate
```

```
extension API implemented by this build: 1

✓ acme-guardana-rules (extension_api >=1,<2) — 6 declared

1 pack(s) checked, 0 with problems.
```

## The manifest

`guardana-pack.yaml`, **inside your package directory** — not at your repository
root:

```yaml
schema_version: 1
name: acme-guardana-rules
extension_api: ">=1,<2"

description: >
  Acme's private security rules.

provides:
  rules:
    - acme.agent.customer_data
    - acme.prompt.overreach
  evaluators:
    - acme.strict_refusal
```

It goes inside the package because `pack validate` runs against an **installed
distribution**, and `pyproject.toml` is not in a wheel. A manifest a user cannot
read from what they installed cannot be checked at the only moment that matters —
which is also why the declaration is not `[tool.guardana]` in `pyproject.toml`.

## `extension_api` is not the product version

This is the field worth understanding before you pin anything.

Guardana's own version breaks API on every minor while it is pre-1.0, by design. A
pack pinned to `guardana>=0.17,<0.18` would need re-releasing on every minor even
when nothing it touches has moved. **`extension_api` moves only when `Rule`,
`Evaluator`, `Target` or `Finding` actually change shape**, so it is the thing a
pack can usefully bind to.

Both ends are required. An open range claims compatibility with an API nobody has
written yet.

**Both directions refuse, with different messages and one outcome:**

| Situation | What you are told |
|---|---|
| the pack needs a *newer* API than this build has | upgrade Guardana |
| the pack needs an *older* API than this build has | upgrade the pack — it may rely on behaviour that has changed |

A "close enough" acceptance would be worse than no declaration at all, because it is
the point at which an author stops checking.

## `provides:` is checked against what you register

Every id you list is compared against what your entry points actually register. The
direction that matters is the **missing** one: a pack promising
`acme.agent.customer_data` and not registering it leaves a team believing a check
runs that never does — a false green arriving through documentation instead of
through code.

Registering *more* than you list is not an error. That is untidy, not a lie, and
failing a build over it would make this something teams switch off.

## Exit codes

| Situation | Verdict | Exit |
|---|---|---|
| every pack is loadable and accurate | pass | `0` |
| a pack is unloadable, or promises what it does not register | fail | `1` |
| nothing declared a manifest | **indeterminate** | `2` |
| the manifest named on the command line could not be read | refused | `3` |

Exit `2` over an empty run is deliberate: validating nothing is not the same as
nothing being wrong.

## Versioning

`schema_version` is required, and a version this build has never heard of is refused
rather than read optimistically. Older versions migrate forward in memory at load.
Unknown keys raise.

**There is no `pack migrate` command, deliberately.** A saved run is generated and
Guardana may rewrite it; a manifest is hand-written and belongs to you.

## Guardana's own pack has one

`guardana-rules` ships a manifest and goes through this same door. Its `provides:`
block is *generated* from the registry — 56 ids is too many to hand-maintain, and a
hand-maintained list of that length is how every stale count in this repository
began. Yours is short, so you write it.

A validator this project exempted itself from would be a bar we ask other people to
clear alone, and the first drift it would stop catching is our own.

## A complete example

[`examples/custom_rule/`](../examples/custom_rule/) is a real third-party package —
a plugin rule, YAML rules, a custom evaluator and this manifest — and CI runs its
tests in an isolated environment on every push.

Reasoning: [`design/extension-author-tooling.md`](design/extension-author-tooling.md).
