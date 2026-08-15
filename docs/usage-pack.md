---
title: "guardana pack"
nav_order: 240
summary: "`guardana pack validate` and `guardana pack lock`: the manifest declaring which extension API your pack needs, and the pin that keeps CI running the same checks"
status: stable
---

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
schema_version: 2
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
  targets:
    - AcmeWarehouseTarget
  taxonomies:
    - ACME-CONTROLS
```

`provides:` names all four extension groups. `taxonomies:` lists **framework
names**, not individual controls — a pack registers a catalogue, and a team shipping
two hundred controls would otherwise maintain two hundred lines that say one thing.

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

**Schema 2 added `provides.taxonomies`.** A schema 1 manifest still loads — it
simply declares no catalogues, which is what it meant, since the group did not exist
for it to name. `pack validate` says so where it happened:

```
✓ acme-guardana-rules (extension_api >=1,<2) — 7 declared · read as schema 1, migrated to 2 in memory
```

A schema 1 manifest that *does* name `taxonomies:` is refused. A key invented after
the version that names it is a manifest whose own `schema_version` no longer
describes it, and an older build reading the same file would drop the key silently.

**There is no `pack migrate` command, deliberately.** A saved run is generated and
Guardana may rewrite it; a manifest is hand-written and belongs to you.

## `guardana pack lock` — pin what a check *is*

A version pin is not a pin for this project. A pack can sharpen a corpus, widen a
prompt set or swap an evaluator inside one patch release; every one of those changes
what a run tests while the version string says nothing moved, and the next
comparison would blame the model for it.

```bash
guardana pack lock                # write ./guardana-lock.yaml
guardana pack lock --check        # in CI: fail if the build has drifted
```

```yaml
schema_version: 1
extension_api: 1
packs:
  - name: acme-guardana-rules
    distribution: acme-guardana-rules
    version: 0.3.1
    rules:
      acme.agent.customer_data: 7ac9df6f3a247391
    evaluators: [acme.strict_refusal]
    targets: [AcmeWarehouseTarget]
    taxonomies:
      ACME-CONTROLS: "sha256:1c4f…"
unlocked: []
```

**Three things are pinned three different ways, and the file says which is which:**

| What | Pinned by | Why not more |
|---|---|---|
| rules | `Rule.digest()` — the declaration, hashed | a sharpened corpus is visible; the Python behind it is not |
| evaluators, targets | id only | an `Evaluator` is Python and has no declaration to hash; inventing a digest from a class name would claim to detect a change it cannot see |
| catalogues | a digest over the references the pack registers | a third-party catalogue has no *file* to pin, but what it registered is content |
| everything else | the distribution version beside it | the coarse pin, and the only one that covers an implementation whose declaration did not move |

`unlocked:` lists extensions registered by a package that declares **no manifest**.
They are recorded and not attributed to a pack, and the command says so on stderr —
a lock that stayed silent about them would read as a fully pinned repository that
is not one.

### What counts as drift

Both directions, always. A rule that vanished is coverage a team still believes they
have; one that appeared is a check nobody reviewed running against production.

| Kind | Meaning |
|---|---|
| `pack_missing` | locked and not installed |
| `pack_unlocked` | installed and the lock does not mention it |
| `version_changed` | same digests, different package version |
| `removed` / `added` | an id left or arrived |
| `changed` | a digest moved — it is not the same check any more |

| Situation | Verdict | Exit |
|---|---|---|
| the build matches the lock | pass | `0` |
| the build has drifted | fail | `1` |
| nothing installed declares a manifest, so there is nothing to pin | **indeterminate** | `2` |
| the lock could not be read, or was taken against another `extension_api` | refused | `3` |

**A lock from a different extension contract is refused rather than compared.**
`extension_api` is what says which `Rule` shape the digests beside it were computed
from, and `Rule.digest()` covers the fields of `RuleMeta` — so a contract that moved
is exactly what makes two digests incomparable even when they are equal. Reported as
drift it would flag every rule as `changed` with a detail naming the wrong cause; the
answer to all of them is one line, so the command says that line. Regenerate the
lock.

`--check` never writes. A check that created the file it was asked to compare
against would pass on every first run, which is the one run nobody looks at.

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
