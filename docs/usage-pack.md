---
title: "guardana pack"
nav_order: 240
summary: "`guardana pack validate` and `guardana pack lock`: the manifest declaring which extension API your pack needs, and the pin that keeps CI running the same checks"
status: stable
---

# `guardana pack validate` — can this build load your pack, and does it do what it says

`guardana pack validate` checks a pack's declarations when you need to verify extension compatibility for `Rule`, `Evaluator`, and `Target`.

```bash
guardana pack validate --plugins allowlist --allow-plugin acme-guardana-rules
```

```
extension APIs implemented by this build: 1, 2 (newest 2)

✓ acme-guardana-rules (extension_api >=2,<3) — 6 declared

1 pack(s) checked, 0 with problems.
```

Both commands start with Guardana's own distributions only, like every other command,
so a pack author admits their own distribution by name, or states it once in a profile
given with `--profile` ([plugin trust](profiles.md#plugin-trust-plugins)). If plugin trust
refused anything, both stop with exit `2` before they read a single manifest: finding a
manifest means importing the package that holds it, and a refused pack is never imported.

## The manifest

`guardana-pack.yaml`, **inside your package directory** — not at your repository
root:

```yaml
schema_version: 2
name: acme-guardana-rules
extension_api: ">=2,<3"

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

`provides:` names all four run groups. A pack that adds an [installed output](outputs.md)
also lists `renderers:` and `reporters:` by name, declares the output API it was written
against as `output_api: ">=1,<2"`, and uses `schema_version: 3`. `taxonomies:` lists **framework
names**, not individual controls — a pack registers a catalogue, and a team shipping
two hundred controls would otherwise maintain two hundred lines that say one thing.

It goes inside the package because `pack validate` runs against an **installed
distribution**, and `pyproject.toml` is not in a wheel. A manifest a user cannot
read from what they installed cannot be checked at the only moment that matters —
which is also why the declaration is not `[tool.guardana]` in `pyproject.toml`.

## `extension_api` is not the product version

This is the field worth understanding before you pin anything.

Before 1.0, a minor release of Guardana may contain a documented breaking change. The
`1.0.0rcN` candidates carry fixes only ([compatibility](compatibility.md#versioning)). A pack
pinned to one minor version of the product needs a new release for every minor version, even
when nothing it uses has changed. **`extension_api` moves only when `Rule`,
`Evaluator`, `Target` or `Finding` actually change shape**, so a pack can bind to it. API 2
adds CLI target locators. Guardana retains API 1 alongside it, so a rule/evaluator pack
declaring `>=1,<2` continues to load. A pack using `Target.scheme` and `from_locator` declares
`>=2,<3`; older builds refuse it because they cannot make its target selectable.

Both ends are required. An open range claims compatibility with an API nobody has
written yet.

**Both directions refuse, with different messages and one outcome:**

| Situation | What you are told |
|---|---|
| the pack needs an API newer than every edition this build implements | upgrade Guardana |
| the pack accepts only API editions this build no longer retains | upgrade the pack — it may rely on behaviour that has changed |

A "close enough" acceptance would be worse than no declaration at all, because it is
the point at which an author stops checking.

## `provides:` is checked against what you register

Every id you list is compared against what your entry points actually register. The
direction that matters is the **missing** one: a pack promising
`acme.agent.customer_data` and not registering it leaves a team believing a check
runs that never does — a false green arriving through documentation instead of
through code.

Each id is looked up under its own group: a rule id that only an evaluator registers is
not a rule your pack provides. For an installed pack, a declared rule, evaluator or
target must also be registered by **your** distribution. One another pack registers
runs today and disappears with that pack, while your manifest still promises it; the
problem names the distribution that does register it. An id registered by no
distribution this build can name (registered in code rather than through an entry
point) is not shown to be yours either, and fails the same way. A framework can have several
owners, because a pack may add controls to a built-in one or to another pack's: a
declared framework passes when your distribution registered at least one reference
into it. The built-in frameworks are owned by the distribution that ships their
catalogues, so declaring one your pack adds nothing to fails. A manifest named on
the command line is not tied to an installed distribution, so it is matched by group
only.

Registering *more* than you list is not an error. That is untidy, not a lie, and
failing a build over it would make this something teams switch off.

## Exit codes

| Situation | Verdict | Exit |
|---|---|---|
| every pack is loadable and accurate | pass | `0` |
| a pack is unloadable, or promises what it does not register | fail | `1` |
| plugin trust refused an installed extension; no manifest was read | **indeterminate** | `2` |
| nothing declared a manifest | **indeterminate** | `2` |
| an installed package registers extensions and declares no manifest | **indeterminate** | `2` |
| the manifest named on the command line could not be read | refused | `3` |

Exit `2` over an empty run is deliberate: validating nothing is not the same as
nothing being wrong.

The second `2` is the same rule applied to a partial run. A package with no
manifest is dropped before validation while its rules, evaluators, targets and
catalogues stay live in the registry — so a verdict counted from the manifests
that *were* found would be a clean bill of health over a subset whose size the
reader cannot see. The command names those packages on stderr instead. Asking
about one manifest by path is a different question and is answered on its own.

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

**Schema 3 adds `provides.renderers`, `provides.reporters` and `output_api`.** Write it only
for a pack that adds an output: schema 2 is still current, and a pack without outputs stays
readable by older builds at 2. `output_api` is required exactly when an output is declared.
A schema 2 manifest naming any of the three is refused, as above.

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

The lock is written whole, through a temporary file and a rename: a write that fails
part-way leaves the earlier lock as it was, and a lock that cannot be written exits `3`.

```yaml
schema_version: 2
extension_api: 2
packs:
  - name: acme-guardana-rules
    distribution: acme-guardana-rules
    version: 0.3.1
    rules:
      acme.agent.customer_data:
        digest: 7ac9df6f3a247391
    evaluators: [acme.strict_refusal]
    targets: [AcmeWarehouseTarget]
    taxonomies:
      ACME-CONTROLS:
        digest: "sha256:1c4f…"
unlocked: []
```

Every digest sits under a `digest:` key of its own. An id can contain `secret`,
`key` or `token`, and an id beside a hex value on one line is what a secret scanner
such as gitleaks reports as a credential. A schema 1 lock, which wrote
`<id>: <digest>`, is still read and checked; `--check` then says to rewrite it with
`guardana pack lock`. A lock with a schema newer than the build is refused with the
advice to upgrade Guardana, never to regenerate the file, which would rewrite a
teammate's lock in the older layout.

**Three things are pinned three different ways, and the file says which is which:**

| What | Pinned by | Why not more |
|---|---|---|
| rules | `Rule.digest()` — the declaration, hashed | a sharpened corpus is visible; the Python behind it is not |
| evaluators, targets | id (a target by class name), and only when the pack's own distribution registers it | an `Evaluator` is Python and has no declaration to hash; inventing a digest from a class name would claim to detect a change it cannot see |
| catalogues | a digest over the references the pack registers | a third-party catalogue has no *file* to pin, but what it registered is content |
| formats, reporters | name, as `renderers:` and `reporters:` in the pack entry, and only when the pack's own distribution registers it | Python, with nothing declared to hash, as for evaluators |
| everything else | the distribution name and version beside it | the coarse pin, and the only one that covers an implementation whose declaration did not move |

A lock is schema 3 only when it pins a format or reporter, or lists one under `unlocked:`
as `renderer:<name>` or `reporter:<name>`; otherwise it stays schema 2, which older builds
read. A schema 2 lock checked against a build with an installed output reports the output as
added and asks for `guardana pack lock`. Both commands also exit `2` when trust refused an
installed output, it failed to load, or two distributions install one output name.

A pack pins only the evaluators, targets and outputs its own distribution registers. An id
another distribution registers is that distribution's code, not the pack's: `pack lock`
refuses to write and names both the pack and the distribution, and `--check` reports the id
`removed`. Two distributions registering a target class of the same name is a load error
naming both, so both commands exit `2` rather than pin either.

`unlocked:` lists installed extensions that **no manifest declares**: extensions from packages
with no manifest, and extensions a package registers but omits from its own manifest.
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
| `distribution_changed` | the same pack name now ships from another distribution, so the code behind its ids is not the code that was pinned |
| `version_changed` | same digests, different package version |
| `removed` / `added` | an id left or arrived |
| `changed` | a digest moved — it is not the same check any more |

| Situation | Verdict | Exit |
|---|---|---|
| the build matches the lock | pass | `0` |
| the build has drifted | fail | `1` |
| plugin trust refused an installed extension; nothing was pinned or compared | **indeterminate** | `2` |
| nothing installed declares a manifest, so there is nothing to pin | **indeterminate** | `2` |
| a pack declares an id nothing registers under that group; no lock is written or compared | **indeterminate** | `2` |
| `pack lock`: a pack declares an evaluator, target or output another distribution registers; no lock is written | **indeterminate** | `2` |
| `--check`: an evaluator, target or output the lock pins is now registered by another distribution | fail (`removed`) | `1` |
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

**A pack that declares what nothing registers is refused, not pinned.** A lock written
without that id would match every later build where the check never runs, so the
command names the missing ids on stderr and writes nothing. Run `pack validate` to see
which promise broke.

## Guardana's own pack has one

`guardana-rules` ships a manifest and goes through this same door. Its `provides:`
block is *generated* from the registry — one id per built-in rule is too many to
hand-maintain, and a hand-maintained list of that length is how every stale count in
this repository began. Yours is short, so you write it.

A validator this project exempted itself from would be a bar we ask other people to
clear alone, and the first drift it would stop catching is our own.

## A complete example

[`examples/custom_rule/`](../examples/custom_rule/) is a real third-party package —
a plugin rule, YAML rules, a custom evaluator and this manifest — and CI runs its
tests in an isolated environment on every push.
