---
title: "guardana new-pack"
nav_order: 235
summary: "one command writes an installable pack — manifest, entry points, three sampled rules, a target and tests — that passes `pack validate` and `rule test` before you edit anything"
status: stable
---

# `guardana new-pack` — start from something that already passes

`guardana new-pack` creates an extension pack when you need a starting point for rules. `guardana init` writes a policy file or, with `--starter`, a first-run project; `guardana new-rule` writes a rule.

```bash
guardana new-pack acme-rules
```

```
Wrote 13 files to acme-rules/
Install and verify it:
  pip install -e acme-rules
  guardana pack validate acme-rules/src/acme_rules/guardana-pack.yaml --plugins allowlist --allow-plugin acme-rules
  guardana rule test 'acme.*' --plugins allowlist --allow-plugin acme-rules
  pytest acme-rules/tests
```

Every command starts with Guardana's own distributions only, so the two `guardana`
lines admit the new pack by its distribution name.

Those four lines are the point. Run them on the generated pack, before changing a
character:

```
extension APIs implemented by this build: 1, 2 (newest 2)

✓ acme-rules (extension_api >=2,<3) — 4 declared
1 pack(s) checked, 0 with problems.

3 rule(s); 9 fixture(s) passed, 0 failed, 0 could not run. 0 rule(s) not fully sampled.

12 passed
```

A scaffold whose first verification is red teaches you to distrust the tool at the
moment you have the least context to judge it. This one is green, so the first red
you ever see is about your own change.

## What it writes

| path | what it is |
|---|---|
| `pyproject.toml` | the four entry-point groups Guardana discovers, and `guardana-core` as the only dependency, pinned from the version that wrote the pack up to, but excluding, the next major because everything the generated pack imports is in the supported surface |
| `src/acme_rules/guardana-pack.yaml` | the manifest: what the pack promises, checked against what it registers |
| `src/acme_rules/catalog/` | one YAML file per rule, each with its finding, clean and inconclusive samples |
| `src/acme_rules/target.py` | a target, reachable as `--target acme-rules://some/directory` |
| `src/acme_rules/__init__.py` | `provide_rules`, `provide_evaluators`, `provide_targets`, `provide_taxonomies`; package code imports only supported names |
| `tests/` | the manifest is true, every rule proves all three outcomes, the target conforms; the pack's own taxonomies are registered before loading its rules, as discovery does |

No licence file is written. Picking one for you is not this command's decision —
add a `LICENSE` and set `license` in `pyproject.toml`.

## The three rule shapes

One rule per shape, because they differ in how a sample is scripted and an author
who starts from one will write the others by guessing:

| shape | the rule declares | a sample scripts |
|---|---|---|
| `prompt` | `prompts:` | `reply:` — one answer |
| `scenario` | `steps:` | `replies:` — one answer per step |
| `agent` | `task:` and `tools:` | `turns:` — `say`, `call` with `arguments`, or both |

`--shape` narrows the set, and narrows the manifest with it:

```bash
guardana new-pack acme-rules --shape prompt --shape agent
```

Every generated rule plants a marker and grades whether it comes back. That is
deliberate: a rule whose "finding" sample is merely a reply without a refusal
marker passes whatever the model did, and a scaffold built to be green would
otherwise teach you that this is what a sample looks like.

## What it refuses, and why

Each of these exits `3` and writes nothing, because a scaffold that emits a pack
the registry will reject has moved the error somewhere harder to read:

| name | refused because |
|---|---|
| `guardana-anything` | rule ids would start with `guardana.`, which the registry reserves |
| `trace`, `file`, `http`, `https`, `mcp` | the target scheme is reserved, so the pack would not load at all |
| `My-Pack`, `pack.name` | not a distribution name — lowercase letters, digits and hyphens |
| `2fast` | the module name would not be importable |
| a name already installed here | two origins claiming one id is a registry error |

`--dir` writes somewhere other than `./<name>`, and a directory that already holds
files is refused rather than written over; there is no `--force`. `.git`,
`.gitignore`, `.DS_Store`, `.idea` and `.vscode` do not count as occupied, so
`git init` first and then scaffolding into `.` works.

## Editing what it wrote

- **Rules.** Change the prompts and the samples together, and keep the marker
  shape: it is what makes a positive sample evidence rather than an opinion.
- **The manifest.** Add every new id to `provides`. `guardana pack validate` fails
  when the manifest declares an id nothing registers, or a rule another installed
  distribution registers; an id registered and not declared is not an error, and
  `pack lock` lists it as unlocked — see
  [`guardana pack`](usage-pack.md).
- **The API range.** `extension_api` pins the extension API, not Guardana's release
  number. Widen it after reading what changed, never before.
- **Your evaluator and your control set.** `provide_evaluators` and
  `provide_taxonomies` return nothing on purpose. Fill them in and declare them.

[Writing rules](writing-rules.md) has the full rule schema, and
[extending Guardana](extending.md) the contract behind the four entry points.
