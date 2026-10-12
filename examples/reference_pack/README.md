# `guardana-reference-pack`

A Guardana extension pack that uses all six extension points and imports nothing outside
the [supported surface](../../docs/compatibility.md). It has its own version (`0.1.2`),
depends on `guardana-core>=0.41` with no upper bound, and declares the `extension_api` and
`output_api` ranges it runs on in its manifest. `guardana pack validate` checks those ranges;
installing the pack or running a scan does not. A CI job that depends on the pack therefore
runs `guardana pack validate` and `guardana pack lock --check`. Install it from this directory
or from the wheel and sdist attached to each GitHub Release. The release workflow's PyPI step
for the pack is off unless a maintainer has registered the pack's trusted publisher on PyPI
and switched the step on in the repository settings.

`custom_rule` and `output_pack` teach one idea each. This pack is an example a third party
can copy: everything in it is checked by the commands and the conformance kit Guardana
ships, from an isolated install.

## What it ships

| Extension point | What | File |
|---|---|---|
| `guardana.rules` | `reference.prompt.codename_disclosure`, a YAML rule graded by the pack's own evaluator | `src/guardana_reference_pack/rules/codename_disclosure.yaml` |
| `guardana.rules` | `reference.supply_chain.unpinned_requirement`, a Python rule over pip requirement files | `src/guardana_reference_pack/unpinned.py` |
| `guardana.evaluators` | `reference.marker`: a reply fails when it repeats a configured marker | `src/guardana_reference_pack/evaluator.py` |
| `guardana.targets` | `reference-requirements://<dir>`: the requirement files under a directory | `src/guardana_reference_pack/target.py` |
| `guardana.taxonomies` | `REFERENCE-CONTROLS`, the pack's own control catalogue (`REF-1`, `REF-2`) | `src/guardana_reference_pack/controls.py` |
| `guardana.renderers` | `--format reference-summary`: the run as Markdown | `src/guardana_reference_pack/summary.py` |
| `guardana.reporters` | `--reporter reference-file://<dir>`: that Markdown, written to `<dir>/guardana-<run id>.md` | `src/guardana_reference_pack/file_reporter.py` |

Both rules declare a finding, a clean and an inconclusive sample, so
`guardana rule test 'reference.*'` proves each one fires, stays silent and declines. The
manifest, `src/guardana_reference_pack/guardana-pack.yaml`, is schema 3, and
`guardana-lock.yaml` pins what the pack registers.

The reporter's `prepare` only checks the locator. `deliver` writes through a temporary
file, `fsync`s it and moves it into place, then reports `delivered`; a directory that does
not exist is `unreachable`, and an `OSError` while writing is `rejected`. The file is
readable by its owner only.

## Try it

From the repository root:

```bash
uv pip install ./examples/reference_pack
ADMIT="--plugins allowlist --allow-plugin guardana-reference-pack"
uv run guardana rule test 'reference.*' $ADMIT
uv run guardana pack validate $ADMIT
mkdir -p summaries
uv run guardana scan --target reference-requirements://. $ADMIT \
  --format reference-summary --reporter reference-file://summaries
```

## Its own suite

`tests/` runs from an isolated install, the way CI and `scripts/ci_local.sh` run it:

```bash
uv run --isolated --no-cache \
  --with ./packages/guardana-core --with ./packages/guardana-rules \
  --with ./packages/guardana-cli --with ./packages/guardana-report \
  --with ./examples/reference_pack --with pytest pytest examples/reference_pack/tests
```

`tests/test_reference_surface.py` walks every import in `src/` and `tests/` and refuses a
`guardana.*` name outside the supported surface, computed from the installed build:
`__all__` of `guardana.core` (less `Runner`), `guardana.core.verify`,
`guardana.core.doubles`, `guardana.core.target.protocols`, `guardana.core.output`,
`guardana.testing` and `guardana.core.testing`, plus `guardana.core.target.WireProtocol`
and the public names of `guardana.core.rule.fixture`.

`guardana-lock.yaml` holds the pack's own entry only: the built-in pack's entry moves with
every Guardana release, so the lock test takes it from the installed build and runs
`pack lock --check` over both. After changing a rule, regenerate the lock from an isolated
install:

```bash
uv run --isolated --no-cache \
  --with ./packages/guardana-core --with ./packages/guardana-rules \
  --with ./packages/guardana-cli --with ./packages/guardana-report \
  --with ./examples/reference_pack \
  guardana pack lock examples/reference_pack/guardana-lock.yaml \
  --plugins allowlist --allow-plugin guardana-reference-pack
```

Then delete every entry but `guardana-reference-pack` under `packs:`.
