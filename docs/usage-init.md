---
title: "guardana init"
nav_order: 12
summary: "`guardana init` writes a policy file; `guardana init --starter DIR` writes a whole first-run project that fails, is fixed and keeps its evidence, offline"
status: stable
---

# `guardana init` — a policy file, or a first run

```bash
guardana init                      # write ./guardana.yaml
guardana init my-profile.yaml      # write it somewhere else
guardana init --starter first-run  # write a first-run project into ./first-run
```

## `--starter DIR`

Writes a small project and a README into `DIR`. The README guides you through the project. You need no account, API key, model or network. The project runs using only Guardana's own distributions.

| Path | What it is |
|---|---|
| `model/weights.pkl` | a pickle that would call `builtins.print` if loaded; `scan` flags it CRITICAL |
| `safe/weights.safetensors` | the replacement, one tensor in a format that cannot run code |
| `checks/codename.yaml` | a local YAML check, `starter.no_internal_codename`, with finding, clean and inconclusive samples |
| `README.md` | the steps below, each with the exit code to expect |

Run the README's steps inside `DIR`:

If you created the starter with `uvx --from guardana-cli guardana`, `guardana` is not on your
shell's PATH. Prefix each README command with the same launcher, for example
`uvx --from guardana-cli guardana scan model --format json --output before.json`. For a
candidate, use the launcher you installed with: `uvx --prerelease allow --from guardana-cli guardana`.
Alternatively install the CLI in your environment ([install guide](install.md)) and use the
README commands as written. Installing needs network access; the starter's steps run offline
once the CLI is present.

1. `guardana scan model --format json --output before.json` fails (exit `1`) on the pickle.
2. Replace the pickle with the safetensors file.
3. `guardana scan model --format json --output after.json` passes (exit `0`); `after.json` saves the evidence.
4. `guardana diff before.json after.json` lists the finding as having left the scan (exit `1`): a comparison never calls a problem resolved when the second run no longer lists its file, and `after.json` is the evidence of the fix.
5. `guardana doctor` lists what an installed pack would execute. On a clean install, it lists nothing.
6. `guardana rule test --rules checks 'starter.*'` runs the local check's three samples offline (exit `0`).
7. Edit the check as the README shows and run step 6 again. Four samples pass.

The check targets an endpoint, so `scan` does not run it. `scan --rules checks` prints a note explaining this. `rule test` runs the check offline. `guardana probe --url … --rules checks` runs it against an endpoint.

`--starter` refuses a `DIR` that exists and is not empty. It also refuses a path given with it. Both cases exit `3` and write nothing. It never writes `./guardana.yaml`.

If you create a starter inside a repository, a CI job that scans `.` fails until you fix or delete it. The planted pickle is a real finding.

## Next

- [Scan your own project](recipe-local-scan.md)
- [Check a run your application already recorded](recipe-recorded-answers.md)
- [Probe your real application](recipe-real-application.md)
