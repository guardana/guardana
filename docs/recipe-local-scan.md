---
title: "Recipe: scan your own project"
nav_order: 13
summary: "a local scan of your own models and code, offline, ending with a saved run you can compare later"
status: stable
---

# Recipe: scan your own project

Scan the files you ship: model weights, notebooks, training and loading code, and configs. The scan runs offline and needs no model.

```bash
guardana plan scan path/to/project
guardana scan path/to/project --format json --output accepted-run.json   # review it, then keep it
# after a change:
guardana scan path/to/project --format json --output run.json
guardana diff accepted-run.json run.json
```

1. `plan scan` lists the rules that would run and those that would be skipped. It exits `3` if the run could not pass with the current configuration.
2. `scan` reads files without loading them. It exits `0` for a pass, `1` for a finding at or above the policy's severity, or `2` when a check could not run at all, such as a refused plugin. A Python file it cannot open, one over the size limit, or one the scanning interpreter cannot decode or parse is an error and a "not scanned" result, which makes the run indeterminate (`2`) under the default gate; exclude such a file with `.guardanaignore` or `rules.paths_exclude` ([details](usage-scan.md#python-files-the-scan-cannot-read)). A model file it cannot read is listed as UNVERIFIED and also counts as an `unexamined_component` shortfall, so the run is indeterminate (`2`) under every preset unless a finding fails it ([details](usage-scan.md#model-files-no-rule-reads)). The saved run records the plugin trust in force (`run.configuration.plugins`).
3. The first run you have reviewed is the accepted one: keep `accepted-run.json` in the repository or your CI's artifact store, and replace it only when you deliberately accept a change. `diff` compares a later run against it and says whether the result is worse, better, unchanged, or cannot be compared.

This does not check how a model responds to a question. Use [`probe`](recipe-real-application.md) for that. The scan does not load or execute the files it reads. A file in a format it reads but cannot parse is listed as UNVERIFIED, never as clean. A file in a format no rule reads is not examined: any format it does not recognise, and TFLite, which it lists but does not read. Check the formats you ship against [model formats](model-formats.md).

To admit an installed pack, name it with `--plugins allowlist --allow-plugin
<distribution>` ([plugin trust](profiles.md#plugin-trust-plugins)).
