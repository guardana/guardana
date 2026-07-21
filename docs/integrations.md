# Integrations — CI and pre-commit

Guardana ships two ready-made ways to gate on AI/LLM supply-chain risk without
wiring anything by hand.

## GitHub Action

The official composite action runs a scan and uploads the results to GitHub code
scanning, so findings show up as annotated alerts on the exact source line.

```yaml
# .github/workflows/ai-security.yml
name: AI security
on: [push, pull_request]

jobs:
  guardana:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: guardana/guardana@v0.1.2
        with:
          path: .
          # args: --preset ci --baseline guardana-baseline.yaml
```

Inputs (all optional):

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory or single file to scan |
| `args` | *(none)* | Extra `guardana scan` args (e.g. `--preset ci`, `--baseline guardana-baseline.yaml`) |
| `version` | *(latest)* | Pin a `guardana-cli` version |
| `sarif-file` | `guardana.sarif` | Where the SARIF is written |
| `upload-sarif` | `true` | Upload to GitHub code scanning |
| `fail-on-findings` | `true` | Fail the job when the gate trips |

The SARIF is uploaded even when the gate fails, so alerts always land; set
`fail-on-findings: false` to run it purely advisory.

## pre-commit

Guardana installs straight from PyPI as a pre-commit hook — scan before anything
leaves the machine. Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: guardana
        name: Guardana AI security scan
        entry: guardana scan .
        language: python
        additional_dependencies: ["guardana-cli"]
        pass_filenames: false
        # Runs on push (heavier) rather than every commit:
        stages: [pre-push]
```

A single-file target is supported too, so a filename-passing hook works — but for
a whole-repo gate `pass_filenames: false` with an explicit path is simplest. Use
`--baseline guardana-baseline.yaml` (see [usage-scan.md](usage-scan.md#baselining-existing-findings))
to turn the gate on for an existing repo without fixing the whole backlog first.
