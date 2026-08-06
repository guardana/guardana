# Integrations — CI and pre-commit

Guardana ships ready-made ways to gate on AI/LLM risk without wiring anything by
hand: a GitHub Action, copyable pipelines for GitLab, Jenkins and Azure DevOps, a
one-line recipe for any CI that can run a container, and a pre-commit hook.

| Platform | What to use |
|---|---|
| GitHub Actions | the composite action below — SARIF lands in code scanning |
| GitLab CI | [`deploy/ci/gitlab-ci.yml`](../deploy/ci/gitlab-ci.yml), includable from a remote URL |
| Jenkins | [`deploy/ci/Jenkinsfile`](../deploy/ci/Jenkinsfile) |
| Azure DevOps | [`deploy/ci/azure-pipelines.yml`](../deploy/ci/azure-pipelines.yml) |
| anything else | [the generic container pipeline](../deploy/ci/README.md#the-generic-container-pipeline) |
| before the push | [pre-commit](#pre-commit) |

Everything except the Action and the hook runs the published image, so the
version of Guardana in a pipeline is a tag somebody pinned rather than whatever
`pip install` resolved this morning.
[`deploy/ci/README.md`](../deploy/ci/README.md) explains the three things a
copied pipeline gets wrong — swallowing the exit code, publishing the report only
on success, and forgetting that the platform wraps commands in a shell — and each
of those is held by a test.

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
      - uses: guardana/guardana@v0.11   # moving tag; pins to the latest 0.11.x
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

## Failing a build on deterioration, not just on findings

The Action gates on what a scan finds *today*. To gate on whether today is worse
than the last accepted run, save both runs and compare them:

```yaml
      - name: Scan and save this run
        run: guardana scan . --format json --output current.json

      - name: Compare against the last accepted run
        run: guardana diff accepted.json current.json --preset ci
```

Keep `accepted.json` in the repository (or in your CI's artifact store) and
refresh it when you deliberately accept a change. `guardana diff` exits `1` on a
regression and `2` when the two runs cannot honestly be compared — treat `2`
exactly like `1` until you have read the reason, because "I could not compare
these" is not "nothing got worse". See [`usage-diff.md`](usage-diff.md).

## GitLab, Jenkins, Azure DevOps, and anything that runs a container

The templates live in [`deploy/ci/`](../deploy/ci/README.md) and are meant to be
copied. The shortest form, which is also what the Jenkins and Azure templates
run:

```bash
docker run --rm -v "$PWD:/work:ro" ghcr.io/guardana/guardana:0.9 \
  scan /work --format junit > guardana-junit.xml
```

The redirect is deliberate: the file is written by your shell, with your user's
ownership, so the workspace can be mounted read-only and the image's non-root
user never writes into a directory your CI owns. Publish `guardana-junit.xml` as
the job's test report — GitLab, Jenkins and Azure all read JUnit natively — and
let the exit code fail the build.

GitLab can include the job rather than copy it:

```yaml
include:
  - remote: "https://raw.githubusercontent.com/guardana/guardana/v0.11/deploy/ci/gitlab-ci.yml"

guardana:
  variables:
    GUARDANA_PATH: "models/"
    GUARDANA_ARGS: "--preset ci --baseline guardana-baseline.yaml"
```

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
