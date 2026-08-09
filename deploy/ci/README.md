# Running Guardana in a CI system that is not GitHub

One recipe, four shapes. Everything here runs the published image, so the version
of Guardana in your pipeline is a tag you pin rather than whatever `pip install`
resolved this morning.

| File | For |
|---|---|
| [`gitlab-ci.yml`](gitlab-ci.yml) | GitLab CI — includable as a remote job |
| [`Jenkinsfile`](Jenkinsfile) | Jenkins declarative pipeline |
| [`azure-pipelines.yml`](azure-pipelines.yml) | Azure DevOps |
| the snippet below | anything else that can run a container |

GitHub Actions has a first-class action instead — see
[`docs/integrations.md`](../../docs/integrations.md).

## The generic container pipeline

```bash
docker run --rm -v "$PWD:/work:ro" ghcr.io/guardana/guardana:0.13 \
  scan /work --format junit > guardana-junit.xml
```

That is the whole thing. The exit code is the gate, the JUnit file is what your
CI's test view reads, and neither needs a plugin.

Note what the redirect buys: the file is written by **your** shell, with your
user's ownership, so the mount can be read-only and the image's non-root user
never has to write into a workspace your CI owns. Writing with `--output` inside
the container is the other option, and then the file belongs to uid 10001 —
fine when the shell also runs in the container (GitLab, Jenkins), a permission
error when it does not.

Three more details decide whether a pipeline built on this is honest:

**Do not swallow the exit code.** No `|| true`, no `allow_failure`, no
`continueOnError`. The table is `0` clean, `1` policy failed, `2` indeterminate,
`3` bad usage, `4` target unavailable, `5` internal error, `6` budget exhausted,
`7` interrupted ([`docs/exit-codes.md`](../../docs/exit-codes.md)). **`2` deserves
particular care**: it means the run could not answer the question, and treating it
as a pass is how a pipeline goes green over a check that never ran.

**Publish the report even when the job fails.** `when: always`,
`condition: always()`, `post { always { … } }` — whichever your platform spells
it. A pipeline that keeps evidence only for green runs keeps the evidence nobody
needs.

**Run as yourself if your workspace is private.** The image runs as uid 10001, so
a checkout only its owner can read produces `Path '/work' is not readable` — a
refusal, deliberately, because a scanner that cannot see its target must not
report "no findings". Add `--user "$(id -u):$(id -g)"`.

**Override the entrypoint when the platform wraps your commands in a shell.**
GitLab and Jenkins both do; the image's `ENTRYPOINT` is `guardana`, so without
`entrypoint: [""]` / `--entrypoint=""` the runner tries to execute
`guardana sh -c …` and the failure looks like Guardana's fault.

## Sending results to a collector

Add the flags and set the key as a masked/secret variable — never on the command
line, where it lands in shell history and in most CI logs:

```bash
docker run --rm -v "$PWD:/work" \
  -e GUARDANA_COLLECTOR_TOKEN \
  ghcr.io/guardana/guardana:0.13 \
  scan /work --ai-system support-agent --environment production \
    --reporter server://https://collector.example.com
```

The commit is read from whatever CI this is (`GITHUB_SHA`, `CI_COMMIT_SHA`,
`GIT_COMMIT`, `BUILD_SOURCEVERSION`). The AI system and the environment are never
guessed — a branch is not an environment — so they are flags you pass.

## Wanting the human report in the log too

`--output` writes the report to a file and prints nothing, which is what a test
view wants and not what a person reading a failed job wants. Add a second,
non-gating pass if your team reads logs:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/guardana/guardana:0.13 scan /work || true
```

Static scans are cheap enough for this. Do **not** do it for `probe` or
`monitor`: those spend requests against a live model, and running them twice
doubles what the run costs.
