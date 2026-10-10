---
title: "Community"
nav_order: 355
summary: "Try Guardana, contribute a fix, share an application result, or suggest coverage."
status: stable
---

# Take part in Guardana

Try the [offline starter](usage-init.md), bring your own application to a pilot,
or contribute a focused fix. The [roadmap](../ROADMAP.md) keeps the
release-candidate work separate from additions after stable 1.0.

## Try a release candidate

An ordinary install selects stable releases. To opt into a candidate and refresh
an existing tool environment:

```bash
uvx --upgrade --prerelease allow --from guardana-cli guardana init --starter first-run
```

Follow the generated project's instructions to find a failure, fix it and edit
one check. `uvx` does not install `guardana` on your shell's PATH: prefix each
README command with the same launcher, as the [first-run guide](usage-init.md)
explains. See [installing](install.md) for pip, source and container options.
For reproducible team runs, pin the exact reviewed version in your environment.

## Join a first run or pilot

- Join a consented [first-run session](studies/first-run-study.md). Record where
  the instructions stop being clear; a failed session is useful evidence too.
- Start an application pilot in [GitHub Discussions](https://github.com/guardana/guardana/discussions)
  or email [contact@guardana.dev](mailto:contact@guardana.dev). Begin with
  synthetic fixtures and harmless tools, then follow the
  [real-application recipe](recipe-real-application.md).
- Try an independently installed extension using the
  [conformance kit](conformance-kit.md). Share its supported surface and a
  redacted reproduction, including failed and incomplete outcomes.

Each participant chooses what to share. The [study guides](studies/adopter-study.md)
describe consent and retained evidence. Do not send production secrets, personal
records or private prompts to a public issue.

## Contribute a focused change

Documentation fixes, tests, examples and maintainer scripts are open during the
candidate period. Use [CONTRIBUTING.md](../CONTRIBUTING.md) and the
[good first issues](https://github.com/guardana/guardana/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).
Candidates keep the supported surface frozen; new rules and feature additions
follow stable 1.0 and demonstrated application needs.

For a bug, include the installed version, the smallest synthetic reproduction,
the expected outcome and the observed outcome. Report suspected vulnerabilities
privately through [SECURITY.md](../SECURITY.md).

## Share a result or publication

Send the canonical link, author, publication date when available, and the
Guardana version discussed to [contact@guardana.dev](mailto:contact@guardana.dev)
or Discussions. A useful application report states what was checked, what the
evidence could not establish, and which release decision it supported.

The landing page links to selected articles and community posts. A directory
listing is distinct from a hands-on review; a fork or star is distinct from a
deployment. A quotation or named application story needs the author's consent
and a reproducible, redacted result. Suggested links are reviewed for identity,
accuracy and source context before publication.

## Follow changes

Watch [GitHub releases](https://github.com/guardana/guardana/releases), subscribe
to the [release feed](https://github.com/guardana/guardana/releases.atom), or read
the [project notes](https://guardana.dev/notes/). [Product status](product-status.md)
states shipped capabilities and limitations; the roadmap gives conditional
priorities, rather than promised release dates.
