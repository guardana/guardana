---
title: "Output plugins"
nav_order: 72
summary: "renderers and reporters as entry points, why the built-in ones are not registered through them, and the one invariant every output must satisfy before it sees a result"
status: proposed
---

# Output plugins: renderers and reporters a pack can add

**Status:** proposed · **Written:** 2026-09-02 · **Cycle 1 of the extensibility program** ([`audit-0.22.md`](audit-0.22.md))

## The gap

`--format` is a closed enum over a hard-coded dict of four renderers, and
`--reporter` understands one scheme. The roadmap's own extension lane cannot be
built on that: a CycloneDX ML-BOM export or an SPDX AI profile is a renderer over
the run's observations, a Prometheus or webhook output is a reporter, and both
are supposed to be packages *outside* the engine so that a standards body's
revision never reaches `guardana-core`. Today the only way to add either is a
pull request against the CLI.

## The decision

Two entry-point groups, resolved by the same registry that resolves everything
else:

| Group | Provides | Selected by |
|---|---|---|
| `guardana.renderers` | `RendererSpec(name, factory)` — `factory(run: RunManifest \| None) -> Renderer` | `--format <name>` |
| `guardana.reporters` | `ReporterSpec(scheme, factory)` — `factory(request: ReporterRequest) -> Reporter` | `--reporter <scheme>://<rest>` |

The `Renderer` and `DiffRenderer` protocols move from `guardana.report.base` to
`guardana.core.output`, where the registry can name them without importing the
report package; `guardana.report.base` keeps re-exporting them. `Reporter` is
already a core protocol.

`ReporterRequest` carries what a reporter legitimately needs and nothing else:
the locator after the scheme, the run manifest, the deployment reference, and the
name of the environment variable holding the credential. It does not carry the
result — that arrives through `submit`, after the invariant below.

### The built-ins are not registered through the groups, on purpose

Rules have no built-in/custom distinction at the registry level, and that is
right for rules. It is wrong here for one reason: `--plugins disabled` loads no
entry points at all, and a run in that mode still has to print. If `human` were
an entry point, the safest mode would be the one that cannot render a report.

So the four renderers and the `server` reporter stay where they are, and the
registry adds discovered specs beside them. A discovered spec may not claim a
built-in name or scheme; the refusal is the same one-owner rule ids get. In
`builtins` and `allowlist` modes, `guardana-report` is one of the reviewed
distributions, so nothing changes there either.

### The invariant: no output sees an unredacted result

Every renderer `get_renderer` returns is wrapped in `_Redacting`, so a renderer
cannot obtain the result before the privacy policy has. That wrapping happens in
the factory, not in each renderer, and a discovered renderer goes through the same
factory. Every reporter receives the result the command already redacted before
building the manifest — the same object the built-in `HttpReporter` receives.

This is pinned by a test in the shape the project prefers: a recording renderer
and a recording reporter registered in a test, a run over a fixture carrying a
fake credential, and an assertion that neither saw it. A third-party output that
needs the raw text is a third-party output that does not exist.

### `--format` becomes a name, not an enum

The typer option becomes a string checked against the union of built-in names
and discovered names; an unknown one exits `3` and lists what is available, with
the trust mode in the message when a plugin might have been the reason.
`diff --format` stays closed: a comparison document has two renderers and no
extension has asked for a third, and a closed list that nobody needs opened is
not a gap.

### Manifest and lock

Pack schema 3 adds `provides.renderers` and `provides.reporters`, checked against
what actually registered, as every other `provides` entry is. The lock pins both by
id, like evaluators — Python with no declaration to hash. The example pack
registers one of each, because a group nothing exercises is the state
`guardana.targets` sat in for twenty-two releases.

## Rejected

**Registering the built-ins through the groups too**, for symmetry with rules. See
above: symmetry is not worth a safe mode that prints nothing.

**A renderer flag saying "give me the unredacted result".** There is no format
that needs the secret to be present to say a secret was present.

**Diff renderers as plugins.** Nothing needs it, and a group with no registrant is
the failure this program is closing elsewhere.

**Making `guardana-report` optional.** The CLI depends on it for `human`, and a CLI
that cannot print without an extra is a CLI whose first run is a stack trace.

## See also

- [`target-locators.md`](target-locators.md) — the same move for what goes into a run
- [`privacy-and-redaction.md`](privacy-and-redaction.md) — the policy every output is behind
- [`../usage-scan.md`](../usage-scan.md) — where `--format` and `--reporter` are documented
