---
title: "Capability protocols"
nav_order: 22
summary: "why a capability without a surface made the extension contract false for four releases, what each capability now promises as a type, and why the registry had to stop letting one plugin quietly become another"
status: accepted
---

# Capability protocols: making the extension contract true

**Status:** implemented in 0.22.0 · **Written:** 2026-08-20

## The promise, and the paragraph that broke it

`docs/extending.md` said this, from 0.1 onward:

> a new artifact-like target that provides `READ_FILES` can run all 19 build-time
> artifact rules unmodified

Four lines above it, the same page said:

> there's no fixed interface beyond the base Target

Both could not be true. It was the first that was false. `Capability` declared
*whether* a target could do something; nothing declared *how* it was asked. So
every rule did the only thing available to it and asked whether the target was
an `ArtifactTarget` — **thirty-five times** across the engine and the rule packs.

The result was a seam that looked open and was closed. A third-party target
declared `READ_FILES`, passed capability selection, was planned into the run, and
was then rejected by every single rule it reached. The scan came back clean on a
directory that plainly was not.

That is not merely a broken feature. A capability that selects rules which then
decline is a **coverage gap wearing the shape of a clean result**, which is the
failure mode this project spends most of its design effort refusing.

## The shape

One `Protocol` per capability, in `guardana.core.target.protocols`:

| Protocol | Capability | What a rule calls |
|---|---|---|
| `FileReader` | `read_files` | `iter_files`, `python_source`, `unread_sources` |
| `ChatEndpoint` | `chat` | `model`, `chat` |
| `ToolOfferingEndpoint` | `call_tools` | the above plus `offer_tools` |
| `TraceReader` | `read_trace` + dimensions | `trace` |
| `ToolListing` | `list_tools` | `list_tools` |
| `AuthorizationInspector` | `inspect_authorization` | `authorization`, `conversation` |

The granularity is not aesthetic. **One protocol per capability** means a rule's
`required_capabilities` and its `isinstance` check cannot come apart: a target
that can hold a conversation but not offer tools satisfies `ChatEndpoint` and not
`ToolOfferingEndpoint`, which is exactly the distinction `CHAT` and `CALL_TOOLS`
already drew.

Selection still belongs to the runner. The protocol is the narrower question
asked at the point of use — and because it is a type, `mypy --strict` verifies
the call, and a third party's target satisfies it structurally without inheriting
anything of ours.

`python_source` is in the contract rather than being an implementation detail of
the built-in target, because the *cost model* depends on it: every rule that
inspects Python asks through there, so a file is read, decoded, parsed and walked
once per scan rather than once per rule. A target that re-reads per call
satisfies the signature and breaks the property the second product principle
exists to protect.

## Both directions, or it is not a contract

`unmet_surfaces()` answers "declares a capability, has no surface" — checked once
by the runner, before a single rule is planned. One error naming the missing
protocol, instead of nineteen rules failing in turn.

The *other* direction has no error at all, and it is the dangerous one.
A target that implements `chat` and forgets to declare `CHAT` is skipped by every
endpoint rule: the scan is green, the coverage is zero, and nothing in the report
distinguishes that from a model with no problems. `guardana.testing.conformance`
checks both, and is shipped in the package rather than living in `tests/` — a
conformance kit somebody has to vendor is a conformance kit nobody runs.

```python
from guardana.testing import assert_target_conforms

def test_my_target_satisfies_the_contract() -> None:
    assert_target_conforms(MyTarget("s3://models/"))
```

## The registry half

The same release closed a matching hole one layer over. `register_rule` was
documented last-wins:

> Last-wins also lets a custom rule override a built-in by reusing its id

The cost of that convenience was the run's own evidence. `rules_run` records
`meta.id`; `Rule.digest()` hashes the *declaration*. So a pack that copied a
built-in's metadata and returned nothing produced an identical id, an identical
digest, and a clean report naming the check it had replaced. `diff` could not see
it either. And `RuleRecord.version` — the one field in the manifest that exists to
tell two providers apart — **had never been populated by anything**, on any run
ever written.

Three changes, together:

- **conflict is refused.** A different origin claiming a held id raises, is
  recorded in `errors`, and the gate refuses the run. Identical origin still
  de-duplicates, which is the legitimate case the old behaviour existed for:
  `rules.paths` and `--rules` pointing at overlapping directories.
- **the reserved namespace is enforced.** `guardana.*` has been documented as
  reserved since 0.1 with nothing checking it. An *installed* plugin claiming one
  is refused; code driving the registry directly is not, because there is no
  supply chain to defend against there — the caller is the origin.
- **the origin is recorded and written down.** `Origin(distribution, version,
  source)` travels from the entry point into `RuleRecord.version` and
  `RuleRecord.origin`, so the saved run answers "whose rule was this" without
  access to the machine that produced it. Named `Origin` rather than `Provenance`
  because two classes already carry that name — on an exchange and on a trace —
  and a third would make the import a question.

Provider loading also became transactional. It validated and registered item by
item, so a pack whose fourth rule was malformed left three registered *and*
recorded the pack as unloadable — a document that lists rules from a pack it says
did not load. One entry point is now one transaction, by snapshot and rollback
rather than by a pre-flight, so a refusal added later stays atomic without needing
a second implementation.

## What is deferred, and why

**`TargetFactory` and CLI selection of a custom target.** A discovered `Target`
is usable by code that drives a `Runner`; the CLI's own selection is still
path/URL-based. Doing it properly needs a decision about how a target names its
configuration on a command line, and the protocols are the prerequisite — a
factory that built an object every rule then rejected would have been the same
false seam one level up.

**A namespaced `Capability` descriptor.** The enum stays closed: opening it to
arbitrary strings turns a typo (`requires: [call_tols]`) from a load error into a
requirement no target can satisfy, which is a rule silently skipped forever. A
versioned, validated external descriptor is the right answer and is a bigger
piece of design than this release.

## See also

- [`../extending.md`](../extending.md) — how to write a target against these
- [`assessment-channel.md`](assessment-channel.md) — the other half of the 0.22 contract work
- [`extension-author-tooling.md`](extension-author-tooling.md) — pack manifests and locks
