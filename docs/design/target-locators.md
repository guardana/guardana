---
title: "Target locators"
nav_order: 71
summary: "how a discovered third-party target becomes something a command can build — a scheme the target declares, a locator the operator types, and the verb still choosing the kind"
status: proposed
---

# Target locators: a custom target the CLI can build

**Status:** proposed · **Written:** 2026-09-02 · **Cycle 1 of the extensibility program** ([`audit-0.22.md`](audit-0.22.md))

## The gap

`guardana.targets` has been an entry-point group since 0.1, `Registry.discover()`
loads it, `pack validate` checks it, `pack lock` pins it — and no command has ever
consumed it. Every target a command runs is a literal: `ArtifactTarget(path)` in
three places, `build_endpoint(...)` behind `probe`, `monitor`, `plan probe` and
`target inspect`, `TraceTarget(read.trace)` behind `analyze-trace`. A team whose
model sits behind an internal gateway with its own wire protocol, whose artifacts
live in an object store, or whose traces come out of a system with its own export
can write a `Target`, prove it with `assert_target_conforms`, and then only reach
it from Python that drives a `Runner`.

0.22.0 deferred this with a precise reason: it "needs a decision about how a
target names its configuration on a command line". This is that decision.

## The decision

**A target declares a scheme; the operator types a locator; the verb still chooses
the kind.**

```console
$ guardana scan   --target acme-prompts://./prompts
$ guardana probe  --target acme-gateway://llm.internal:8443/v1 --target-option model=support-v3
$ guardana analyze-trace --target acme-langfuse://exports/2026-09-01.jsonl
```

The scheme, the locator and the verb each do one job:

1. **The scheme is declared on the class.** `Target.scheme` is a class attribute,
   `None` by default, and `Target.from_locator(locator)` is a classmethod that
   raises `LocatorError` by default. A target that sets neither is exactly what it
   is today: discoverable, usable from Python, not selectable. Nothing an existing
   pack implements changes meaning.
2. **The locator is `scheme://rest`, plus options.** Everything after `://` is
   handed to the target untouched — a path, a host and port, an object-store key.
   Options are `--target-option key=value`, repeatable, and reach the target as a
   mapping. Secrets are named by environment variable, the way `--api-key-env`
   already works, and never as option values that land in a shell history.
3. **The verb decides the kind, and refuses a mismatch.** `scan` builds artifact
   targets, `probe` and `monitor` endpoint targets, `analyze-trace` trace targets.
   A locator whose target reports another kind is refused with exit `3` before a
   rule runs. The verb is the layer selector, as it has always been; a locator does
   not get to change what `scan` means.

### The registry side

- `register_target` validates a declared scheme (`^[a-z][a-z0-9-]*$`), refuses a
  reserved one (`file`, `http`, `https`, `mcp`, `trace`) and refuses a scheme
  another origin already holds, with the same message shape as a rule-id conflict.
  A scheme is a claim about what `--target` will run, so it gets the same
  one-owner rule an id gets.
- `Registry.target_for(scheme)` returns the class or `None`; `Registry.schemes()`
  lists what `--target` can build. `guardana doctor` prints them, so "why does my
  scheme say unknown" is answered by the command that answers everything else
  about an installation.
- Under `--plugins builtins` or `disabled`, third-party schemes are not loaded and a
  locator naming one exits `3` with the trust mode in the message. The refusal
  names the policy rather than pretending the scheme does not exist.

### The CLI side

One helper, used by every command that builds a target from a path or URL —
`scan`, `baseline create`, `baseline update`, `plan scan`, `probe`, `plan probe`,
`monitor`, `target inspect`, `analyze-trace`:

```python
def resolve_target(registry, *, locator, options, kind, fallback) -> Target
```

`fallback` is the literal construction the command does today, so the default path
is untouched and the new path is one branch. Exit codes follow the existing table:
`3` for an unknown scheme, an invalid locator, an option the target rejects, or a
kind mismatch (invalid configuration); `4` when the target's own constructor
reports it cannot reach what it names (target unavailable).

### What a custom endpoint target gets from `probe`

`probe` runs one pass per planted canary, each on a target built with a fresh
system prompt. That construction is endpoint-shaped today. It becomes a protocol:

```python
@runtime_checkable
class SystemPromptPlanter(Protocol):
    def planting(self, system_prompt: str) -> Target: ...
```

`EndpointTarget` implements it. A custom target that implements it gets the canary
passes, exactly as the built-in does; one that does not gets the plain pass, and
the rules needing `plant_system_prompt` are skipped by the runner for the reason
it already records — the target did not declare it. That is the honest outcome:
fewer rules ran, the report says which and why, and nothing was graded against a
marker that was never planted.

The protocol is deliberately **not** added to `CAPABILITY_SURFACE`. Doing so would
turn a target that declares `plant_system_prompt` today — constructed with its
prompt already in place, as the built-in is — into one the runner refuses, which
is a contract change for every existing pack to serve a convenience for new ones.
`plant_system_prompt` stays what `protocols.py` says it is, a fact about
construction; `planting` is how `probe` asks for a differently constructed copy.

### Budgets, usage, observations, protocols

Unchanged, and already fail-closed. A custom target that does not implement
`apply_budgets` refuses any ceiling set against it; one that does not meter itself
reports `usage: None`, which the manifest records as unknown rather than free;
`observe()` produces no inventory for a target that implements neither
`FileReader` nor `ChatEndpoint`, which the manifest shows as an absence.

## The example follows, and is held to it

`examples/custom_rule`'s target gains `scheme = "acme-prompts"`, implements
`FileReader` properly (which the audit found it did not), and its isolated test
suite runs `guardana scan --target acme-prompts://…` as a subprocess, calls
`assert_target_conforms`, and runs the `Runner` over it with the built-in registry.
`guardana new-pack` scaffolds the same shape. A seam nothing exercises is a seam
nobody has run, and this one has been that for twenty-two releases.

## Extension API

Nothing an existing pack implements changes, so a pack declaring `>=1,<2` still
loads. A pack *using* `scheme` and `from_locator` on a build without them would
still load and its target would still be unselectable — a silent absence, which is
exactly what `extension_api` exists to turn into a refusal. So the build advertises
that it implements API `2` alongside `1`, and a pack written against the locator
contract declares `>=2,<3`. The range check becomes "does the pack's range contain
any version this build implements", which is the additive rule every later cycle
follows: a new seam is a new number, and an older pack keeps loading.

## Rejected

**A separate `TargetFactory` registered in its own group.** Two objects for one
thing: the class knows how to build itself or it does not, and a factory that
outlives the class it builds is a second place for the two to disagree.

**Options in the locator's query string.** `acme-gateway://host/v1?model=x` reads
well until the rest of the locator is a URL with its own query string, at which
point the parser has to guess whose `?` it is. A repeatable flag has no such edge.

**Auto-detecting a scheme from the positional argument.** `guardana scan s3://…`
silently routed to whichever installed pack claims `s3` is a plugin deciding what
a command does. `--target` says the operator chose it.

**Schemes for the built-in targets.** `file://` and `mcp://` would add a second
spelling for every documented command and change nothing a user can do. They stay
reserved so nobody else can claim them, and unused until there is a reason.

**A `targets:` block in `guardana.yaml`.** Probably right eventually — a team
shares options the way it shares a policy — but the profile is a closed schema on
purpose, and a block designed before a design partner has typed a real locator
is a shape nobody asked for. The flag form is enough to learn what the block
should hold.

## See also

- [`capability-protocols.md`](capability-protocols.md) — the contract a target satisfies
- [`output-plugins.md`](output-plugins.md) — the same move for what comes out of a run
- [`../usage-target.md`](../usage-target.md) — the user page
