---
title: "Namespaced extension ids"
nav_order: 76
summary: "capabilities and assertion kinds a pack can declare — an open registry with closed validation, so a typo stays a load error and a third party's concept gets the same runner and the same gate as a built-in"
status: proposed
---

# Namespaced extension ids: opening two closed lists without opening the typo

**Status:** proposed · **Written:** 2026-09-02 · **Cycle 5 of the extensibility program** ([`audit-0.22.md`](audit-0.22.md))

## Two lists, closed for one reason

`Capability` and `AssertionKind` are closed enums, and the reason written on both
is right: an unknown string read leniently is `requires: [call_tols]` becoming a
requirement no target can satisfy — a rule silently skipped forever, which is a
fail-open. "A third party adding a capability adds it here, in a pull request
someone reads."

That is the correct rule for a list, and the wrong rule for an ecosystem. A team
whose target retrieves from a vector store, executes SQL through a tool, or
answers with a structured plan has a concept no built-in capability names, and a
rule that needs it has nowhere to say so. Their choice today is to declare
nothing — and be skipped by every rule that needs the concept — or to declare the
nearest built-in and lie. Both are the failure the closed list exists to prevent,
arriving from the other side.

## The answer: an open registry, a closed check

An id is valid if it is a built-in member **or** a namespaced id
(`<namespace>.<name>`, `guardana.` reserved) that a loaded pack registered.
Anything else is refused at the moment it is read. `acme.retrive` is not a rule
skipped forever; it is a `RuleLoadError` at registration, recorded in `errors`,
failing the gate, naming the id and the registered ids nearest to it.

That preserves both halves of the original argument: a typo is still loud, and
the thing that makes it loud is a registry rather than an enum.

### Capabilities

```python
@dataclass(frozen=True, slots=True)
class CapabilityDescriptor:
    id: str                    # "acme.retrieve"
    surface: type              # a Protocol a rule will isinstance-check
    title: str
```

- Discovered through `guardana.capabilities`, loaded **before** rules, as
  taxonomies are, because a rule resolves `requires:` while its own pack loads.
- `Capability` stays a `StrEnum` for the built-ins; `CustomCapability(str)` checks
  the namespaced shape in `__new__`; `CapabilityId = Capability | CustomCapability`.
  `RuleMeta.required_capabilities` and `Target.capabilities()` widen to it. Set
  arithmetic in the runner is unchanged, because both are strings.
- `CAPABILITY_SURFACE` gains the registered descriptors, so `unmet_surfaces` and
  `assert_target_conforms` check a custom capability's surface exactly as they
  check `read_files`: declared without the protocol is refused, implemented
  without the declaration is refused.
- `register_rule` refuses a rule whose custom capability nobody registered. The
  pack that needs the capability is the pack that registers it, or depends on one
  that does, and the manifest says which under `provides.capabilities`.

### Assertion kinds

```python
@dataclass(frozen=True, slots=True)
class AssertionKindSpec:
    kind: str                                   # "acme.data_residency"
    dimensions: tuple[Dimension, ...]           # what evidence it needs
    allowed_keys: frozenset[str]                # what the YAML may say
    build: Callable[[Mapping, Common, str], Assertion]
    compile: Callable[[Contract, Assertion], Rule]
```

- Discovered through `guardana.assertion_kinds`; declared under
  `provides.assertion_kinds`.
- The four dispatch tables that exist today — dimensions, allowed keys, builders in
  core, and the `isinstance` chain in `guardana.rules.contract.compile` — become one
  table of specs, with the five built-ins as its first five rows. One table read
  from every direction, which is what the assertion module already says it wants.
- The contract loader takes the registry's kinds. An unknown kind is refused as it
  is today, and the message adds the trust mode, because "unknown kind" under
  `--plugins builtins` is usually "the pack that defines it was not loaded".
- The contract schema does not change: `type:` was always a string, and the set
  of strings it accepts is what widened.

## Extension API

A pack using either seam on an older build fails at import, which is honest but
late. The build advertises API `4` beside `1`, `2` and `3` (locators and outputs,
then techniques), and a pack that needs custom ids declares a range containing
`4`. Pack schema 5 carries the two new `provides` lists; the lock pins both by id.

## Rejected

**Free strings with a warning.** A warning is the fail-open in a different font.

**Soft requirements** — a rule declaring "run me if you can, skip me if not"
without naming what it needs. The skip reason is the evidence; a rule that cannot
name it cannot be reported honestly.

**Capability inheritance** (`acme.retrieve` implies `chat`). Implied capabilities
are capabilities nobody declared, and the runner selects on declarations.

**Opening `TargetKind` at the same time.** A kind is what a verb selects; see the
audit. A target with a new concept declares a capability, not a kind.

## See also

- [`capability-protocols.md`](capability-protocols.md) — why a declaration must have a surface
- [`security-contracts.md`](security-contracts.md) — the assertion kinds this opens
- [`extension-author-tooling.md`](extension-author-tooling.md) — the manifest and lock that carry the new lists
