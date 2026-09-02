---
title: "Attack techniques"
nav_order: 75
summary: "the technique as its own extension point — a deterministic transform of a prompt, crossed with a rule's corpus, so coverage is a product of two small sets and a failed transform is a skipped case rather than a plain prompt"
status: proposed
---

# Attack techniques: the second dimension, as a seam

**Status:** proposed · **Written:** 2026-09-02 · **Cycle 4 of the extensibility program** ([`audit-0.22.md`](audit-0.22.md))

## Why now

The roadmap has said since 0.12 that the technique is "designed before 1.0",
because an extension point added after `Rule` and `Evaluator` freeze is a major
version the week after promising stability. It has also said why it matters for
coverage: a vulnerability crossed with an encoding is a new rule today, so every
new technique costs rules-times-vulnerabilities, and the only way to close the
attack-coverage gap without violating "cost grows with the target, not with the
rule count" is to make the two dimensions multiply.

## The shape

```python
class Technique(ABC):
    id: str
    def apply(self, prompt: str) -> str: ...
    def describe(self) -> str: ...
```

Deterministic, offline, and blind: a technique sees a prompt and nothing else —
not the target, not the expectation, not the evaluator. It may raise
`TechniqueError` when it cannot transform an input, and that is the whole
contract.

Discovered through `guardana.techniques`, registered with the same one-owner rule
as evaluators (bare ids for the built-ins, namespaced for a pack, `guardana.*`
reserved), pinned by id in the lock, declared under `provides.techniques` in pack
schema 4, listed by `guardana techniques`.

## How a rule uses one

```yaml
id: acme.prompt.exfiltration
prompts: [...]
techniques: [base64, roleplay]
```

Every prompt still runs plain, and additionally once per technique. Each
combination is its own case: `case_id_for(rule_id, prompt, technique_id)`, tagged
`technique:<id>`, named in the finding's evidence. `estimated_requests` is
`prompts × (1 + techniques)`, so `plan` prices the product. The technique ids are
part of the rule's `digest()`, because a rule that acquired an encoding is a
different test and a comparison must say so.

The expectation does not change. The goal is the same goal; a canary is graded on
the reply, which the technique never touches.

**A technique that raises produces a `skipped` assessment for that case**, with the
error in the rationale — never the plain prompt in its place. Substituting the
untransformed prompt would grade the wrong test and report it as the right one,
which is the failure this repository is organised around.

Available on `prompts:` rules and suites. Scenarios and trajectories are deferred:
a technique applied to one step of a conversation changes what the conversation
is, and a technique applied to an agent's task changes what the agent was asked to
do; both need their own design rather than a flag.

## The built-ins

Four, in `guardana-rules`, one short file each, deterministic transforms with no
model and no randomness:

| id | what it does |
|---|---|
| `base64` | encodes the prompt and asks for it to be decoded and followed |
| `homoglyph` | substitutes confusable Unicode letters from a fixed table |
| `roleplay` | wraps the prompt in a fixed persona framing |
| `payload_split` | splits the prompt in two and asks for the halves to be joined |

Each ships tests for determinism, for an empty prompt raising `TechniqueError`,
and for round-trip where the transform is reversible. None claims to bypass
anything; they are the transforms the neighbouring tools separate from their
vulnerabilities, offered as data a rule author can select.

## Rejected

**Adaptive or model-driven techniques.** Gated on calibration, unchanged from the
roadmap. A technique that calls a model is an attacker, and this tool runs none.

**Techniques applied globally from the profile.** Multiplying every rule's corpus
by a profile setting turns a probe's cost into a number nobody typed. A rule
names its techniques; a profile can still exclude the rule.

**The technique as an evaluator parameter.** It changes what is sent, not how the
reply is judged; putting it on the grader would let a rule's cost change without
its declaration changing.

**A `techniques:` list on a scenario step.** See above — deferred, not refused.

## See also

- [`extension-author-tooling.md`](extension-author-tooling.md) — where the technique was first named as owed
- [`quality-suites.md`](quality-suites.md) — the other rule shape a technique applies to
