---
title: "The 0.21 audit"
nav_order: 24
summary: "what a full audit of the released 0.21.0 found, which findings were closed in 0.22.0 and with which gate, and which were deliberately left open"
status: accepted
---

# The 0.21 audit: what it found, and what closed it

**Status:** accepted · **Written:** 2026-08-20 · **Subject:** the released 0.21.0

An audit of the released build — code, architecture, documentation and market
position — conducted against `4cb87d7`. Kept because the *pattern* in the findings
is more useful than any one of them, and because half of what it found had passed
every gate this repository has.

## Method, and its limits

Static reading, plus running the documented commands and reading the artifacts
they produced. Every finding was then re-verified against the source before this
was written; none turned out to be false, four were made more precise, and one
grew a consequence its first version had missed.

What was **not** done, stated so nobody reads more into this than it says: no
network pentest of the collector, no probes against real vLLM/Ollama/TGI/MCP
servers, no precision/recall measurement of the 51 rules against an independent
corpus, no load test, and no user interviews. Market judgement is qualitative
inference from published sources, not a sizing.

## The pattern worth keeping

Three of the five most serious findings share a shape: **a claim that was true
when it was written and became false without anything noticing.** A promise about
a future release. A pin to a container image. A statement that the collector
lacked a feature it later gained.

None of these is a bug in the ordinary sense — there is no wrong branch to find —
and none can be caught by reading the diff that introduced it, because the diff
was correct. They are caught only by asking, periodically, *is this still true*.
That is why every fix in 0.22.0 came with a gate rather than an edit, and why the
gates check the whole repository rather than a list of files: **the list is what
failed**.

## Findings, and their disposition

| Finding | What it was | Disposition |
|---|---|---|
| **Assessment channel missing** | a run recorded only problems, so "improved", "tested less" and "sampled differently" were indistinguishable | closed in 0.22.0 — [`assessment-channel.md`](assessment-channel.md) |
| **Capability contract false** | `docs/extending.md` promised a `READ_FILES` target could run the artifact rules; 35 `isinstance` checks made that impossible | closed in 0.22.0 — [`capability-protocols.md`](capability-protocols.md) |
| **Silent rule/evaluator override** | any installed pack could take over a built-in id, and neither `rules_run`, nor the rule digest, nor the never-populated `RuleRecord.version` could show it | closed in 0.22.0 — conflict refused, namespace enforced, provenance recorded in the manifest |
| **Documentation contradicted the build** | six image pins from series 0.9–0.13, five future-tense claims about features shipped in 0.7, a collector described as lacking lifecycle/audit/retention it gained in 0.11, and a dashboard footer calling itself unauthenticated one screen below its Sign out button | closed in 0.22.0 — repo-wide pin scan, shipped-milestone gate, capability-denial gate |
| **The Action did not pin its own CLI** | `guardana/guardana@v0.21` installed the newest `guardana-cli`, so a pinned workflow changed engine on the next release; arguments were also word-split and glob-expanded | closed in 0.22.0 — version default, shell-like argument splitting |
| **Supply-chain hardening of CI** | eleven external actions on moving major tags, and `ci.yml` with no `permissions:` block at all | **partly** closed in 0.22.0 — every action pinned to a commit, least-privilege tokens declared and gated. **CodeQL is not added**: it is a new workflow that cannot be exercised locally, and adding an untested one in a release commit is the mistake this release exists to stop repeating. Tracked, not done |
| **Non-transactional plugin load** | a pack failing half way left part of itself registered *and* reported as unloadable | closed in 0.22.0 — snapshot and rollback per entry point |
| **No fuzzing of hostile parsers** | named in the threat model as an open gap from v0.7 | closed in 0.22.0 — property tests over every extension a rule opens, plus the trace reader |
| **Global coverage hid hotspots** | one 90% aggregate let simple code pay for an untested parser | closed in 0.22.0 — per-area floors, in CI |
| **Over-absolute competitive claims** | "no red-team harness ships an exit-code contract, a saved run or a regression comparison" was disprovable by 2026 | closed in 0.22.0 — dated, sourced comparisons; no "none/only/first" |
| **`monitor` is not passive monitoring** | scheduled active probing, correctly documented, but not what "continuous" suggests to a reader | open by design — [`production-intake.md`](production-intake.md), Horizon 2 |
| **Too many sources of documentation truth** | the same status restated in several files | **partly** closed — one owner per claim is written down in `ROADMAP.md`, and the roadmap's narration of shipped milestones is gone (1042 → ~1000 lines while gaining a whole new strategy section). Not closed: no capability manifest generated from code, no provider matrix generated from conformance, no CLI-help snapshot, and no gate on the freshness date of a competitive comparison |
| **Several large modules** | manifest loading, MCP authorization, endpoint and trace each past 400 lines | open — split when the next subsystem lands in them, not mechanically |
| **Release velocity vs. API stability** | 0.1 to 0.21 in a month, with the extension API frozen only at 1.0 | open by design — the 1.0 criteria are the answer, and the conformance kit shipped in 0.22.0 is the first half |
| **Self-hosted operational gaps** | no Helm, no SSO/RBAC, no HA workers, no tested provider conformance matrix | open — Horizon 3 |

## Found while fixing the above

Four defects the audit did not see, three of which only appeared because the fix
touched code the audit had no reason to read:

- **`super()` cannot work inside a slotted dataclass.** `YamlRule.digest()` and
  its two siblings raised `TypeError` on every rule not parsed from a file. Only
  reachable for a hand-built rule, so no fixture had one.
- **`compare_reports` rebuilt `RunDiff` field by field** and dropped the whole new
  channel. Found by running the documented command and reading the output.
- **Two more stale pins** — `site/README.md` at `v0.13`, `docs/maintainers/
  github-setup.md` at `:0.11` — found by the new repo-wide gate, not by the audit.
- **Three more stale milestone claims**, found only after the gate was widened:
  `CLAUDE.md` named the 0.7 milestone as current fifteen releases on, and the
  threat model still described the plugin surface as "not mitigated beyond
  documentation" and the allowlist as future work. The first gate for this class
  required a closing `**` and missed all three.

The last one is the lesson: **a gate written against the instance you just found
catches the instance you just found.** Widening it cost one character and found
three more, in the file that is project law and in the document a security reader
opens first.

## What was *not* found

Worth recording, because an audit that only lists problems is not a measurement
either. The verdict semantics held up under adversarial reading: `unverified`,
`errors` and `coverage_shortfall` behave as documented, the gate's precedence is
correct, and no new class of fail-open was found in the execution path. The
package boundary is enforced rather than asserted, the redaction seam is single,
and the release pipeline's outputs (SBOM, provenance, OIDC) are ahead of the
project's age.

The two worst findings were both in the same place: **the seam between what the
project claims and what it does.** Not the engine.

## See also

- [`assessment-channel.md`](assessment-channel.md) · [`capability-protocols.md`](capability-protocols.md) · [`production-intake.md`](production-intake.md)
- [`../../ROADMAP.md`](../../ROADMAP.md) — the direction this audit set
- [`../product-status.md`](../product-status.md) — the single list of current limitations
