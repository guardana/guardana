---
name: auto
description: Autonomous, non-interactive run of the whole lifecycle for one development task — size, plan, build, gate, review, fix, commit — without stopping for questions. Use when the user hands over a task and wants it finished unattended ("zrób to do końca", "/auto …"). Stops only at the hard lines listed inside.
argument-hint: "[issue #N | next | task description | path to a work file]"
disable-model-invocation: true
---
# Auto — finish it without asking

Task: $ARGUMENTS

Run `work` → `plan` → `build` → `gate` → `review` → fix → `gate` → commit, in one go.

For `issue #N` or `next`, follow `/work` § From an issue: read the issue, its comments and
linked PRs, pick only an unclaimed ready one, and copy its acceptance criteria into the work
file. Claiming it on GitHub is a hard line below; record the claim in the work file instead.
An idea with unmet start conditions is not a task, and an unmeasured criterion is not met.

1. **Check it is still true.** Reproduce the bug / confirm the feature is missing / confirm the
   dead code is still there. Look at `git log -15`, `git status` and `.work/` first; the tree
   may hold changes that are not yours. Nothing to do → say so and stop cleanly. A work file
   already covers it → continue THAT file from its Handoff section; never start a duplicate.
2. **Decide instead of asking.** For every open question take the most REVERSIBLE option, and
   record it under "Decisions" in the work file as `decided alone: … — reverse by …` so the user
   can overrule it afterwards. Only a question on the hard-lines list below stops the run.
3. **Checkpoint.** After each lane: tick it, update the Handoff section (done / next / how to
   verify), run the scoped verification. Every third lane run the full gate. If context gets
   long, the work file alone must let a fresh session continue.
4. **Review loop, bounded.** `/review` → fix findings → gate → re-review ONLY the fixes. At most
   three rounds; what is still open after that goes into the report, not into a fourth round.
5. **Commit, do not push** — `/ship` § 1 exactly (explicit paths, one commit per logical change,
   no attribution, the five documentation places, the work file closed). The push — a site
   deploy — stays with the user unless they said "and push" in the task; a tag never happens
   here. `Closes #N` only when every acceptance box is ticked with evidence, else `Refs #N`.
6. **Retro, one minute.** If a missing rule or skill line cost you a detour, add that ONE line to
   the right `.claude/rules/` file or skill now.

## Hard lines — stop and report instead of crossing

- `git push`, a version tag, `scripts/release.py`, a GitHub release, force operations, history
  rewrites;
- any write to GitHub — assigning, labelling, commenting on or closing an issue, opening a PR,
  a milestone, a setting;
- any command that contacts a live endpoint or MCP server, or spends money on a provider —
  `probe`, `monitor`, `calibrate` with a judge, `target inspect` against a real URL;
- renaming or dropping a protected contract (`CLAUDE.md` lists them): a `schema_version`, an exit
  code, a rule id, an entry-point group, a CLI flag, the collector envelope, the Action inputs;
- making a check return clean to get green — the verdict is `inconclusive` or a finding, or the
  task stops here;
- reader-facing wording that nobody has reviewed as text;
- deleting a user-facing page or a fixture;
- a gate red for a reason that is not yours and that you cannot fix inside the task.

## Report

What was asked → what is now true; commits; the gate's verdict lines; review rounds and what
stayed open; decisions made alone (each reversible how); what was NOT verified; the next step
that needs the user (usually: push, or a release).
