---
name: work
description: Entry point for any development task in this repo — feature, bugfix, refactor, cleanup, a new command, target or evaluator, a collector change. Sizes the task, picks the lightest lifecycle that is still safe, and says which model tier does which part. Use at the start of a task, or to resume one from .work/.
argument-hint: "[issue #N | next | task description | path to a work file]"
---
# Work — the lifecycle

Task: $ARGUMENTS

In-flight work files: !`ls .work/*.md 2>/dev/null || echo none`

## From an issue, or `next`

GitHub Issues are the work queue and milestones the release scope (`CONTRIBUTING.md` § Planning
work in public). Read before planning — every call below is a GET:

```bash
gh issue view N --json number,title,body,state,labels,milestone,assignees,url,closedByPullRequestsReferences
gh issue view N --comments          # a comment may already claim it ("I'd like to take this")
gh pr list --state open --search "N" --json number,title,author,headRefName
gh api repos/guardana/guardana/milestones --jq '.[] | select(.state=="open") | {title, open_issues}'
gh issue list --state open --milestone "<title>" --json number,title,labels,assignees,url
```

- **`next`** takes the open milestone of the nearest release (`1.0.0rc2` before `1.0.0rc3`
  before `1.0.0`) and picks one issue with no assignee, no open PR, no claiming comment, no
  `needs-evidence` label, and acceptance criteria that still match HEAD. Order: a release
  blocker, then a bug, then the rest. No milestone, no ready issue or no `gh` access → say so
  and stop; never invent work to fill the slot.
- **Claiming is public.** Assigning, labelling or commenting on an issue needs the user's yes
  unless the task said so; record the claim in the work file either way.
- **Every issue gets a work file**, even an S one (Goal, Issue, Acceptance, Handoff are
  enough), so another session can continue it. Copy each acceptance criterion into it as a
  checkbox with the evidence that will prove it, and state the release impact from
  `docs/compatibility.md#versioning`. While a candidate milestone is open, only fixes qualify:
  no new CLI flag, persisted field, rule family or public API.
- **Close only on evidence.** `Closes #N` goes into a commit or PR only when every acceptance
  box is ticked with its evidence; otherwise `Refs #N`, and the work file says what remains.
  An issue about a release or a measurement closes when the artifact or the measure exists,
  not when the code merges.
- An unscoped idea goes to Discussions Ideas, not into a work file.

## 0. Check it is still true, and that nobody holds it

Several sessions work in this repo. Before anything else: reproduce the bug or confirm the gap
(`git log -15 --oneline`, `git status --short`, the list above). Already fixed → say so and stop.
A work file already covers it → continue THAT file from its Handoff section, never a duplicate.
Uncommitted changes that are not yours stay untouched and unstaged.

## 1. Size it (say the size out loud, one line)

| size | it is this when | lifecycle |
|---|---|---|
| **S** | ≤ 2 files, no schema / exit code / CLI flag / extension-contract change, the fix is obvious | do it → `/gate` → `/ship` |
| **M** | one package, several files, or any change a saved run, a report or a finding could show | `/plan` → build it yourself (or one `coder`) → `/gate` → `/review` → `/ship` |
| **L** | crosses packages, adds a command / target / evaluator / schema / migration, touches the collector envelope or the extension contract | `/plan` with lanes → `/build` (parallel `coder`s) → `/gate` → `/review` → `/ship` in ordered commits → close |

When unsure between two sizes, take the smaller and escalate the moment a second package shows up.
Specialised entries: new coverage is `add-a-rule` (a rule, evaluator or target — never the
engine); a documentation-only task is `/docs`; a symptom is `/debug` first; "nothing changes
for users" is `/refactor`; a roadmap question is an issue or a discussion before it is a plan.
`/auto <task>` runs the whole chain unattended, deciding reversibly instead of asking, and stops
only at its hard lines (push, tags, paid probes, protected contracts).

## 2. Spend tokens where they buy quality

| part of the job | who | why |
|---|---|---|
| find code, a rule, a test; read a log; summarise output | `scout` (Haiku) | the answer matters, not the pages |
| run the gate, a suite, a `--check` script | `runner` (Haiku) | thousands of lines stay out of context |
| design, hard or cross-cutting code, integration | main session | needs the whole picture |
| one well-briefed lane of code + tests | `coder` (Opus, high) | code is where quality is non-negotiable |
| pre-ship review | `reviewer` (Opus, high) | fresh context finds what the author cannot |
| a deliberate hunt for a false green | `false-green-hunter` (Opus, high) | the defect class this project exists to prevent |
| the landing page or docs site in a browser | `browser` (Sonnet) | snapshots are huge |

Rules of thumb: never spawn an agent for something one Grep answers; give every agent the exact
files, the question and the shape of the answer; two agents may run in parallel only when their
file sets are disjoint; an agent's report is evidence to check, not a fact; agents do not spawn
agents.

## 3. Always true

- Work files live in `.work/` (git ignores it) and hold ONLY work in flight. Shipping deletes
  the file; what must outlive it moves to its home (a `docs/` page, a `.claude/rules/` line,
  the commit message). Open leftovers become issues.
- A task is done when the gate is green with the verdict lines read, the change is reviewed
  (M/L), the five documentation places are answered, it is committed — and, if it changes what a
  command writes, the documented command was run against a real or faked target and its
  artifact read.
- "Not measured" is never "passed". Say what you did not verify.
