---
name: build
description: Execute the lanes of a work file in .work/ — yourself or through parallel coder subagents — keeping the suite green lane by lane and the Handoff section current. Use after /plan for M and L tasks, or to resume a half-built work file.
argument-hint: "[path to work file]"
---
# Build — run the lanes

Work file: $ARGUMENTS (default: the only file in `.work/`, else ask which).

1. **Read the work file once.** It is the brief; do not restate it to yourself. Tick lanes in the
   file as they land — the file is the ledger, there is no second one.
2. **Decide who does each lane.**
   - `main` lanes and anything that turns out subtler than planned: do them here.
   - `coder` lanes: spawn `coder` with a prompt of ≤ 15 lines — the work file path, the lane
     number, the exact files, the verification command, "do not commit". No background story;
     the work file has it.
   - Independent lanes with disjoint files: spawn them in ONE message so they run concurrently.
     Lanes sharing a file, a schema version or a fixture run one after another. For risky
     parallel edits use `isolation: worktree` and merge lane by lane.
3. **Check every hand-back before trusting it**: read the diff (`git diff --stat`, then the
   hunks that matter), re-run the lane's verification command yourself or through `runner`, and
   compare the verdict line with the one reported. A lane is ticked only after that.
4. **Checkpoint.** After every lane update the work file's Handoff section (done / next / how to
   verify), so a fresh session — or you after compaction — continues from the file alone. On a
   long plan run the full gate (`scripts/ci_local.sh --quiet`) every third lane instead of
   discovering drift at the end.
5. **Integrate.** After the last lane: regenerate what a rule or evaluator change moved
   (`uv run python scripts/generate_docs.py`), then the full gate (`/gate`). Red for a reason that
   is not yours: say so in the work file and in the commit message — never push past it silently.
6. **Wording lanes** are reviewed as text; their output enters a page or a rule only through the
   normal gates (the docs tests, `build_site.py --check`, the rule's fixtures).
7. **Stop conditions.** A lane that fails twice for the same reason is a design problem: go back
   to the work file, change the plan, note why. Do not let a subagent widen its lane to make a
   test pass, and never let it make a check return clean to get green.

Then `/review` → fix → gate → re-review only the fixes, at most three rounds (what is still open
after that goes to the user, not into a fourth round). Then `/land`.
