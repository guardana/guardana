---
name: review
description: Pre-ship code review by a fresh-context Opus reviewer that checks the change against this project's hard rules — a false green, a channel rebuilt field by field, engine purity, schema versions, tenancy, the fixture pair, the five documentation places. Use after the gate is green and before /ship on every M or L change.
argument-hint: "[git range, e.g. main~3..HEAD — default: uncommitted working tree]"
context: fork
agent: reviewer
background: false
---
Review this change.

Range: $ARGUMENTS
(If the range is empty, review the uncommitted working tree: `git diff` plus untracked files from
`git status --short`.)

In-flight work files — read the one that matches the change for its goal and done-criteria:

```!
ls .work/*.md 2>/dev/null || echo "none"
```

Changed files right now:

```!
git status --short | head -60
```

Other people's uncommitted work may sit in this tree. Review only what belongs to the change
described by the work file or the range; list anything else under "not reviewed".

When the work file names an issue, check each ticked acceptance box against its evidence and
say which are not proven; a closing keyword over an unproven box is a finding.

Follow your review order and report format exactly.
