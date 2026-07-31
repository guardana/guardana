"""Comparing two runs, to answer whether the second one is worse than the first.

`monitor` watches a live model and a baseline waives known findings, but nothing
answered the question a customer has at every change — a new model, an edited
system prompt, one more tool: *is this worse than yesterday?* That is what makes
security testing part of the change process rather than a launch ritual.

The hard part is not subtracting two lists. It is that a check has to be
recognisable across runs whose evidence differs by design, that "worse" has five
meanings and one of them is "we can no longer tell", and that comparing a
narrower run against a wider one must never read as progress.
"""

from guardana.core.diff.compare import Identity, compare, finding_identity
from guardana.core.diff.errors import IncomparableRunsError
from guardana.core.diff.gate import gate_diff
from guardana.core.diff.model import Change, ChangeKind, CheckState, RunDiff
from guardana.core.diff.reports import compare_reports

__all__ = [
    "Change",
    "ChangeKind",
    "CheckState",
    "Identity",
    "IncomparableRunsError",
    "RunDiff",
    "compare",
    "compare_reports",
    "finding_identity",
    "gate_diff",
]
