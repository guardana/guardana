"""The exit-code table, as an importable enum rather than as literals in nine files.

Machine consumers must never have to parse human output to find out what
happened, which means the codes are a contract — so they are named, exported, and
pinned by a test against the documented table. `pytest.ExitCode` is the model:
seven meanings, part of the public API, and documented.

Every non-zero code is a non-pass. Nothing here means "probably fine", so a CI job
that treats any non-zero as failure is correct by default and gets finer control
only if it asks for it.
"""

from enum import IntEnum

from guardana.core.gate import GateOutcome, exit_code_for
from guardana.core.report import StopReason


class ExitCode(IntEnum):
    """What a Guardana command's exit status means."""

    OK = 0
    """The run completed and the policy passed."""

    POLICY_FAILED = 1
    """The run completed and the policy failed — a finding over the threshold."""

    INDETERMINATE = 2
    """The result could not be established, or a comparison could not be made.

    Never "nothing was found". It means the question was not answered: no rule
    ran, a check could not run, or one side of a comparison never finished.
    Sharing a code with a clean run would let a broken setup read as a green
    build — the failure this project exists to prevent.
    """

    INVALID_USAGE = 3
    """The configuration or the command line was wrong.

    Kept apart from `POLICY_FAILED` so a typo in `guardana.yaml` never looks like
    a security finding.
    """

    TARGET_UNAVAILABLE = 4
    """The target could not be reached, or refused the credentials.

    Kept apart from `INTERNAL_ERROR` because one is the user's environment and the
    other is our defect; conflating them sends bug reports to the wrong place.
    """

    INTERNAL_ERROR = 5
    """Guardana itself failed. This one is a bug report."""

    BUDGET_EXHAUSTED = 6
    """A budget ran out and the run stopped early.

    Its own code, not folded into `POLICY_FAILED`, in both directions: an
    under-budgeted pipeline must not report a security failure that never
    happened, and — the one that matters more — a team must not be able to fix a
    red gate by lowering the budget until the run stops early.
    """

    INTERRUPTED = 7
    """The run was cut short and partial evidence was written."""


def code_for(outcome: GateOutcome, stopped_by: StopReason | None = None) -> ExitCode:
    """Map a run's verdict to its exit code.

    Delegates to the engine, which owns the codes that describe a *result*, so the
    two cannot drift. The codes for situations with no result at all — invalid
    usage, an unreachable target, an internal error — belong to the CLI and are
    raised where they happen.
    """
    return ExitCode(exit_code_for(outcome, stopped_by))
