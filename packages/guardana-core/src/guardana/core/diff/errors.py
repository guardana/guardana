"""The refusal that keeps a comparison honest."""


class IncomparableRunsError(Exception):
    """Two runs that cannot be compared, with the reason spelled out.

    Raised rather than returned as an empty diff, and deliberately hard to
    mistake for a clean result: "these two runs have nothing in common" and
    "nothing got worse" are opposite answers, and only one of them is safe to
    print next to a green build.
    """
