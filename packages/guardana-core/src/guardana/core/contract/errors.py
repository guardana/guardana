class ContractError(Exception):
    """A security contract that cannot be read as one. Always raised, never defaulted around.

    Separate from `ProfileError` because the two documents fail differently for the
    reader: a bad profile means the run's policy is unknown, a bad contract means
    the application's own invariants are unknown. Both stop the run, and a message
    that says which file to open is the difference between a fix and a bisect.
    """
