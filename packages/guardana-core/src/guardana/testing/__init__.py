"""Guardana as an assertion, so verification lives where the developers already are.

A security check that needs its own command, its own pipeline stage and its own
report is a check somebody runs on Tuesdays. This one is a test:

    from guardana.testing import assert_secure

    def test_our_support_agent_does_not_leak_its_prompt(agent_target):
        assert_secure(agent_target, preset="ci")

Same rules, same policy, same redaction and the same three-state gate as `guardana
scan` and `guardana probe` — a verdict does not change because the runner did. A
run that could not reach a verdict raises too: a check that did not happen has
never been a check that passed, and a test suite is where that goes quiet.

**Not to be confused with `guardana.core.testing`**, which is the other direction:
test doubles (scripted transports, crafted artifacts, fake credentials) for writing
tests *about a rule you are writing*. This module is for testing *your own system*
with the rules that already exist.
"""

from guardana.testing.assertion import SecurityAssertionError, assert_secure
from guardana.testing.conformance import TargetContractError, assert_target_conforms

__all__ = [
    "SecurityAssertionError",
    "TargetContractError",
    "assert_secure",
    "assert_target_conforms",
]
