"""Reading a `WWW-Authenticate` challenge costs time linear in the header, whatever its shape.

A probed server sets this header, so a crafted one must not be able to stall the parse.
"""

from _cost import growth
from guardana.core.target._mcp_authorization import challenge_parameters


def test_control_a_challenge_of_parameters_costs_linear_time() -> None:
    assert growth(challenge_parameters, 'a="x", ' * 2_000, 'a="x", ' * 8_000) < 1.3


def test_a_word_run_without_a_parameter_costs_linear_time() -> None:
    assert growth(challenge_parameters, 'Bearer realm="x", ' + "a" * 2_000, "a" * 8_000) < 1.3
