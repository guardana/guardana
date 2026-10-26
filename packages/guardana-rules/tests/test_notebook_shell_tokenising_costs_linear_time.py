"""Reading a notebook cell's shell line costs time linear in the line, whatever its shape.

A scanned `.ipynb` is attacker-controlled, so one crafted line must not stall the scan.
"""

from _cost import growth
from guardana.rules.supply_chain._ipython_cells import (
    NotebookState,
    _define_magic_alias,
    _shell_words,
    local_scripts,
)


def test_control_a_shell_line_of_words_costs_linear_time() -> None:
    assert growth(_shell_words, "bash a.sh " * 2_000, "bash a.sh " * 8_000) < 1.3


def test_one_unquoted_run_costs_linear_time() -> None:
    assert growth(_shell_words, "!" + "a" * 100_000 + "=", "!" + "a" * 400_000 + "=") < 1.3


def test_reading_scripts_from_one_long_line_costs_linear_time() -> None:
    assert growth(local_scripts, "bash " + "a" * 100_000, "bash " + "a" * 400_000) < 1.3


def test_reading_one_long_alias_magic_line_costs_linear_time() -> None:
    def define(args: str) -> bool:
        return _define_magic_alias(args, NotebookState())

    assert growth(define, "t bash " + "a" * 100_000, "t bash " + "a" * 400_000) < 1.3
