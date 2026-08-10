"""Compiling contracts: what becomes a rule, what becomes a skip, and what refuses.

The interesting half is the last two. A contract about another system must not print a
green tick, and a set of contracts none of which is about this execution must not
print one either — that is the wrong-file case, and it is the only way the
not-applicable state could become a silent pass.
"""

import pytest
from contract_fixtures import contract
from guardana.core.contract import ContractError
from guardana.core.report import ShortfallKind, SkipReason
from guardana.core.trace import Dimension
from guardana.rules.contract import compile_contract, compile_contracts

_SHELL = {"id": "no-shell", "type": "forbidden_sink", "sinks": ["shell"]}
_PAY = {"id": "pay", "type": "approval_required"}


def test_an_applicable_contract_becomes_namespaced_rules() -> None:
    compiled = compile_contract(contract(_SHELL, name="checkout"), None)

    assert [r.meta.id for r in compiled.rules] == ["contract.checkout.no-shell"]


def test_a_contract_about_another_system_is_skipped_and_demands_nothing() -> None:
    """Not applicable is recorded and printed — and it is not a coverage gap.

    Nothing is missing when a contract is about something else, so `fail_on_skipped`
    must not fire on it. And a contract that is not about this execution has no
    standing to require evidence of it either.
    """
    compiled = compile_contract(
        contract(_PAY, name="checkout", applies_to={"ai_system": "checkout-agent"}),
        "support-agent",
    )

    assert compiled.rules == ()
    assert compiled.required_dimensions == ()
    (skip,) = compiled.skipped
    assert skip.reason is SkipReason.NOT_APPLICABLE
    assert skip.is_coverage_gap is False


def test_a_contract_naming_the_system_under_test_applies() -> None:
    compiled = compile_contract(
        contract(_PAY, name="checkout", applies_to={"ai_system": "checkout-agent"}),
        "checkout-agent",
    )

    assert len(compiled.rules) == 1
    assert compiled.required_dimensions == (Dimension.APPROVAL, Dimension.EFFECTS)


def test_contracts_that_all_turn_out_not_to_apply_refuse_the_run() -> None:
    """The wrong-file case: a pipeline pointed at the wrong trace, or a renamed system."""
    compiled = compile_contracts(
        [
            contract(_SHELL, name="checkout", applies_to={"ai_system": "checkout-agent"}),
            contract(_PAY, name="support", applies_to={"ai_system": "support-agent"}),
        ],
        "billing-agent",
    )

    assert compiled.rules == ()
    (gap,) = compiled.shortfall
    assert gap.kind is ShortfallKind.CONTRACT_NOT_APPLICABLE


def test_one_applicable_contract_among_several_is_enough() -> None:
    """A team with one contract per agent must not be punished for pointing all of them."""
    compiled = compile_contracts(
        [
            contract(_SHELL, name="checkout", applies_to={"ai_system": "checkout-agent"}),
            contract(_PAY, name="support", applies_to={"ai_system": "support-agent"}),
        ],
        "checkout-agent",
    )

    assert [r.meta.id for r in compiled.rules] == ["contract.checkout.no-shell"]
    assert compiled.shortfall == ()
    assert len(compiled.skipped) == 1


def test_no_contracts_at_all_is_not_a_shortfall() -> None:
    """Not loading contracts is a choice; loading them and grading none is a mistake."""
    assert compile_contracts([], None).shortfall == ()


def test_two_contracts_producing_one_rule_id_are_refused() -> None:
    """The registry is last-one-wins, so one team's invariants would silently vanish."""
    with pytest.raises(ContractError, match="two contracts produce the rule id"):
        compile_contracts(
            [contract(_SHELL, name="checkout"), contract(_SHELL, name="checkout")], None
        )


def test_the_digest_moves_when_an_assertion_is_weakened() -> None:
    """A widened allow-list must read as a changed test, not as a target that got worse.

    The base `Rule.digest()` covers `meta`, which is identical for two assertions of
    one kind differing only in their parameters — so `diff` would have reported the new
    findings as a regression in the system rather than a change in the check.
    """
    strict = compile_contract(
        contract({"id": "s", "type": "allowed_scopes", "allow": ["payments.read"]}), None
    ).rules[0]
    loose = compile_contract(
        contract({"id": "s", "type": "allowed_scopes", "allow": ["payments.*", "users.*"]}), None
    ).rules[0]

    assert strict.meta.id == loose.meta.id
    assert strict.digest() != loose.digest()


def test_a_compiled_assertion_declares_it_sends_nothing() -> None:
    """`plan` prints "plus N rules of unknown cost", and reading a file is not unknown."""
    assert compile_contract(contract(_SHELL), None).rules[0].estimated_requests == 0


def test_the_shipped_example_contract_loads_and_compiles() -> None:
    """The example in `examples/contracts/` is documentation people will copy.

    A sample that no longer parses teaches the schema wrong, and it is the first
    file anybody writing their own will start from — so it is loaded through the
    real loader here rather than described in prose.
    """
    from pathlib import Path  # noqa: PLC0415

    from guardana.core.contract import load_contract  # noqa: PLC0415

    path = Path(__file__).resolve().parents[4] / "examples" / "contracts" / "checkout-agent.yaml"
    loaded = load_contract(path)

    compiled = compile_contract(loaded, "checkout-agent")

    assert len(compiled.rules) == len(loaded.assertions)
    assert compile_contract(loaded, "support-agent").rules == ()
