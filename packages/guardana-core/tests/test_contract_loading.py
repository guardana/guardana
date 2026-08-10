"""A contract is a document a team keeps, so every way of misreading one is refused here.

The failure this file exists to prevent is not a crash. It is a contract that loads
*partially* — a misspelled key dropped, a selector coerced from a string into
single-character globs, an assertion silently absent — and produces a run that grades
nothing and exits `0`. That is a gate somebody believes they configured and did not,
which this repository holds to be worse than no gate at all.
"""

from pathlib import Path

import pytest
from guardana.core.contract import (
    CONTRACT_SCHEMA_VERSION,
    AllowedScopes,
    ApprovalRequired,
    ContractError,
    CredentialBoundary,
    ForbiddenSink,
    TenantBoundary,
    contract_from_dict,
    load_contract,
)
from guardana.core.severity import Severity
from guardana.core.trace import Dimension, EffectStatus


def _document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "name": "checkout",
        "assertions": [{"id": "never-shell", "type": "forbidden_sink", "sinks": ["shell"]}],
    }
    return {**document, **overrides}


def _load(**overrides: object) -> object:
    return contract_from_dict(_document(**overrides), source="memory")


def test_a_contract_reads_into_typed_assertions() -> None:
    contract = contract_from_dict(
        _document(
            assertions=[
                {"id": "one-tenant", "type": "tenant_boundary", "sources": ["kb://*"]},
                {"id": "pay", "type": "approval_required", "actions": ["payment.*"]},
                {"id": "scopes", "type": "allowed_scopes", "allow": ["payments.*"]},
                {"id": "no-token", "type": "credential_boundary", "boundaries": ["https://*"]},
                {"id": "no-shell", "type": "forbidden_sink", "sinks": ["shell"]},
            ]
        ),
        source="memory",
    )

    kinds = [type(a) for a in contract.assertions]
    assert kinds == [
        TenantBoundary,
        ApprovalRequired,
        AllowedScopes,
        CredentialBoundary,
        ForbiddenSink,
    ]


def test_the_required_dimensions_are_the_union_of_what_the_assertions_need() -> None:
    """The set the gate demands comes from the assertions, so nobody has to restate it.

    Two tables — one for what a rule needs to run and one for what the run requires —
    would eventually disagree, and the disagreement would be an assertion that is
    skipped and reported clean in the same run.
    """
    contract = contract_from_dict(
        _document(
            assertions=[
                {"id": "pay", "type": "approval_required"},
                {"id": "no-shell", "type": "forbidden_sink", "sinks": ["shell"]},
                {"id": "scopes", "type": "allowed_scopes", "allow": ["a"]},
            ]
        ),
        source="memory",
    )

    assert contract.required_dimensions() == (
        Dimension.APPROVAL,
        Dimension.EFFECTS,
        Dimension.DELEGATION,
    )


def test_a_contract_with_no_schema_version_is_refused() -> None:
    """A document with no version is exactly the one whose meaning cannot be pinned later."""
    document = _document()
    del document["schema_version"]

    with pytest.raises(ContractError, match="no schema_version"):
        contract_from_dict(document, source="memory")


def test_a_contract_from_a_future_version_is_refused_rather_than_read_optimistically() -> None:
    """A newer writer may have changed the meaning of a key this reader still recognises.

    Grading an application against a contract that was misunderstood is worse than
    grading it against none: the report looks like the invariants were checked.
    """
    with pytest.raises(ContractError, match="schema_version 99"):
        _load(schema_version=99)


@pytest.mark.parametrize("version", ["1", 1.5, True])
def test_a_non_integer_schema_version_is_refused(version: object) -> None:
    with pytest.raises(ContractError, match="whole number"):
        _load(schema_version=version)


def test_an_unknown_top_level_key_is_refused() -> None:
    """A misspelled `assertoins:` would load as a contract that checks nothing."""
    with pytest.raises(ContractError, match="unknown contract key"):
        _load(assertoins=[])


def test_an_unknown_assertion_key_is_refused() -> None:
    """Per-kind, so `sinks:` on a scope assertion is caught rather than ignored."""
    with pytest.raises(ContractError, match="unknown allowed_scopes assertion key"):
        _load(assertions=[{"id": "a", "type": "allowed_scopes", "allow": ["x"], "sinks": ["sql"]}])


def test_an_unknown_assertion_type_is_refused() -> None:
    with pytest.raises(ContractError, match="unknown assertion type"):
        _load(assertions=[{"id": "a", "type": "tenant_boundry"}])


def test_a_contract_with_no_assertions_is_refused() -> None:
    """It would report clean on every execution, which is the shape of a fake gate."""
    with pytest.raises(ContractError, match="non-empty list"):
        _load(assertions=[])


def test_two_assertions_sharing_an_id_are_refused() -> None:
    """The registry is keyed by rule id and last one wins, so one would replace the other."""
    with pytest.raises(ContractError, match="share the id"):
        _load(
            assertions=[
                {"id": "a", "type": "forbidden_sink", "sinks": ["shell"]},
                {"id": "a", "type": "forbidden_sink", "sinks": ["sql"]},
            ]
        )


@pytest.mark.parametrize("name", ["Checkout", "check.out", "-checkout", "", "check out", "a*b"])
def test_a_name_that_would_break_a_rule_id_is_refused(name: object) -> None:
    """The name becomes part of a rule id, which profiles glob on and baselines waive by.

    A dot is the one worth naming: `contract.check.out.a` would let an `exclude:`
    pattern somebody wrote for a different contract swallow this one's namespace. A
    `*` is worse — it is a glob, in a string that becomes the thing globs match.
    """
    with pytest.raises(ContractError, match="lower-case letters"):
        _load(name=name)


def test_a_selector_written_as_a_string_is_refused_rather_than_exploded() -> None:
    """YAML accepts `sinks: shell`, and `tuple()` of it is six globs that match nothing.

    An assertion that matches nothing reports clean on every execution, so this is a
    hard error rather than a coercion — the same treatment `rules.include` gets.
    """
    with pytest.raises(ContractError, match="must be a list of strings"):
        _load(assertions=[{"id": "a", "type": "forbidden_sink", "sinks": "shell"}])


def test_a_sink_the_model_does_not_have_is_refused() -> None:
    """`SinkKind` is closed so a typo cannot become a sink no effect ever matches."""
    with pytest.raises(ContractError, match="unknown sink"):
        _load(assertions=[{"id": "a", "type": "forbidden_sink", "sinks": ["sql_server"]}])


def test_a_forbidden_sink_with_no_sinks_is_refused() -> None:
    with pytest.raises(ContractError, match="'sinks' is required"):
        _load(assertions=[{"id": "a", "type": "forbidden_sink"}])


def test_an_empty_allow_list_is_refused_rather_than_read_as_allow_nothing() -> None:
    """Both readings are defensible, which is precisely why the document must say which."""
    with pytest.raises(ContractError, match="matches nothing"):
        _load(assertions=[{"id": "a", "type": "allowed_scopes", "allow": []}])


def test_a_credential_boundary_with_no_boundaries_is_refused() -> None:
    with pytest.raises(ContractError, match="'boundaries' is required"):
        _load(assertions=[{"id": "a", "type": "credential_boundary"}])


def test_an_unknown_severity_is_refused() -> None:
    with pytest.raises(ContractError, match="unknown severity"):
        _load(
            assertions=[
                {"id": "a", "type": "forbidden_sink", "sinks": ["shell"], "severity": "bad"}
            ]
        )


def test_severity_defaults_to_high_and_is_the_team_s_own_judgement() -> None:
    contract = contract_from_dict(_document(), source="memory")
    assert contract.assertions[0].severity is Severity.HIGH

    louder = contract_from_dict(
        _document(
            assertions=[
                {"id": "a", "type": "forbidden_sink", "sinks": ["shell"], "severity": "critical"}
            ]
        ),
        source="memory",
    )
    assert louder.assertions[0].severity is Severity.CRITICAL


def test_forbidden_sink_counts_an_attempt_by_default_and_not_a_refusal() -> None:
    """An agent stopped mid-reach still reached; a failure is the system refusing."""
    contract = contract_from_dict(_document(), source="memory")
    assertion = contract.assertions[0]
    assert isinstance(assertion, ForbiddenSink)
    assert assertion.statuses == (EffectStatus.EXECUTED, EffectStatus.ATTEMPTED)


def test_an_unknown_effect_status_is_refused() -> None:
    with pytest.raises(ContractError, match="unknown effect status"):
        _load(
            assertions=[
                {"id": "a", "type": "forbidden_sink", "sinks": ["shell"], "statuses": ["maybe"]}
            ]
        )


def test_an_empty_applies_to_system_is_refused_rather_than_matching_nothing() -> None:
    with pytest.raises(ContractError, match=r"applies_to\.ai_system' is empty"):
        _load(applies_to={"ai_system": "  "})


def test_a_contract_naming_a_system_refuses_to_guess_when_none_was_given() -> None:
    """The branch this exists for: "I cannot tell" has two wrong answers and no right one.

    Applying it grades the wrong application; skipping it reports clean on a system
    nobody checked.
    """
    contract = contract_from_dict(_document(applies_to={"ai_system": "checkout"}), source="memory")

    assert contract.applies_to_system("checkout") is True
    assert contract.applies_to_system("support") is False
    with pytest.raises(ContractError, match="no --ai-system was given"):
        contract.applies_to_system(None)


def test_a_contract_naming_no_system_applies_to_whatever_it_is_pointed_at() -> None:
    contract = contract_from_dict(_document(), source="memory")
    assert contract.applies_to_system(None) is True
    assert contract.applies_to_system("anything") is True


def test_a_file_that_is_not_a_mapping_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_text("- just\n- a list\n", encoding="utf-8")

    with pytest.raises(ContractError, match="top level must be a mapping"):
        load_contract(path)


def test_an_unreadable_file_is_refused_with_its_path(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="cannot read contract"):
        load_contract(tmp_path / "missing.yaml")
