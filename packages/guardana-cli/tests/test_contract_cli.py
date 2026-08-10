"""`analyze-trace --contract` — four outcomes, and only one of them is exit `0`.

The exit codes are the contract feature's real interface: a pipeline reads them and
nothing else. So each of the four paths is pinned here, including the two that used to
be one — a contract that could not be checked and a contract that was about another
system both used to look exactly like a contract that held.
"""

from pathlib import Path

from guardana.cli.main import app
from guardana.core.trace import (
    Dimension,
    EffectStatus,
    Provenance,
    SideEffect,
    SinkKind,
    Span,
    SpanKind,
    Trace,
    serialize_trace,
)
from typer.testing import CliRunner, Result

runner = CliRunner()

_CONTRACT = """
schema_version: 1
name: checkout
applies_to:
  ai_system: checkout-agent
assertions:
  - id: never-shell
    type: forbidden_sink
    title: The checkout agent has no business running a shell
    severity: critical
    sinks: [shell]
"""

_NEEDS_APPROVAL = """
schema_version: 1
name: approvals
assertions:
  - id: refunds-need-a-human
    type: approval_required
    actions: ["payment.*"]
"""


def _trace_file(tmp_path: Path, *records: Dimension, ran_a_shell: bool = False) -> Path:
    effects = [
        SideEffect(sink=SinkKind.PAYMENT, action="payment.refund", status=EffectStatus.EXECUTED)
    ]
    if ran_a_shell:
        effects.append(SideEffect(sink=SinkKind.SHELL, action="sh", status=EffectStatus.ATTEMPTED))
    trace = Trace(
        trace_id="t-1",
        spans=(
            Span(span_id="s1", kind=SpanKind.TOOL_EXECUTION, name="refund", effects=tuple(effects)),
        ),
        provenance=Provenance(producer="acme", source="a.jsonl", dialect="guardana"),
        instrumented=frozenset(records),
    )
    path = tmp_path / "trace.jsonl"
    path.write_text(serialize_trace(trace), encoding="utf-8")
    return path


def _contract_file(tmp_path: Path, body: str, name: str = "contract.yaml") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def _run(*args: str) -> "Result":
    return runner.invoke(app, ["analyze-trace", *args])


def test_an_applicable_contract_whose_invariant_holds_passes(tmp_path: Path) -> None:
    result = _run(
        str(_trace_file(tmp_path, Dimension.EFFECTS)),
        "--contract",
        str(_contract_file(tmp_path, _CONTRACT)),
        "--ai-system",
        "checkout-agent",
    )

    assert result.exit_code == 0, result.output
    assert "1 assertion(s) apply" in result.output


def test_an_applicable_contract_whose_invariant_breaks_fails(tmp_path: Path) -> None:
    result = _run(
        str(_trace_file(tmp_path, Dimension.EFFECTS, ran_a_shell=True)),
        "--contract",
        str(_contract_file(tmp_path, _CONTRACT)),
        "--ai-system",
        "checkout-agent",
    )

    assert result.exit_code == 1, result.output
    assert "contract.checkout.never-shell" in result.output


def test_a_contract_needing_evidence_the_producer_does_not_record_is_indeterminate(
    tmp_path: Path,
) -> None:
    """The meeting point of both halves, and the default that used to be exit `0`.

    The assertion is skipped for a missing capability, and `fail_on_skipped` defaults
    to false — so without the shortfall channel this run would print "no findings" and
    green-light a build on an invariant nothing checked.

    `identity` is recorded as well as `effects` so that a built-in rule actually runs.
    Without it this test passed for the wrong reason: `0 rules ran` is its own
    indeterminate branch, and the assertion would have held with the shortfall check
    deleted outright.
    """
    result = _run(
        str(_trace_file(tmp_path, Dimension.EFFECTS, Dimension.IDENTITY)),
        "--contract",
        str(_contract_file(tmp_path, _NEEDS_APPROVAL)),
    )

    assert "rule(s) run" in result.output
    assert " 0 rule(s) run" not in result.output, "otherwise the empty-plan branch decides this"
    assert result.exit_code == 2, result.output
    assert "requires approval evidence" in result.output


def test_a_run_where_no_contract_was_about_this_execution_is_indeterminate(
    tmp_path: Path,
) -> None:
    """The wrong-file case: green would mean "none of your invariants were graded".

    Built-in rules do run here — that is the point. The run is otherwise a perfectly
    ordinary pass, and it is the unapplied contract alone that takes the verdict away.
    """
    result = _run(
        str(_trace_file(tmp_path, Dimension.EFFECTS, Dimension.IDENTITY)),
        "--contract",
        str(_contract_file(tmp_path, _CONTRACT)),
        "--ai-system",
        "support-agent",
    )

    assert " 0 rule(s) run" not in result.output, "otherwise the empty-plan branch decides this"
    assert result.exit_code == 2, result.output
    assert "none of them is about" in result.output


def test_a_contract_naming_a_system_refuses_when_none_was_given(tmp_path: Path) -> None:
    """ "I cannot tell whether this applies" must resolve to neither answer."""
    result = _run(
        str(_trace_file(tmp_path, Dimension.EFFECTS)),
        "--contract",
        str(_contract_file(tmp_path, _CONTRACT)),
    )

    assert result.exit_code == 3, result.output
    assert "no --ai-system was given" in result.output


def test_a_mistyped_contract_path_is_refused_rather_than_contributing_nothing(
    tmp_path: Path,
) -> None:
    """It would otherwise run the built-ins, grade no invariant, and exit `0`."""
    result = _run(
        str(_trace_file(tmp_path, Dimension.EFFECTS)),
        "--contract",
        str(tmp_path / "typo.yaml"),
    )

    assert result.exit_code == 3, result.output
    assert "does not exist" in result.output


def test_a_malformed_contract_is_refused_and_never_downgraded_to_a_warning(
    tmp_path: Path,
) -> None:
    result = _run(
        str(_trace_file(tmp_path, Dimension.EFFECTS)),
        "--contract",
        str(_contract_file(tmp_path, "schema_version: 1\nname: a\nassertoins: []\n")),
    )

    assert result.exit_code == 3, result.output
    assert "unknown contract key" in result.output


def test_a_directory_of_contracts_loads_every_file_in_it(tmp_path: Path) -> None:
    directory = tmp_path / "contracts"
    directory.mkdir()
    _contract_file(directory, _NEEDS_APPROVAL.replace("approvals", "one"), "one.yaml")
    _contract_file(directory, _NEEDS_APPROVAL.replace("approvals", "two"), "two.yaml")

    result = _run(
        str(_trace_file(tmp_path, Dimension.EFFECTS, Dimension.APPROVAL)),
        "--contract",
        str(directory),
    )

    assert result.exit_code == 1, result.output
    assert "2 assertion(s) apply" in result.output


def test_a_directory_with_no_contracts_is_refused(tmp_path: Path) -> None:
    """Loading nothing from a path somebody named is the silent half of a fail-open."""
    directory = tmp_path / "empty"
    directory.mkdir()

    result = _run(str(_trace_file(tmp_path, Dimension.EFFECTS)), "--contract", str(directory))

    assert result.exit_code == 3, result.output
    assert "contains no .yaml" in result.output


def test_contracts_can_be_configured_once_in_a_profile(tmp_path: Path) -> None:
    contract = _contract_file(tmp_path, _CONTRACT)
    profile = tmp_path / "guardana.yaml"
    profile.write_text(f"name: t\ncontracts: ['{contract}']\n", encoding="utf-8")

    result = _run(
        str(_trace_file(tmp_path, Dimension.EFFECTS, ran_a_shell=True)),
        "--profile",
        str(profile),
        "--ai-system",
        "checkout-agent",
    )

    assert result.exit_code == 1, result.output
    assert "contract.checkout.never-shell" in result.output


def test_an_assertion_the_policy_excluded_demands_no_evidence(tmp_path: Path) -> None:
    """The demand belongs to the assertion, so switching the assertion off withdraws it.

    A contract's requirement is *implied by* an assertion, unlike `trace.require:`,
    which the operator states outright. Keeping the implication alive after the policy
    dropped the rule turns off a check and then fails the build for not having run it —
    an accusation with no accuser, and the fastest route to a team deleting the whole
    mechanism from its pipeline.
    """
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: t\nrules:\n  exclude: ['contract.approvals.*']\n", encoding="utf-8")

    result = _run(
        str(_trace_file(tmp_path, Dimension.EFFECTS, Dimension.IDENTITY)),
        "--contract",
        str(_contract_file(tmp_path, _NEEDS_APPROVAL)),
        "--profile",
        str(profile),
    )

    assert " 0 rule(s) run" not in result.output, "otherwise the empty-plan branch decides this"
    assert "requires approval evidence" not in result.output
    assert result.exit_code == 0, result.output


def test_an_excluded_assertion_is_never_reported_as_one_that_applied(tmp_path: Path) -> None:
    """Withdrawing the demand must not also withdraw the sentence saying it was withdrawn.

    "1 assertion(s) apply to this execution" over a green report reads as "your
    invariant held". Said about a rule this run will not execute, it is false in the
    one direction this project cannot afford, so the exclusion is printed beside it.
    """
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: t\nrules:\n  exclude: ['contract.approvals.*']\n", encoding="utf-8")

    result = _run(
        str(_trace_file(tmp_path, Dimension.EFFECTS, Dimension.APPROVAL)),
        "--contract",
        str(_contract_file(tmp_path, _NEEDS_APPROVAL)),
        "--profile",
        str(profile),
    )

    assert "contract.approvals.refunds-need-a-human" in result.output
    assert "excluded by this run's policy" in result.output


def test_an_assertion_the_policy_kept_still_demands_its_evidence(tmp_path: Path) -> None:
    """The other half of the same switch, so the fix cannot be "stop demanding anything".

    An `exclude:` aimed at a different rule leaves this assertion running, and a
    producer that records no approvals still takes the verdict away.
    """
    profile = tmp_path / "guardana.yaml"
    profile.write_text(
        "name: t\nrules:\n  exclude: ['contract.something-else.*']\n", encoding="utf-8"
    )

    result = _run(
        str(_trace_file(tmp_path, Dimension.EFFECTS, Dimension.IDENTITY)),
        "--contract",
        str(_contract_file(tmp_path, _NEEDS_APPROVAL)),
        "--profile",
        str(profile),
    )

    assert result.exit_code == 2, result.output
    assert "requires approval evidence" in result.output


def test_an_explicit_trace_require_survives_a_policy_that_excludes_every_rule(
    tmp_path: Path,
) -> None:
    """`trace.require:` is the operator's own sentence, not an implication of a rule.

    It is what a team writes when it is paying for instrumentation and wants to know
    when it did not arrive, and no rule has to want the dimension for that to be a
    fair thing to demand. So it holds where a contract's implied demand gives way.
    """
    profile = tmp_path / "guardana.yaml"
    profile.write_text(
        "name: t\nrules:\n  exclude: ['*']\ntrace:\n  require: [approval]\n", encoding="utf-8"
    )

    result = _run(str(_trace_file(tmp_path, Dimension.EFFECTS)), "--profile", str(profile))

    assert result.exit_code == 2, result.output
    assert "requires approval evidence" in result.output


def test_the_saved_run_records_why_it_was_indeterminate(tmp_path: Path) -> None:
    """A conclusion with no cause in its own evidence is a conclusion nobody can act on."""
    import json  # noqa: PLC0415

    output = tmp_path / "run.json"
    result = _run(
        str(_trace_file(tmp_path, Dimension.EFFECTS)),
        "--contract",
        str(_contract_file(tmp_path, _NEEDS_APPROVAL)),
        "--format",
        "json",
        "--output",
        str(output),
    )

    assert result.exit_code == 2, result.output
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["run"]["result_summary"]["gate"] == "indeterminate"
    assert document["run"]["coverage"]["shortfall"] == [
        {
            "kind": "missing_dimension",
            "name": "approval",
            "detail": document["run"]["coverage"]["shortfall"][0]["detail"],
        }
    ]
