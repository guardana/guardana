"""Two documents Guardana writes and never reads back.

A comparison and a plan are produced for somebody else's pipeline: nothing here
loads one, so there is no reader to disagree with the writer, and the usual
round trip has no second half. What stands in for the reader is the **published
schema**, which is what a consumer builds against — and a schema that would accept
the document with a key removed is a schema that is not holding the writer to
anything.

So the two questions become: does every field of the dataclass reach the document,
and does the published contract actually require what the document carries. The
first is asked by emptying each field in turn rather than by naming them, because a
list of names is what the next added field escapes.
"""

import json
from dataclasses import fields, is_dataclass, replace
from pathlib import Path
from typing import Any, TypeVar, cast

import pytest
from _roundtrip import Document, key_paths, render, without
from guardana.cli.plan import PLAN_SCHEMA_VERSION, _render_json
from guardana.core.budget import Budgets
from guardana.core.diff.model import Change, ChangeKind, CheckState, RunDiff
from guardana.core.plan import RunPlan
from guardana.core.severity import Severity
from guardana.report import get_diff_renderer
from jsonschema import Draft202012Validator

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"

_EMPTY: dict[type, object] = {int: 0, float: 0.0, bool: False, str: "", tuple: ()}


def _validator(name: str) -> Draft202012Validator:
    schema: dict[str, Any] = json.loads((_SCHEMAS / name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def _diff() -> RunDiff:
    """A comparison with every field carrying something, both change directions included."""
    before = CheckState(
        outcome="unverified", severity=Severity.LOW, confidence=0.8, count=1, waived=False
    )
    after = CheckState(
        outcome="fail", severity=Severity.HIGH, confidence=0.95, count=3, waived=True
    )
    return RunDiff(
        changes=(
            Change(
                kind=ChangeKind.ESCALATED,
                rule_id="guardana.prompt.system_prompt_leak.canary",
                location="http://model.invalid/v1",
                detail="the canary came back where it did not before",
                before=before,
                after=after,
                rule_changed=True,
            ),
        ),
        unchanged=7,
        notes=("the tool version changed between these runs",),
        incomplete=("the second run stopped when its request budget ran out",),
    )


def _plan() -> RunPlan:
    """A plan with every field carrying something, including the one that keeps it honest."""
    return RunPlan(
        rules=("guardana.prompt.system_prompt_leak.canary",),
        skipped=("guardana.mcp.tool_poisoning",),
        unknown_cost=("acme.agent.customer_data",),
        min_requests=4,
        max_requests=12,
        budgets=Budgets(
            max_requests=100,
            max_input_tokens=50_000,
            max_output_tokens=25_000,
            max_duration_seconds=90.5,
        ),
    )


_Document = TypeVar("_Document", RunDiff, RunPlan)


def _emptied(value: _Document, name: str) -> _Document:
    """The same document with one field cleared, so its absence has to show in the output."""
    current = getattr(value, name)
    # A nested block empties to one where every ceiling is unset, which is the real
    # "this run declared no budget" case rather than a synthetic blank.
    blank: Any = cast("Any", type(current))() if is_dataclass(current) else _EMPTY[type(current)]
    return replace(value, **{name: blank})


@pytest.mark.parametrize("name", [f.name for f in fields(RunDiff)])
def test_every_field_of_a_comparison_reaches_the_document(name: str) -> None:
    """Emptied one at a time, because a field written nowhere costs a reader the change itself."""
    render_json = get_diff_renderer("json").render

    assert render_json(_diff()) != render_json(_emptied(_diff(), name)), (
        f"clearing RunDiff.{name} changes nothing in the rendered comparison, so the "
        f"field never reaches the document a pipeline reads"
    )


@pytest.mark.parametrize("name", [f.name for f in fields(RunPlan)])
def test_every_field_of_a_plan_reaches_the_document(name: str) -> None:
    assert _render_json(_plan()) != _render_json(_emptied(_plan(), name)), (
        f"clearing RunPlan.{name} changes nothing in the rendered plan, so the field "
        f"never reaches the document a pipeline reads"
    )


def _unrequired(document: Document, schema: str) -> list[str]:
    """Every key the document carries that its published schema would accept missing."""
    validator = _validator(schema)
    return [
        render(path, "document")
        for path in key_paths(document)
        if not list(validator.iter_errors(without(document, path)))
    ]


def test_the_published_diff_schema_requires_every_key_the_writer_emits() -> None:
    """The reader a written-only document has is whoever validates it, so it has to bite.

    A key the schema would accept missing is a key a consumer cannot rely on being
    there — and for a comparison, the keys that go missing are the ones that say the
    comparison was incomplete.
    """
    document: Document = json.loads(get_diff_renderer("json").render(_diff()))

    optional = _unrequired(document, "diff-v1.schema.json")

    assert not optional, (
        "keys the comparison writes that `diff-v1.schema.json` does not require, so a "
        "consumer validating against it is not promised them:\n  " + "\n  ".join(optional)
    )


def test_the_published_plan_schema_requires_every_key_the_writer_emits() -> None:
    document: Document = json.loads(_render_json(_plan()))

    optional = _unrequired(document, "plan-v1.schema.json")

    assert not optional, (
        "keys the plan writes that `plan-v1.schema.json` does not require:\n  "
        + "\n  ".join(optional)
    )


def test_the_plan_document_declares_the_version_the_code_writes() -> None:
    assert json.loads(_render_json(_plan()))["schema_version"] == PLAN_SCHEMA_VERSION
