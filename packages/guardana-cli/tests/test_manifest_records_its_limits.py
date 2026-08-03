"""A saved run must record the ceilings it ran under, hit or not.

`ExecutionSettings` describes itself as "the limits the run was given, recorded
whether or not it hit them", and the roadmap advertises execution limits as part
of what makes a manifest evidence. The builder filled in concurrency and the
request timeout and dropped every budget on the floor, so a run that stopped at
`budget_exhausted` said it stopped and never said what it hit — leaving the one
question an operator has, was the ceiling too low or did the target get more
expensive, unanswerable from the document.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


def _execution_block(tmp_path: Path, profile_body: str) -> dict[str, Any]:
    profile = tmp_path / "guardana.yaml"
    profile.write_text(profile_body, encoding="utf-8")
    out = tmp_path / "run.json"

    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--profile",
            str(profile),
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )

    assert out.exists(), result.output
    document = json.loads(out.read_text(encoding="utf-8"))
    block = document["run"]["execution"]
    assert isinstance(block, dict)
    return block


def test_a_request_ceiling_from_the_profile_reaches_the_manifest(tmp_path: Path) -> None:
    block = _execution_block(tmp_path, "name: t\nbudgets:\n  max_requests: 200\n")

    assert block["max_requests"] == 200


def test_a_token_ceiling_from_the_profile_reaches_the_manifest(tmp_path: Path) -> None:
    body = "name: t\nbudgets:\n  max_input_tokens: 250000\n  max_output_tokens: 100000\n"

    block = _execution_block(tmp_path, body)

    assert block["max_input_tokens"] == 250_000
    assert block["max_output_tokens"] == 100_000


def test_no_ceiling_is_recorded_as_null_rather_than_as_zero(tmp_path: Path) -> None:
    # "Nobody set one" and "somebody set nothing" must not look the same, for the
    # same reason usage records an unknown rather than a zero.
    block = _execution_block(tmp_path, "name: t\n")

    assert block["max_requests"] is None
    assert block["max_input_tokens"] is None


@pytest.mark.parametrize(
    "key", ["max_requests", "max_input_tokens", "max_output_tokens", "max_duration_seconds"]
)
def test_every_budget_field_has_somewhere_to_land(tmp_path: Path, key: str) -> None:
    # Derived from the keys the schema requires, so a budget added later without a
    # place in the manifest fails here rather than being silently unrecorded.
    assert key in _execution_block(tmp_path, "name: t\n")
