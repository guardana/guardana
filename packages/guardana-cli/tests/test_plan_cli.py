"""`guardana plan` — and the one property that makes it worth having.

A command whose job is to say what a run will cost must not cost anything. The
first test below is the load-bearing one: it substitutes a transport that raises
on every call, so any request at all turns into a failure rather than into a
quietly larger bill.
"""

import json
from collections.abc import Sequence
from pathlib import Path

import pytest
from guardana.cli import _endpoint as endpoint_module
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.target.endpoint import ChatMessage
from typer.testing import CliRunner, Result

runner = CliRunner()


class _RefusesToBeCalled:
    """Any request at all is a test failure, which is the point of this command."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        raise AssertionError("guardana plan must not send a request")


def _probe_plan(monkeypatch: pytest.MonkeyPatch, *args: str) -> Result:
    monkeypatch.setattr(endpoint_module, "transport_factory", _RefusesToBeCalled)
    return runner.invoke(app, ["plan", "probe", "--url", "http://fake", "--model", "m", *args])


def test_planning_a_probe_sends_no_request(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _probe_plan(monkeypatch)

    assert result.exit_code == ExitCode.OK, result.output
    assert "No request was sent" in result.output


def test_a_probe_plan_states_a_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.loads(_probe_plan(monkeypatch, "--format", "json").output)

    assert payload["requests"]["max"] > 0
    assert payload["requests"]["min"] == len(payload["rules"])
    assert payload["complete"] is True, payload["unknown_cost"]


def test_a_scan_plan_lists_the_rules_it_would_run(tmp_path: Path) -> None:
    result = runner.invoke(app, ["plan", "scan", str(tmp_path), "--format", "json"])

    payload = json.loads(result.output)
    assert payload["rules"], "a scan plan that lists no rules would be describing nothing"
    assert payload["schema_version"] == 1


def test_a_narrowed_profile_produces_a_visibly_smaller_plan(tmp_path: Path) -> None:
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: narrow\nrules:\n  include: ['guardana.prompt.*']\n", encoding="utf-8")

    wide = json.loads(
        runner.invoke(app, ["plan", "scan", str(tmp_path), "--format", "json"]).output
    )
    narrow = json.loads(
        runner.invoke(
            app, ["plan", "scan", str(tmp_path), "--profile", str(profile), "--format", "json"]
        ).output
    )

    assert len(narrow["rules"]) < len(wide["rules"])


def test_a_plan_that_does_not_fit_its_budget_says_so_and_exits_three(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Found before the run rather than halfway through it — which is the entire
    # reason to have this command in a paid pipeline.
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: tight\nbudgets:\n  max_requests: 2\n", encoding="utf-8")

    result = _probe_plan(monkeypatch, "--profile", str(profile))

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "does not fit" in result.output


def test_a_plan_that_fits_its_budget_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: roomy\nbudgets:\n  max_requests: 10000\n", encoding="utf-8")

    result = _probe_plan(monkeypatch, "--profile", str(profile))

    assert result.exit_code == ExitCode.OK, result.output


def test_a_plan_document_satisfies_its_published_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The document is a contract the moment something parses it."""
    import json as _json  # noqa: PLC0415
    from pathlib import Path as _Path  # noqa: PLC0415

    from jsonschema import Draft202012Validator  # noqa: PLC0415

    schema = _json.loads(
        (_Path(__file__).resolve().parents[3] / "schemas" / "plan-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    payload = _json.loads(_probe_plan(monkeypatch, "--format", "json").output)

    Draft202012Validator(schema).validate(payload)
