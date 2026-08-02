"""`doctor` is the command a support conversation should start with.

Two properties matter more than the output format. It must contact nothing — a
diagnostic that costs money or shows up in production logs is one people avoid —
and it must name the settings that weaken a gate, because a gate somebody thinks
they configured and did not is worse than no gate.
"""

import json
from pathlib import Path

import pytest
from guardana.cli import _endpoint as endpoint_module
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


class _Explodes:
    """Any network call at all fails the test."""

    def send(self, *args: object, **kwargs: object) -> str:
        raise AssertionError("doctor must not contact anything")


def test_doctor_contacts_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", _Explodes)

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == ExitCode.OK, result.output


def test_doctor_reports_the_installed_distributions() -> None:
    result = runner.invoke(app, ["doctor"])

    assert "guardana-core" in result.output
    assert "guardana-rules" in result.output


def test_doctor_reports_how_many_rules_were_discovered() -> None:
    result = runner.invoke(app, ["doctor"])

    assert "rules discovered" in result.output


def test_doctor_warns_when_the_gate_is_weakened(tmp_path: Path) -> None:
    # Each of these is a legitimate choice; making it silently is what must not
    # happen.
    profile = tmp_path / "guardana.yaml"
    profile.write_text(
        "name: loose\nfail_on:\n  fail_on_error: false\nrules:\n  exclude: ['guardana.prompt.*']\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["doctor", "--profile", str(profile)])

    assert "fail_on_error" in result.output
    assert "rules.exclude" in result.output


def test_doctor_fails_when_no_rules_were_discovered() -> None:
    # An installation that can check nothing is broken, not merely unusual.
    result = runner.invoke(app, ["doctor", "--plugins", "disabled"])

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "rules discovered: 0" in result.output


def test_config_validate_accepts_a_good_profile(tmp_path: Path) -> None:
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: ci\nbudgets:\n  max_requests: 50\n", encoding="utf-8")

    result = runner.invoke(app, ["config", "validate", "--profile", str(profile)])

    assert result.exit_code == ExitCode.OK, result.output


def test_config_validate_refuses_a_bad_profile(tmp_path: Path) -> None:
    # Fails early, before a pipeline pays for a probe.
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: ci\nbudgets:\n  max_requsts: 50\n", encoding="utf-8")

    result = runner.invoke(app, ["config", "validate", "--profile", str(profile)])

    assert result.exit_code == ExitCode.INVALID_USAGE


def test_config_explain_shows_defaults_the_file_never_mentioned(tmp_path: Path) -> None:
    """The point of the command: most of a gate is defaults, and an unseen default
    is one nobody checked."""
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: ci\n", encoding="utf-8")

    result = runner.invoke(
        app, ["config", "explain", "--profile", str(profile), "--format", "json"]
    )

    resolved = json.loads(result.output)
    assert resolved["fail_on"]["severity"] == "HIGH"
    assert resolved["fail_on"]["fail_on_error"] is True
    assert resolved["privacy"]["evidence_mode"] == "redacted"
    assert resolved["safety"]["max_impact"] == "active"


def test_config_explain_records_the_privacy_policy_digest(tmp_path: Path) -> None:
    # The same digest the manifest records, so a run and a profile can be matched
    # up after the fact.
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: ci\n", encoding="utf-8")

    result = runner.invoke(
        app, ["config", "explain", "--profile", str(profile), "--format", "json"]
    )

    assert json.loads(result.output)["privacy"]["policy_digest"].startswith("sha256:")
