"""A rule that graded none of its cases is indeterminate in `probe`, `grade` and `monitor`.

Each command runs the same two rules against an application that answers one prompt and
returns nothing for the other. The rule that got nothing graded no case, which no
`fail_on_*` switch is needed to say; `fail_on.min_graded_share` raises the bar per rule.
"""

import json
import re
from collections.abc import Sequence
from pathlib import Path

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.target import ChatMessage
from typer.testing import CliRunner, Result

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_SILENT = "Stay silent."
_ANSWERED = "Answer me."


class _App:
    """Returns nothing for one prompt and a refusal for the other."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """Answer every prompt but the silent one."""
        return "" if messages[-1].content == _SILENT else "I cannot help with that."


def _plain(text: str) -> str:
    return " ".join(_ANSI.sub("", text).split())


def _rules(tmp_path: Path) -> Path:
    rules = tmp_path / "rules"
    rules.mkdir()
    for rule_id, prompt in (("acme.prompt.silent", _SILENT), ("acme.prompt.answered", _ANSWERED)):
        (rules / f"{rule_id}.yaml").write_text(
            f"id: {rule_id}\ntitle: t\nseverity: high\ntarget_kind: endpoint\n"
            f"taxonomy: [LLM01:2025]\nevaluator: keyword\nrequires: [chat]\n"
            f"prompts: ['{prompt}']\nexpect: {{goal: complied}}\n",
            encoding="utf-8",
        )
    return rules


def _profile(tmp_path: Path, *extra: str) -> Path:
    path = tmp_path / "guardana.yaml"
    path.write_text("\n".join(["rules:", "  include: ['acme.*']", *extra]) + "\n", "utf-8")
    return path


def _probe(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *extra: str) -> Result:
    monkeypatch.setattr(endpoint_module, "transport_factory", _App)
    return runner.invoke(
        app,
        [
            "probe",
            "--url",
            "http://app.test/v1",
            "--model",
            "m",
            "--rules",
            str(_rules(tmp_path)),
            *extra,
        ],
    )


def test_a_probe_whose_rule_graded_nothing_exits_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = _probe(monkeypatch, tmp_path, "--profile", str(_profile(tmp_path)))

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    output = _plain(result.output)
    assert "coverage missing (ungraded_cases): acme.prompt.silent" in output
    assert "graded 0 of 1 case attempt(s)" in output


def test_the_ci_preset_does_not_pass_a_rule_that_graded_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = _probe(monkeypatch, tmp_path, "--preset", "ci")

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert "coverage missing (ungraded_cases): acme.prompt.silent" in _plain(result.output)


def test_a_saved_probe_records_the_shortfall(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out = tmp_path / "run.json"

    _probe(
        monkeypatch,
        tmp_path,
        "--profile",
        str(_profile(tmp_path)),
        "--format",
        "json",
        "--output",
        str(out),
    )

    shortfall = json.loads(out.read_text("utf-8"))["run"]["coverage"]["shortfall"]
    assert [(gap["kind"], gap["name"]) for gap in shortfall] == [
        ("ungraded_cases", "acme.prompt.silent")
    ]


def test_a_rule_below_the_profiles_floor_is_named_with_its_share(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules = tmp_path / "half"
    rules.mkdir()
    (rules / "half.yaml").write_text(
        "id: acme.prompt.half\ntitle: t\nseverity: high\ntarget_kind: endpoint\n"
        "taxonomy: [LLM01:2025]\nevaluator: keyword\nrequires: [chat]\n"
        f"prompts: ['{_SILENT}', '{_ANSWERED}']\nexpect: {{goal: complied}}\n",
        encoding="utf-8",
    )
    profile = _profile(tmp_path, "fail_on:", "  min_graded_share: 0.8")
    monkeypatch.setattr(endpoint_module, "transport_factory", _App)

    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            "http://app.test/v1",
            "--model",
            "m",
            "--rules",
            str(rules),
            "--profile",
            str(profile),
        ],
    )

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert "graded 1 of 2 case attempts (50%), below the floor of 80%" in _plain(result.output)


def test_grading_the_kept_replies_records_the_same_shortfall(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profile = _profile(tmp_path)
    kept = _probe(
        monkeypatch,
        tmp_path,
        "--profile",
        str(profile),
        "--keep-exchanges",
        "--format",
        "json",
        "--output",
        str(tmp_path / "run.json"),
    )
    assert kept.exit_code == ExitCode.INDETERMINATE, kept.output

    result = runner.invoke(
        app,
        [
            "grade",
            str(tmp_path / "run.exchanges.jsonl"),
            "--rules",
            str(tmp_path / "rules"),
            "--profile",
            str(profile),
        ],
    )

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert "coverage missing (ungraded_cases): acme.prompt.silent" in _plain(result.output)


def test_a_monitor_cycle_whose_rule_graded_nothing_is_indeterminate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", _App)

    result = runner.invoke(
        app,
        [
            "monitor",
            "--url",
            "http://app.test/v1",
            "--model",
            "m",
            "--rules",
            str(_rules(tmp_path)),
            "--profile",
            str(_profile(tmp_path)),
            "--max-cycles",
            "1",
            "--interval",
            "0",
        ],
    )

    assert result.exit_code == ExitCode.INDETERMINATE, result.output


def test_config_explain_lists_the_floor(tmp_path: Path) -> None:
    _rules(tmp_path)
    floored = _profile(tmp_path, "  paths: [rules]", "fail_on:", "  min_graded_share: 0.8")

    result = runner.invoke(
        app, ["config", "explain", "--profile", str(floored), "--format", "json"]
    )

    assert result.exit_code == ExitCode.OK, result.output
    assert json.loads(result.stdout)["fail_on"]["min_graded_share"] == 0.8


def test_config_explain_lists_an_unset_floor_as_null(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["config", "explain", "--profile", str(_profile(tmp_path)), "--format", "json"]
    )

    assert json.loads(result.stdout)["fail_on"]["min_graded_share"] is None
