"""`guardana grade` and `probe --keep-exchanges`: answers graded again without the target."""

import json
import re
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any
from urllib.error import URLError

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.target import ChatMessage
from typer.testing import CliRunner

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

_SUITE = "acme.quality.answers"
_TARGET = "http://app.test/v1"
_JUDGE = "http://judge.test:8080/v1"
_ANSWERS = {
    "How do I reset my password?": "Open Settings, then Security.",
    "Where is my invoice?": "Billing lists every invoice.",
    "Can I export my data?": "Settings has an export button.",
}


class _App:
    """The application: answers each question its own way and counts what reached it."""

    sent = 0

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """Answer the question, or pass a judge's verdict when the judge is asked."""
        if "judge" in base_url:
            return "PASS: it names a place"
        type(self).sent += 1
        return _ANSWERS[messages[-1].content]


class _JudgeDown(_App):
    """The application answers; the judge cannot be reached."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """Fail as the judge; answer as the application."""
        if "judge" in base_url:
            raise URLError(f"connection refused by {base_url}")
        return super().send(base_url, model, messages, api_key)


def _plain(text: str) -> str:
    """Rendered output without styling or panel borders, as CI's coloured terminal prints it."""
    return " ".join(_ANSI.sub("", text).replace("│", " ").split())


def _rules(tmp_path: Path, evaluator: str = "contains", expected: str = "Settings") -> Path:
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)
    header = {"guardana_dataset": 1, "name": "support", "version": "1"}
    case_expect: dict[str, object] = (
        {"contains_any": [expected]} if evaluator == "contains" else {"goal": "names a place"}
    )
    lines = [json.dumps(header)] + [
        json.dumps({"input": question, "expect": case_expect}) for question in _ANSWERS
    ]
    (rules / "answers.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rule: dict[str, object] = {
        "id": _SUITE,
        "title": "The support bot names where to go",
        "severity": "high",
        "target_kind": "endpoint",
        "taxonomy": ["LLM09:2025"],
        "evaluator": evaluator,
        "requires": ["chat"],
        "dataset": "./answers.jsonl",
        "expect": {"contains_any": []} if evaluator == "contains" else {"goal": "g"},
        "gate": {"min_pass_rate": 0.5, "min_sample": 3},
    }
    (rules / "answers.yaml").write_text(json.dumps(rule), encoding="utf-8")
    return rules


def _profile(tmp_path: Path, *extra: str, judge: bool = False) -> Path:
    lines = ["rules:", "  include: ['acme.*']", *extra]
    if judge:
        lines += ["evaluators:", f"  llm_judge: {{endpoint: '{_JUDGE}', model: j}}"]
    path = tmp_path / "guardana.yaml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _probe_keeping(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *extra: str) -> Any:  # noqa: ANN401 — typer's Result
    monkeypatch.setattr(endpoint_module, "transport_factory", _App)
    return runner.invoke(
        app,
        [
            "probe",
            "--url",
            _TARGET,
            "--model",
            "m",
            "--rules",
            str(_rules(tmp_path)),
            "--profile",
            str(_profile(tmp_path)),
            "--keep-exchanges",
            *extra,
        ],
    )


def _kept(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    result = _probe_keeping(
        monkeypatch, tmp_path, "--format", "json", "--output", str(tmp_path / "run.json")
    )
    assert result.exit_code == ExitCode.OK, result.output
    assert f"kept {len(_ANSWERS)} exchange(s) in" in result.stderr
    return tmp_path / "run.exchanges.jsonl"


def test_a_kept_probe_writes_its_exchanges_beside_the_run_and_says_so(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)

    assert sidecar.is_file()
    run = json.loads((tmp_path / "run.json").read_text("utf-8"))
    assert run["run"]["exchanges"]["count"] == len(_ANSWERS)


def test_a_kept_probe_declares_no_subject_kind(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A probe is told only an endpoint, so what answered is not its to declare."""
    sidecar = _kept(monkeypatch, tmp_path)

    header = json.loads(sidecar.read_text("utf-8").splitlines()[0])

    assert header["guardana_recording"] == 3
    assert "subject_kind" not in header


def test_grading_a_kept_probe_sends_nothing_to_the_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)
    _App.sent = 0
    graded = tmp_path / "graded.json"

    result = runner.invoke(
        app,
        [
            "grade",
            str(sidecar),
            "--rules",
            str(_rules(tmp_path)),
            "--profile",
            str(_profile(tmp_path)),
            "--format",
            "json",
            "--output",
            str(graded),
        ],
    )

    assert result.exit_code == ExitCode.OK, result.output
    assert _App.sent == 0
    document = json.loads(graded.read_text("utf-8"))["run"]
    assert document["usage"]["requests"] == 0
    assert document["target"]["ref"].startswith("recording:")
    assert document["recording"]["origin"]["run_id"]


def test_a_stricter_rule_fails_the_same_replies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)
    stricter = tmp_path / "stricter"
    stricter.mkdir()

    result = runner.invoke(
        app,
        [
            "grade",
            str(sidecar),
            "--rules",
            str(_rules(stricter, expected="Billing")),
            "--profile",
            str(_profile(tmp_path)),
        ],
    )

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output


def test_a_hand_written_recording_is_graded(tmp_path: Path) -> None:
    recording = tmp_path / "answers.jsonl"
    lines = [
        {
            "guardana_recording": 1,
            "name": "support-bot",
            "version": "1",
            "verbatim": True,
            "rule": _SUITE,
        }
    ]
    lines += [{"input": question, "reply": reply} for question, reply in _ANSWERS.items()]
    recording.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "grade",
            str(recording),
            "--rules",
            str(_rules(tmp_path)),
            "--profile",
            str(_profile(tmp_path)),
        ],
    )

    assert result.exit_code == ExitCode.OK, result.output


def test_a_misspelled_include_refuses_the_grade_and_grades_nothing(tmp_path: Path) -> None:
    recording = tmp_path / "answers.jsonl"
    lines: list[dict[str, object]] = [
        {"guardana_recording": 1, "name": "b", "version": "1", "verbatim": True, "rule": _SUITE}
    ]
    lines += [{"input": question, "reply": reply} for question, reply in _ANSWERS.items()]
    recording.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")
    profile = tmp_path / "guardana.yaml"
    profile.write_text("rules:\n  include: ['acme.*', 'acme.quality.answer']\n", encoding="utf-8")
    output = tmp_path / "run.json"

    result = runner.invoke(
        app,
        [
            "grade",
            str(recording),
            "--rules",
            str(_rules(tmp_path)),
            "--profile",
            str(profile),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert result.stderr.splitlines()[-1] == (
        'error: rules.include contains unmatched patterns: "acme.quality.answer" — check the '
        "spelling and registered rules."
    )
    assert not output.exists()


def test_an_unreadable_recording_is_invalid_usage(tmp_path: Path) -> None:
    broken = tmp_path / "broken.jsonl"
    broken.write_text('{"guardana_recording": 1}\n', encoding="utf-8")

    result = runner.invoke(app, ["grade", str(broken)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "broken.jsonl" in result.stderr


def test_a_judge_graded_grade_states_its_judge_traffic_and_a_dead_judge_exits_4(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)
    judged = tmp_path / "judged"
    judged.mkdir()
    monkeypatch.setattr(endpoint_module, "transport_factory", _JudgeDown)

    result = runner.invoke(
        app,
        [
            "grade",
            str(sidecar),
            "--rules",
            str(_rules(judged, evaluator="llm_judge")),
            "--profile",
            str(_profile(tmp_path, judge=True)),
        ],
    )

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output
    assert "evaluators.llm_judge" in result.stderr
    assert "no request reaches the target" in result.stderr
    assert "judge calls: at most" in result.stderr


@pytest.mark.parametrize(
    ("extra", "said"),
    [
        ((), "--format json --output"),
        (("--format", "human", "--output", "x.txt"), "--format json"),
    ],
)
def test_keeping_without_a_saved_run_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, extra: tuple[str, ...], said: str
) -> None:
    result = _probe_keeping(monkeypatch, tmp_path, *extra)

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert said in _plain(result.output)


def test_keeping_an_mcp_server_is_refused(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "probe",
            "--mcp",
            "https://93.184.215.14/mcp",
            "--keep-exchanges",
            "--format",
            "json",
            "--output",
            str(tmp_path / "run.json"),
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output


def test_keeping_under_metadata_only_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", _App)
    profile = _profile(tmp_path, "privacy:", "  evidence_mode: metadata_only")

    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            _TARGET,
            "--model",
            "m",
            "--profile",
            str(profile),
            "--keep-exchanges",
            "--format",
            "json",
            "--output",
            str(tmp_path / "run.json"),
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output


def test_grading_at_other_trials_than_kept_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)

    result = runner.invoke(
        app,
        [
            "grade",
            str(sidecar),
            "--rules",
            str(_rules(tmp_path)),
            "--profile",
            str(_profile(tmp_path)),
            "--trials",
            "3",
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "kept 1, this run grades 3" in result.stderr


def test_plan_grade_prices_no_target_request_and_names_what_it_skips(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)
    profile = tmp_path / "wide.yaml"
    profile.write_text("rules:\n  include: ['acme.*', 'guardana.output.*']\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "plan",
            "grade",
            str(sidecar),
            "--rules",
            str(_rules(tmp_path)),
            "--profile",
            str(profile),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    plan = json.loads(result.stdout)
    assert plan["requests"] == {"min": 0, "max": 0}
    assert "guardana.output.secrets" in plan["skipped"]
    assert _SUITE in plan["rules"]


def test_rules_the_recording_does_not_answer_are_named_and_refused_by_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)
    everything = ["grade", str(sidecar), "--rules", str(_rules(tmp_path))]

    default = runner.invoke(app, everything)
    release = runner.invoke(app, [*everything, "--preset", "release"])

    assert default.exit_code == ExitCode.OK, default.output
    assert "answers none of their questions" in default.stderr
    assert release.exit_code == ExitCode.INDETERMINATE, release.output


def test_a_profile_shared_with_a_keeping_probe_grades_its_recording(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)
    shared = _profile(tmp_path, "privacy:", "  keep_exchanges: true")

    result = runner.invoke(
        app, ["grade", str(sidecar), "--rules", str(_rules(tmp_path)), "--profile", str(shared)]
    )

    assert result.exit_code == ExitCode.OK, result.output


def test_plan_grade_refuses_other_trials_as_grade_does(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)
    selection = ["--rules", str(_rules(tmp_path)), "--profile", str(_profile(tmp_path))]

    planned = runner.invoke(app, ["plan", "grade", str(sidecar), *selection, "--trials", "2"])
    graded = runner.invoke(app, ["grade", str(sidecar), *selection, "--trials", "2"])

    assert planned.exit_code == graded.exit_code == ExitCode.INVALID_USAGE, planned.output
    assert "kept 1, this run grades 2" in planned.stderr


def test_a_line_for_a_rule_nobody_loaded_is_named_by_the_plan_and_the_run(tmp_path: Path) -> None:
    recording = tmp_path / "typo.jsonl"
    lines: list[dict[str, object]] = [
        {"guardana_recording": 1, "name": "bot", "version": "1", "verbatim": True}
    ]
    lines += [{"rule": _SUITE, "input": q, "reply": a} for q, a in _ANSWERS.items()]
    lines.append({"rule": "acme.typo.answers", "input": "Hi?", "reply": "Hello."})
    recording.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
    selection = ["--rules", str(_rules(tmp_path)), "--profile", str(_profile(tmp_path))]

    planned = runner.invoke(app, ["plan", "grade", str(recording), *selection])
    graded = runner.invoke(app, ["grade", str(recording), *selection])

    assert planned.exit_code == ExitCode.INVALID_USAGE, planned.output
    assert "acme.typo.answers" in planned.stderr
    assert graded.exit_code == ExitCode.INDETERMINATE, graded.output


def test_a_later_run_at_the_same_path_removes_the_exchanges_an_earlier_one_kept(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)

    later = runner.invoke(
        app,
        [
            "probe",
            "--url",
            _TARGET,
            "--model",
            "m",
            "--rules",
            str(_rules(tmp_path)),
            "--profile",
            str(_profile(tmp_path)),
            "--format",
            "json",
            "--output",
            str(tmp_path / "run.json"),
        ],
    )

    assert later.exit_code == ExitCode.OK, later.output
    assert not sidecar.exists()
    assert "an earlier run at this path kept" in later.stderr


def _kept_by(tmp_path: Path, *, stopped_by: str | None) -> Path:
    """A recording whose header names the probe that kept it and whether that probe stopped."""
    tmp_path.mkdir(exist_ok=True)
    recording = tmp_path / "kept.jsonl"
    origin = {
        "run_id": "run-7",
        "target": _TARGET,
        "started_at": None,
        "stopped_by": stopped_by,
        "gate": None,
        "trials": {_SUITE: 1},
        "rules": [_SUITE],
    }
    lines: list[dict[str, object]] = [
        {"guardana_recording": 1, "name": "bot", "version": "1", "verbatim": True, "origin": origin}
    ]
    lines += [{"rule": _SUITE, "input": q, "reply": a} for q, a in _ANSWERS.items()]
    recording.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
    return recording


@pytest.mark.parametrize(
    ("stopped_by", "expected", "code"),
    [
        ("budget_exhausted", "Settings", ExitCode.INDETERMINATE),
        ("budget_exhausted", "Billing", ExitCode.POLICY_FAILED),
        (None, "Settings", ExitCode.OK),
        (None, "Billing", ExitCode.POLICY_FAILED),
    ],
    ids=["stopped, suite passes", "stopped, suite fails", "finished, passes", "finished, fails"],
)
def test_a_recording_kept_from_a_stopped_run_never_grades_to_a_pass(
    tmp_path: Path, stopped_by: str | None, expected: str, code: ExitCode
) -> None:
    rules = tmp_path / "suite"
    rules.mkdir()
    graded = tmp_path / "graded.json"

    result = runner.invoke(
        app,
        [
            "grade",
            str(_kept_by(tmp_path, stopped_by=stopped_by)),
            "--rules",
            str(_rules(rules, expected=expected)),
            "--profile",
            str(_profile(tmp_path)),
            "--format",
            "json",
            "--output",
            str(graded),
        ],
    )

    assert result.exit_code == code, result.output
    shortfall = json.loads(graded.read_text("utf-8"))["run"]["coverage"]["shortfall"]
    kinds = [gap["kind"] for gap in shortfall]
    assert kinds == (["incomplete_recording"] if stopped_by else [])


def test_plan_grade_refuses_a_recording_kept_from_a_stopped_run(tmp_path: Path) -> None:
    selection = ["--rules", str(_rules(tmp_path)), "--profile", str(_profile(tmp_path))]
    stopped = _kept_by(tmp_path / "stopped", stopped_by="budget_exhausted")
    finished = _kept_by(tmp_path / "finished", stopped_by=None)

    refused = runner.invoke(app, ["plan", "grade", str(stopped), *selection])
    planned = runner.invoke(app, ["plan", "grade", str(finished), *selection])

    assert refused.exit_code == ExitCode.INVALID_USAGE, refused.output
    assert "run-7" in _plain(refused.stderr)
    assert "budget_exhausted" in _plain(refused.stderr)
    assert planned.exit_code == ExitCode.OK, planned.output


def _grade_quietly(tmp_path: Path, recording: Path) -> Any:  # noqa: ANN401 — typer's Result
    return runner.invoke(
        app,
        [
            "grade",
            str(recording),
            "--rules",
            str(_rules(tmp_path)),
            "--profile",
            str(_profile(tmp_path)),
        ],
    )


def _warnings(stderr: str) -> list[str]:
    lines = (" ".join(_ANSI.sub("", line).split()) for line in stderr.splitlines())
    return [line for line in lines if line.startswith("warning:")]


def _edit_the_sidecar(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, run: Path) -> None:
    sidecar = tmp_path / "run.exchanges.jsonl"
    sidecar.write_text(sidecar.read_text("utf-8") + "\n", encoding="utf-8")


def _save_a_run_that_kept_none(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, run: Path) -> None:
    sidecar = tmp_path / "run.exchanges.jsonl"
    kept = sidecar.read_bytes()
    monkeypatch.setattr(endpoint_module, "transport_factory", _App)
    later = runner.invoke(
        app,
        [
            "probe",
            "--url",
            _TARGET,
            "--model",
            "m",
            "--rules",
            str(_rules(tmp_path)),
            "--profile",
            str(_profile(tmp_path)),
            "--format",
            "json",
            "--output",
            str(run),
        ],
    )
    assert later.exit_code == ExitCode.OK, later.output
    sidecar.write_bytes(kept)


def _spoil_the_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, run: Path) -> None:
    run.write_text("not a run\n", encoding="utf-8")


@pytest.mark.parametrize(
    ("change", "said"),
    [
        (_edit_the_sidecar, "is not the exchanges"),
        (_save_a_run_that_kept_none, "records no exchanges"),
        (_spoil_the_run, "could not be checked against"),
    ],
    ids=["another digest", "no digest", "unreadable run"],
)
@pytest.mark.parametrize("saved_as", ["run.json", "run"])
def test_a_sidecar_its_run_does_not_vouch_for_is_graded_with_a_warning(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    change: Callable[[pytest.MonkeyPatch, Path, Path], None],
    said: str,
    saved_as: str,
) -> None:
    run = tmp_path / saved_as
    kept = _probe_keeping(monkeypatch, tmp_path, "--format", "json", "--output", str(run))
    assert kept.exit_code == ExitCode.OK, kept.output
    sidecar = tmp_path / "run.exchanges.jsonl"
    change(monkeypatch, tmp_path, run)

    result = _grade_quietly(tmp_path, sidecar)

    assert result.exit_code == ExitCode.OK, result.output
    warnings = _warnings(result.stderr)
    assert len(warnings) == 1, result.stderr
    assert said in warnings[0]
    assert str(sidecar) in warnings[0]
    assert warnings[0].endswith("grading it as given")


def test_a_sidecar_its_run_recorded_is_graded_without_a_warning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)

    result = _grade_quietly(tmp_path, sidecar)

    assert result.exit_code == ExitCode.OK, result.output
    assert _warnings(result.stderr) == []


def test_a_sidecar_with_no_run_beside_it_is_graded_without_a_warning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)
    sidecar.write_text(sidecar.read_text("utf-8") + "\n", encoding="utf-8")
    (tmp_path / "run.json").unlink()

    result = _grade_quietly(tmp_path, sidecar)

    assert result.exit_code == ExitCode.OK, result.output
    assert _warnings(result.stderr) == []


@pytest.mark.parametrize("saved_as", ["run.json", "run"])
def test_grade_refuses_a_report_that_would_remove_the_recording_it_grades(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, saved_as: str
) -> None:
    run = tmp_path / saved_as
    kept = _probe_keeping(monkeypatch, tmp_path, "--format", "json", "--output", str(run))
    assert kept.exit_code == ExitCode.OK, kept.output
    sidecar = tmp_path / "run.exchanges.jsonl"
    before = {path: path.read_bytes() for path in (run, sidecar)}
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        [
            "grade",
            str(sidecar),
            "--rules",
            str(_rules(tmp_path)),
            "--profile",
            str(_profile(tmp_path)),
            "--format",
            "json",
            "--output",
            saved_as,
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    error = _plain(result.stderr)
    assert f"error: {sidecar} is where a run saved at {saved_as} keeps its exchanges" in error
    assert {path: path.read_bytes() for path in before} == before


def test_grade_refuses_a_report_that_would_replace_the_recording_it_grades(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)
    before = sidecar.read_bytes()

    result = runner.invoke(
        app,
        [
            "grade",
            str(sidecar),
            "--rules",
            str(_rules(tmp_path)),
            "--profile",
            str(_profile(tmp_path)),
            "--format",
            "json",
            "--output",
            str(sidecar),
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert f"error: --output {sidecar} is the recording being graded" in _plain(result.stderr)
    assert sidecar.read_bytes() == before


def test_grade_refuses_an_output_whose_sidecar_is_the_recording_under_another_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)
    linked = tmp_path / "linked.jsonl"
    linked.hardlink_to(sidecar)
    before = sidecar.read_bytes()

    result = runner.invoke(
        app,
        [
            "grade",
            str(linked),
            "--rules",
            str(_rules(tmp_path)),
            "--profile",
            str(_profile(tmp_path)),
            "--format",
            "json",
            "--output",
            str(tmp_path / "run.json"),
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "would remove the recording being graded" in _plain(result.stderr)
    assert sidecar.read_bytes() == before


def _plan_quietly(tmp_path: Path, recording: Path) -> Any:  # noqa: ANN401 — typer's Result
    return runner.invoke(
        app,
        [
            "plan",
            "grade",
            str(recording),
            "--rules",
            str(_rules(tmp_path)),
            "--profile",
            str(_profile(tmp_path)),
        ],
    )


@pytest.mark.parametrize("edited", [False, True], ids=["matching", "edited"])
def test_plan_grade_warns_of_a_sidecar_its_run_did_not_record_as_grade_does(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, edited: bool
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)
    if edited:
        sidecar.write_text(sidecar.read_text("utf-8") + "\n", encoding="utf-8")

    planned = _plan_quietly(tmp_path, sidecar)

    assert planned.exit_code == ExitCode.OK, planned.output
    warnings = _warnings(planned.stderr)
    if edited:
        assert len(warnings) == 1, planned.stderr
        assert "is not the exchanges" in warnings[0]
    else:
        assert warnings == []


def test_a_sidecar_named_in_another_case_is_checked_where_the_filesystem_ignores_case(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)
    sidecar.write_text(sidecar.read_text("utf-8") + "\n", encoding="utf-8")
    renamed = sidecar.rename(tmp_path / "run.Exchanges.JSONL")
    ignores_case = (tmp_path / "RUN.JSON").exists()

    result = _grade_quietly(tmp_path, renamed)

    assert result.exit_code == ExitCode.OK, result.output
    warnings = _warnings(result.stderr)
    if ignores_case:
        assert len(warnings) == 1, result.stderr
        assert "is not the exchanges" in warnings[0]
    else:
        assert warnings == [], "a case-sensitive filesystem keeps run.json's sidecar apart"


def test_a_run_spelled_otherwise_on_disk_is_not_paired_with_the_sidecar(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = _kept(monkeypatch, tmp_path)
    sidecar.write_text(sidecar.read_text("utf-8") + "\n", encoding="utf-8")
    (tmp_path / "run.json").rename(tmp_path / "RUN.JSON")

    result = _grade_quietly(tmp_path, sidecar)

    assert result.exit_code == ExitCode.OK, result.output
    assert _warnings(result.stderr) == []


@pytest.mark.parametrize("vouched", [True, False], ids=["run vouches", "neither vouches"])
def test_a_sidecar_either_run_beside_it_recorded_is_graded_without_a_warning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, vouched: bool
) -> None:
    bare = tmp_path / "run"
    kept = _probe_keeping(monkeypatch, tmp_path, "--format", "json", "--output", str(bare))
    assert kept.exit_code == ExitCode.OK, kept.output
    sidecar = tmp_path / "run.exchanges.jsonl"
    named = tmp_path / "run.json"
    recorded_none = json.loads(bare.read_text("utf-8"))
    recorded_none["run"]["exchanges"] = None
    named.write_text(json.dumps(recorded_none), encoding="utf-8")
    if not vouched:
        sidecar.write_text(sidecar.read_text("utf-8") + "\n", encoding="utf-8")

    result = _grade_quietly(tmp_path, sidecar)

    assert result.exit_code == ExitCode.OK, result.output
    warnings = _warnings(result.stderr)
    if vouched:
        assert warnings == []
    else:
        assert len(warnings) == 1, result.stderr
        assert warnings[0].startswith(f"warning: {named} records no exchanges")
