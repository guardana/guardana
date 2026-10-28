"""Fuzz targets refuse what their reader documents, crash on anything else, and run in CI.

A harness that swallowed every exception would fuzz for hours and report nothing, so the
line between a documented refusal and a crash is tested here, where Atheris is not needed.
"""

import sys
import tomllib
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import fuzz_artifacts
import fuzz_profile
import fuzz_trace
import pytest
import yaml
from guardana.core.profile import ProfileError
from guardana.core.report import ScanResult
from guardana.core.report.check_error import CheckError
from guardana.core.trace import TraceLoadError

_ROOT = Path(__file__).resolve().parents[2]
_TARGETS = (fuzz_artifacts, fuzz_profile, fuzz_trace)


def _workflow(name: str) -> dict[Any, Any]:
    loaded = yaml.safe_load((_ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _steps(workflow: dict[Any, Any], job: str) -> list[dict[str, Any]]:
    steps = workflow["jobs"][job]["steps"]
    assert isinstance(steps, list)
    return steps


@pytest.mark.parametrize(
    ("seeds", "one_input"),
    [(target.seeds, target.one_input) for target in _TARGETS],
    ids=[target.__name__ for target in _TARGETS],
)
def test_every_seed_is_read_without_a_crash(
    seeds: Callable[[], Iterable[bytes]], one_input: Callable[[bytes], None]
) -> None:
    for seed in seeds():
        one_input(seed)


def test_importing_the_targets_does_not_need_atheris() -> None:
    assert "atheris" not in sys.modules


def test_a_trace_the_reader_refuses_is_not_a_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    def _refuse(path: Path) -> None:
        raise TraceLoadError(f"{path} is not a trace")

    monkeypatch.setattr(fuzz_trace, "read_trace", _refuse)

    fuzz_trace.one_input(b"anything")


def test_an_undocumented_trace_reader_exception_is_a_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    def _break(path: Path) -> None:
        raise IndexError(str(path))

    monkeypatch.setattr(fuzz_trace, "read_trace", _break)

    with pytest.raises(IndexError):
        fuzz_trace.one_input(b"anything")


def test_a_profile_the_loader_refuses_is_not_a_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    def _refuse(path: Path) -> None:
        raise ProfileError("invalid profile")

    monkeypatch.setattr(fuzz_profile, "load_profile", _refuse)

    fuzz_profile.one_input(b"anything")


def test_a_profile_that_is_not_utf8_is_refused_not_a_crash() -> None:
    fuzz_profile.one_input(b"\xe9fail_on: high\n")


@pytest.mark.parametrize(
    "escape",
    [KeyError("guardana.yaml"), UnicodeDecodeError("utf-8", b"\xe9", 0, 1, "invalid")],
    ids=["key-error", "not-utf-8"],
)
def test_an_undocumented_profile_loader_exception_is_a_crash(
    monkeypatch: pytest.MonkeyPatch, escape: Exception
) -> None:
    def _break(path: Path) -> None:
        raise escape

    monkeypatch.setattr(fuzz_profile, "load_profile", _break)

    with pytest.raises(type(escape)):
        fuzz_profile.one_input(b"anything")


@pytest.mark.parametrize(
    "data",
    [
        b"on: x\n",
        b"1: x\n",
        b"&piode:  ri ",
        b"schema_version: 1\nrules:\n  1: x\n",
        b"fail_on:\n  severity: !!int high\n",
        b"name: !!timestamp x\n",
        b"rules:\n  exclude: [!!int ]\n",
    ],
    ids=[
        "boolean-key",
        "integer-key",
        "anchored-null-key",
        "nested-key",
        "int",
        "timestamp",
        "empty",
    ],
)
def test_yaml_the_loader_lets_out_a_known_way_is_not_a_crash(data: bytes) -> None:
    fuzz_profile.one_input(data)


def _raising(error: type[Exception]) -> Callable[[Path], None]:
    def _load(path: Path) -> None:
        raise error(str(path))

    return _load


@pytest.mark.parametrize(
    "data",
    [b"a:\n  - b: [{null: x}]\n", b"a: &a [*a, {2: x}]\n", b"a: [b, !!float x]\n"],
    ids=["deep-key", "key-through-an-alias", "tagged-scalar"],
)
def test_a_known_escape_is_found_anywhere_in_the_profile(
    monkeypatch: pytest.MonkeyPatch, data: bytes
) -> None:
    monkeypatch.setattr(fuzz_profile, "load_profile", _raising(TypeError))

    fuzz_profile.one_input(data)


@pytest.mark.parametrize("error", [AttributeError, IndexError, TypeError, ValueError])
@pytest.mark.parametrize(
    "data",
    [b"name: x\n", b"a: &a [*a]\n", b"\xe9: x\n", b"{unclosed\n"],
    ids=["text-keys", "self-alias", "not-utf-8", "not-yaml"],
)
def test_the_same_exception_on_yaml_that_builds_with_text_keys_is_a_crash(
    monkeypatch: pytest.MonkeyPatch, data: bytes, error: type[Exception]
) -> None:
    monkeypatch.setattr(fuzz_profile, "load_profile", _raising(error))

    with pytest.raises(error):
        fuzz_profile.one_input(data)


def _result(*errors: CheckError) -> ScanResult:
    return ScanResult(
        findings=(),
        rules_run=("guardana.supply_chain.pickle_opcode",),
        rules_skipped=(),
        errors=errors,
    )


def test_a_rule_that_raised_while_running_is_a_crash() -> None:
    raised = CheckError(
        source="guardana.supply_chain.pickle_opcode", stage="run", reason="IndexError: x"
    )

    with pytest.raises(fuzz_artifacts.RuleRaisedError, match="pickle_opcode"):
        fuzz_artifacts.raise_on_rule_failures(_result(raised))


def test_an_input_the_run_could_not_read_is_not_a_crash() -> None:
    unread = CheckError(source="model.pkl", stage="read", reason="PermissionError: x")

    fuzz_artifacts.raise_on_rule_failures(_result(unread))


def test_a_rule_that_raised_deciding_whether_it_applies_is_a_crash() -> None:
    raised = CheckError(
        source="guardana.supply_chain.pickle_opcode", stage="applicability", reason="KeyError: x"
    )

    with pytest.raises(fuzz_artifacts.RuleRaisedError, match="pickle_opcode: KeyError"):
        fuzz_artifacts.raise_on_rule_failures(_result(raised))


class _Registry:
    def __init__(self, *errors: CheckError) -> None:
        self.load_errors = errors


def test_a_rule_that_failed_to_load_stops_the_target_before_it_fuzzes() -> None:
    failed = CheckError(source="guardana.supply_chain.pickle_opcode", stage="load", reason="bad")

    with pytest.raises(fuzz_artifacts.RuleRaisedError, match="pickle_opcode: bad"):
        fuzz_artifacts.loaded_registry(_Registry(failed))  # type: ignore[arg-type]


def test_the_fuzz_workflow_runs_every_target_and_only_those() -> None:
    on_disk = {path.stem for path in (_ROOT / "fuzz").glob("fuzz_*.py")}
    matrix = _workflow("fuzz.yml")["jobs"]["fuzz"]["strategy"]["matrix"]["target"]

    assert set(matrix) == on_disk
    assert on_disk == {target.__name__ for target in _TARGETS}


def test_the_fuzz_workflow_installs_atheris_and_bounds_each_run() -> None:
    steps = _steps(_workflow("fuzz.yml"), "fuzz")
    runs = " ".join(str(step.get("run", "")) for step in steps)
    uv = next(step for step in steps if str(step.get("uses", "")).startswith("astral-sh/setup-uv@"))

    assert "--group fuzz" in runs
    assert "-max_total_time=" in runs
    assert uv["with"]["python-version"] == "3.12"
    assert not any("upload-artifact" in str(step.get("uses", "")) for step in steps)


def test_a_failing_fuzz_run_prints_its_input_whatever_its_size() -> None:
    """libFuzzer prints only small inputs itself, and the runner's files are gone after the job."""
    steps = _steps(_workflow("fuzz.yml"), "fuzz")
    fuzz = next(
        step for step in steps if "fuzz/${{ matrix.target }}.py" in str(step.get("run", ""))
    )
    printed = steps[steps.index(fuzz) + 1]

    assert "-artifact_prefix=findings/" in str(fuzz["run"])
    assert printed.get("if") == "failure()"
    assert "base64" in str(printed["run"])
    assert "findings/*" in str(printed["run"])


def test_atheris_is_a_non_default_group_limited_to_the_platforms_it_publishes_wheels_for() -> None:
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    (requirement,) = project["dependency-groups"]["fuzz"]
    defaults = project.get("tool", {}).get("uv", {}).get("default-groups", ["dev"])

    assert requirement.startswith("atheris==")
    assert "sys_platform == 'linux'" in requirement
    assert "platform_machine == 'x86_64'" in requirement
    assert "python_version >= '3.12'" in requirement
    assert "fuzz" not in defaults


def test_scorecard_publishes_its_results_with_only_the_job_holding_write_scopes() -> None:
    workflow = _workflow("scorecard.yml")
    job = workflow["jobs"]["analysis"]
    scorecard = next(
        step
        for step in job["steps"]
        if str(step.get("uses", "")).startswith("ossf/scorecard-action@")
    )

    assert scorecard["with"]["publish_results"] is True
    assert workflow["permissions"] == {"contents": "read"}
    assert job["permissions"]["id-token"] == "write"
    assert job["permissions"]["security-events"] == "write"
