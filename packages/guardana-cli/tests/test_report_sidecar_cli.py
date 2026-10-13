"""A report written at `--output` never sits beside exchanges another run kept.

Whatever command writes the report, the exchanges the run it replaced recorded beside
`output` are removed, and the removal is said on stderr. A sidecar no replaced run recorded
is kept with a warning. A report that cannot be written removes nothing and exits `3`.
"""

import contextlib
import hashlib
import json
import os
import re
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli._output import emit
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.testing import RefusingTransport
from guardana.core.verify import exchanges_path
from typer.testing import CliRunner, Result

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _lines(text: str) -> list[str]:
    return [line.strip() for line in _ANSI.sub("", text).splitlines() if line.strip()]


def _removals(result: Result) -> list[str]:
    return [line for line in _lines(result.stderr) if line.startswith("removed ")]


def _removed_sidecar(sidecar: Path) -> str:
    return f"removed {sidecar}, which an earlier run at this path kept"


@pytest.fixture(autouse=True)
def endpoint(monkeypatch: pytest.MonkeyPatch) -> RefusingTransport:
    transport = RefusingTransport()
    monkeypatch.setattr(endpoint_module, "transport_factory", lambda: transport)
    return transport


def _probe(*arguments: str) -> Result:
    return runner.invoke(app, ["probe", "--url", "http://fake", "--model", "m", *arguments])


def _probe_that_kept_exchanges(saved: Path) -> Path:
    """Probe once with `--keep-exchanges` into `saved` and return the sidecar it wrote."""
    earlier = _probe("--keep-exchanges", "--format", "json", "--output", str(saved))
    assert earlier.exit_code == ExitCode.OK, earlier.output
    sidecar = exchanges_path(saved)
    assert sidecar.is_file(), earlier.output
    return sidecar


def _scan(tmp_path: Path, saved: Path) -> Result:
    tree = tmp_path / "tree"
    tree.mkdir(exist_ok=True)
    (tree / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return runner.invoke(app, ["scan", str(tree), "--format", "json", "--output", str(saved)])


def _grade(tmp_path: Path, saved: Path) -> Result:
    recording = tmp_path / "answers.jsonl"
    shutil.copyfile(exchanges_path(saved), recording)
    return runner.invoke(app, ["grade", str(recording), "--format", "json", "--output", str(saved)])


def _analyze_trace(tmp_path: Path, saved: Path) -> Result:
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        '{"guardana_trace": 1, "trace_id": "t-1", "producer": {"name": "acme"}, '
        '"instrumented": ["messages", "tools"]}\n'
        '{"span_id": "s1", "kind": "tool_execution", "name": "http", "tool": {"name": "http"}}\n',
        encoding="utf-8",
    )
    return runner.invoke(
        app, ["analyze-trace", str(trace), "--format", "json", "--output", str(saved)]
    )


def _import_observations(tmp_path: Path, saved: Path) -> Result:
    results = tmp_path / "garak.jsonl"
    results.write_text(
        '{"entry_type": "start_run setup", "garak_version": "0.17.0"}\n'
        '{"entry_type": "eval", "probe": "dan.Dan_11_0", "detector": "dan.DAN", "passed": 3, '
        '"fails": 2, "nones": 0, "total_evaluated": 5, "total_processed": 5}\n',
        encoding="utf-8",
    )
    return runner.invoke(
        app, ["import-observations", str(results), "--format", "json", "--output", str(saved)]
    )


@pytest.mark.parametrize(
    "command",
    [_scan, _grade, _analyze_trace, _import_observations],
    ids=["scan", "grade", "analyze-trace", "import-observations"],
)
def test_a_command_writing_over_a_probes_run_removes_the_exchanges_it_kept(
    tmp_path: Path, command: Callable[[Path, Path], Result]
) -> None:
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)

    result = command(tmp_path, saved)

    assert result.exit_code not in {ExitCode.INVALID_USAGE, ExitCode.INTERNAL_ERROR}, result.output
    assert '"schema_version"' in saved.read_text(encoding="utf-8")
    assert not sidecar.exists()
    assert _removals(result) == [_removed_sidecar(sidecar)]


def test_a_command_printing_to_stdout_leaves_a_sidecar_alone(tmp_path: Path) -> None:
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("print('hello')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tree), "--format", "json"])

    assert result.exit_code == ExitCode.OK, result.output
    assert sidecar.is_file()
    assert _removals(result) == []


def test_a_probe_that_keeps_exchanges_again_says_nothing_of_removing_its_own(
    tmp_path: Path,
) -> None:
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)

    result = _probe("--keep-exchanges", "--format", "json", "--output", str(saved))

    assert result.exit_code == ExitCode.OK, result.output
    assert sidecar.is_file()
    assert _removals(result) == []
    assert any(line.startswith("kept ") for line in _lines(result.stderr))


def test_a_probe_keeping_nothing_removes_an_earlier_sidecar_once(tmp_path: Path) -> None:
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)

    result = _probe("--format", "json", "--output", str(saved))

    assert result.exit_code == ExitCode.OK, result.output
    assert not sidecar.exists()
    assert _removals(result) == [_removed_sidecar(sidecar)]


@pytest.mark.parametrize(
    "command", [_scan, _import_observations], ids=["scan", "import-observations"]
)
def test_a_report_that_cannot_be_written_removes_nothing(
    tmp_path: Path, command: Callable[[Path, Path], Result]
) -> None:
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)
    before = {path: path.read_bytes() for path in (saved, sidecar)}
    saved.chmod(0o444)

    result = command(tmp_path, saved)

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert {path: path.read_bytes() for path in before} == before
    assert _removals(result) == []


def test_a_read_only_file_that_is_no_run_survives_a_report_that_cannot_be_written(
    tmp_path: Path,
) -> None:
    notes = tmp_path / "notes.txt"
    notes.write_text("notes\n", encoding="utf-8")
    notes.chmod(0o444)

    result = _scan(tmp_path, notes)

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert notes.read_text(encoding="utf-8") == "notes\n"
    assert _removals(result) == []


def test_a_report_path_that_is_a_directory_leaves_the_exchanges_beside_it(
    tmp_path: Path,
) -> None:
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)
    before = sidecar.read_bytes()
    saved.unlink()
    saved.mkdir()

    result = _probe("--format", "json", "--output", str(saved))

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert saved.is_dir()
    assert sidecar.read_bytes() == before
    assert _removals(result) == []


def test_kept_exchanges_are_the_bytes_the_run_digests(tmp_path: Path) -> None:
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)

    recorded = json.loads(saved.read_text(encoding="utf-8"))["run"]["exchanges"]["digest"]

    assert recorded == "sha256:" + hashlib.sha256(sidecar.read_bytes()).hexdigest()


def test_exchanges_that_cannot_be_written_end_the_probe_with_exit_3(tmp_path: Path) -> None:
    saved = tmp_path / "run.json"
    exchanges_path(saved).mkdir()

    result = _probe("--keep-exchanges", "--format", "json", "--output", str(saved))

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    errors = [line for line in _lines(result.stderr) if line.startswith("error: ")]
    assert len(errors) == 1, result.stderr
    assert errors[0].startswith(
        f"error: could not write the kept exchanges to {exchanges_path(saved)}: "
    )


def test_a_run_whose_exchanges_could_not_be_written_records_none(tmp_path: Path) -> None:
    saved = tmp_path / "run.json"
    exchanges_path(saved).mkdir()

    result = _probe("--keep-exchanges", "--format", "json", "--output", str(saved))

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert json.loads(saved.read_text(encoding="utf-8"))["run"]["exchanges"] is None


def _fill_the_disk_writing(monkeypatch: pytest.MonkeyPatch, destination: Path) -> None:
    """Make the file staged to replace `destination` stop part way, as a full disk does."""
    open_file = Path.open

    class _Full:
        def __init__(self, handle: IO[bytes]) -> None:
            self.handle = handle

        def __enter__(self) -> "_Full":
            return self

        def __exit__(self, *exc: object) -> None:
            self.handle.close()

        def write(self, data: bytes) -> int:
            self.handle.write(data[:10])
            raise OSError("No space left on device")

    def opening(  # noqa: PLR0913, PLR0917 — Path.open's own parameters
        path: Path,
        mode: str = "r",
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> object:
        handle = open_file(path, mode, buffering, encoding, errors, newline)
        if "x" in mode and path.name.startswith(f".{destination.name}."):
            return _Full(handle)
        return handle

    monkeypatch.setattr(Path, "open", opening)


def test_exchanges_written_part_way_leave_neither_a_sidecar_nor_a_digest_of_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    saved = tmp_path / "run.json"
    sidecar = exchanges_path(saved)
    _fill_the_disk_writing(monkeypatch, sidecar)

    result = _probe("--keep-exchanges", "--format", "json", "--output", str(saved))

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert json.loads(saved.read_text(encoding="utf-8"))["run"]["exchanges"] is None
    assert sorted(path.name for path in tmp_path.iterdir()) == [saved.name]


def _write_text_as_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every text write translate newlines to CRLF, as `write_text` does on Windows."""
    write_text = Path.write_text

    def translating(
        path: Path,
        data: str,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> int:
        if newline is None:
            data, newline = data.replace("\n", "\r\n"), ""
        return write_text(path, data, encoding, errors, newline)

    monkeypatch.setattr(Path, "write_text", translating)


def test_kept_exchanges_match_their_digest_where_text_gets_crlf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    saved = tmp_path / "run.json"
    _write_text_as_windows(monkeypatch)

    sidecar = _probe_that_kept_exchanges(saved)

    assert b"\r\n" in saved.read_bytes(), "the report went through the translating write"
    recorded = json.loads(saved.read_text(encoding="utf-8"))["run"]["exchanges"]["digest"]
    assert recorded == "sha256:" + hashlib.sha256(sidecar.read_bytes()).hexdigest()


_V1_RUN = (
    '{"schema_version": 1, "run": {"tool_version": "0.6.0", "target_kind": "endpoint", '
    '"target_ref": "http://localhost:11434#llama3", "profile": "ci", "rules": {}, '
    '"rules_skipped": [], "started_at": "2026-07-25T09:00:00+00:00"}, "findings": [], '
    '"unverified": [], "waived": [], "errors": [], "observations": []}\n'
)
_TRACE = (
    '{"guardana_trace": 1, "trace_id": "t-1", "producer": {"name": "acme"}, '
    '"instrumented": ["messages", "tools"]}\n'
    '{"span_id": "s1", "kind": "tool_execution", "name": "http", "tool": {"name": "http"}}\n'
)
_GARAK = (
    '{"entry_type": "start_run setup", "garak_version": "0.17.0"}\n'
    '{"entry_type": "eval", "probe": "dan.Dan_11_0", "detector": "dan.DAN", "passed": 3, '
    '"fails": 2, "nones": 0, "total_evaluated": 5, "total_processed": 5}\n'
)
_READERS = {
    "scan": (["scan"], "print('hello')\n", ["--format", "json"]),
    "analyze-trace": (["analyze-trace"], _TRACE, ["--format", "json"]),
    "import-observations": (["import-observations"], _GARAK, ["--format", "json"]),
    "run migrate": (["run", "migrate"], _V1_RUN, []),
}


@pytest.mark.parametrize("command", sorted(_READERS))
def test_a_report_whose_exchanges_would_be_the_input_is_refused_before_it_is_read(
    tmp_path: Path, command: str
) -> None:
    words, content, flags = _READERS[command]
    given = tmp_path / "session.exchanges.jsonl"
    given.write_text(content, encoding="utf-8")
    before = given.read_bytes()
    saved = tmp_path / "session.json"

    result = runner.invoke(app, [*words, str(given), *flags, "--output", str(saved)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert given.read_bytes() == before
    assert not saved.exists()
    assert _lines(result.stderr)[-1] == (
        f"error: {given} is where a run saved at {saved} keeps its exchanges, and writing "
        f"the report there would remove it — choose another --output"
    )


@pytest.mark.parametrize("command", ["scan", "analyze-trace", "import-observations"])
def test_a_report_written_over_its_own_input_is_refused_before_it_is_read(
    tmp_path: Path, command: str
) -> None:
    words, content, flags = _READERS[command]
    given = tmp_path / "input.json"
    given.write_text(content, encoding="utf-8")
    before = given.read_bytes()

    result = runner.invoke(app, [*words, str(given), *flags, "--output", str(given)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert given.read_bytes() == before
    assert _lines(result.stderr)[-1] == (
        f"error: --output {given} is {given}, which this command reads, and the report would "
        f"replace it — choose another --output"
    )


def test_a_migration_may_still_be_written_over_its_input(tmp_path: Path) -> None:
    given = tmp_path / "old.json"
    given.write_text(_V1_RUN, encoding="utf-8")

    result = runner.invoke(app, ["run", "migrate", str(given), "--output", str(given)])

    assert result.exit_code == ExitCode.OK, result.output
    assert '"schema_version": 1,' not in given.read_text(encoding="utf-8")


def test_a_directory_scanned_keeps_no_say_over_the_sidecar_beside_its_report(
    tmp_path: Path,
) -> None:
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--output", str(saved)])

    assert result.exit_code not in {ExitCode.INVALID_USAGE, ExitCode.INTERNAL_ERROR}, result.output
    assert not sidecar.exists()


def _tree(tmp_path: Path) -> Path:
    tree = tmp_path / "tree"
    tree.mkdir(exist_ok=True)
    (tree / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return tree


def _baseline(tmp_path: Path) -> Path:
    written = tmp_path / "baseline.json"
    result = runner.invoke(app, ["scan", str(_tree(tmp_path)), "--write-baseline", str(written)])
    assert written.is_file(), result.output
    return written


def _trace_file(tmp_path: Path) -> Path:
    trace = tmp_path / "trace.jsonl"
    trace.write_text(_TRACE, encoding="utf-8")
    return trace


def _a_file(tmp_path: Path, name: str, content: str) -> Path:
    given = tmp_path / name
    given.write_text(content, encoding="utf-8")
    return given


@pytest.mark.parametrize("kind", ["baseline", "profile", "rules file", "contract"])
def test_a_report_written_over_any_file_the_command_reads_is_refused(
    tmp_path: Path, kind: str
) -> None:
    if kind == "baseline":
        given = _baseline(tmp_path)
        arguments = ["scan", str(_tree(tmp_path)), "--baseline", str(given)]
    elif kind == "profile":
        given = _a_file(tmp_path, "guardana.yaml", "rules:\n  include: ['guardana.*']\n")
        arguments = ["import-observations", str(_a_file(tmp_path, "g.jsonl", _GARAK))]
        arguments += ["--profile", str(given)]
    elif kind == "rules file":
        given = _a_file(tmp_path, "rule.yaml", "id: acme.example\n")
        arguments = ["scan", str(_tree(tmp_path)), "--rules", str(given)]
    else:
        given = _a_file(tmp_path, "contract.yaml", "contract: 1\n")
        arguments = ["analyze-trace", str(_trace_file(tmp_path)), "--contract", str(given)]
    before = given.read_bytes()

    result = runner.invoke(app, [*arguments, "--format", "json", "--output", str(given)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert given.read_bytes() == before
    assert _lines(result.stderr)[-1] == (
        f"error: --output {given} is {given}, which this command reads, and the report would "
        f"replace it — choose another --output"
    )


@pytest.mark.parametrize("names", ["the report", "the report's exchanges", "the trace"])
def test_a_native_trace_written_over_the_report_or_its_input_is_refused(
    tmp_path: Path, names: str
) -> None:
    trace = _trace_file(tmp_path)
    saved = tmp_path / "session.json"
    written = {
        "the report": saved,
        "the report's exchanges": exchanges_path(saved),
        "the trace": trace,
    }[names]
    before = trace.read_bytes()

    result = runner.invoke(
        app,
        [
            "analyze-trace",
            str(trace),
            "--format",
            "json",
            "--output",
            str(saved),
            "--write-trace",
            str(written),
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert trace.read_bytes() == before
    assert not saved.exists()
    assert not exchanges_path(saved).exists()
    error = _lines(result.stderr)[-1]
    assert error.startswith(f"error: --write-trace {written} is ")
    assert error.endswith("— choose another --write-trace")


def test_a_sidecar_the_runs_partner_recorded_is_kept_and_said_to_be(tmp_path: Path) -> None:
    kept_by = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(kept_by)
    before = sidecar.read_bytes()

    result = _scan(tmp_path, tmp_path / "run")

    assert result.exit_code == ExitCode.OK, result.output
    assert sidecar.read_bytes() == before
    assert _removals(result) == []
    assert f"warning: kept {sidecar}: it holds the exchanges {kept_by} recorded" in _lines(
        result.stderr
    )


def _kept_sidecar(sidecar: Path, output: Path) -> str:
    return (
        f"warning: kept {sidecar}: no run saved at {output} before this one recorded it, so it "
        f"is not an earlier run's exchanges"
    )


@pytest.mark.parametrize("partner", ["another digest", "no exchanges"])
def test_a_sidecar_neither_run_of_the_pair_recorded_is_kept_and_said_to_be(
    tmp_path: Path, partner: str
) -> None:
    kept_by = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(kept_by)
    if partner == "another digest":
        sidecar.write_bytes(sidecar.read_bytes() + b"\n")
    else:
        other = tmp_path / "other.json"
        assert _scan(tmp_path, other).exit_code == ExitCode.OK
        kept_by.write_bytes(other.read_bytes())
    before = sidecar.read_bytes()
    saved = tmp_path / "run"

    result = _scan(tmp_path, saved)

    assert result.exit_code == ExitCode.OK, result.output
    assert sidecar.read_bytes() == before
    assert _removals(result) == []
    assert _kept_sidecar(sidecar, saved) in _lines(result.stderr)


@pytest.mark.parametrize(
    "earlier", ["nothing", "a file that is no run", "a run recording none", "a run recording other"]
)
def test_a_recording_beside_the_report_that_no_replaced_run_recorded_is_kept(
    tmp_path: Path, earlier: str
) -> None:
    saved = tmp_path / "results.json"
    if earlier == "a file that is no run":
        saved.write_text('{"results": []}\n', encoding="utf-8")
    elif earlier == "a run recording none":
        assert _scan(tmp_path, saved).exit_code == ExitCode.OK
    elif earlier == "a run recording other":
        _probe_that_kept_exchanges(saved)
    recording = exchanges_path(saved)
    recording.write_text('{"messages": [{"role": "user", "content": "hi"}]}\n', encoding="utf-8")

    result = _scan(tmp_path, saved)

    assert result.exit_code == ExitCode.OK, result.output
    assert '"schema_version"' in saved.read_text(encoding="utf-8")
    assert recording.read_text(encoding="utf-8").startswith('{"messages"')
    assert _removals(result) == []
    assert _kept_sidecar(recording, saved) in _lines(result.stderr)


def test_a_probe_keeping_beside_a_sidecar_its_partner_recorded_is_refused_before_sending(
    tmp_path: Path, endpoint: RefusingTransport, monkeypatch: pytest.MonkeyPatch
) -> None:
    kept_by = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(kept_by)
    before = {path: path.read_bytes() for path in (kept_by, sidecar)}
    sent: list[object] = []
    monkeypatch.setattr(endpoint, "send", lambda *args, **kwargs: sent.append(args))
    saved = tmp_path / "run"

    result = _probe("--keep-exchanges", "--format", "json", "--output", str(saved))

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert sent == []
    assert not saved.exists()
    assert {path: path.read_bytes() for path in before} == before
    assert _lines(result.stderr)[-1] == (
        f"error: {sidecar} holds the exchanges {kept_by} recorded, and keeping this run's "
        f"beside {saved} would replace them — choose another --output"
    )


@pytest.mark.parametrize("beside", ["a sidecar its partner did not record", "a recording alone"])
def test_a_probe_keeping_beside_exchanges_no_run_there_recorded_is_refused_before_sending(
    tmp_path: Path, endpoint: RefusingTransport, monkeypatch: pytest.MonkeyPatch, beside: str
) -> None:
    if beside == "a recording alone":
        sidecar = exchanges_path(tmp_path / "run.json")
        sidecar.write_text('{"messages": []}\n', encoding="utf-8")
    else:
        sidecar = _probe_that_kept_exchanges(tmp_path / "run.json")
        sidecar.write_bytes(sidecar.read_bytes() + b"\n")
    before = {path: path.read_bytes() for path in tmp_path.iterdir()}
    sent: list[object] = []
    monkeypatch.setattr(endpoint, "send", lambda *args, **kwargs: sent.append(args))
    saved = tmp_path / "run"

    result = _probe("--keep-exchanges", "--format", "json", "--output", str(saved))

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert sent == []
    assert {path: path.read_bytes() for path in tmp_path.iterdir()} == before
    assert _lines(result.stderr)[-1] == (
        f"error: {sidecar} holds exchanges no run saved at {saved} recorded, and keeping this "
        f"run's beside it would replace them — choose another --output"
    )


def test_kept_exchanges_replace_a_link_at_their_path_and_never_write_through_it(
    tmp_path: Path,
) -> None:
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_text("not exchanges\n", encoding="utf-8")
    saved = tmp_path / "run.json"
    exchanges_path(saved).symlink_to(elsewhere)

    sidecar = _probe_that_kept_exchanges(saved)

    assert elsewhere.read_text(encoding="utf-8") == "not exchanges\n"
    assert not sidecar.is_symlink()
    recorded = json.loads(saved.read_text(encoding="utf-8"))["run"]["exchanges"]["digest"]
    assert recorded == "sha256:" + hashlib.sha256(sidecar.read_bytes()).hexdigest()


def test_a_scan_over_a_tree_holding_a_probes_run_replaces_it_and_removes_its_exchanges(
    tmp_path: Path,
) -> None:
    tree = _tree(tmp_path)
    saved = tree / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)

    result = runner.invoke(app, ["scan", str(tree), "--format", "json", "--output", str(saved)])

    assert result.exit_code == ExitCode.OK, result.output
    assert json.loads(saved.read_text(encoding="utf-8"))["run"]["exchanges"] is None
    assert not sidecar.exists()
    assert _removals(result) == [_removed_sidecar(sidecar)]


def test_exchanges_that_changed_after_the_run_there_was_read_are_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)

    def edited_meanwhile(*args: Any, **kwargs: Any) -> None:  # noqa: ANN401 — emit's own arguments
        sidecar.write_bytes(sidecar.read_bytes() + b"\n")
        emit(*args, **kwargs)

    monkeypatch.setattr("guardana.cli._outputs.emit", edited_meanwhile)

    result = _scan(tmp_path, saved)

    assert result.exit_code == ExitCode.OK, result.output
    assert sidecar.is_file()
    assert _removals(result) == []
    assert _kept_sidecar(sidecar, saved) in _lines(result.stderr)


def test_exchanges_planted_while_the_probe_ran_are_kept_and_none_are_claimed(
    tmp_path: Path, endpoint: RefusingTransport, monkeypatch: pytest.MonkeyPatch
) -> None:
    saved = tmp_path / "run.json"
    sidecar = exchanges_path(saved)
    send = endpoint.send

    def planting(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401 — the transport's own call
        if not sidecar.exists():
            sidecar.write_bytes(b'{"messages": []}\n')
        return send(*args, **kwargs)

    monkeypatch.setattr(endpoint, "send", planting)

    result = _probe("--keep-exchanges", "--format", "json", "--output", str(saved))

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert sidecar.read_bytes() == b'{"messages": []}\n'
    assert json.loads(saved.read_text(encoding="utf-8"))["run"]["exchanges"] is None
    assert (
        f"error: {sidecar} changed while the probe ran and no run saved at {saved} records it, "
        f"so it was kept and this run's exchanges were not written"
    ) in _lines(result.stderr)


def test_kept_exchanges_replace_a_hard_link_at_their_path_and_never_write_through_it(
    tmp_path: Path,
) -> None:
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)
    elsewhere = tmp_path / "elsewhere.jsonl"
    os.link(sidecar, elsewhere)
    linked = elsewhere.read_bytes()

    result = _probe("--keep-exchanges", "--format", "json", "--output", str(saved))

    assert result.exit_code == ExitCode.OK, result.output
    assert elsewhere.read_bytes() == linked
    assert not elsewhere.samefile(sidecar)


def test_a_link_planted_while_the_probe_ran_is_replaced_and_never_written_through(
    tmp_path: Path, endpoint: RefusingTransport, monkeypatch: pytest.MonkeyPatch
) -> None:
    saved = tmp_path / "run.json"
    sidecar = exchanges_path(saved)
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_text("not exchanges\n", encoding="utf-8")
    send = endpoint.send

    def planting(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401 — the transport's own call
        with contextlib.suppress(FileExistsError):
            sidecar.symlink_to(elsewhere)
        return send(*args, **kwargs)

    monkeypatch.setattr(endpoint, "send", planting)

    result = _probe("--keep-exchanges", "--format", "json", "--output", str(saved))

    assert result.exit_code == ExitCode.OK, result.output
    assert elsewhere.read_text(encoding="utf-8") == "not exchanges\n"
    assert not sidecar.is_symlink()
    recorded = json.loads(saved.read_text(encoding="utf-8"))["run"]["exchanges"]["digest"]
    assert recorded == "sha256:" + hashlib.sha256(sidecar.read_bytes()).hexdigest()
