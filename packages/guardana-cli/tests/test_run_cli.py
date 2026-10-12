"""`guardana run inspect` and `run migrate` — reading a saved run without re-running it.

The interesting behaviour is what `inspect` says about a run that predates the
fields being asked about. "Not recorded" and "zero" have to look different on
screen, because the whole reason the loader keeps them apart is that somebody
eventually reads the output and decides something.
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli.main import app
from guardana.core.report import load_report
from guardana.core.report.run import REPORT_SCHEMA_VERSION
from guardana.core.testing import RefusingTransport
from guardana.core.verify import exchanges_path
from typer.testing import CliRunner, Result

runner = CliRunner()

_INVALID_USAGE = 3

_V1_RUN = {
    "schema_version": 1,
    "run": {
        "tool_version": "0.6.0",
        "target_kind": "endpoint",
        "target_ref": "http://localhost:11434#llama3",
        "profile": "ci",
        "rules": {"guardana.prompt.injection": "aaaabbbbccccdddd"},
        "rules_skipped": [],
        "started_at": "2026-07-25T09:00:00+00:00",
    },
    "findings": [],
    "unverified": [],
    "waived": [],
    "errors": [],
    "observations": [],
}


def _write_v1(tmp_path: Path, name: str = "old.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(_V1_RUN), encoding="utf-8")
    return path


def _scan_run(tmp_path: Path) -> Path:
    (tmp_path / "notes.txt").write_text("nothing to see\n", encoding="utf-8")
    out = tmp_path / "run.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--output", str(out)])
    assert result.exit_code == 0, result.output
    return out


def test_inspect_describes_a_current_run(tmp_path: Path) -> None:
    result = runner.invoke(app, ["run", "inspect", str(_scan_run(tmp_path))])

    assert result.exit_code == 0, result.output
    assert "artifact" in result.output
    assert "pass" in result.output


def test_inspect_says_a_migrated_run_does_not_record_its_cost(tmp_path: Path) -> None:
    # The point of the command. A blank here would read as "it cost nothing".
    result = runner.invoke(app, ["run", "inspect", str(_write_v1(tmp_path))])

    assert result.exit_code == 0, result.output
    assert "not recorded" in result.output
    assert "migrated from schema 1" in result.output


def test_inspect_says_a_migrated_run_has_no_recorded_verdict(tmp_path: Path) -> None:
    result = runner.invoke(app, ["run", "inspect", str(_write_v1(tmp_path))])

    assert "not recorded" in result.output
    # And specifically not one this build computed on the old run's behalf.
    assert "gate: pass" not in result.output
    assert "gate: fail" not in result.output


def test_inspect_emits_json_when_asked(tmp_path: Path) -> None:
    result = runner.invoke(app, ["run", "inspect", str(_scan_run(tmp_path)), "--format", "json"])

    payload = json.loads(result.output)
    assert payload["target"]["type"] == "artifact"
    assert payload["result_summary"]["gate"] == "pass"


def test_inspect_names_the_recipe_and_what_it_declared_answered(tmp_path: Path) -> None:
    path = _scan_run(tmp_path)
    plain = runner.invoke(app, ["run", "inspect", str(path)])
    document = json.loads(path.read_text(encoding="utf-8"))
    document["run"]["recipe"] = {
        "name": "checkout-assistant",
        "digest": "sha256:" + "ab" * 32,
        "lock_digest": None,
        "kind": "model_harness",
        "source": "recording",
        "unpinned": [],
    }
    path.write_text(json.dumps(document), encoding="utf-8")

    result = runner.invoke(app, ["run", "inspect", str(path)])

    assert result.exit_code == 0, result.output
    lines = [" ".join(line.split()) for line in result.output.splitlines()]
    assert "recipe: checkout-assistant (model_harness, from a recording)" in lines
    assert "recipe:" not in plain.output


def test_inspect_names_the_fixtures_a_run_was_given_and_what_they_declare(tmp_path: Path) -> None:
    path = _scan_run(tmp_path)
    plain = runner.invoke(app, ["run", "inspect", str(path)])
    document = json.loads(path.read_text(encoding="utf-8"))
    document["run"]["fixtures"] = {
        "name": "support-bot",
        "digest": "sha256:" + "ab" * 32,
        "data": {"declared": "synthetic"},
        "tenants": ["acme", "globex"],
        "counts": {"documents": 3, "records": 2, "tools": 0},
        "markers": 1,
    }
    path.write_text(json.dumps(document), encoding="utf-8")

    result = runner.invoke(app, ["run", "inspect", str(path)])

    assert result.exit_code == 0, result.output
    lines = [" ".join(line.split()) for line in result.output.splitlines()]
    assert (
        "fixtures: support-bot (data: synthetic, as declared); tenants acme, globex; "
        "3 document(s), 2 record(s), 0 tool(s)"
    ) in lines
    assert "fixtures:" not in plain.output


def test_inspect_refuses_a_file_that_is_not_a_run(tmp_path: Path) -> None:
    junk = tmp_path / "junk.json"
    junk.write_text("{}", encoding="utf-8")

    result = runner.invoke(app, ["run", "inspect", str(junk)])

    assert result.exit_code == _INVALID_USAGE


def test_migrate_rewrites_a_version_one_file_in_place(tmp_path: Path) -> None:
    path = _write_v1(tmp_path)
    out = tmp_path / "new.json"

    result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text(encoding="utf-8"))["schema_version"] == REPORT_SCHEMA_VERSION
    assert load_report(out).manifest.migrated_from == 1


def test_migrate_keeps_the_unknowns_unknown(tmp_path: Path) -> None:
    # Migration must not be a place where blanks quietly become numbers.
    out = tmp_path / "new.json"
    runner.invoke(app, ["run", "migrate", str(_write_v1(tmp_path)), "--output", str(out)])

    written = json.loads(out.read_text(encoding="utf-8"))["run"]
    assert written["usage"]["requests"] is None
    assert written["result_summary"]["gate"] is None


def test_migrate_leaves_a_current_run_alone(tmp_path: Path) -> None:
    path = _scan_run(tmp_path)
    before = path.read_text(encoding="utf-8")
    out = tmp_path / "again.json"

    result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert "already" in result.output
    assert path.read_text(encoding="utf-8") == before


def test_migrate_refuses_an_object_that_only_claims_the_current_schema(tmp_path: Path) -> None:
    # "Already current" is a statement about a run, so it needs a run: the same
    # document `run inspect` refuses is not one migrate may wave through.
    fake = tmp_path / "fake.json"
    fake.write_text(json.dumps({"schema_version": REPORT_SCHEMA_VERSION}), encoding="utf-8")

    migrated = runner.invoke(app, ["run", "migrate", str(fake)])
    inspected = runner.invoke(app, ["run", "inspect", str(fake)])

    assert inspected.exit_code == _INVALID_USAGE
    assert migrated.exit_code == _INVALID_USAGE, migrated.output
    assert "already" not in migrated.output


def _earlier_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, out: Path, *, recorded: bool
) -> Path:
    """Leave exchanges beside `out`: a probe's saved there, or a file no run there recorded."""
    sidecar = exchanges_path(out)
    if recorded:
        run, kept = _probe_that_kept_exchanges(tmp_path, monkeypatch)
        run.rename(out)
        kept.rename(sidecar)
    else:
        sidecar.write_text("kept by no run\n", encoding="utf-8")
    return sidecar


def _sidecar_outcome(result: Result, sidecar: Path, out: Path, *, recorded: bool) -> None:
    assert result.exit_code == 0, result.output
    if recorded:
        assert not sidecar.exists()
        assert f"removed {sidecar}, which an earlier run at this path kept" in result.stderr
    else:
        assert sidecar.read_text(encoding="utf-8") == "kept by no run\n"
        assert "removed" not in result.stderr
        assert (
            f"warning: kept {sidecar}: no run saved at {out} before this one recorded it"
        ) in result.stderr


@pytest.mark.parametrize("recorded", [True, False], ids=["an earlier run's", "no run's"])
def test_migrate_to_another_output_removes_only_the_exchanges_the_run_there_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, recorded: bool
) -> None:
    out = tmp_path / "new.json"
    sidecar = _earlier_sidecar(tmp_path, monkeypatch, out, recorded=recorded)

    result = runner.invoke(app, ["run", "migrate", str(_write_v1(tmp_path)), "--output", str(out)])

    _sidecar_outcome(result, sidecar, out, recorded=recorded)


@pytest.mark.parametrize("output", [None, "old"], ids=["in place", "run.json to run"])
def test_migrate_keeps_the_exchanges_the_migrated_run_kept(
    tmp_path: Path, output: str | None
) -> None:
    path = _write_v1(tmp_path)
    own = tmp_path / "old.exchanges.jsonl"
    own.write_text("kept by this run\n", encoding="utf-8")
    where = [] if output is None else ["--output", str(tmp_path / output)]

    result = runner.invoke(app, ["run", "migrate", str(path), *where])

    assert result.exit_code == 0, result.output
    assert own.read_text(encoding="utf-8") == "kept by this run\n"
    assert "removed" not in result.stderr


def test_migrate_copies_a_current_run_to_another_output(tmp_path: Path) -> None:
    path = _scan_run(tmp_path)
    before = path.read_text(encoding="utf-8")
    out = tmp_path / "again.json"
    out.write_text("a stale earlier file\n", encoding="utf-8")

    result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert f"copied it unchanged → {out}" in result.output
    assert json.loads(out.read_text(encoding="utf-8")) == json.loads(before)
    assert path.read_text(encoding="utf-8") == before


@pytest.mark.parametrize("recorded", [True, False], ids=["an earlier run's", "no run's"])
def test_migrate_copying_a_current_run_removes_only_the_exchanges_the_run_there_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, recorded: bool
) -> None:
    out = tmp_path / "again.json"
    sidecar = _earlier_sidecar(tmp_path, monkeypatch, out, recorded=recorded)

    result = runner.invoke(app, ["run", "migrate", str(_scan_run(tmp_path)), "--output", str(out)])

    _sidecar_outcome(result, sidecar, out, recorded=recorded)


def test_migrate_of_a_current_run_in_place_writes_nothing(tmp_path: Path) -> None:
    path = _scan_run(tmp_path)
    path.chmod(0o444)

    try:
        result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(path)])
    finally:
        path.chmod(0o644)

    assert result.exit_code == 0, result.output
    assert "nothing to do" in result.output
    assert "copied" not in result.output


@pytest.mark.parametrize("source", ["v1", "current"])
@pytest.mark.parametrize("locked", ["file", "directory"], ids=["read-only file", "read-only dir"])
def test_migrate_that_cannot_write_is_a_usage_error_that_removes_nothing(
    tmp_path: Path, source: str, locked: str
) -> None:
    path = _write_v1(tmp_path) if source == "v1" else _scan_run(tmp_path)
    folder = tmp_path / "saved"
    folder.mkdir()
    out = folder / "new.json"
    sidecar = folder / "new.exchanges.jsonl"
    sidecar.write_text("kept by an earlier run\n", encoding="utf-8")
    if locked == "file":
        out.write_text("an earlier run\n", encoding="utf-8")
        out.chmod(0o444)
    else:
        folder.chmod(0o555)
    before = {kept: kept.read_bytes() for kept in folder.iterdir()}

    try:
        result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(out)])
    finally:
        folder.chmod(0o755)

    assert result.exit_code == _INVALID_USAGE, result.output
    assert f"error: could not write {out}: " in result.stderr
    assert not isinstance(result.exception, OSError)
    assert {kept: kept.read_bytes() for kept in folder.iterdir()} == before
    assert "removed" not in result.stderr


_UNDER_A_FILE_SIZE_LIMIT = """
import resource, sys
from guardana.cli.main import app

limit = int(sys.argv[1])
resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
app(["run", "migrate", *sys.argv[2:]])
"""


def test_migrate_in_place_that_fails_part_way_leaves_the_run_as_it_was(tmp_path: Path) -> None:
    path = _write_v1(tmp_path)
    before = path.read_bytes()

    # The limit lets the migrated document start to land and stops it part-way.
    result = subprocess.run(  # noqa: S603 — this interpreter, a script defined above
        [sys.executable, "-c", _UNDER_A_FILE_SIZE_LIMIT, str(len(before)), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == _INVALID_USAGE, result.stdout + result.stderr
    assert f"error: could not write {path}: " in result.stderr
    assert path.read_bytes() == before
    assert sorted(tmp_path.iterdir()) == [path]


def test_migrate_copies_a_current_run_byte_for_byte(tmp_path: Path) -> None:
    path = _scan_run(tmp_path)
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    before = path.read_bytes()
    out = tmp_path / "again.json"

    result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert out.read_bytes() == before


@pytest.mark.parametrize("source", ["v1", "current"])
def test_migrate_refuses_an_output_that_is_the_runs_own_exchanges(
    tmp_path: Path, source: str
) -> None:
    path = _write_v1(tmp_path, "run.json") if source == "v1" else _scan_run(tmp_path)
    own = tmp_path / "run.exchanges.jsonl"
    own.write_text("kept by this run\n", encoding="utf-8")
    before = path.read_bytes()

    result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(own)])

    assert result.exit_code == _INVALID_USAGE, result.output
    assert f"error: --output {own} is where {path} keeps its exchanges" in result.stderr
    assert own.read_text(encoding="utf-8") == "kept by this run\n"
    assert path.read_bytes() == before


def test_migrate_in_place_keeps_the_files_mode(tmp_path: Path) -> None:
    path = _write_v1(tmp_path)
    path.chmod(0o640)

    result = runner.invoke(app, ["run", "migrate", str(path)])

    assert result.exit_code == 0, result.output
    assert path.stat().st_mode & 0o777 == 0o640


def test_migrate_to_a_new_output_gets_the_mode_a_plain_write_would(tmp_path: Path) -> None:
    out = tmp_path / "new.json"
    umask = os.umask(0o022)
    os.umask(umask)

    result = runner.invoke(app, ["run", "migrate", str(_write_v1(tmp_path)), "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert out.stat().st_mode & 0o777 == 0o666 & ~umask


def test_migrate_through_a_symlink_writes_the_file_it_names(tmp_path: Path) -> None:
    real = _write_v1(tmp_path)
    link = tmp_path / "link.json"
    link.symlink_to(real)

    result = runner.invoke(app, ["run", "migrate", str(link)])

    assert result.exit_code == 0, result.output
    assert link.is_symlink()
    assert load_report(real).manifest.migrated_from == 1


def test_migrate_to_a_directory_is_a_usage_error_that_leaves_nothing_behind(
    tmp_path: Path,
) -> None:
    path = _write_v1(tmp_path)
    out = tmp_path / "new.json"
    out.mkdir()
    before = sorted(tmp_path.iterdir())

    result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(out)])

    assert result.exit_code == _INVALID_USAGE, result.output
    assert f"error: could not write {out}: " in result.stderr
    assert sorted(tmp_path.iterdir()) == before
    assert out.is_dir()
    assert not any(out.iterdir())


def _probe_that_kept_exchanges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, schema: int = REPORT_SCHEMA_VERSION
) -> tuple[Path, Path]:
    """Save a probe that kept its exchanges at `schema`; return the run and its sidecar."""
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)
    path = tmp_path / "probe.json"
    result = runner.invoke(
        app,
        [
            "probe",
            *("--url", "http://fake", "--model", "m", "--keep-exchanges"),
            *("--format", "json", "--output", str(path)),
        ],
    )
    assert result.exit_code == 0, result.output
    if schema != REPORT_SCHEMA_VERSION:
        document = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps({**document, "schema_version": schema}), encoding="utf-8")
    sidecar = exchanges_path(path)
    assert sidecar.is_file(), result.output
    return path, sidecar


def _recorded(run: Path) -> str:
    return str(json.loads(run.read_text(encoding="utf-8"))["run"]["exchanges"]["digest"])


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("schema", [REPORT_SCHEMA_VERSION, REPORT_SCHEMA_VERSION - 1])
def test_migrate_to_another_output_copies_the_sidecar_its_run_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, schema: int
) -> None:
    path, sidecar = _probe_that_kept_exchanges(tmp_path, monkeypatch, schema=schema)
    before = sidecar.read_bytes()
    out = tmp_path / "copy" / "run.json"
    out.parent.mkdir()

    result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert exchanges_path(out).read_bytes() == before
    assert _recorded(out) == _digest(exchanges_path(out))
    assert sidecar.read_bytes() == before
    assert f"copied the exchanges {path} records → {exchanges_path(out)}" in result.stderr


def test_migrate_refuses_an_output_whose_sidecar_holds_other_exchanges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _sidecar = _probe_that_kept_exchanges(tmp_path, monkeypatch)
    out = tmp_path / "again.json"
    out.write_text("an earlier run\n", encoding="utf-8")
    beside = exchanges_path(out)
    beside.write_text("kept by an earlier run\n", encoding="utf-8")
    before = {kept: kept.read_bytes() for kept in tmp_path.iterdir()}

    result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(out)])

    assert result.exit_code == _INVALID_USAGE, result.output
    assert (
        f"error: {beside} holds other exchanges than the ones {path} records, and the copy at "
        f"{out} would claim them — choose another --output"
    ) in " ".join(result.stderr.split())
    assert {kept: kept.read_bytes() for kept in tmp_path.iterdir()} == before


def test_migrate_to_an_output_whose_sidecar_already_holds_these_exchanges_keeps_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, sidecar = _probe_that_kept_exchanges(tmp_path, monkeypatch)
    out = tmp_path / "again.json"
    exchanges_path(out).write_bytes(sidecar.read_bytes())

    result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert _recorded(out) == _digest(exchanges_path(out))
    assert "removed" not in result.stderr


@pytest.mark.parametrize("sidecar_state", ["missing", "other bytes"])
def test_migrate_of_a_run_without_its_sidecar_copies_nothing_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sidecar_state: str
) -> None:
    path, sidecar = _probe_that_kept_exchanges(tmp_path, monkeypatch)
    if sidecar_state == "missing":
        sidecar.unlink()
    else:
        sidecar.write_bytes(sidecar.read_bytes() + b"\n")
    out = tmp_path / "copy" / "run.json"
    out.parent.mkdir()

    result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert not exchanges_path(out).exists()
    assert (
        f"warning: {sidecar} is not the exchanges {path} records, so none were copied beside {out}"
    ) in " ".join(result.stderr.split())


def test_migrate_whose_run_cannot_be_written_removes_the_sidecar_it_copied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _sidecar = _probe_that_kept_exchanges(tmp_path, monkeypatch)
    folder = tmp_path / "copy"
    folder.mkdir()
    out = folder / "run.json"
    out.write_text("an earlier run\n", encoding="utf-8")
    out.chmod(0o444)

    try:
        result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(out)])
    finally:
        out.chmod(0o644)

    assert result.exit_code == _INVALID_USAGE, result.output
    assert f"error: could not write {out}: " in result.stderr
    assert sorted(folder.iterdir()) == [out]
    assert out.read_text(encoding="utf-8") == "an earlier run\n"


def test_migrate_in_place_of_a_run_that_kept_exchanges_leaves_them_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, sidecar = _probe_that_kept_exchanges(
        tmp_path, monkeypatch, schema=REPORT_SCHEMA_VERSION - 1
    )
    before = sidecar.read_bytes()

    result = runner.invoke(app, ["run", "migrate", str(path)])

    assert result.exit_code == 0, result.output
    assert sidecar.read_bytes() == before
    assert _recorded(path) == _digest(sidecar)
    assert "copied the exchanges" not in result.stderr
