"""An installed format writes verbatim, a failed one exits 8, and every reporter prints one line.

The delivery line is printed once for a selected reporter on every path: after the
report on a finished run, and as `not_sent` with its reason when the command ends
first. `unknown` and a failed format exit `8`, and a failure of Guardana's own redaction
exits `5`, unless the run stopped, whose code outranks all three; every other delivery
status keeps the verdict's code. Whenever the exit replaces the verdict's code, the
verdict is printed.
"""

import io
import re
import sys
from collections.abc import Iterator
from contextlib import redirect_stderr
from pathlib import Path
from typing import IO
from urllib.error import URLError

import guardana.cli._endpoint as endpoint_module
import guardana.core.output as output_module
import pytest
import typer
from _fake_distribution import FakeModule, FakeSite
from guardana.cli._formats import OutputFormat
from guardana.cli._outputs import RunOutputs
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.entrypoints import RENDERER_GROUP, REPORTER_GROUP
from guardana.core.origin import Origin
from guardana.core.output import (
    Delivery,
    PreparedReporter,
    ReporterRequest,
    ReporterSpec,
)
from guardana.core.target import EndpointError
from guardana.core.testing import FailingTransport, RefusingTransport
from guardana.core.verify import Verification, exchanges_path
from typer.testing import CliRunner, Result

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_DIST = "acme-guardana-outputs"
_ADMIT = ["--plugins", "allowlist", "--allow-plugin", _DIST]
_HOOK = "acme-webhook://https://hooks.example.invalid/guardana"
_TO = "acme-webhook to https://hooks.example.invalid"
_COLLECTOR = "http://collector.example.invalid:8000"
_NOT_FORWARDED = (
    "warning: nothing was forwarded to the collector: the run's report was not produced"
)

_HEADER = """\
from pathlib import Path

from guardana.core.output import Delivery, DeliveryStatus, RendererSpec, ReporterSpec

Path(__file__).with_name(__name__ + ".imported").write_text("imported", encoding="utf-8")
SEEN = []
"""

_TABLE = (
    _HEADER
    + """

def _render(verification):
    SEEN.append(verification)
    return RENDERED


def provide():
    return RendererSpec(name="acme-table", summary="a table", render=_render)
"""
)

_HOOK_MODULE = (
    _HEADER
    + """

class _Deliverer:
    destination = "https://hooks.example.invalid"

    def sent_secrets(self):
        return ()

    def deliver(self, verification):
        SEEN.append(verification)
        DELIVER


def provide():
    return ReporterSpec(name="acme-webhook", summary="a hook", prepare=lambda r: _Deliverer())
"""
)


def _plain(text: str) -> str:
    return " ".join(_ANSI.sub("", text).replace("│", " ").split())


def _lines(text: str) -> list[str]:
    return [line.strip() for line in _ANSI.sub("", text).splitlines() if line.strip()]


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


@pytest.fixture
def endpoint(monkeypatch: pytest.MonkeyPatch) -> RefusingTransport:
    transport = RefusingTransport()
    monkeypatch.setattr(endpoint_module, "transport_factory", lambda: transport)
    return transport


@pytest.fixture
def clean_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return tree


@pytest.fixture
def failing_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "failing"
    tree.mkdir()
    (tree / "bad.py").write_text("import torch\ntorch.load('m.pt')\n", encoding="utf-8")
    return tree


def _table(site: FakeSite, rendered: str = "'a,b\\r\\n1,2\\r\\n'") -> FakeModule:
    module = site.module(_TABLE.replace("RENDERED", rendered))
    site.distribution(_DIST, (RENDERER_GROUP, "acme-table", module.name))
    return module


def _hook(site: FakeSite, deliver: str) -> FakeModule:
    module = site.module(_HOOK_MODULE.replace("DELIVER", deliver))
    site.distribution(_DIST, (REPORTER_GROUP, "acme-webhook", module.name))
    return module


def _both(site: FakeSite, rendered: str, deliver: str) -> tuple[FakeModule, FakeModule]:
    table = site.module(_TABLE.replace("RENDERED", rendered))
    hook = site.module(_HOOK_MODULE.replace("DELIVER", deliver))
    site.distribution(
        _DIST,
        (RENDERER_GROUP, "acme-table", table.name),
        (REPORTER_GROUP, "acme-webhook", hook.name),
    )
    return table, hook


def _seen(module: FakeModule) -> list[Verification]:
    seen: list[Verification] = sys.modules[module.name].SEEN
    return seen


def _delivery_lines(output: str) -> list[str]:
    return [line for line in _lines(output) if line.startswith("delivery:")]


def _probe(*arguments: str) -> Result:
    return runner.invoke(app, ["probe", "--url", "http://fake", "--model", "m", *arguments])


def _trace(tmp_path: Path) -> Path:
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        '{"guardana_trace": 1, "trace_id": "t-1", "producer": {"name": "acme"}, '
        '"instrumented": ["messages", "tools"]}\n'
        '{"span_id": "s1", "kind": "tool_execution", "name": "http", "tool": {"name": "http"}}\n',
        encoding="utf-8",
    )
    return trace


def _failing_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make Guardana's own redaction at the output boundary raise, for both kinds of output."""

    def outbound(verification: Verification, *, leaves_machine: bool) -> Verification:
        raise RuntimeError("cannot redact")

    monkeypatch.setattr(output_module, "outbound", outbound)


def test_an_installed_format_is_written_verbatim(
    site: FakeSite, clean_tree: Path, tmp_path: Path
) -> None:
    module = _table(site)
    saved = tmp_path / "run.csv"

    result = runner.invoke(
        app, ["scan", str(clean_tree), "--format", "acme-table", "--output", str(saved), *_ADMIT]
    )

    assert result.exit_code == ExitCode.OK, result.output
    assert saved.read_bytes() == b"a,b\r\n1,2\r\n"
    assert "acme-table format, which `guardana diff` cannot read" in _plain(result.output)
    assert len(_seen(module)) == 1


def test_an_installed_format_is_printed_without_an_added_newline(
    site: FakeSite, clean_tree: Path
) -> None:
    _table(site, rendered="'no newline at the end'")

    result = runner.invoke(app, ["scan", str(clean_tree), "--format", "acme-table", *_ADMIT])

    assert result.exit_code == ExitCode.OK, result.output
    assert result.stdout == "no newline at the end"


@pytest.mark.parametrize(
    ("rendered", "reason"),
    [
        ("(_ for _ in ()).throw(ValueError('the table broke'))", "ValueError: the table broke"),
        ("''", "it returned no text"),
    ],
)
def test_a_failed_format_exits_8_with_the_verdict_and_writes_nothing(
    site: FakeSite, failing_tree: Path, tmp_path: Path, rendered: str, reason: str
) -> None:
    _table(site, rendered=rendered)
    saved = tmp_path / "run.csv"

    result = runner.invoke(
        app,
        ["scan", str(failing_tree), "--format", "acme-table", "--output", str(saved), *_ADMIT],
    )

    assert result.exit_code == ExitCode.OUTPUT_FAILED, result.output
    lines = _lines(result.output)
    verdict = lines.index("the run's verdict: fail (exit 1)")
    assert lines[verdict + 1] == (
        f"error: the format acme-table from {_DIST} 1.0 failed: {reason} — nothing was "
        f"written; report it to {_DIST}"
    )
    assert not saved.exists()
    assert _delivery_lines(result.output) == []


@pytest.mark.parametrize(
    ("rendered", "code"),
    [("''", ExitCode.OUTPUT_FAILED), ("'a,b'", ExitCode.INTERNAL_ERROR)],
    ids=["format-failed", "redaction-failed"],
)
def test_a_failed_format_removes_an_earlier_run_at_its_output(  # noqa: PLR0913 — the matrix
    site: FakeSite,
    clean_tree: Path,
    failing_tree: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    rendered: str,
    code: ExitCode,
) -> None:
    saved = tmp_path / "run.json"
    earlier = runner.invoke(
        app, ["scan", str(clean_tree), "--format", "json", "--output", str(saved)]
    )
    assert earlier.exit_code == ExitCode.OK, earlier.output
    assert saved.is_file()
    _table(site, rendered=rendered)
    if code is ExitCode.INTERNAL_ERROR:
        _failing_boundary(monkeypatch)

    result = runner.invoke(
        app,
        ["scan", str(failing_tree), "--format", "acme-table", "--output", str(saved), *_ADMIT],
    )

    assert result.exit_code == code, result.output
    assert not saved.exists()
    assert _lines(result.output)[-1] == f"removed {saved}: this run did not write it"


@pytest.mark.parametrize(
    ("rendered", "code"),
    [("''", ExitCode.OUTPUT_FAILED), ("'a,b'", ExitCode.INTERNAL_ERROR)],
    ids=["format-failed", "redaction-failed"],
)
def test_a_failed_format_keeps_a_read_only_file_at_its_output(  # noqa: PLR0913 — the matrix
    site: FakeSite,
    failing_tree: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    rendered: str,
    code: ExitCode,
) -> None:
    """A file this process may not write to is one the user protected, run or not."""
    notes = tmp_path / "notes.txt"
    notes.write_text("notes\n", encoding="utf-8")
    notes.chmod(0o444)
    _table(site, rendered=rendered)
    if code is ExitCode.INTERNAL_ERROR:
        _failing_boundary(monkeypatch)

    result = runner.invoke(
        app,
        ["scan", str(failing_tree), "--format", "acme-table", "--output", str(notes), *_ADMIT],
    )

    assert result.exit_code == code, result.output
    assert notes.read_text(encoding="utf-8") == "notes\n"
    lines = _lines(result.output)
    assert lines[-1] == (
        f"warning: kept {notes}: it is not writable, so it still holds what was there "
        f"before this run"
    )
    assert not [line for line in lines if line.startswith("removed ")]


def _probe_that_kept_exchanges(saved: Path) -> Path:
    """Probe once with `--keep-exchanges` into `saved` and return the sidecar it wrote."""
    earlier = _probe("--keep-exchanges", "--format", "json", "--output", str(saved))
    assert earlier.exit_code == ExitCode.OK, earlier.output
    sidecar = exchanges_path(saved)
    assert sidecar.is_file(), earlier.output
    return sidecar


@pytest.mark.parametrize(
    ("rendered", "code"),
    [("''", ExitCode.OUTPUT_FAILED), ("'a,b'", ExitCode.INTERNAL_ERROR)],
    ids=["format-failed", "redaction-failed"],
)
def test_a_failed_format_removes_the_exchanges_an_earlier_probe_kept_at_its_output(  # noqa: PLR0913 — the matrix
    site: FakeSite,
    endpoint: RefusingTransport,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    rendered: str,
    code: ExitCode,
) -> None:
    """Left in place, the earlier probe's exchanges would read as kept beside this run."""
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)
    _table(site, rendered=rendered)
    if code is ExitCode.INTERNAL_ERROR:
        _failing_boundary(monkeypatch)

    result = _probe("--format", "acme-table", "--output", str(saved), *_ADMIT)

    assert result.exit_code == code, result.output
    assert not saved.exists()
    assert not sidecar.exists()
    assert _lines(result.output)[-2:] == [
        f"removed {saved}: this run did not write it",
        f"removed {sidecar}, which an earlier run at this path kept",
    ]


def test_a_failed_format_keeps_a_read_only_sidecar_beside_its_output(
    site: FakeSite, endpoint: RefusingTransport, tmp_path: Path
) -> None:
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)
    kept = sidecar.read_bytes()
    sidecar.chmod(0o444)
    _table(site, rendered="''")

    result = _probe("--format", "acme-table", "--output", str(saved), *_ADMIT)

    assert result.exit_code == ExitCode.OUTPUT_FAILED, result.output
    assert not saved.exists()
    assert sidecar.read_bytes() == kept
    assert _lines(result.output)[-2:] == [
        f"removed {saved}: this run did not write it",
        f"warning: kept {sidecar}: it is not writable, so it still holds what was there "
        f"before this run",
    ]


def test_a_failed_format_keeps_exchanges_the_run_it_replaced_did_not_record(
    site: FakeSite, endpoint: RefusingTransport, tmp_path: Path
) -> None:
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)
    sidecar.write_bytes(sidecar.read_bytes() + b"\n")
    kept = sidecar.read_bytes()
    _table(site, rendered="''")

    result = _probe("--format", "acme-table", "--output", str(saved), *_ADMIT)

    assert result.exit_code == ExitCode.OUTPUT_FAILED, result.output
    assert not saved.exists()
    assert sidecar.read_bytes() == kept
    assert _lines(result.output)[-2:] == [
        f"removed {saved}: this run did not write it",
        f"warning: kept {sidecar}: no run saved at {saved} before this one recorded it, so it "
        f"is not an earlier run's exchanges",
    ]


def test_a_sidecar_that_cannot_be_removed_is_a_warning(
    site: FakeSite,
    endpoint: RefusingTransport,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)
    _table(site, rendered="''")
    unlink = Path.unlink

    def refuse_the_sidecar(path: Path, missing_ok: bool = False) -> None:
        if path == sidecar:
            raise PermissionError("read-only")
        unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", refuse_the_sidecar)

    result = _probe("--format", "acme-table", "--output", str(saved), *_ADMIT)

    assert result.exit_code == ExitCode.OUTPUT_FAILED, result.output
    assert sidecar.is_file()
    assert _lines(result.output)[-1] == (
        f"warning: {sidecar} still holds exchanges an earlier run kept, not this run's: "
        f"could not remove it: read-only"
    )


def test_a_probe_whose_format_succeeds_removes_an_earlier_sidecar_once(
    site: FakeSite, endpoint: RefusingTransport, tmp_path: Path
) -> None:
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)
    _table(site)

    result = _probe("--format", "acme-table", "--output", str(saved), *_ADMIT)

    assert result.exit_code == ExitCode.OK, result.output
    assert saved.read_bytes() == b"a,b\r\n1,2\r\n"
    assert not sidecar.exists()
    removed = [line for line in _lines(result.output) if line.startswith("removed ")]
    assert removed == [f"removed {sidecar}, which an earlier run at this path kept"]


def test_a_probe_that_cannot_remove_an_earlier_sidecar_warns_and_keeps_its_verdict(
    site: FakeSite,
    endpoint: RefusingTransport,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saved = tmp_path / "run.json"
    sidecar = _probe_that_kept_exchanges(saved)
    _table(site)
    unlink = Path.unlink

    def refuse_the_sidecar(path: Path, missing_ok: bool = False) -> None:
        if path == sidecar:
            raise PermissionError("read-only")
        unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", refuse_the_sidecar)

    result = _probe("--format", "acme-table", "--output", str(saved), *_ADMIT)

    assert result.exit_code == ExitCode.OK, result.output
    assert sidecar.is_file()
    assert (
        f"warning: {sidecar} still holds exchanges an earlier run kept, not this run's: "
        f"could not remove it: read-only"
    ) in _lines(result.output)


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


@pytest.mark.parametrize(
    ("budget", "code"),
    [((), ExitCode.INVALID_USAGE), (("--max-requests", "1"), ExitCode.BUDGET_EXHAUSTED)],
    ids=["finished", "stopped"],
)
def test_exchanges_that_cannot_be_written_send_nothing_and_remove_nothing(  # noqa: PLR0913 — the matrix
    site: FakeSite,
    endpoint: RefusingTransport,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    budget: tuple[str, ...],
    code: ExitCode,
) -> None:
    hook = _hook(site, "return Delivery(DeliveryStatus.DELIVERED)")
    saved = tmp_path / "run.json"
    sidecar = exchanges_path(saved)
    _fill_the_disk_writing(monkeypatch, sidecar)

    result = _probe(
        "--keep-exchanges",
        "--format",
        "json",
        "--output",
        str(saved),
        "--reporter",
        _HOOK,
        *budget,
        *_ADMIT,
    )

    assert result.exit_code == code, result.output
    lines = _lines(result.output)
    assert (
        f"error: could not write the kept exchanges to {sidecar}: No space left on device"
    ) in lines
    assert not any(line.startswith("removed ") for line in lines)
    assert _delivery_lines(result.output) == [
        f"delivery: not_sent — {_TO}: the run's kept exchanges could not be written"
    ]
    assert _seen(hook) == []


def test_a_failed_format_says_its_report_was_not_produced_to_the_reporter(
    site: FakeSite, clean_tree: Path
) -> None:
    _table_module, hook = _both(
        site,
        rendered="''",
        deliver="return Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=204)",
    )

    result = runner.invoke(
        app,
        ["scan", str(clean_tree), "--format", "acme-table", "--reporter", _HOOK, *_ADMIT],
    )

    assert result.exit_code == ExitCode.OUTPUT_FAILED, result.output
    lines = _lines(result.output)
    assert lines[-3] == "the run's verdict: pass (exit 0)"
    assert lines[-2].startswith("error: the format acme-table")
    assert lines[-1] == f"delivery: not_sent — {_TO}: the run's report was not produced"
    assert len(_delivery_lines(result.output)) == 1
    assert _seen(hook) == []


@pytest.mark.parametrize(
    ("deliver", "line"),
    [
        (
            "return Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=204)",
            f"delivery: delivered — {_TO} (HTTP 204, 1 attempt)",
        ),
        (
            "return Delivery(DeliveryStatus.REJECTED, detail='the receiver no longer accepts "
            "deliveries', attempts=1, http_status=410)",
            f"delivery: rejected — {_TO} (HTTP 410, 1 attempt): the receiver no longer accepts "
            f"deliveries",
        ),
        (
            "return Delivery(DeliveryStatus.UNREACHABLE, detail='timed out', attempts=3)",
            f"delivery: unreachable — {_TO} (3 attempts): timed out",
        ),
        (
            "return Delivery(DeliveryStatus.NOT_SENT, detail='the body is too large')",
            f"delivery: not_sent — {_TO}: the body is too large",
        ),
    ],
)
@pytest.mark.parametrize(("tree", "code"), [("clean_tree", ExitCode.OK), ("failing_tree", 1)])
def test_a_delivery_prints_its_line_once_and_keeps_the_verdicts_code(  # noqa: PLR0913 — the matrix
    site: FakeSite,
    request: pytest.FixtureRequest,
    *,
    deliver: str,
    line: str,
    tree: str,
    code: int,
) -> None:
    hook = _hook(site, deliver)
    scanned: Path = request.getfixturevalue(tree)

    result = runner.invoke(app, ["scan", str(scanned), "--reporter", _HOOK, *_ADMIT])

    assert result.exit_code == code, result.output
    assert _delivery_lines(result.output) == [line]
    assert len(_seen(hook)) == 1


def test_a_delivery_follows_the_report(site: FakeSite, clean_tree: Path) -> None:
    _hook(site, "return Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=204)")

    result = runner.invoke(
        app, ["scan", str(clean_tree), "--format", "json", "--reporter", _HOOK, *_ADMIT]
    )

    assert result.exit_code == ExitCode.OK, result.output
    output = _ANSI.sub("", result.output)
    assert output.index('"schema_version"') < output.index("delivery: delivered")


def test_a_reporter_that_raises_is_unknown_and_exits_8(site: FakeSite, clean_tree: Path) -> None:
    _hook(site, "raise RuntimeError('the hook is broken')")

    result = runner.invoke(app, ["scan", str(clean_tree), "--reporter", _HOOK, *_ADMIT])

    assert result.exit_code == ExitCode.OUTPUT_FAILED, result.output
    assert _lines(result.output)[-2:] == [
        f"delivery: unknown — {_TO}: RuntimeError: the hook is broken",
        "the run's verdict: pass (exit 0)",
    ]
    assert len(_delivery_lines(result.output)) == 1


def test_a_probe_delivers_after_the_endpoint_answered(
    site: FakeSite, endpoint: RefusingTransport
) -> None:
    hook = _hook(site, "return Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=204)")

    result = _probe("--reporter", _HOOK, *_ADMIT)

    assert result.exit_code == ExitCode.OK, result.output
    assert endpoint.seen != []
    assert _delivery_lines(result.output) == [f"delivery: delivered — {_TO} (HTTP 204, 1 attempt)"]
    assert _seen(hook)[0].manifest.target.ref == "http://fake#m"


def test_a_stopped_probe_keeps_its_code_over_an_unknown_delivery(
    site: FakeSite, endpoint: RefusingTransport
) -> None:
    _hook(site, "raise RuntimeError('the hook is broken')")

    result = _probe("--reporter", _HOOK, "--max-requests", "1", *_ADMIT)

    assert result.exit_code == ExitCode.BUDGET_EXHAUSTED, result.output
    assert _delivery_lines(result.output) == [
        f"delivery: unknown — {_TO}: RuntimeError: the hook is broken"
    ]
    assert not any(line.startswith("the run's verdict:") for line in _lines(result.output))


def test_a_stopped_probe_keeps_its_code_over_a_failed_format(
    site: FakeSite, endpoint: RefusingTransport
) -> None:
    _table(site, rendered="''")

    result = _probe("--format", "acme-table", "--max-requests", "1", *_ADMIT)

    assert result.exit_code == ExitCode.BUDGET_EXHAUSTED, result.output
    assert "the run's verdict: indeterminate (exit 6)" in _lines(result.output)


@pytest.mark.parametrize(
    ("arguments", "rendered", "redaction_fails"),
    [
        (["--format", "acme-table"], "''", False),
        (["--format", "acme-table"], "'a,b'", True),
        ([], "'a,b'", True),
    ],
    ids=["format-failed", "format-redaction-failed", "reporter-redaction-failed"],
)
def test_a_probe_its_target_stopped_names_the_stop_when_its_output_fails(
    site: FakeSite,
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
    rendered: str,
    *,
    redaction_fails: bool,
) -> None:
    monkeypatch.setattr(
        endpoint_module,
        "transport_factory",
        lambda: FailingTransport(URLError(ConnectionRefusedError("refused"))),
    )
    _both(site, rendered=rendered, deliver="return Delivery(DeliveryStatus.DELIVERED)")
    if redaction_fails:
        _failing_boundary(monkeypatch)

    result = _probe(*arguments, "--reporter", _HOOK, *_ADMIT)

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output
    lines = _lines(result.output)
    assert "the run's verdict: indeterminate (exit 4)" in lines
    assert "error: could not reach endpoint http://fake#m: <urlopen error refused>" in lines


def test_a_format_whose_redaction_fails_exits_5_with_the_verdict_and_writes_nothing(
    site: FakeSite, failing_tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    table, hook = _both(
        site,
        rendered="'a,b'",
        deliver="return Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=204)",
    )
    _failing_boundary(monkeypatch)
    saved = tmp_path / "run.csv"

    result = runner.invoke(
        app,
        [
            "scan",
            str(failing_tree),
            "--format",
            "acme-table",
            "--output",
            str(saved),
            "--reporter",
            _HOOK,
            *_ADMIT,
        ],
    )

    assert result.exit_code == ExitCode.INTERNAL_ERROR, result.output
    refused = (
        "error: the run could not be redacted for the format acme-table: RuntimeError — "
        "nothing was written; this is a defect in Guardana"
    )
    assert _lines(result.output)[-3:] == [
        "the run's verdict: fail (exit 1)",
        refused,
        f"delivery: not_sent — {_TO}: the run's report was not produced",
    ]
    assert not saved.exists()
    assert _seen(table) == []
    assert _seen(hook) == []


def test_a_reporter_whose_redaction_fails_sends_nothing_and_exits_5(
    site: FakeSite, clean_tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hook = _hook(site, "return Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=204)")
    _failing_boundary(monkeypatch)

    result = runner.invoke(app, ["scan", str(clean_tree), "--reporter", _HOOK, *_ADMIT])

    assert result.exit_code == ExitCode.INTERNAL_ERROR, result.output
    refused = (
        "error: the run could not be redacted for the reporter acme-webhook: RuntimeError — "
        "nothing was sent; this is a defect in Guardana"
    )
    assert _lines(result.output)[-3:] == [
        "the run's verdict: pass (exit 0)",
        refused,
        f"delivery: not_sent — {_TO}: redaction failed: RuntimeError",
    ]
    assert len(_delivery_lines(result.output)) == 1
    assert _seen(hook) == []


@pytest.mark.parametrize(
    ("arguments", "said"),
    [
        (["--reporter", _HOOK], "redaction failed: RuntimeError"),
        (["--format", "acme-table"], "the run's report was not produced"),
    ],
    ids=["reporter", "format"],
)
@pytest.mark.parametrize("debug", [True, False], ids=["debug", "quiet"])
def test_a_failed_redaction_prints_its_traceback_only_with_guardana_debug(  # noqa: PLR0913 — the matrix
    site: FakeSite,
    clean_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
    said: str,
    *,
    debug: bool,
) -> None:
    _both(site, rendered="'a,b'", deliver="return Delivery(DeliveryStatus.DELIVERED)")
    _failing_boundary(monkeypatch)
    if debug:
        monkeypatch.setenv("GUARDANA_DEBUG", "1")
    else:
        monkeypatch.delenv("GUARDANA_DEBUG", raising=False)
    if "--format" in arguments:
        arguments = [*arguments, "--reporter", _HOOK]

    result = runner.invoke(app, ["scan", str(clean_tree), *arguments, *_ADMIT])

    assert result.exit_code == ExitCode.INTERNAL_ERROR, result.output
    lines = _lines(result.output)
    assert lines[-3].startswith("the run's verdict: pass (exit 0)")
    assert lines[-2].startswith("error: the run could not be redacted for the ")
    assert lines[-1] == f"delivery: not_sent — {_TO}: {said}"
    printed = "Traceback (most recent call last):" in lines
    assert printed is debug
    assert ("RuntimeError: cannot redact" in lines) is debug
    if debug:
        assert lines.index("Traceback (most recent call last):") < len(lines) - 3


@pytest.mark.parametrize(
    ("arguments", "said"),
    [
        (["--reporter", _HOOK], "nothing was sent"),
        (["--format", "acme-table"], "nothing was written"),
    ],
)
def test_a_stopped_probe_keeps_its_code_over_a_failed_redaction(
    site: FakeSite,
    endpoint: RefusingTransport,
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
    said: str,
) -> None:
    _both(site, rendered="'a,b'", deliver="return Delivery(DeliveryStatus.DELIVERED)")
    _failing_boundary(monkeypatch)

    result = _probe(*arguments, "--max-requests", "1", *_ADMIT)

    assert result.exit_code == ExitCode.BUDGET_EXHAUSTED, result.output
    lines = _lines(result.output)
    assert "the run's verdict: indeterminate (exit 6)" in lines
    assert any(line.startswith("error: the run could not be redacted") for line in lines)
    assert said in _plain(result.output)


@pytest.mark.parametrize(
    ("rendered", "code"),
    [("''", ExitCode.OUTPUT_FAILED), ("'a,b'", ExitCode.INTERNAL_ERROR)],
)
@pytest.mark.parametrize("command", ["scan", "probe", "analyze-trace"])
def test_a_failed_format_says_nothing_was_forwarded_to_the_collector(  # noqa: PLR0913 — the matrix
    site: FakeSite,
    clean_tree: Path,
    tmp_path: Path,
    endpoint: RefusingTransport,
    monkeypatch: pytest.MonkeyPatch,
    *,
    rendered: str,
    code: ExitCode,
    command: str,
) -> None:
    _table(site, rendered=rendered)
    if code is ExitCode.INTERNAL_ERROR:
        _failing_boundary(monkeypatch)
    arguments = ["--format", "acme-table", "--reporter", _COLLECTOR, *_ADMIT]

    if command == "scan":
        result = runner.invoke(app, ["scan", str(clean_tree), *arguments])
    elif command == "probe":
        result = _probe(*arguments)
    else:
        result = runner.invoke(app, ["analyze-trace", str(_trace(tmp_path)), *arguments])

    assert result.exit_code == code, result.output
    assert _lines(result.output)[-1] == _NOT_FORWARDED


def test_an_unwritable_report_says_nothing_was_sent(
    site: FakeSite, clean_tree: Path, tmp_path: Path
) -> None:
    hook = _hook(site, "return Delivery(DeliveryStatus.DELIVERED)")

    result = runner.invoke(
        app,
        [
            "scan",
            str(clean_tree),
            "--format",
            "json",
            "--output",
            str(tmp_path / "missing" / "run.json"),
            "--reporter",
            _HOOK,
            *_ADMIT,
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "could not write the report" in _plain(result.output)
    assert _delivery_lines(result.output) == [
        f"delivery: not_sent — {_TO}: the run's report could not be written"
    ]
    assert _seen(hook) == []


def test_a_run_its_target_stopped_is_delivered_and_keeps_exit_4(
    site: FakeSite, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        endpoint_module,
        "transport_factory",
        lambda: FailingTransport(URLError(ConnectionRefusedError("refused"))),
    )
    hook = _hook(site, "return Delivery(DeliveryStatus.DELIVERED, attempts=1)")

    result = _probe("--reporter", _HOOK, *_ADMIT)

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output
    assert _delivery_lines(result.output) == [f"delivery: delivered — {_TO} (1 attempt)"]
    assert _seen(hook)[0].result.stopped_by is not None


def test_a_target_that_never_started_says_nothing_was_sent(
    site: FakeSite, monkeypatch: pytest.MonkeyPatch
) -> None:
    def never_starts(connection: object) -> object:
        raise EndpointError("the server did not start")

    monkeypatch.setattr("guardana.cli._mcp_run.build_mcp_target", never_starts)
    hook = _hook(site, "return Delivery(DeliveryStatus.DELIVERED)")

    result = runner.invoke(
        app, ["probe", "--mcp", "http://127.0.0.1:1/mcp", "--reporter", _HOOK, *_ADMIT]
    )

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output
    assert _delivery_lines(result.output) == [
        f"delivery: not_sent — {_TO}: the target or judge was unavailable"
    ]
    assert _seen(hook) == []


def test_an_mcp_probe_refused_after_selection_says_nothing_was_sent(site: FakeSite) -> None:
    _hook(site, "return Delivery(DeliveryStatus.DELIVERED)")

    result = runner.invoke(
        app, ["probe", "--mcp", "acme-mcp-server --stdio", "--reporter", _HOOK, *_ADMIT]
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert _delivery_lines(result.output) == [
        f"delivery: not_sent — {_TO}: the run was refused before sending"
    ]


def test_analyze_trace_hands_an_installed_format_the_runs_verdict(
    site: FakeSite, tmp_path: Path
) -> None:
    module = _table(site)

    result = runner.invoke(
        app, ["analyze-trace", str(_trace(tmp_path)), "--format", "acme-table", *_ADMIT]
    )

    seen = _seen(module)
    assert len(seen) == 1
    assert result.exit_code == seen[0].exit_code, result.output
    assert seen[0].manifest.result_summary is not None
    assert seen[0].gate == seen[0].manifest.result_summary.gate


class _Deliverer:
    destination = "https://hooks.example.invalid"

    def sent_secrets(self) -> tuple[str, ...]:
        return ()

    def deliver(self, verification: Verification) -> Delivery:
        raise AssertionError("never called here")


def _prepared() -> PreparedReporter:
    def prepare(request: ReporterRequest) -> _Deliverer:
        return _Deliverer()

    spec = ReporterSpec(name="acme-webhook", summary="a hook", prepare=prepare)
    return PreparedReporter(
        name="acme-webhook",
        spec=spec,
        deliverer=_Deliverer(),
        origin=Origin(_DIST, "1.0"),
        destination="https://hooks.example.invalid",
    )


def _guarded(raised: BaseException) -> str:
    said = io.StringIO()

    def ended() -> None:
        with redirect_stderr(said), RunOutputs(OutputFormat.human, _prepared()):
            raise raised

    with pytest.raises(type(raised)):
        ended()
    return said.getvalue()


@pytest.mark.parametrize(
    ("raised", "why"),
    [
        (KeyboardInterrupt(), "the run was interrupted"),
        (typer.Exit(code=ExitCode.TARGET_UNAVAILABLE), "the target or judge was unavailable"),
        (RuntimeError("a defect"), "the run ended before its report was produced"),
    ],
)
def test_the_guard_says_why_nothing_was_sent(raised: BaseException, why: str) -> None:
    assert _guarded(raised) == f"delivery: not_sent — {_TO}: {why}\n"


def test_the_guard_says_a_refused_budget_sent_nothing() -> None:
    from guardana.core.budget import BudgetExhausted  # noqa: PLC0415

    refusal = typer.Exit(code=ExitCode.INVALID_USAGE)
    refusal.__cause__ = BudgetExhausted("max_requests")

    assert _guarded(refusal) == (
        f"delivery: not_sent — {_TO}: the budget was refused before sending\n"
    )


def test_the_guard_prints_one_line_however_often_it_is_told() -> None:
    said = io.StringIO()
    with redirect_stderr(said), RunOutputs(OutputFormat.human, _prepared()) as outputs:
        outputs.not_sent("the run's report was not produced")
        outputs.not_sent("a second reason")

    assert said.getvalue() == f"delivery: not_sent — {_TO}: the run's report was not produced\n"


def test_the_guard_is_silent_without_a_reporter() -> None:
    said = io.StringIO()

    def interrupted() -> None:
        with redirect_stderr(said), RunOutputs(OutputFormat.human, None):
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        interrupted()
    assert said.getvalue() == ""


def test_exit_code_8_means_an_installed_output_failed() -> None:
    assert int(ExitCode.OUTPUT_FAILED) == 8
