"""A report written to `--output` never replaces or removes a file the command reads.

Every input counts, whoever names it: a flag, a file inside a `--rules` directory, or a
file the profile names under `rules.paths`, `contracts:`, `calibrations:` or a judge's
`adapter`. Each is refused with exit `3` before anything is read or sent, and the message
names the flag or key and the path.
"""

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from guardana.cli._mcp_run import McpConnection
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.calibration.store import RecordedCalibration, write_calibrations
from guardana.core.target import McpServerTarget
from guardana.core.testing import RefusingTransport
from guardana.core.verify import exchanges_path
from typer.testing import CliRunner

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_CHAT = ["--url", "http://192.0.2.1", "--model", "m"]
_MCP = ["--mcp", "https://93.184.215.14/mcp"]
_ENDPOINT_RULE = (
    "id: acme.prompt.demo\n"
    "title: demo\n"
    "severity: high\n"
    "target_kind: endpoint\n"
    "evaluator: keyword\n"
    "requires: [chat]\n"
    "prompts: ['hi']\n"
    "expect: {goal: 'complied'}\n"
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


def _lines(text: str) -> list[str]:
    return [line.strip() for line in _ANSI.sub("", text).splitlines() if line.strip()]


def _files_under(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _replaced(output: Path, name: str) -> str:
    return (
        f"error: --output {output} is {output}, which {name} names, and the report would "
        f"replace it — choose another --output"
    )


def _a_file(path: Path, content: str = "an input\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def model(monkeypatch: pytest.MonkeyPatch) -> RefusingTransport:
    """The chat endpoint every probe here would send to, counting what reached it."""
    transport = RefusingTransport()
    monkeypatch.setattr("guardana.cli._endpoint.transport_factory", lambda: transport)
    return transport


@pytest.fixture
def mcp_servers(monkeypatch: pytest.MonkeyPatch) -> list[McpConnection]:
    """Every MCP server a probe here would have connected to."""
    built: list[McpConnection] = []

    def build(connection: McpConnection) -> McpServerTarget:
        built.append(connection)
        raise AssertionError("nothing may connect before the inputs are checked")

    monkeypatch.setattr("guardana.cli._mcp_run.build_mcp_target", build)
    return built


def _fixtures_document(adapter: str) -> str:
    return yaml.safe_dump(
        {
            "schema_version": 1,
            "name": "support-bot",
            "data": "synthetic",
            "tenants": {"acme": {"adapter": adapter}, "globex": {"api_key_env": "GLOBEX_KEY"}},
            "documents": [
                {"id": "acme-loyalty", "tenant": "acme", "topic": "the loyalty programme"},
                {"id": "globex-shipping", "tenant": "globex", "topic": "shipping times"},
            ],
        },
        sort_keys=False,
    )


def _probe_input(tmp_path: Path, flag: str) -> tuple[list[str], Path, str]:
    """Return the probe's arguments, the file the flag makes it read and the flag's name."""
    if flag == "--rules directory":
        rules = tmp_path / "rules"
        given = _a_file(rules / "rule.yaml", _ENDPOINT_RULE)
        return [*_CHAT, "--rules", str(rules)], given, f"--rules {rules}"
    if flag == "--fixtures tenant":
        given = _a_file(tmp_path / "tenant-adapter.yaml")
        fixtures = _a_file(tmp_path / "fixtures.yaml", _fixtures_document(given.name))
        return [*_CHAT, "--fixtures", str(fixtures)], given, "--fixtures tenant acme"
    given = _a_file(tmp_path / "input.yaml")
    mode = _MCP if flag.startswith("--mcp") else _CHAT
    return [*mode, flag, str(given)], given, flag


_PROBE_FLAGS = [
    "--profile",
    "--rules",
    "--rules directory",
    "--system-prompt-file",
    "--fixtures",
    "--fixtures tenant",
    "--adapter",
    "--mcp-pin",
    "--mcp-registry-entry",
]


@pytest.mark.parametrize("flag", _PROBE_FLAGS)
def test_a_probe_report_written_over_a_file_a_flag_names_is_refused_before_sending(
    tmp_path: Path, model: RefusingTransport, mcp_servers: list[McpConnection], flag: str
) -> None:
    arguments, given, name = _probe_input(tmp_path, flag)
    before = _files_under(tmp_path)

    result = runner.invoke(app, ["probe", *arguments, "--format", "json", "--output", str(given)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert _lines(result.stderr)[-1] == _replaced(given, name)
    assert _files_under(tmp_path) == before
    assert model.seen == []
    assert mcp_servers == []


def test_a_probe_report_whose_exchanges_would_replace_a_flags_file_is_refused(
    tmp_path: Path, model: RefusingTransport
) -> None:
    prompt = _a_file(tmp_path / "run.exchanges.jsonl", "You are a support agent.\n")
    saved = tmp_path / "run.json"
    assert exchanges_path(saved) == prompt
    before = _files_under(tmp_path)

    result = runner.invoke(
        app,
        [
            "probe",
            *_CHAT,
            "--system-prompt-file",
            str(prompt),
            "--format",
            "json",
            "--output",
            str(saved),
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert _lines(result.stderr)[-1] == (
        f"error: {prompt} is where a run saved at {saved} keeps its exchanges, and writing "
        f"the report there would remove {prompt}, which --system-prompt-file names "
        f"— choose another --output"
    )
    assert _files_under(tmp_path) == before
    assert model.seen == []


def test_a_probe_reading_the_same_flags_saves_its_report_anywhere_else(
    tmp_path: Path, model: RefusingTransport
) -> None:
    rules = tmp_path / "rules"
    _a_file(rules / "rule.yaml", _ENDPOINT_RULE)
    prompt = _a_file(tmp_path / "prompt.txt", "You are a support agent.\n")
    profile = _a_file(tmp_path / "guardana.yaml", "name: t\n")
    saved = tmp_path / "run.json"

    result = runner.invoke(
        app,
        [
            "probe",
            *_CHAT,
            "--profile",
            str(profile),
            "--rules",
            str(rules),
            "--system-prompt-file",
            str(prompt),
            "--format",
            "json",
            "--output",
            str(saved),
        ],
    )

    assert result.exit_code != ExitCode.INVALID_USAGE, result.output
    assert saved.is_file()
    assert model.seen != []


def _calibration(path: Path) -> Path:
    write_calibrations(
        path,
        {
            "canary": RecordedCalibration(
                evaluator="canary",
                dataset_digest="sha256:" + "ab" * 32,
                measured_at=datetime(2026, 1, 1, tzinfo=UTC),
                brier=0.1,
                ece=0.05,
                samples=60,
            )
        },
    )
    return path


def _profile_naming_files(tmp_path: Path) -> tuple[Path, dict[str, Path]]:
    """Write a profile naming one file under every key, each beside it, valid for a scan."""
    config = tmp_path / "config"
    named = {
        "rules.paths": _a_file(config / "rules" / "rule.yaml", _ENDPOINT_RULE),
        "contracts": _a_file(config / "contracts" / "checkout.yaml", "contract: 1\n"),
        "calibrations": _calibration(config / "cal.json"),
        "evaluators.llm_judge.adapter": _a_file(config / "judge.yaml"),
    }
    profile = _a_file(
        config / "guardana.yaml",
        "name: t\n"
        "rules:\n  paths: [rules]\n"
        "contracts: [contracts]\n"
        "calibrations: [cal.json]\n"
        "evaluators:\n"
        "  llm_judge:\n    endpoint: http://judge.test\n    model: j\n    adapter: judge.yaml\n",
    )
    return profile, named


def _command(tmp_path: Path, command: str) -> list[str]:
    if command == "scan":
        return ["scan", str(_a_file(tmp_path / "tree" / "app.py", "print('hello')\n").parent)]
    if command == "probe":
        return ["probe", *_CHAT]
    if command == "grade":
        return ["grade", str(_a_file(tmp_path / "answers.jsonl", "{}\n"))]
    if command == "analyze-trace":
        return ["analyze-trace", str(_a_file(tmp_path / "trace.jsonl", _TRACE))]
    return ["import-observations", str(_a_file(tmp_path / "garak.jsonl", _GARAK))]


@pytest.mark.parametrize(
    "command", ["scan", "probe", "grade", "analyze-trace", "import-observations"]
)
@pytest.mark.parametrize(
    "key", ["rules.paths", "contracts", "calibrations", "evaluators.llm_judge.adapter"]
)
def test_a_report_written_over_a_file_the_profile_names_is_refused(
    tmp_path: Path,
    model: RefusingTransport,
    command: str,
    key: str,
) -> None:
    arguments = _command(tmp_path, command)
    profile, named = _profile_naming_files(tmp_path)
    given = named[key]
    before = _files_under(tmp_path)

    result = runner.invoke(
        app, [*arguments, "--profile", str(profile), "--format", "json", "--output", str(given)]
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert _lines(result.stderr)[-1] == _replaced(given, f"the profile's {key}")
    assert _files_under(tmp_path) == before
    assert model.seen == []


def test_a_scan_with_a_profile_naming_files_saves_its_report_beside_them(
    tmp_path: Path,
) -> None:
    arguments = _command(tmp_path, "scan")
    profile, named = _profile_naming_files(tmp_path)
    saved = named["calibrations"].with_name("run.json")

    result = runner.invoke(
        app, [*arguments, "--profile", str(profile), "--format", "json", "--output", str(saved)]
    )

    assert result.exit_code == ExitCode.OK, result.output
    assert saved.is_file()


@pytest.mark.parametrize("read", [".guardanaignore", "--rules directory"])
def test_a_scan_report_written_over_a_file_the_scan_reads_is_refused(
    tmp_path: Path, read: str
) -> None:
    tree = tmp_path / "tree"
    _a_file(tree / "app.py", "print('hello')\n")
    ignore = _a_file(tree / ".guardanaignore", "*.log\n")
    rules = tmp_path / "rules"
    rule = _a_file(rules / "rule.yaml", _ENDPOINT_RULE)
    given = ignore if read == ".guardanaignore" else rule
    before = _files_under(tmp_path)

    result = runner.invoke(
        app,
        ["scan", str(tree), "--rules", str(rules), "--format", "json", "--output", str(given)],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    expected = (
        f"error: --output {given} is {given}, which this command reads, and the report "
        f"would replace it — choose another --output"
        if read == ".guardanaignore"
        else _replaced(given, f"--rules {rules}")
    )
    assert _lines(result.stderr)[-1] == expected
    assert _files_under(tmp_path) == before


@pytest.mark.parametrize("written", ["the recording", "beside the recording"])
def test_a_scan_report_over_a_scanned_recording_named_like_exchanges_is_refused(
    tmp_path: Path, written: str
) -> None:
    data = tmp_path / "data"
    _a_file(data / "app.py", "print('hello')\n")
    recording = _a_file(data / "customer.exchanges.jsonl", '{"messages": []}\n')
    output = recording if written == "the recording" else data / "customer.json"
    before = _files_under(tmp_path)

    result = runner.invoke(app, ["scan", str(data), "--format", "json", "--output", str(output)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert _lines(result.stderr)[-1] == (
        f"error: --output {output} would replace {recording}, which this scan read — choose "
        f"another --output"
    )
    assert _files_under(tmp_path) == before


def _trace_reading_a_directory(tmp_path: Path, flag: str) -> tuple[list[str], Path, str]:
    """Return analyze-trace's arguments, a file read from the flag's directory and the flag."""
    trace = _a_file(tmp_path / "trace.jsonl", _TRACE)
    if flag == "--rules":
        folder = tmp_path / "rules"
        given = _a_file(folder / "check.yaml", _ENDPOINT_RULE)
        return ["analyze-trace", str(trace), "--rules", str(folder)], given, f"--rules {folder}"
    folder = tmp_path / "contracts"
    given = _a_file(folder / "checkout.yaml", "contract: 1\n")
    return ["analyze-trace", str(trace), "--contract", str(folder)], given, "--contract"


def _trace_written_over(given: Path, name: str) -> str:
    return (
        f"error: --write-trace {given} is {given}, which {name} names, and writing it would "
        f"replace it — choose another --write-trace"
    )


@pytest.mark.parametrize("flag", ["--rules", "--contract"])
def test_a_native_trace_written_over_a_file_in_a_directory_a_flag_names_is_refused(
    tmp_path: Path, flag: str
) -> None:
    arguments, given, name = _trace_reading_a_directory(tmp_path, flag)
    before = _files_under(tmp_path)

    result = runner.invoke(app, [*arguments, "--write-trace", str(given)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert _lines(result.stderr)[-1] == _trace_written_over(given, name)
    assert _files_under(tmp_path) == before


@pytest.mark.parametrize(
    "key", ["rules.paths", "contracts", "calibrations", "evaluators.llm_judge.adapter"]
)
def test_a_native_trace_written_over_a_file_the_profile_names_is_refused(
    tmp_path: Path, key: str
) -> None:
    arguments = _command(tmp_path, "analyze-trace")
    profile, named = _profile_naming_files(tmp_path)
    given = named[key]
    before = _files_under(tmp_path)

    result = runner.invoke(
        app, [*arguments, "--profile", str(profile), "--write-trace", str(given)]
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert _lines(result.stderr)[-1] == _trace_written_over(given, f"the profile's {key}")
    assert _files_under(tmp_path) == before


def test_a_native_trace_written_beside_the_files_it_reads_is_written(tmp_path: Path) -> None:
    arguments, given, _ = _trace_reading_a_directory(tmp_path, "--rules")
    written = tmp_path / "native.jsonl"

    result = runner.invoke(app, [*arguments, "--write-trace", str(written)])

    assert result.exit_code != ExitCode.INVALID_USAGE, result.output
    assert written.read_text(encoding="utf-8").startswith('{"guardana_trace"')
    assert given.read_text(encoding="utf-8") == _ENDPOINT_RULE
