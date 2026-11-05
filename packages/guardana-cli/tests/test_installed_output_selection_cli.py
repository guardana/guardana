"""An installed format or reporter that cannot be selected is refused with exit 3, before the run.

Every refusal is decided before discovery and before a target is built, so a scripted
endpoint behind `probe` receives no request at all. Distributions are `.dist-info`
directories on `sys.path`, read by the real metadata finder, and their modules leave a
marker when imported, so "never imported" is proven by what never ran.
"""

import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

import guardana.cli._endpoint as endpoint_module
import guardana.cli._reporting as reporting_module
import pytest
from _fake_distribution import FakeModule, FakeSite
from _output_modules import RAISING_PROVIDER, RECORDING_RENDERER, RECORDING_REPORTER, body
from guardana.cli._reporting import split_reporter
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.entrypoints import RENDERER_GROUP, REPORTER_GROUP
from guardana.core.manifest import DeploymentRef
from guardana.core.report import ScanResult
from guardana.core.testing import RefusingTransport
from typer.testing import CliRunner, Result

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_DIST = "acme-guardana-outputs"
_ADMIT = ["--plugins", "allowlist", "--allow-plugin", _DIST]


def _plain(text: str) -> str:
    return " ".join(_ANSI.sub("", text).replace("│", " ").split())


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


@pytest.fixture
def endpoint(monkeypatch: pytest.MonkeyPatch) -> RefusingTransport:
    """The model `probe --url` reaches; it records every request it is sent."""
    transport = RefusingTransport()
    monkeypatch.setattr(endpoint_module, "transport_factory", lambda: transport)
    return transport


@pytest.fixture
def clean_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return tree


def _install(
    site: FakeSite,
    template: str,
    *,
    group: str = RENDERER_GROUP,
    name: str = "acme-table",
    distribution: str = _DIST,
) -> FakeModule:
    module = site.module(body(template, name))
    site.distribution(distribution, (group, name, module.name))
    return module


def _not_imported(*modules: FakeModule) -> bool:
    return all(m.name not in sys.modules and not m.marker.exists() for m in modules)


def _probe(*arguments: str) -> Result:
    return runner.invoke(app, ["probe", "--url", "http://fake", "--model", "m", *arguments])


def test_an_unknown_format_is_refused_before_the_endpoint_hears_anything(
    site: FakeSite, endpoint: RefusingTransport
) -> None:
    _install(site, RECORDING_RENDERER)

    result = _probe("--format", "acme-tabel", *_ADMIT)

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert (
        "error: the format acme-tabel is not installed; built-in: human, json, sarif, junit; "
        "installed: acme-table (admitted)"
    ) in _plain(result.output)
    assert endpoint.seen == []


@pytest.mark.parametrize(
    ("flag", "value", "message"),
    [
        (
            "--format",
            "guardana-csv",
            "error: guardana-csv is a built-in format name, so no installed format can use it",
        ),
        (
            "--reporter",
            "guardana-hook://x",
            "error: guardana-hook is a built-in reporter name, so no installed reporter can use it",
        ),
    ],
)
def test_a_reserved_name_is_refused_before_the_endpoint_hears_anything(
    site: FakeSite, endpoint: RefusingTransport, flag: str, value: str, message: str
) -> None:
    group = RENDERER_GROUP if flag == "--format" else REPORTER_GROUP
    template = RECORDING_RENDERER if flag == "--format" else RECORDING_REPORTER
    module = _install(site, template, group=group, name=value.split(":", maxsplit=1)[0])

    result = _probe(flag, value, "--plugins", "all")

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert message in _plain(result.output)
    assert endpoint.seen == []
    assert _not_imported(module)


def test_a_colliding_format_is_refused_and_neither_install_is_imported(
    site: FakeSite, endpoint: RefusingTransport
) -> None:
    first = _install(site, RECORDING_RENDERER, distribution="acme-a")
    second = _install(site, RECORDING_RENDERER, distribution="acme-b")

    result = _probe("--format", "acme-table", "--plugins", "all")

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert (
        "error: the format acme-table is installed by 2 distributions (acme-a 1.0, acme-b 1.0), "
        "so neither is used"
    ) in _plain(result.output)
    assert endpoint.seen == []
    assert _not_imported(first, second)


def test_a_format_trust_refuses_names_the_ways_to_admit_it(
    site: FakeSite, endpoint: RefusingTransport
) -> None:
    module = _install(site, RECORDING_RENDERER)

    result = _probe("--format", "acme-table")

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    said = _plain(result.output)
    assert (
        "error: the format acme-table comes from acme-guardana-outputs 1.0, which plugin trust "
        "builtins does not admit"
    ) in said
    assert f"narrowest first: --plugins allowlist --allow-plugin {_DIST}" in said
    assert f"or plugins: {{mode: allowlist, allow: [{_DIST}]}} in guardana.yaml" in said
    assert "or --plugins all" in said
    assert endpoint.seen == []
    assert _not_imported(module)


def test_a_reporter_trust_refuses_is_refused_before_the_endpoint_hears_anything(
    site: FakeSite, endpoint: RefusingTransport
) -> None:
    module = _install(site, RECORDING_REPORTER, group=REPORTER_GROUP, name="acme-webhook")

    result = _probe("--reporter", "acme-webhook://https://hooks.example.invalid")

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "error: the reporter acme-webhook comes from" in _plain(result.output)
    assert endpoint.seen == []
    assert _not_imported(module)


def test_a_broken_format_is_refused_before_the_endpoint_hears_anything(
    site: FakeSite, endpoint: RefusingTransport
) -> None:
    _install(site, RAISING_PROVIDER)

    result = _probe("--format", "acme-table", *_ADMIT)

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert (
        "error: the format acme-table from acme-guardana-outputs 1.0 could not be loaded: "
        "ValueError: the provider is broken"
    ) in _plain(result.output)
    assert endpoint.seen == []


def test_scan_grade_and_analyze_trace_refuse_an_unknown_format(
    site: FakeSite, clean_tree: Path, tmp_path: Path
) -> None:
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        json.dumps({"guardana_trace": 1, "trace_id": "t", "producer": {"name": "acme"}}) + "\n",
        encoding="utf-8",
    )
    recording = tmp_path / "answers.jsonl"
    recording.write_text(
        json.dumps({"guardana_recording": 1, "name": "bot", "version": "1"}) + "\n",
        encoding="utf-8",
    )

    for command in (
        ["scan", str(clean_tree)],
        ["grade", str(recording)],
        ["analyze-trace", str(trace)],
    ):
        result = runner.invoke(app, [*command, "--format", "no-such-format"])

        assert result.exit_code == ExitCode.INVALID_USAGE, (command, result.output)
        assert "error: the format no-such-format is not installed" in _plain(result.output)
        assert "rule(s) run" not in result.output


def test_a_misspelt_collector_scheme_is_an_unknown_reporter_naming_the_collector_forms(
    clean_tree: Path,
) -> None:
    result = runner.invoke(app, ["scan", str(clean_tree), "--reporter", "htps://x"])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert (
        "error: the reporter htps is not installed; built-in: server://URL or an http(s) "
        "collector URL; installed: none"
    ) in _plain(result.output)


@pytest.mark.parametrize(
    "value",
    ["server://collector.example.com", "collector.example.com:8000", "127.0.0.1:8000"],
)
def test_a_collector_value_without_a_scheme_keeps_its_own_message(
    clean_tree: Path, value: str
) -> None:
    result = runner.invoke(app, ["scan", str(clean_tree), "--reporter", value])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "http://" in result.output
    assert "is not installed" not in result.output


class _Collector:
    """Captures what a collector would receive instead of sending it."""

    urls: ClassVar[list[str]] = []

    def __init__(
        self,
        url: str,
        *,
        api_key: str | None = None,
        deployment: DeploymentRef | None = None,
        run: object | None = None,
    ) -> None:
        _Collector.urls.append(url)

    accepted_uncompared = False

    def submit(self, result: ScanResult, *, source: str) -> None:
        """Accept the submission."""


@pytest.mark.parametrize(
    ("value", "reaches"),
    [
        ("http://collector/findings", "http://collector/findings"),
        ("server://https://collector.example.com", "https://collector.example.com"),
    ],
)
def test_a_collector_url_still_reaches_the_collector(
    monkeypatch: pytest.MonkeyPatch, clean_tree: Path, value: str, reaches: str
) -> None:
    _Collector.urls.clear()
    monkeypatch.setattr(reporting_module, "HttpReporter", _Collector)

    result = runner.invoke(app, ["scan", str(clean_tree), "--reporter", value])

    assert result.exit_code == ExitCode.OK, result.output
    assert _Collector.urls == [reaches]
    assert "delivery:" not in result.output


@pytest.mark.parametrize(
    ("value", "split"),
    [
        ("acme-webhook://env:ACME_WEBHOOK_URL", ("acme-webhook", "env:ACME_WEBHOOK_URL")),
        ("acme-webhook://https://h.example/x", ("acme-webhook", "https://h.example/x")),
        ("htps://x", ("htps", "x")),
        ("server://http://c", None),
        ("http://c", None),
        ("https://c", None),
        ("HTTP://c", None),
        ("c.example:8000", None),
        ("acme_hook://x", None),
        (None, None),
    ],
)
def test_only_a_name_shaped_scheme_is_split_off_as_an_installed_reporter(
    value: str | None, split: tuple[str, str] | None
) -> None:
    assert split_reporter(value) == split


def test_monitor_refuses_an_installed_reporter_without_reading_metadata(site: FakeSite) -> None:
    module = _install(site, RECORDING_REPORTER, group=REPORTER_GROUP, name="acme-webhook")

    result = runner.invoke(
        app,
        [
            "monitor",
            "--url",
            "http://127.0.0.1:1",
            "--model",
            "m",
            "--max-cycles",
            "1",
            "--reporter",
            "acme-webhook://https://hooks.example.invalid",
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert (
        "error: monitor runs cycles, not a saved run; an installed reporter runs with scan, "
        "probe or analyze-trace"
    ) in _plain(result.output)
    assert _not_imported(module)


def test_import_observations_refuses_an_installed_reporter(tmp_path: Path) -> None:
    results = tmp_path / "results.json"
    results.write_text("[]", encoding="utf-8")

    result = runner.invoke(
        app, ["import-observations", str(results), "--reporter", "acme-webhook://x"]
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert (
        "error: import-observations loads no plugins; it forwards to the collector only"
        in _plain(result.output)
    )


@pytest.mark.parametrize("extra", [["--format", "acme-table"], ["--reporter", "acme-webhook://x"]])
def test_writing_a_baseline_refuses_an_installed_output(
    clean_tree: Path, tmp_path: Path, extra: list[str]
) -> None:
    baseline = tmp_path / "baseline.yaml"

    result = runner.invoke(
        app, ["scan", str(clean_tree), "--write-baseline", str(baseline), *extra]
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert (
        "error: an installed output needs the run's report, which --write-baseline does not produce"
    ) in _plain(result.output)
    assert not baseline.exists()


@pytest.mark.parametrize("extra", [["--format", "acme-table"], ["--reporter", "acme-webhook://x"]])
def test_writing_an_mcp_pin_refuses_an_installed_output(tmp_path: Path, extra: list[str]) -> None:
    pin = tmp_path / "pin.json"

    result = runner.invoke(
        app, ["probe", "--mcp", "http://127.0.0.1:1/mcp", "--write-mcp-pin", str(pin), *extra]
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert (
        "error: an installed output needs the run's report, which --write-mcp-pin does not produce"
    ) in _plain(result.output)
    assert not pin.exists()


def test_keeping_exchanges_stays_refused_for_an_installed_format(
    site: FakeSite, endpoint: RefusingTransport, tmp_path: Path
) -> None:
    _install(site, RECORDING_RENDERER)

    result = _probe(
        "--format", "acme-table", "--output", str(tmp_path / "run.csv"), "--keep-exchanges"
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "pass --format json --output run.json" in _plain(result.output)
    assert endpoint.seen == []
