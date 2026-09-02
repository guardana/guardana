"""Every command that discovers plugins asks the same resolver.

`baseline` hard-coded `all`, `target inspect` and `calibrate` called a bare
`Registry.discover()`, and `plan probe` passed a literal. A security control that
one command honours and the next ignores is a control the user believes they have.
"""

import re
from collections.abc import Callable
from pathlib import Path

import pytest
from guardana.cli.main import app
from guardana.core.trace import Provenance, Trace, serialize_trace
from typer.testing import CliRunner

_CLI = Path(__file__).resolve().parents[1] / "src" / "guardana" / "cli"
_BARE_DISCOVER = re.compile(r"Registry\.discover\(\s*\)")
_LITERAL_TRUST = re.compile(r"resolve_trust\(\s*\"(all|builtins|allowlist)\"")


def test_no_command_calls_discover_without_a_trust_policy() -> None:
    offenders = [
        str(path.relative_to(_CLI))
        for path in sorted(_CLI.glob("*.py"))
        if _BARE_DISCOVER.search(path.read_text(encoding="utf-8"))
    ]

    assert not offenders, f"bare Registry.discover() in: {offenders}"


def test_no_command_hard_codes_a_trust_mode_except_the_one_that_runs_nothing() -> None:
    offenders = [
        str(path.relative_to(_CLI))
        for path in sorted(_CLI.glob("*.py"))
        if _LITERAL_TRUST.search(path.read_text(encoding="utf-8"))
    ]

    assert not offenders, f"hard-coded trust mode in: {offenders}"


@pytest.mark.parametrize(
    "argv",
    [
        ["baseline", "create", ".", "--plugins", "nonsense"],
        ["baseline", "update", ".", "--plugins", "nonsense"],
        ["target", "inspect", "--url", "http://x", "--model", "m", "--plugins", "nonsense"],
        ["calibrate", "--evaluator", "keyword", "--corpus", "x.jsonl", "--plugins", "nonsense"],
        ["plan", "scan", ".", "--plugins", "nonsense"],
        ["plan", "probe", "--url", "http://x", "--model", "m", "--plugins", "nonsense"],
    ],
)
def test_an_unknown_plugin_mode_is_a_usage_error_everywhere(argv: list[str]) -> None:
    result = CliRunner().invoke(app, argv)

    assert result.exit_code == 3, result.output
    assert "unknown plugin mode" in result.output


@pytest.mark.parametrize(
    "argv",
    [
        ["baseline", "create", ".", "--allow-plugin", "acme"],
        ["plan", "scan", ".", "--allow-plugin", "acme"],
    ],
)
def test_naming_a_distribution_without_the_allowlist_mode_is_refused(argv: list[str]) -> None:
    result = CliRunner().invoke(app, argv)

    assert result.exit_code == 3, result.output
    assert "--allow-plugin only applies with --plugins allowlist" in result.output


def _minimal_trace(tmp_path: Path) -> str:
    """A trace file with nothing in it — enough for `trace inspect`/`analyze-trace`
    to open and report on, without a claim about what it does or does not record."""
    trace = Trace(
        trace_id="t-1",
        spans=(),
        provenance=Provenance(producer="acme", source="a.jsonl", dialect="guardana"),
    )
    path = tmp_path / "trace.jsonl"
    path.write_text(serialize_trace(trace), encoding="utf-8")
    return str(path)


_REFUSAL_LEAK_PHRASES = ("does not register", "is gone", "no installed catalogue")
"""Each states a fact about the registry as if it were proven. Under a restrictive
`--plugins` mode part of the registry was never examined, so none of the three may
ever be true — see `pack/discover.py`, `pack/lock.py` and `taxonomy.py`, the only
three places in this tree that can print them."""

_REFUSAL_COMMANDS: tuple[tuple[str, Callable[[Path], list[str]]], ...] = (
    ("pack validate", lambda tmp_path: ["pack", "validate", "--plugins", "disabled"]),
    (
        "pack lock",
        lambda tmp_path: [
            "pack",
            "lock",
            str(tmp_path / "guardana-lock.yaml"),
            "--plugins",
            "disabled",
        ],
    ),
    ("taxonomy", lambda tmp_path: ["taxonomy", "LLM99:2025", "--plugins", "disabled"]),
    (
        "trace inspect",
        lambda tmp_path: ["trace", "inspect", _minimal_trace(tmp_path), "--plugins", "disabled"],
    ),
    (
        "analyze-trace",
        lambda tmp_path: ["analyze-trace", _minimal_trace(tmp_path), "--plugins", "disabled"],
    ),
    ("rules", lambda tmp_path: ["rules", "--plugins", "disabled"]),
    ("rule test", lambda tmp_path: ["rule", "test", "--plugins", "disabled"]),
    ("doctor", lambda tmp_path: ["doctor", "--plugins", "disabled"]),
)
"""Every command that takes `--plugins` and can be run without a live endpoint or a
prepared external fixture. `baseline create`/`update` and `plan scan` take a real
scan target, `calibrate` needs a labelled corpus, and `target inspect`/`probe`/`scan`/
`monitor`/`plan probe` need a reachable endpoint — exercising any of those honestly
needs its own fixture, and a bogus one would fail for an unrelated reason (a missing
file, a connection error) rather than prove anything about this defect. None of their
source contains any of the three phrases below, confirmed by grep across
`guardana-cli` and `guardana-core`."""


@pytest.mark.parametrize(
    ("label", "build_argv"), _REFUSAL_COMMANDS, ids=[c[0] for c in _REFUSAL_COMMANDS]
)
def test_a_refusal_never_reads_as_a_proven_fact(
    label: str, build_argv: Callable[[Path], list[str]], tmp_path: Path
) -> None:
    """The one test that would have caught all three defects at once.

    `--plugins disabled` refuses every entry point, this build's own built-ins
    included, so nothing any of these commands prints can honestly claim a
    manifest does not register something, that a locked extension is gone, or
    that no installed catalogue defines a reference — every one of those is a
    claim about a registry this run did not fully load.
    """
    result = CliRunner().invoke(app, build_argv(tmp_path))

    for phrase in _REFUSAL_LEAK_PHRASES:
        assert phrase not in result.output, f"{label}: {phrase!r} leaked — {result.output}"


def test_the_refusal_warning_formats_the_error_fields_rather_than_a_repr() -> None:
    """`warn_about_load_errors` is the one place this cycle nominated as *the*
    place a refusal is printed — every discovering command's warning goes
    through it, so a raw dataclass repr here would reach every one of them at
    once. `source`, `stage` and `reason` must all still be readable, just not
    spelled `CheckError(source=..., stage=..., reason=...)`.
    """
    result = CliRunner().invoke(app, ["pack", "validate", "--plugins", "disabled"])

    assert "CheckError(" not in result.stderr
    assert "source=" not in result.stderr
    assert "(discovery):" in result.stderr
