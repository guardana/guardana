"""`probe --require-auth` decides whether the named chat route refuses no credential.

Driven against a real HTTP double, so the requests asserted are the ones that reached it:
the request with no credential first and bare, the keyed one only after a refusal, and
nothing at all when the flags rule the check out.
"""

import json
import re
from pathlib import Path

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.report import load_report
from guardana.core.report.shortfall import ShortfallKind
from guardana.core.testing._fake_provider import FakeProvider, openai_reply, status_reply
from typer.testing import CliRunner

runner = CliRunner()

_RULE_ID = "guardana.endpoint.unauthenticated_inference"
_KEY = "acme-test-0123456789abcdef"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    return " ".join(_ANSI.sub("", text).replace("│", " ").split())


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "guardana.yaml").write_text(
        f"name: t\nrules:\n  include: ['{_RULE_ID}']\n", encoding="utf-8"
    )
    monkeypatch.setenv("ACME_KEY", _KEY)
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    return tmp_path


def _probe(setup: Path, url: str, *extra: str) -> tuple[int, str]:
    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            url,
            "--model",
            "m",
            "--profile",
            str(setup / "guardana.yaml"),
            "--format",
            "json",
            "--output",
            str(setup / "run.json"),
            *extra,
        ],
    )
    return result.exit_code, result.output


def test_a_route_answering_no_credential_fails_the_run_after_one_bare_request(
    setup: Path,
) -> None:
    with FakeProvider(openai_reply("OK")) as provider:
        code, output = _probe(setup, provider.url, "--api-key-env", "ACME_KEY", "--require-auth")

    assert code == ExitCode.POLICY_FAILED, output
    (sent,) = provider.requests
    assert "authorization" not in sent.headers
    (finding,) = load_report(setup / "run.json").result.findings
    assert (finding.rule_id, finding.severity.name) == (_RULE_ID, "CRITICAL")
    assert _KEY not in (setup / "run.json").read_text(encoding="utf-8")


def test_a_route_refusing_no_credential_and_answering_the_key_passes(setup: Path) -> None:
    with FakeProvider(status_reply(401), openai_reply("OK")) as provider:
        code, output = _probe(setup, provider.url, "--api-key-env", "ACME_KEY", "--require-auth")

    assert code == ExitCode.OK, output
    anonymous, control = provider.requests
    assert "authorization" not in anonymous.headers
    assert control.headers["authorization"] == f"Bearer {_KEY}"
    saved = load_report(setup / "run.json").result
    assert saved.findings == ()
    assert saved.rules_run == (_RULE_ID,)


def test_a_route_refusing_the_key_too_leaves_the_run_indeterminate(setup: Path) -> None:
    with FakeProvider(status_reply(401), status_reply(403)) as provider:
        code, output = _probe(setup, provider.url, "--api-key-env", "ACME_KEY", "--require-auth")

    assert code == ExitCode.INDETERMINATE, output
    assert len(provider.requests) == 2
    shortfalls = load_report(setup / "run.json").result.coverage_shortfall
    assert [(s.kind, s.name) for s in shortfalls if s.kind is ShortfallKind.DEMANDED_CHECK] == [
        (ShortfallKind.DEMANDED_CHECK, _RULE_ID)
    ]


def test_a_budget_with_no_room_for_the_keyed_request_stops_the_run_as_spent(
    setup: Path,
) -> None:
    with FakeProvider(status_reply(401), openai_reply("OK")) as provider:
        code, output = _probe(
            setup,
            provider.url,
            "--api-key-env",
            "ACME_KEY",
            "--require-auth",
            "--max-requests",
            "1",
        )

    assert code == ExitCode.BUDGET_EXHAUSTED, output
    assert len(provider.requests) == 1
    assert load_report(setup / "run.json").result.findings == ()


@pytest.mark.parametrize(
    ("extra", "refusal"),
    [
        ((), "--require-auth needs --api-key-env"),
        (("--api-key-env", "ACME_KEY", "--provider", "ollama"), "combined with --provider ollama"),
        (("--api-key-env", "ACME_KEY", "--adapter", "{adapter}"), "combined with --adapter"),
        (("--api-key-env", "ACME_KEY", "--fixtures", "{fixtures}"), "combined with --fixtures"),
    ],
)
def test_a_flag_the_check_cannot_run_beside_is_refused_before_anything_is_sent(
    setup: Path, extra: tuple[str, ...], refusal: str
) -> None:
    adapter = setup / "adapter.yaml"
    adapter.write_text("url: http://127.0.0.1:9/chat\nbody: {m: '{{prompt}}'}\n", encoding="utf-8")
    fixtures = setup / "fixtures.yaml"
    fixtures.write_text("schema_version: 1\n", encoding="utf-8")
    named = [part.format(adapter=adapter, fixtures=fixtures) for part in extra]
    with FakeProvider(openai_reply("OK")) as provider:
        code, output = _probe(setup, provider.url, *named, "--require-auth")

    assert code == ExitCode.INVALID_USAGE, output
    assert refusal in _plain(output)
    assert provider.requests == []


@pytest.mark.parametrize(
    "elsewhere",
    [
        ("--mcp", "http://127.0.0.1:9/mcp"),
        ("--a2a", "http://127.0.0.1:9/a2a"),
        ("--target", "acme://somewhere"),
    ],
)
def test_the_flag_beside_another_target_is_refused(setup: Path, elsewhere: tuple[str, str]) -> None:
    result = runner.invoke(
        app,
        ["probe", *elsewhere, "--require-auth", "--profile", str(setup / "guardana.yaml")],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "--require-auth" in _plain(result.output)


def _plan(setup: Path, *extra: str, profile: str = "guardana.yaml") -> tuple[int, str]:
    result = runner.invoke(
        app,
        [
            "plan",
            "probe",
            "--url",
            "http://127.0.0.1:9",
            "--model",
            "m",
            "--profile",
            str(setup / profile),
            "--format",
            "json",
            *extra,
        ],
    )
    return result.exit_code, result.output


def _planned(output: str) -> dict[str, object]:
    start = output.index("{")
    end = output.rindex("}") + 1
    planned: dict[str, object] = json.loads(output[start:end])
    return planned


def test_the_plan_prices_the_check_only_when_asked(setup: Path) -> None:
    asked_code, asked = _plan(setup, "--require-auth")
    plain_code, plain = _plan(setup)

    assert asked_code == ExitCode.OK, asked
    assert _planned(asked)["rules"] == [_RULE_ID]
    assert _planned(asked)["requests"] == {"min": 1, "max": 2}
    assert plain_code == ExitCode.INVALID_USAGE, "a plan selecting no rule cannot pass"
    assert _RULE_ID in _planned(plain)["skipped"]  # type: ignore[operator]


def test_a_plan_that_asks_for_the_check_and_excludes_it_cannot_pass(setup: Path) -> None:
    (setup / "excluding.yaml").write_text(
        f"name: t\nrules:\n  include: ['guardana.output.secrets']\n  exclude: ['{_RULE_ID}']\n",
        encoding="utf-8",
    )

    code, output = _plan(setup, "--require-auth", profile="excluding.yaml")

    assert code == ExitCode.INVALID_USAGE, output
    assert "coverage shortfall" in _plain(output)
    assert _RULE_ID in _plain(output)
