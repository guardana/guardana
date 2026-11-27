"""`probe --require-auth` decides whether the named chat route refuses no credential.

Driven against a real HTTP double, so the requests asserted are the ones that reached it:
the request with no credential first and bare, the keyed one only after a refusal, and
nothing at all when the flags rule the check out.
"""

import itertools
import json
import re
from pathlib import Path

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.report import load_report
from guardana.core.report.shortfall import ShortfallKind
from guardana.core.testing._fake_provider import (
    FakeProvider,
    RecordedRequest,
    openai_reply,
    status_reply,
)
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


_BOTH = ("--api-key-env", "ACME_KEY", "--require-auth", "--require-key-check")


def _bearer(sent: RecordedRequest) -> str:
    return sent.headers["authorization"].removeprefix("Bearer ")


def test_a_route_serving_a_key_that_cannot_be_valid_fails_the_run(setup: Path) -> None:
    with FakeProvider(status_reply(401), openai_reply("OK"), openai_reply("OK")) as provider:
        code, output = _probe(setup, provider.url, *_BOTH)

    assert code == ExitCode.POLICY_FAILED, output
    anonymous, control, invalid = provider.requests
    assert "authorization" not in anonymous.headers
    assert _bearer(control) == _KEY
    assert _bearer(invalid) not in ("", _KEY)
    assert _KEY not in _bearer(invalid)
    saved = (setup / "run.json").read_text(encoding="utf-8")
    assert _bearer(invalid) not in saved
    assert _KEY not in saved
    (finding,) = load_report(setup / "run.json").result.findings
    assert (finding.rule_id, finding.severity.name) == (_RULE_ID, "CRITICAL")


def test_a_route_refusing_a_key_that_cannot_be_valid_passes_after_three_requests(
    setup: Path,
) -> None:
    with FakeProvider(status_reply(401), openai_reply("OK"), status_reply(401)) as provider:
        code, output = _probe(setup, provider.url, *_BOTH)

    assert code == ExitCode.OK, output
    assert len(provider.requests) == 3
    assert load_report(setup / "run.json").result.findings == ()


def test_any_other_answer_to_a_key_that_cannot_be_valid_is_indeterminate(setup: Path) -> None:
    with FakeProvider(status_reply(401), openai_reply("OK"), status_reply(503)) as provider:
        code, output = _probe(setup, provider.url, *_BOTH)

    assert code == ExitCode.INDETERMINATE, output
    assert len(provider.requests) == 3


def _keep(setup: Path, name: str) -> Path:
    return (setup / "run.json").rename(setup / name)


def test_runs_with_and_without_the_key_check_are_never_compared_as_one_check(
    setup: Path,
) -> None:
    replies = (status_reply(401), openai_reply("OK"))
    runs = []
    for name, flags, expected in (
        ("keyed.json", _BOTH, ExitCode.POLICY_FAILED),
        ("unkeyed.json", _BOTH[:3], ExitCode.OK),
        ("keyed-again.json", _BOTH, ExitCode.POLICY_FAILED),
    ):
        with FakeProvider(*replies, openai_reply("OK")) as provider:
            assert _probe(setup, provider.url, *flags)[0] == expected
        runs.append(_keep(setup, name))

    for before, after in itertools.pairwise(runs):
        result = runner.invoke(app, ["diff", str(before), str(after)])

        output = _plain(result.output)
        assert result.exit_code == ExitCode.INDETERMINATE, output
        assert "RESOLVED" not in output
        assert "APPEARED" not in output
        assert "graded differently" in output
        assert _RULE_ID in output


def test_the_key_check_alone_is_refused_before_anything_is_sent(setup: Path) -> None:
    with FakeProvider(openai_reply("OK")) as provider:
        code, output = _probe(
            setup, provider.url, "--api-key-env", "ACME_KEY", "--require-key-check"
        )

    assert code == ExitCode.INVALID_USAGE, output
    assert "--require-key-check needs --require-auth" in _plain(output)
    assert provider.requests == []


def test_the_key_check_beside_another_target_is_refused(setup: Path) -> None:
    result = runner.invoke(
        app,
        [
            "probe",
            "--mcp",
            "http://127.0.0.1:9/mcp",
            "--require-key-check",
            "--profile",
            str(setup / "guardana.yaml"),
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "--require-key-check" in _plain(result.output)


def test_the_plan_prices_the_invalid_key_request_only_when_asked(setup: Path) -> None:
    code, output = _plan(setup, "--require-auth", "--require-key-check")
    alone_code, alone = _plan(setup, "--require-key-check")

    assert code == ExitCode.OK, output
    assert _planned(output)["requests"] == {"min": 1, "max": 3}
    assert alone_code == ExitCode.INVALID_USAGE, alone
    assert "--require-key-check needs --require-auth" in _plain(alone)
