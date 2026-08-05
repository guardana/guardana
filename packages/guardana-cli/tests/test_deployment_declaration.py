"""What a run says it verified, where it runs, and which version of it.

Two kinds of fact gathered two ways, and the split is the point. What CI *states*
is read from the environment, because the answer that matters is the one nobody had
to remember to pass. What only a human knows is declared and never guessed: a
branch is not an environment and a repository is not an AI system, and a guessed
value is one a team would build a dashboard on.
"""

import io
import json
from pathlib import Path
from urllib.error import HTTPError

import pytest
from guardana.cli._run_meta import detect_deployment
from guardana.cli.main import app
from guardana.core.manifest import DeploymentRef
from typer.testing import CliRunner

runner = CliRunner()


def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    for variable in (
        "GUARDANA_AI_SYSTEM",
        "GUARDANA_ENVIRONMENT",
        "GUARDANA_DEPLOYMENT_ID",
        "GITHUB_SHA",
        "CI_COMMIT_SHA",
        "GIT_COMMIT",
        "BUILD_SOURCEVERSION",
        "GUARDANA_IMAGE_DIGEST",
    ):
        monkeypatch.delenv(variable, raising=False)


def test_nothing_declared_means_nothing_known(monkeypatch: pytest.MonkeyPatch) -> None:
    # Null means "not known", never "not applicable" — a laptop run has no commit,
    # and a consumer must be able to tell that from a commit of all zeroes.
    _clear(monkeypatch)

    assert detect_deployment() == DeploymentRef()


def test_a_flag_declares_what_only_a_human_knows(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)

    declared = detect_deployment("support-agent", "production", "2026-08-05.3")

    assert declared.ai_system == "support-agent"
    assert declared.environment == "production"
    assert declared.deployment_id == "2026-08-05.3"


def test_an_environment_variable_is_the_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    # A pipeline sets the repository default once; one job still says it is
    # production without every step repeating the system name.
    _clear(monkeypatch)
    monkeypatch.setenv("GUARDANA_AI_SYSTEM", "support-agent")
    monkeypatch.setenv("GUARDANA_ENVIRONMENT", "staging")

    declared = detect_deployment(environment="production")

    assert declared.ai_system == "support-agent"
    assert declared.environment == "production", "a flag must win over the variable"


@pytest.mark.parametrize(
    "variable", ["GITHUB_SHA", "CI_COMMIT_SHA", "GIT_COMMIT", "BUILD_SOURCEVERSION"]
)
def test_the_commit_is_read_from_whatever_ci_this_is(
    monkeypatch: pytest.MonkeyPatch, variable: str
) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv(variable, "abc1234")

    assert detect_deployment().commit_sha == "abc1234"


def test_the_environment_is_never_guessed_from_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    """The one that would be tempting and wrong.

    A branch name is not an environment, and a repository name is not an AI system:
    a monorepo has several systems, and one repository deployed twice is one system
    in two environments.
    """
    _clear(monkeypatch)
    monkeypatch.setenv("GITHUB_SHA", "abc1234")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/support-agent")

    declared = detect_deployment()

    assert declared.environment is None
    assert declared.ai_system is None


def test_scan_records_the_declaration_in_the_run_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The saved run is deployment evidence, so it has to carry which deployment."""
    _clear(monkeypatch)
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    report = tmp_path / "run.json"

    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--ai-system",
            "support-agent",
            "--environment",
            "production",
            "--format",
            "json",
            "--output",
            str(report),
        ],
    )

    assert result.exit_code == 0, result.output
    document = json.loads(report.read_text(encoding="utf-8"))
    assert document["run"]["deployment"]["ai_system"] == "support-agent"
    assert document["run"]["deployment"]["environment"] == "production"


def test_scan_forwards_the_declaration_to_the_collector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reaching the manifest is not reaching the collector, and only one of them gates."""
    _clear(monkeypatch)
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    captured: list[bytes] = []

    class _Recording:
        def __init__(
            self, url: str, *, api_key: str | None = None, deployment: object = None
        ) -> None:
            self.deployment = deployment

        def submit(self, result: object, *, source: str) -> None:
            captured.append(json.dumps({"deployment": self.deployment is not None}).encode())

    monkeypatch.setattr("guardana.cli._reporting.HttpReporter", _Recording)

    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--ai-system",
            "support-agent",
            "--environment",
            "production",
            "--reporter",
            "server://http://collector",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(captured[0])["deployment"] is True


def test_a_refused_submission_repeats_the_collectors_own_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `403` for a pinned key is not a schema-version problem, and must not read as one.

    The same mistake as reporting a database outage as a rejected credential: the
    operator is sent after the wrong thing, and the right thing stays broken.
    """
    _clear(monkeypatch)
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")

    class _Refusing:
        def __init__(
            self, url: str, *, api_key: str | None = None, deployment: object = None
        ) -> None:
            pass

        def submit(self, result: object, *, source: str) -> None:
            raise HTTPError(
                "http://collector/findings",
                403,
                "Forbidden",
                {},  # type: ignore[arg-type]
                io.BytesIO(
                    json.dumps(
                        {"detail": "this key is pinned to the 'production' environment"}
                    ).encode()
                ),
            )

    monkeypatch.setattr("guardana.cli._reporting.HttpReporter", _Refusing)

    result = runner.invoke(app, ["scan", str(tmp_path), "--reporter", "server://http://collector"])

    assert result.exit_code == 0, "a rejected submission never changes the gate"
    assert "pinned to the 'production' environment" in result.output
    assert "schema version" not in result.output
