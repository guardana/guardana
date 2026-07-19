from pathlib import Path

from guardana.cli.main import app
from guardana.core.registry import Registry
from typer.testing import CliRunner

runner = CliRunner()


def test_new_rule_creates_yaml_with_id_substituted(tmp_path: Path) -> None:
    result = runner.invoke(app, ["new-rule", "acme.prompt.demo", "--dir", str(tmp_path)])

    assert result.exit_code == 0
    written = tmp_path / "demo.yaml"
    assert written.exists()
    assert "id: acme.prompt.demo" in written.read_text()


def test_new_rule_refuses_to_overwrite(tmp_path: Path) -> None:
    first = runner.invoke(app, ["new-rule", "acme.prompt.demo", "--dir", str(tmp_path)])
    assert first.exit_code == 0

    second = runner.invoke(app, ["new-rule", "acme.prompt.demo", "--dir", str(tmp_path)])
    assert second.exit_code == 1


def test_new_rule_tells_you_how_to_actually_run_it(tmp_path: Path) -> None:
    # The scaffold is an endpoint rule, so `scan` (artifact-only) would never run
    # it. Pointing the author at `scan` would send them to a command that reports
    # nothing and teaches them the rule is broken.
    result = runner.invoke(app, ["new-rule", "acme.prompt.demo", "--dir", str(tmp_path)])

    assert result.exit_code == 0
    assert "guardana probe" in result.stdout
    assert "guardana scan" not in result.stdout


def test_scaffolded_rule_loads_and_is_a_valid_endpoint_rule(tmp_path: Path) -> None:
    # The scaffold must survive the loader's strict validation — a template that
    # fails to load is worse than no template.
    runner.invoke(app, ["new-rule", "acme.prompt.demo", "--dir", str(tmp_path)])

    registry = Registry.discover()
    outcome = registry.load_yaml_rule_dirs([tmp_path])

    assert outcome.errors == ()
    assert outcome.loaded == ("acme.prompt.demo",)


def test_scaffolded_canary_rule_loads(tmp_path: Path) -> None:
    runner.invoke(
        app, ["new-rule", "acme.leak.demo", "--evaluator", "canary", "--dir", str(tmp_path)]
    )

    outcome = Registry.discover().load_yaml_rule_dirs([tmp_path])

    assert outcome.errors == ()
    assert outcome.loaded == ("acme.leak.demo",)
