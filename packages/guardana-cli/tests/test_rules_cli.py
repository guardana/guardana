"""`guardana rules` — an empty listing must never look like a deliberate one.

Every sibling that renders something built from a discovered registry refuses
rather than hand back an empty, exit-`0` result when a restrictive `--plugins`
mode emptied it: `rule test` says "nothing was verified, which is not the same
as nothing being wrong" over an unmatched selector. `rules` used to be the one
place this was missing — `--plugins disabled` printed nothing at all and exited
`0`, indistinguishable from a build that genuinely ships no rules.
"""

import json

from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


def test_a_restrictive_plugin_mode_refuses_an_empty_listing() -> None:
    result = runner.invoke(app, ["rules", "--plugins", "disabled"])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert result.stdout == ""
    assert "no rule was loaded" in result.stderr
    assert "refused by plugin trust" in result.stderr


def test_the_json_form_also_refuses_rather_than_an_empty_array() -> None:
    result = runner.invoke(app, ["rules", "--format", "json", "--plugins", "disabled"])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert result.stdout == ""


def test_full_trust_still_lists_the_built_in_rules() -> None:
    """The inversion target: refusing an empty listing must not become refusing
    every listing."""
    result = runner.invoke(app, ["rules"])

    assert result.exit_code == ExitCode.OK, result.output
    assert "no rule was loaded" not in result.output
    assert result.stdout != ""


def test_full_trust_json_form_still_lists_rules() -> None:
    result = runner.invoke(app, ["rules", "--format", "json"])

    assert result.exit_code == ExitCode.OK, result.output
    assert json.loads(result.stdout)
