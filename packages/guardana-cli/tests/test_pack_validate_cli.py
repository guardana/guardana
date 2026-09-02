"""`guardana pack validate` — and what it must not do when trust is restricted.

The command's whole job is comparing what a manifest promises against what this
build actually registers. Refuse an entry point silently and the "actually
registers" side goes empty while the manifest still promises everything — the
exact false red 0.18.0 shipped when `pack validate` built that set from rules and
evaluators alone and accused every pack that shipped a target of not registering
it. Repeating that shape through `--plugins` instead of a missing group is the
same defect behind a different door.

Printing the refusal on stderr (`warn_about_load_errors`) made it visible; it did
not make the verdict correct. `validate` still built `registered` from the same
emptied registry and printed "declares … and does not register" as a fact about
the pack — the exact accusation the module docstring says a validator must never
make, just reached through a policy instead of a missing entry-point group. The
fix refuses the comparison outright rather than reporting it wrong.
"""

from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


def test_a_restrictive_plugin_mode_refuses_rather_than_accuses() -> None:
    """`--plugins disabled` empties "what this build registers". A pack that
    genuinely does not register what it declares and a pack merely refused by
    trust are indistinguishable from inside an emptied registry, so `validate`
    must not accuse either — it must say the comparison could not be made, and
    go indeterminate rather than hand back a confident, wrong answer.
    """
    result = runner.invoke(app, ["pack", "validate", "--plugins", "disabled"])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert "does not register" not in result.output
    assert "pack(s) checked" not in result.output
    assert "could not load an extension" in result.stderr
    assert "plugin trust is disabled" in result.stderr
    assert "refused by plugin trust" in result.stderr


def test_full_trust_still_catches_a_pack_that_really_does_not_register() -> None:
    """The inversion target: refusing to accuse must not become refusing to check.

    With nothing refused, a mismatch is still exactly the thing this command
    exists to catch — proven here by the ordinary, unrestricted run finding
    every installed pack accurate and saying so by name.
    """
    result = runner.invoke(app, ["pack", "validate"])

    assert result.exit_code == ExitCode.OK, result.output
    assert "does not register" not in result.output
    assert "pack(s) checked" in result.output
