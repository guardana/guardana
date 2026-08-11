"""`guardana rule test` — run a rule's own fixtures, including the one nobody writes.

The inner loop for somebody authoring a rule: edit it, run its samples, see whether
it still classifies them correctly. Sends nothing anywhere — every fixture is a
scripted double — so it is safe to run on every keystroke.

**An unsampled rule is never reported as passing.** A command whose whole purpose is
to disprove false greens cannot print "ok" over an empty set of cases in its own
output, so a rule with no fixtures, or with no `inconclusive` fixture, exits `2`.
"""

from fnmatch import fnmatch
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._evaluators import wire_config_evaluators
from guardana.cli._plugins import resolve_trust
from guardana.cli._profile import resolve_profile
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli.exit_codes import ExitCode
from guardana.core.calibration.corpus import dump_corpus
from guardana.core.calibration.sample import CalibrationSample
from guardana.core.exchange import Exchange
from guardana.core.registry import Registry
from guardana.core.rule import FixtureOutcome, Rule, RuleContext
from guardana.core.rule.verify import FixtureVerdict, RuleVerification, verify_rule
from guardana.core.target import ChatMessage, EndpointTarget

rule_app = typer.Typer(help="Work on one rule: run its fixtures.")


@rule_app.command("test")
def run_fixtures(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; the command's surface
    selector: Annotated[
        str, typer.Argument(help="Rule id or glob, e.g. 'acme.*'. Defaults to every rule.")
    ] = "*",
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    rules: Annotated[
        list[Path],
        typer.Option("--rules", help="Directory or file of custom YAML rules; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    plugins: Annotated[
        str,
        typer.Option(help="Which installed plugins to load: all|builtins|allowlist|disabled"),
    ] = "all",
    allow_plugin: Annotated[
        list[str],
        typer.Option("--allow-plugin", help="Distribution to trust; repeatable, needs allowlist."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    write_corpus: Annotated[
        Path | None,
        typer.Option(
            "--write-corpus",
            help="Write the fixtures out as a labelled corpus for `guardana calibrate`.",
        ),
    ] = None,
    unsampled_ok: Annotated[
        bool,
        typer.Option(
            "--unsampled-ok",
            help="Do not go indeterminate over rules that declare no fixtures.",
        ),
    ] = False,
) -> None:
    """Run the fixtures a rule declares, and say what they did not establish.

    Exit `0` every fixture classified as declared · `1` one did not · `2` the rule
    was never sampled, or a fixture could not run · `3` the selector matched nothing.
    """
    prof = resolve_profile(profile, None)
    registry = Registry.discover(resolve_trust(plugins, allow_plugin, no_plugins=False))
    load_custom_rules(registry, prof, rules)
    wire_config_evaluators(registry, prof)
    for error in registry.load_errors:
        typer.echo(f"warning: could not load rule — {error}", err=True)

    selected = [r for r in registry.rules() if fnmatch(r.meta.id, selector)]
    if not selected:
        typer.echo(
            f"error: no rule matches {selector!r} — nothing was verified, which is not "
            f"the same as nothing being wrong",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INVALID_USAGE)

    verifications = tuple(
        verify_rule(
            rule,
            # The same context the runner builds, per rule. Grading a fixture with
            # default settings while the run grades with the profile's would verify a
            # rule nobody executes — the check would be green about behaviour the
            # pipeline never sees.
            RuleContext(
                config=dict(prof.rule_config.get(rule.meta.id, {})),
                evaluators=registry.evaluators(),
            ),
        )
        for rule in selected
    )
    for line in _render(verifications, unsampled_ok=unsampled_ok):
        typer.echo(line)
    if write_corpus is not None:
        _write_corpus(selected, write_corpus)
    raise typer.Exit(code=_exit_code(verifications, unsampled_ok=unsampled_ok))


def _exit_code(verifications: tuple[RuleVerification, ...], *, unsampled_ok: bool) -> int:
    """Worst outcome wins, and a wrong answer outranks an unasked question.

    A rule that classified a sample wrongly is a defect somebody must fix; a rule
    nobody sampled is a question nobody put. Reporting the second over the first
    would bury the actionable half.
    """
    if any(v.failed for v in verifications):
        return ExitCode.POLICY_FAILED
    if any(v.errored for v in verifications):
        return ExitCode.INDETERMINATE
    if not unsampled_ok and any(v.gaps for v in verifications):
        return ExitCode.INDETERMINATE
    return ExitCode.OK


def _render(verifications: tuple[RuleVerification, ...], *, unsampled_ok: bool) -> list[str]:
    lines: list[str] = []
    passed = failed = errored = 0
    for verification in verifications:
        for result in verification.results:
            if result.verdict is FixtureVerdict.PASSED:
                passed += 1
                continue
            failed += result.verdict is FixtureVerdict.FAILED
            errored += result.verdict is FixtureVerdict.ERRORED
            mark = "✖" if result.verdict is FixtureVerdict.FAILED else "!"
            lines.append(f"{mark} {result.rule_id} — {result.fixture}")
            lines.append(f"    {result.detail}")
        lines.extend(f"? {gap}" for gap in verification.gaps)
    unsampled = sum(1 for v in verifications if v.gaps)
    lines.append("")
    lines.append(
        f"{len(verifications)} rule(s); {passed} fixture(s) passed, {failed} failed, "
        f"{errored} could not run. {unsampled} rule(s) not fully sampled."
    )
    if unsampled and unsampled_ok:
        lines.append(
            "note: --unsampled-ok is set, so the unsampled rules above did not take "
            "the verdict away. They are still unchecked."
        )
    return lines


def _write_corpus(selected: list[Rule], destination: Path) -> None:
    """Turn the fixtures into a labelled corpus `guardana calibrate` can measure against.

    `inconclusive` fixtures are **left out**, and the count is printed rather than
    passed over: calibration measures an evaluator's confidence against a known
    outcome, and a sample whose outcome is undecidable has none to measure against.
    Writing them with a guessed label would make the resulting Brier score a
    measurement of the guess.
    """
    samples: list[CalibrationSample] = []
    skipped = 0
    for rule in selected:
        expectation = next((e for _id, e in rule.declared_expectations()), None)
        for fixture in rule.fixtures():
            if fixture.outcome is FixtureOutcome.INCONCLUSIVE or expectation is None:
                skipped += 1
                continue
            reply = _scripted_reply(fixture.target)
            if reply is None:
                skipped += 1
                continue
            samples.append(
                CalibrationSample(
                    exchange=Exchange(
                        (
                            ChatMessage(role="user", content=f"fixture: {fixture.name}"),
                            ChatMessage(role="assistant", content=reply),
                        )
                    ),
                    expectation=expectation,
                    attack_succeeded=fixture.outcome is FixtureOutcome.FINDING,
                )
            )
    destination.write_text(dump_corpus(samples), encoding="utf-8")
    typer.echo(
        f"wrote {len(samples)} labelled sample(s) to {destination}"
        + (f"; {skipped} fixture(s) carry no measurable label and were left out" if skipped else "")
    )


def _scripted_reply(target: object) -> str | None:
    """Read back what a fixture's scripted transport will answer, if it is one.

    A plugin fixture may drive an artifact or an MCP server, and neither is an
    exchange a judge can be measured on. Returning `None` is how those are left out
    rather than rendered as an empty conversation.
    """
    if not isinstance(target, EndpointTarget):
        return None
    scripted = getattr(target.transport, "scripted", None)
    if isinstance(scripted, tuple) and scripted and isinstance(scripted[0], str):
        return scripted[0]
    return None


__all__ = ["rule_app"]
