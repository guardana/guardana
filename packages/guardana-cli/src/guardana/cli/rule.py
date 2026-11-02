"""`guardana rule test` — run a rule's own fixtures, including the one nobody writes.

The inner loop for somebody authoring a rule: edit it, run its samples, see whether
it still classifies them correctly. Sends nothing anywhere — every fixture is a
scripted double — so it is safe to run on every keystroke.

**An unsampled rule is never reported as passing.** A command whose whole purpose is
to disprove false greens cannot print "ok" over an empty set of cases in its own
output, so a rule with no fixtures, or with no `inconclusive` fixture, exits `2`.
"""

from collections.abc import Callable
from fnmatch import fnmatch
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._atomic import write_whole
from guardana.cli._evaluators import wire_config_evaluators
from guardana.cli._exit import refuse_invalid_profile, refuse_unenforceable_budget
from guardana.cli._plugins import (
    AllowPluginOption,
    PluginsOption,
    hint_refused_plugins,
    resolve_trust,
    warn_about_load_errors,
)
from guardana.cli._profile import resolve_profile
from guardana.cli._profile_files import profile_file_inputs, rule_flag_inputs
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli._run_meta import calibrations_or_exit
from guardana.cli._sidecar import refuse_writing_over_an_input, refuse_writing_over_named_inputs
from guardana.cli.exit_codes import ExitCode
from guardana.core.budget import BudgetExhausted
from guardana.core.calibration.corpus import dump_corpus
from guardana.core.calibration.sample import CalibrationSample
from guardana.core.exchange import Exchange
from guardana.core.profile import ProfileError
from guardana.core.registry import Registry
from guardana.core.report import CheckError
from guardana.core.rule import FixtureOutcome, Rule, RuleContext, RuleFixture
from guardana.core.rule.suite_rule import SuiteRule
from guardana.core.rule.verify import FixtureVerdict, RuleVerification, verify_rule
from guardana.core.target import ChatMessage, EndpointTarget, TargetKind

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
    plugins: PluginsOption = None,
    allow_plugin: AllowPluginOption = None,
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

    Exit `0` every fixture classified as declared and every regression pair holds ·
    `1` a fixture did not, or a pair's side graded the wrong way · `2` the rule was
    never sampled, a fixture could not run, a pair's side declined or raised, or a rule
    could not be loaded · `3` the selector matched nothing, or a suite holding
    regression pairs has an evaluator that cannot regrade them without sending.
    """
    refuse_writing_over_an_input(write_corpus, [profile, *rules])
    refuse_writing_over_named_inputs(write_corpus, rule_flag_inputs(rules))
    prof = resolve_profile(profile, None)
    refuse_writing_over_named_inputs(write_corpus, profile_file_inputs(prof))
    resolved = resolve_trust(plugins, allow_plugin, prof)
    registry = Registry.discover(resolved.trust)
    load_custom_rules(registry, prof, rules)
    try:
        wire_config_evaluators(registry, prof, budgets=prof.budgets)
    except BudgetExhausted as exc:
        raise refuse_unenforceable_budget(exc) from exc
    except ProfileError as exc:
        raise refuse_invalid_profile(exc) from exc
    warn_about_load_errors(registry, resolved, what="rule")
    hint_refused_plugins(registry, resolved)
    calibrations = {key: value.as_record() for key, value in calibrations_or_exit(prof).items()}

    selected = [r for r in registry.rules() if fnmatch(r.meta.id, selector)]
    if not selected:
        typer.echo(
            f"error: no rule matches {selector!r} — nothing was verified, which is not "
            f"the same as nothing being wrong",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INVALID_USAGE)

    def context(rule: Rule) -> RuleContext:
        # The same context the runner builds, per rule. Grading a fixture with
        # default settings while the run grades with the profile's would verify a
        # rule nobody executes — the check would be green about behaviour the
        # pipeline never sees.
        return RuleContext(
            config=dict(prof.rule_config.get(rule.meta.id, {})),
            evaluators=registry.evaluators(),
            calibrations=calibrations,
        )

    verifications = tuple(verify_rule(rule, context(rule)) for rule in selected)
    # Under the unstated default the refusals were already named once, by the hint.
    shown = registry.load_errors if resolved.stated else registry.load_failures
    refused = 0 if resolved.stated else len(registry.refused)
    for line in _render(verifications, shown, refused=refused, unsampled_ok=unsampled_ok):
        typer.echo(line)
    if write_corpus is not None:
        _write_corpus(selected, verifications, write_corpus, context)
    raise typer.Exit(
        code=_exit_code(verifications, registry.load_errors, unsampled_ok=unsampled_ok)
    )


def _exit_code(
    verifications: tuple[RuleVerification, ...],
    load_errors: tuple[CheckError, ...],
    *,
    unsampled_ok: bool,
) -> int:
    """Worst outcome wins, and a wrong answer outranks an unasked question.

    A rule that classified a sample wrongly is a defect somebody must fix; a rule
    nobody sampled is a question nobody put. Reporting the second over the first
    would bury the actionable half. A rule that never loaded was never verified,
    and whether the selector would have matched it cannot be known, so it holds
    the verdict at indeterminate whatever else passed. A suite whose regression
    pairs cannot be regraded is refused before any of that: the command was asked
    a question it must not answer by skipping.
    """
    if any(v.unprovable is not None for v in verifications):
        return ExitCode.INVALID_USAGE
    if any(v.failed or v.wrong_way for v in verifications):
        return ExitCode.POLICY_FAILED
    if load_errors or any(v.errored or v.broken for v in verifications):
        return ExitCode.INDETERMINATE
    if not unsampled_ok and any(v.gaps for v in verifications):
        return ExitCode.INDETERMINATE
    return ExitCode.OK


def _render(
    verifications: tuple[RuleVerification, ...],
    load_errors: tuple[CheckError, ...],
    *,
    refused: int,
    unsampled_ok: bool,
) -> list[str]:
    """Render one line per failing fixture and gap, `load_errors` each, then the totals.

    `refused` counts entry points plugin trust kept out that `load_errors` omits;
    they enter the totals so the count of what was not verified stays whole.
    """
    lines = [
        f"! could not load {error.source} ({error.stage}): {error.reason}" for error in load_errors
    ]
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
        for broken in verification.broken:
            mark = "✖" if broken in verification.wrong_way else "!"
            lines.append(f"{mark} {broken.rule_id} — regression case at dataset line {broken.line}")
            lines.append(f"    the pair no longer holds: {broken.proof.describe()}")
        if verification.unprovable is not None:
            lines.append(f"✖ refused: {verification.unprovable}")
        lines.extend(f"? {gap}" for gap in verification.gaps)
    unsampled = sum(1 for v in verifications if v.gaps)
    pairs = sum(len(v.regressions) for v in verifications)
    broken_pairs = sum(len(v.broken) for v in verifications)
    lines.append("")
    lines.append(
        f"{len(verifications)} rule(s); {passed} fixture(s) passed, {failed} failed, "
        f"{errored} could not run. {unsampled} rule(s) not fully sampled."
        + (f" {len(load_errors)} rule source(s) could not be loaded." if load_errors else "")
        + (f" {refused} entry point(s) were refused by plugin trust." if refused else "")
        + (f" {pairs - broken_pairs} of {pairs} regression pair(s) hold." if pairs else "")
    )
    if unsampled and unsampled_ok:
        lines.append(
            "note: --unsampled-ok is set, so the unsampled rules above did not take "
            "the verdict away. They are still unchecked."
        )
    return lines


_LEFT_OUT = (
    "from a suite (its outcome is a pass rate, not one reply's label)",
    "inconclusive (no measurable label)",
    "not offered (the sample lacks what the rule examines)",
    "not applicable (the sample holds nothing the rule grades)",
    "artifact or trace sample(s) (the corpus holds model replies only)",
    "from a rule that declares no expectation or more than one",
    "not a single scripted reply (a conversation or an agent run)",
    "not classified as declared",
    "no request reached the scripted model",
)
(
    _SUITE,
    _INCONCLUSIVE,
    _NOT_OFFERED,
    _NOT_APPLICABLE,
    _NO_REPLY_KIND,
    _NOT_ONE_EXPECTATION,
    _NOT_ONE_REPLY,
    _NOT_VERIFIED,
    _NOTHING_SENT,
) = _LEFT_OUT
_NO_REPLY_KINDS = frozenset({TargetKind.ARTIFACT, TargetKind.TRACE})
_NO_LABEL = {
    FixtureOutcome.INCONCLUSIVE: _INCONCLUSIVE,
    FixtureOutcome.NOT_OFFERED: _NOT_OFFERED,
    FixtureOutcome.NOT_APPLICABLE: _NOT_APPLICABLE,
}
"""The declared outcomes no measurable label follows from."""


def _write_corpus(
    selected: list[Rule],
    verifications: tuple[RuleVerification, ...],
    destination: Path,
    context: Callable[[Rule], RuleContext],
) -> None:
    """Turn the fixtures into a labelled corpus `guardana calibrate` can measure against.

    A fixture becomes a row only when the row can be labelled truthfully: a known
    outcome, one expectation to grade it with, one scripted reply for that
    expectation to read, and a rule that classified it as its author declared.
    Everything else is **left out** and counted per reason rather than passed over;
    a guessed or disputed label would make the resulting Brier score a measurement
    of the guess.

    The row pairs the reply with the first prompt the rule really sent. The label is
    the fixture's outcome for the rule as a whole, which is exact for a rule that
    sends one prompt and for an evaluator that does not read the prompt. A suite's
    outcome is about a rate over many cases, so no fixture of one labels a reply.

    A corpus that cannot be written exits `3` and leaves the file at `destination` as it was.
    """
    samples: list[CalibrationSample] = []
    left_out = dict.fromkeys(_LEFT_OUT, 0)
    for rule, verification in zip(selected, verifications, strict=True):
        expectations = tuple(e for _id, e in rule.declared_expectations())
        for index, fixture in enumerate(rule.fixtures()):
            reply = _scripted_reply(fixture.target)
            if (unlabelled := _unlabelled(rule, fixture, expectations)) is not None:
                left_out[unlabelled] += 1
            elif reply is None:
                left_out[_NOT_ONE_REPLY] += 1
            elif not _classified_as_declared(verification, index, fixture):
                left_out[_NOT_VERIFIED] += 1
            elif (prompt := _first_request(rule, fixture, context(rule))) is None:
                left_out[_NOTHING_SENT] += 1
            else:
                samples.append(
                    CalibrationSample(
                        exchange=Exchange((*prompt, ChatMessage(role="assistant", content=reply))),
                        expectation=expectations[0],
                        attack_succeeded=fixture.outcome is FixtureOutcome.FINDING,
                    )
                )
    try:
        write_whole(destination, dump_corpus(samples).encode("utf-8"))
    except OSError as exc:
        typer.echo(f"error: could not write the corpus to {destination}: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    reasons = ", ".join(f"{count} {reason}" for reason, count in left_out.items() if count)
    typer.echo(
        f"wrote {len(samples)} labelled sample(s) to {destination}"
        + (f"; left out: {reasons}" if reasons else "")
    )


def _unlabelled(rule: Rule, fixture: RuleFixture, expectations: tuple[object, ...]) -> str | None:
    """Why this fixture cannot become a corpus row, or None when it still might."""
    if isinstance(rule, SuiteRule):
        return _SUITE
    unlabelled = _NO_LABEL.get(fixture.outcome)
    if unlabelled is not None:
        return unlabelled
    if fixture.target.kind in _NO_REPLY_KINDS:
        return _NO_REPLY_KIND
    if len(expectations) != 1:
        return _NOT_ONE_EXPECTATION
    return None


def _classified_as_declared(
    verification: RuleVerification, index: int, fixture: RuleFixture
) -> bool:
    """Whether the verdict at this fixture's position is a pass about this very fixture.

    `fixtures()` is called again to build the corpus, and a plugin whose samples are
    not stable across calls must not get a row labelled from another sample's verdict.
    """
    if index >= len(verification.results):
        return False
    result = verification.results[index]
    return (
        result.verdict is FixtureVerdict.PASSED
        and result.fixture == fixture.name
        and result.expected is fixture.outcome
    )


def _first_request(
    rule: Rule, fixture: RuleFixture, ctx: RuleContext
) -> tuple[ChatMessage, ...] | None:
    """Play the fixture once more and read back the first request the rule sent.

    A row has to carry the exchange the evaluator graded. A placeholder user turn
    labels a different one: an evaluator that reads the prompt, as `amplification`
    does, is measured on text the rule never sent, and a judge reads the fixture's
    name where the prompt should be.
    """
    try:
        list(rule.run(fixture.target, ctx))
    except (Exception, SystemExit):  # classified as declared; a replay that raises gets no row
        return None
    seen = getattr(getattr(fixture.target, "transport", None), "seen", None)
    if not isinstance(seen, list) or not seen:
        return None
    return tuple(seen[0])


def _scripted_reply(target: object) -> str | None:
    """Read back the one reply a fixture's scripted transport will answer, if that is all it is.

    A plugin fixture may drive an artifact or an MCP server, a scenario several
    turns and an agent run a tool loop; none of those is one exchange a judge can be
    measured on. Returning `None` is how they are left out rather than rendered as
    an empty conversation or as the first turn of a longer one.
    """
    if not isinstance(target, EndpointTarget):
        return None
    scripted = getattr(target.transport, "scripted", None)
    if isinstance(scripted, tuple) and len(scripted) == 1 and isinstance(scripted[0], str):
        return scripted[0]
    return None


__all__ = ["rule_app"]
