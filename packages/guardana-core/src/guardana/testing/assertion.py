"""One call that runs Guardana and fails a test when the verdict is not a pass.

Deliberately not a second engine. It resolves a profile, discovers rules, runs the
same `Runner`, applies the same redactor and asks the same `gate_outcome` the
commands ask — so a check that passes in `pytest` and fails in CI is a bug in the
target, never a difference of opinion between two implementations of "secure".
"""

from pathlib import Path

from guardana.core.budget import BudgetExhausted
from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.profile import Profile, default_profile, load_profile
from guardana.core.profile import preset as named_preset
from guardana.core.redaction import EvidenceRedactor
from guardana.core.registry import Registry
from guardana.core.report import ScanResult, relativize, relativize_findings
from guardana.core.runner import Runner
from guardana.core.target import ArtifactTarget, Target
from guardana.testing.message import failure_message

_HIDDEN = True
"""Kept out of the traceback pytest prints, in every frame that can raise.

`__tracebackhide__` is pytest's contract for an assertion helper, and here it is the
difference between a failure that reads and one nobody reads: without it pytest
renders the whole of `assert_secure` — signature, docstring and all — above the
finding, and the reason the build went red arrives after fifty lines of prose about
why it might. Found by running the documented example rather than by a test, which
is the only way this kind of defect is ever found.
"""


class SecurityAssertionError(AssertionError):
    """A target that did not pass, carrying the result that says why.

    An `AssertionError`, so `pytest` reports it as an ordinary failed assertion and
    no plugin has to be installed for the output to read properly. The result and
    the outcome hang off it because a test that wants to inspect what happened
    should not have to parse a message written for a human.
    """

    def __init__(self, message: str, *, result: ScanResult, outcome: GateOutcome) -> None:
        super().__init__(message)
        self.result = result
        self.outcome = outcome
        """`FAIL` — something was found. `INDETERMINATE` — the question went unanswered.

        Kept apart here for the same reason the gate keeps them apart: both stop a
        build, and only one of them is fixed by changing the model.
        """


def assert_secure(
    target: Target | str | Path,
    *,
    profile: Profile | Path | None = None,
    preset: str | None = None,
    registry: Registry | None = None,
) -> ScanResult:
    """Run Guardana against `target` and raise unless the run passed its policy.

    Returns the `ScanResult` on a pass, so a test can go on to assert something
    narrower. Raises `SecurityAssertionError` on anything else — including a run
    that could not reach a verdict, because a check that did not happen is not a
    check that passed, and a test suite is exactly where that distinction goes
    quiet.

        from guardana.testing import assert_secure

        def test_the_repository_ships_no_dangerous_artifact():
            assert_secure("models", preset="ci")

    `target` is a `Target` — usually an `EndpointTarget` or one from
    `guardana.adapters` — or a path to scan. A path that does not exist raises
    `ValueError` rather than passing: a scan pointed at a typo finds nothing, and
    "no findings" from a directory nobody looked in is the worst shape of false
    green there is.

    `profile` and `preset` are the two ways to say what "secure" means here, and
    they are mutually exclusive, exactly as `--profile` and `--preset` are. Without
    either, `default_profile()` applies: every rule, fail on `HIGH`, evidence
    redacted.

    `registry` is for a test that wants to decide what is loaded — a bare
    `Registry()` for no plugins at all, or one built by hand. Left out, entry points
    are discovered and the profile's `rules.paths` are loaded on top; passed in, it
    is used exactly as given, because a registry somebody assembled is not one this
    should add to behind their back.

    Evidence is redacted by the profile's privacy policy before the message is
    built. The message goes into a CI log, which is a file on somebody's build
    server, and a security tool that writes the credential it just found into one
    has produced a second incident out of the first.
    """
    __tracebackhide__ = _HIDDEN
    active = _profile_for(profile, preset)
    under_test = _target_for(target, active)
    result = _run(under_test, active, registry)
    result = EvidenceRedactor(active.privacy).redact_result(relativize_findings(result, Path.cwd()))
    outcome = gate_outcome(result, active.policy)
    if outcome is GateOutcome.PASS:
        return result
    raise SecurityAssertionError(
        failure_message(
            result,
            outcome=outcome,
            policy=active.policy,
            target_ref=relativize(under_test.ref, Path.cwd()),
        ),
        result=result,
        outcome=outcome,
    )


def _profile_for(profile: Profile | Path | None, preset: str | None) -> Profile:
    __tracebackhide__ = _HIDDEN
    if profile is not None and preset is not None:
        raise ValueError("pass either profile= or preset=, not both")
    if preset is not None:
        return named_preset(preset)
    if isinstance(profile, Profile):
        return profile
    if profile is not None:
        return load_profile(Path(profile))
    return default_profile()


def _target_for(target: Target | str | Path, profile: Profile) -> Target:
    """Take the target as given, or build one over a path that is really there."""
    __tracebackhide__ = _HIDDEN
    if isinstance(target, Target):
        return target
    path = Path(target)
    if not path.exists():
        raise ValueError(
            f"{path} does not exist, so there is nothing to verify. A path that is not "
            f"there yields no files, and a run that looked at nothing must not report a "
            f"pass. Pass a Target for a live model or an agent"
        )
    return ArtifactTarget(path, excludes=profile.path_excludes)


def _run(target: Target, profile: Profile, registry: Registry | None) -> ScanResult:
    """Run the rules, turning an unenforceable budget into a usage error.

    A token ceiling a transport cannot meter is a ceiling that can never fire, and
    `EndpointTarget` refuses it before the first request. That refusal is a mistake
    in the test's configuration rather than a verdict about the target, so it is a
    `ValueError` and not a failed assertion — a red test saying "insecure" about a
    profile typo would send somebody after the wrong thing entirely.
    """
    __tracebackhide__ = _HIDDEN
    try:
        return Runner(registry=registry or _discover(profile), profile=profile).run(target)
    except BudgetExhausted as exc:
        raise ValueError(str(exc)) from exc


def _discover(profile: Profile) -> Registry:
    """Entry-point rules plus whatever the profile points at.

    The profile's own rule directories are loaded because a team that keeps rules in
    its repository expects them here too; a file that fails to load lands in
    `load_errors`, reaches `result.errors`, and makes the run indeterminate rather
    than quietly running one rule fewer.
    """
    registry = Registry.discover()
    registry.load_yaml_rule_dirs(Path(path) for path in profile.rule_paths)
    return registry
