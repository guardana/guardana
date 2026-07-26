"""A check that could not run must never read as a check that passed.

Every test here is a regression on a defect reproduced against the released
engine: a third-party rule with an ordinary bug aborted the whole scan, and a
built-in rule that raised landed in `rules_skipped` — the same bucket as "this
target has no files to read" — leaving the build green.
"""

import tempfile
from collections.abc import Iterable
from pathlib import Path

import pytest
from guardana.core.profile import FailOn, Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import CheckError, Evidence, Finding, ScanResult, apply_baseline
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.rule.errors import RuleError
from guardana.core.runner import Runner, gate
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind


def _profile(*, fail_on_error: bool = True) -> Profile:
    return Profile(
        name="test",
        policy=Policy(fail_on=FailOn(severity=Severity.HIGH, fail_on_error=fail_on_error)),
    )


def _finding(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.LOW,
        title="x",
        taxonomy=(),
        target_ref="t",
        evidence=Evidence(summary="s", detail="d"),
    )


def _rule(
    rule_id: str,
    *,
    raises: BaseException | None = None,
    yields: int = 0,
    capabilities: frozenset[Capability] = frozenset({Capability.READ_FILES}),
) -> Rule:
    class _Constructed(Rule):
        meta = RuleMeta(
            id=rule_id,
            title="x",
            severity=Severity.HIGH,
            target_kind=TargetKind.ARTIFACT,
            taxonomy=(),
            required_capabilities=capabilities,
        )

        def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
            """Yield the configured findings, then raise the configured error."""
            for _ in range(yields):
                yield _finding(rule_id)
            if raises is not None:
                raise raises

    return _Constructed()


def _run(*rules: Rule, fail_on_error: bool = True) -> tuple[object, bool]:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    profile = _profile(fail_on_error=fail_on_error)
    with tempfile.TemporaryDirectory() as directory:
        result = Runner(registry, profile).run(ArtifactTarget(Path(directory)))
    return result, gate(result, profile.policy)


def test_an_ordinary_bug_in_a_third_party_rule_does_not_abort_the_scan() -> None:
    # The engine caught only RuleError, so a plugin raising anything else took the
    # whole scan with it — and 0.2.0 published the extension API that invites more
    # plugins.
    result, _ = _run(
        _rule("acme.buggy", raises=ValueError("typo in a third-party rule")),
        _rule("guardana.healthy"),
    )
    assert result.rules_run == 1  # type: ignore[attr-defined]
    assert [e.source for e in result.errors] == ["acme.buggy"]  # type: ignore[attr-defined]
    assert result.errors[0].stage == "run"  # type: ignore[attr-defined]
    assert "ValueError" in result.errors[0].reason  # type: ignore[attr-defined]


def test_a_rule_that_errored_fails_the_gate() -> None:
    # The defect: a CRITICAL rule blowing up left `rules_run > 0`, so the gate
    # green-lit a target whose most important check never ran.
    result, failed = _run(
        _rule("guardana.critical", raises=RuleError("cannot parse this artifact")),
        _rule("guardana.healthy"),
    )
    assert failed is True
    assert [e.source for e in result.errors] == ["guardana.critical"]  # type: ignore[attr-defined]


def test_a_rule_skipped_for_capability_is_not_an_error() -> None:
    # Skipping is normal and expected; erroring is a defect. Conflating them is
    # what let the defect hide.
    result, failed = _run(
        _rule("guardana.needs_chat", capabilities=frozenset({Capability.CHAT})),
    )
    assert result.rules_skipped == ("guardana.needs_chat",)  # type: ignore[attr-defined]
    assert result.errors == ()  # type: ignore[attr-defined]
    assert failed is True  # zero rules ran — the pre-existing zero-rule guard


def test_findings_produced_before_the_exception_are_kept() -> None:
    # A rule is a generator: what it already yielded is real, exactly as a
    # dangerous pickle global found before a deliberately broken tail is real.
    result, failed = _run(
        _rule("guardana.partial", yields=2, raises=RuntimeError("died halfway")),
        _rule("guardana.healthy"),
    )
    assert len(result.findings) == 2  # type: ignore[attr-defined]
    assert len(result.errors) == 1  # type: ignore[attr-defined]
    assert failed is True


def test_a_keyboard_interrupt_is_not_swallowed() -> None:
    # Catching Exception, never BaseException: Ctrl-C must still stop the run.
    with pytest.raises(KeyboardInterrupt):
        _run(_rule("guardana.interrupted", raises=KeyboardInterrupt()))


def test_a_system_exit_is_not_swallowed() -> None:
    with pytest.raises(SystemExit):
        _run(_rule("guardana.exiting", raises=SystemExit(2)))


def test_fail_on_error_false_restores_a_green_build() -> None:
    # The documented escape hatch. The error is still reported — it just stops
    # blocking the build.
    result, failed = _run(
        _rule("acme.buggy", raises=ValueError("boom")),
        _rule("guardana.healthy"),
        fail_on_error=False,
    )
    assert len(result.errors) == 1  # type: ignore[attr-defined]
    assert failed is False


def test_a_giant_exception_message_is_bounded() -> None:
    # An exception message from third-party code is untrusted input that lands in
    # a report, so it is truncated rather than pasted whole.
    result, _ = _run(_rule("acme.verbose", raises=ValueError("x" * 10_000)))
    assert len(result.errors[0].reason) < 1_000  # type: ignore[attr-defined]


def test_check_error_records_the_exception_type_and_message() -> None:
    error = CheckError.from_exception("acme.r", "run", ValueError("bad input"))
    assert error.source == "acme.r"
    assert error.stage == "run"
    assert error.reason == "ValueError: bad input"


def test_an_os_error_from_an_artifact_rule_is_rule_local() -> None:
    # A permission error while reading one file is about that rule, not about the
    # target as a whole — unlike an unreachable endpoint, which every rule would
    # hit identically and which therefore still propagates to the CLI's exit 2.
    result, failed = _run(
        _rule("acme.unreadable", raises=PermissionError("denied")),
        _rule("guardana.healthy"),
    )
    assert [e.source for e in result.errors] == ["acme.unreadable"]  # type: ignore[attr-defined]
    assert result.rules_run == 1  # type: ignore[attr-defined]
    assert failed is True


def test_merging_results_carries_every_channel() -> None:
    # The defect this method exists to make impossible: probe, monitor and
    # baselines each rebuilt ScanResult field by field, and each silently dropped
    # whichever channel its author had not heard of.
    error = CheckError("acme.r", "run", "ValueError: x")
    finding = _finding("acme.r")
    merged = ScanResult.merged(
        [
            ScanResult((finding,), 1, ("skipped.a",), errors=(error,)),
            ScanResult((), 2, (), unverified=(finding,), waived=(finding,)),
        ]
    )
    assert merged.rules_run == 3
    assert merged.findings == (finding,)
    assert merged.rules_skipped == ("skipped.a",)
    assert merged.unverified == (finding,)
    assert merged.waived == (finding,)
    assert merged.errors == (error,)


def test_applying_a_baseline_keeps_checks_that_could_not_run() -> None:
    error = CheckError("guardana.critical", "run", "ValueError: boom")
    result = ScanResult((), 3, (), errors=(error,))
    waived = apply_baseline(result, frozenset())

    assert waived.errors == (error,)
    assert gate(waived, _profile().policy) is True
