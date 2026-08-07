"""Guardana as an assertion in somebody else's test suite.

The properties that matter here are not "does it find things" — the rules are
tested where they live. They are the ones a test suite is uniquely good at hiding:
a run that verified nothing reading as a pass, and a credential from a model reply
landing in a CI log because the failure message is the one output path nobody
thought of as an output path.
"""

import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

import pytest
from guardana.core.evaluator.base import Verdict
from guardana.core.gate import GateOutcome
from guardana.core.profile import FailOn, Policy, Profile
from guardana.core.redaction import EvidenceMode, RedactionPolicy
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, Target, TargetKind
from guardana.core.testing import fake_aws_key
from guardana.testing import SecurityAssertionError, assert_secure

_FAKE_KEY = fake_aws_key()


class _Fires(Rule):
    """A rule that reports one finding, so the gate has something to fail on."""

    meta = RuleMeta(
        id="acme.test.fires",
        title="Something was found",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Report one finding whose evidence carries a credential-shaped string."""
        yield Finding(
            self.meta.id,
            Severity.HIGH,
            "Something was found",
            (),
            target.ref,
            Evidence(summary=f"the model replied with {_FAKE_KEY}"),
        )


class _Quiet(Rule):
    """A rule that runs and finds nothing — the only honest way to reach a pass."""

    meta = RuleMeta(
        id="acme.test.quiet",
        title="Nothing found",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Report nothing."""
        return ()


class _Ungradable(Rule):
    """A rule that ran and could not reach a verdict."""

    meta = RuleMeta(
        id="acme.test.ungradable",
        title="Could not grade",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Report one inconclusive finding, which lands in `unverified`."""
        yield Finding(
            self.meta.id,
            Severity.HIGH,
            "Could not grade",
            (),
            target.ref,
            Evidence(summary="the judge did not answer"),
            verdict=Verdict("inconclusive", 0.0, "no reply", "llm_judge"),
        )


class _Broken(Rule):
    """A rule that throws — a check that did not run at all."""

    meta = RuleMeta(
        id="acme.test.broken",
        title="Does not run",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Fail the way a third-party rule with an ordinary bug in it fails."""
        raise RuntimeError("boom")


class _NeedsMore(Rule):
    """A rule the target cannot satisfy, so the runner skips it."""

    meta = RuleMeta(
        id="acme.test.needs_more",
        title="Needs a capability",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.CHAT}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:  # pragma: no cover
        """Never called: the runner refuses to run a rule its target cannot satisfy."""
        return ()


def _registry(*rules: Rule) -> Registry:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    return registry


def _profile(**fail_on: object) -> Profile:
    """A profile that redacts, like every command — the library default is `full`."""
    return Profile(
        name="test",
        policy=Policy(fail_on=FailOn(**fail_on)),  # type: ignore[arg-type]
        privacy=RedactionPolicy(mode=EvidenceMode.REDACTED),
    )


def test_a_clean_target_passes_and_hands_back_the_result(tmp_path: Path) -> None:
    result = assert_secure(tmp_path, profile=_profile(), registry=_registry(_Quiet()))

    assert result.rules_run == ("acme.test.quiet",)


def test_a_finding_over_the_bar_raises_and_names_the_rule(tmp_path: Path) -> None:
    with pytest.raises(SecurityAssertionError) as raised:
        assert_secure(tmp_path, profile=_profile(), registry=_registry(_Fires()))

    assert raised.value.outcome is GateOutcome.FAIL
    assert "acme.test.fires" in str(raised.value)
    assert raised.value.result.findings[0].rule_id == "acme.test.fires"


def test_the_failure_message_cannot_carry_a_credential(tmp_path: Path) -> None:
    """The message goes into a CI log, which is a file on somebody's build server.

    A security tool that writes the credential it just found into one has made a
    second incident out of the first. This is the output path nobody thinks of as an
    output path, which is exactly why it needs the same seam as the renderers.
    """
    with pytest.raises(SecurityAssertionError) as raised:
        assert_secure(tmp_path, profile=_profile(), registry=_registry(_Fires()))

    assert _FAKE_KEY not in str(raised.value)
    assert "[redacted:" in str(raised.value)


def test_a_run_that_verified_nothing_is_not_a_pass(tmp_path: Path) -> None:
    """An empty registry, an over-narrow profile, a target no rule applies to.

    All three end here, and all three used to be indistinguishable from a clean
    result — which is the fail-open this whole project is against, reached through a
    test file instead of through a rule.
    """
    with pytest.raises(SecurityAssertionError) as raised:
        assert_secure(tmp_path, profile=_profile(), registry=_registry())

    assert raised.value.outcome is GateOutcome.INDETERMINATE
    assert "no rule ran at all" in str(raised.value)


def test_a_check_that_could_not_run_is_reported_as_that(tmp_path: Path) -> None:
    with pytest.raises(SecurityAssertionError) as raised:
        assert_secure(tmp_path, profile=_profile(), registry=_registry(_Quiet(), _Broken()))

    assert raised.value.outcome is GateOutcome.INDETERMINATE
    assert "could not run" in str(raised.value)
    assert "acme.test.broken" in str(raised.value)


def test_a_check_that_could_not_grade_is_reported_as_that(tmp_path: Path) -> None:
    with pytest.raises(SecurityAssertionError) as raised:
        assert_secure(
            tmp_path,
            profile=_profile(fail_on_inconclusive=True),
            registry=_registry(_Quiet(), _Ungradable()),
        )

    assert raised.value.outcome is GateOutcome.INDETERMINATE
    assert "could not grade" in str(raised.value)


def test_a_skipped_rule_can_be_made_to_count(tmp_path: Path) -> None:
    """Coverage somebody is paying for and did not get, when they ask to hear about it."""
    with pytest.raises(SecurityAssertionError) as raised:
        assert_secure(
            tmp_path,
            profile=_profile(fail_on_skipped=True),
            registry=_registry(_Quiet(), _NeedsMore()),
        )

    assert "skipped" in str(raised.value)
    assert "acme.test.needs_more" in str(raised.value)


def test_a_finding_below_the_bar_passes_but_is_still_returned(tmp_path: Path) -> None:
    """Redaction is not suppression and neither is a threshold."""
    result = assert_secure(
        tmp_path,
        profile=_profile(severity=Severity.CRITICAL),
        registry=_registry(_Fires()),
    )

    assert [f.rule_id for f in result.findings] == ["acme.test.fires"]


def test_a_path_that_is_not_there_refuses_rather_than_passing() -> None:
    """A scan pointed at a typo finds nothing, and nothing is not a pass.

    The same hole `guardana scan` had: a missing directory yields no files, so the
    run reported "no findings" and exited `0` while gating a build on nothing.
    """
    with pytest.raises(ValueError, match="does not exist"):
        assert_secure("no-such-directory-anywhere")


def test_an_empty_directory_is_a_different_answer_and_may_pass(tmp_path: Path) -> None:
    """Nothing to find is not nothing to look at."""
    assert assert_secure(tmp_path, profile=_profile(), registry=_registry(_Quiet()))


def test_a_profile_and_a_preset_together_are_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not both"):
        assert_secure(tmp_path, profile=_profile(), preset="ci")


def test_a_preset_is_accepted_by_name(tmp_path: Path) -> None:
    result = assert_secure(tmp_path, preset="ci", registry=_registry(_Quiet()))

    assert result.rules_run == ("acme.test.quiet",)


def test_what_pytest_prints_is_the_finding_and_not_this_helper(tmp_path: Path) -> None:
    """Run through a real `pytest`, because that is the only place this is visible.

    Without `__tracebackhide__`, pytest renders the whole of `assert_secure` —
    signature, docstring and all — above the finding, so the reason a build went red
    arrives after fifty lines of prose about why it might. Every unit test in this
    file passed while that was true; only running the documented example showed it.
    """
    (tmp_path / "requirements.txt").write_text("ultralytics==8.3.41\n", encoding="utf-8")
    test_file = tmp_path / "test_it.py"
    test_file.write_text(
        "from guardana.testing import assert_secure\n\n\n"
        f"def test_scan():\n    assert_secure({str(tmp_path)!r}, preset='ci')\n",
        encoding="utf-8",
    )

    run = subprocess.run(  # noqa: S603 — this interpreter, on a file this test just wrote
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(test_file)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )

    assert run.returncode != 0
    assert "guardana.supply_chain.malicious_dependency" in run.stdout
    assert "Returns the `ScanResult` on a pass" not in run.stdout


def test_a_registry_the_caller_built_is_used_exactly_as_given(tmp_path: Path) -> None:
    """A registry somebody assembled is not one this should add to behind their back.

    The profile points at a rule directory that does not exist; loading it would put
    an error in the result and make this indeterminate. It passes, which is how we
    know the caller's registry was left alone.
    """
    profile = Profile(
        name="test",
        policy=Policy(),
        rule_paths=("./no-such-rule-directory",),
        privacy=RedactionPolicy(mode=EvidenceMode.REDACTED),
    )

    assert assert_secure(tmp_path, profile=profile, registry=_registry(_Quiet()))
