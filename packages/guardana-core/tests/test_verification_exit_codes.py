"""The Python facade reports a stopped run with the exit code the CLI gives it.

`Verification.exit_code` is what an embedder gates a build on. A run whose target
stopped answering returns a `Verification` exiting `4`, never the `2` or `0` its
partial counts would earn. An interrupted run returns none at all: Ctrl-C propagates.
Only a saved run that records the interruption reads back as `7`.
"""

import io
from collections.abc import Iterable
from dataclasses import replace
from email.message import Message
from pathlib import Path
from urllib.error import HTTPError

import pytest
from guardana.core.gate import GateOutcome, StopReason
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import (
    Capability,
    ChatMessage,
    EndpointTarget,
    Target,
    TargetKind,
)
from guardana.core.target.endpoint import TargetChanged
from guardana.core.testing import FailingTransport, RefusingTransport
from guardana.core.verify import Verification, Verifier, load_verification

_TRUST = PluginTrust(mode=PluginMode.BUILTINS)


class _Asking(Rule):
    """Send one prompt and report nothing; it completes only if the target answers."""

    def __init__(self, rule_id: str) -> None:
        self.meta = RuleMeta(
            id=rule_id,
            title=rule_id,
            severity=Severity.HIGH,
            target_kind=TargetKind.ENDPOINT,
            taxonomy=(),
            required_capabilities=frozenset({Capability.CHAT}),
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Ask the target once."""
        if isinstance(target, EndpointTarget):
            target.chat([ChatMessage(role="user", content="hello")])
        return ()


class _Interrupted(Rule):
    """Stand in for the operator pressing Ctrl-C while this rule runs."""

    meta = RuleMeta(
        id="acme.interrupted",
        title="interrupted",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(),
        required_capabilities=frozenset({Capability.CHAT}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Raise what Ctrl-C raises."""
        raise KeyboardInterrupt


def _verifier(*rules: Rule) -> Verifier:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    return Verifier(trust=_TRUST, registry=registry)


def _endpoint(transport: object) -> EndpointTarget:
    return EndpointTarget("http://model.invalid", "m", transport=transport)  # type: ignore[arg-type]


def _unavailable() -> HTTPError:
    return HTTPError("http://model.invalid", 503, "unavailable", Message(), io.BytesIO(b"{}"))


@pytest.mark.parametrize(
    ("error", "stop"),
    [
        (_unavailable(), StopReason.TARGET_UNAVAILABLE),
        (TargetChanged("the server dropped the agreed revision"), StopReason.TARGET_CHANGED),
    ],
    ids=["unavailable", "changed"],
)
def test_a_run_whose_target_stops_returns_a_verification_exiting_4(
    error: Exception, stop: StopReason
) -> None:
    verification = _verifier(_Asking("acme.first"), _Asking("acme.second")).run(
        _endpoint(FailingTransport(error))
    )

    assert verification.result.stopped_by is stop
    assert verification.gate is not GateOutcome.PASS
    assert verification.exit_code == 4


def test_a_run_interrupted_by_ctrl_c_returns_no_verification() -> None:
    with pytest.raises(KeyboardInterrupt):
        _verifier(_Interrupted()).run(_endpoint(RefusingTransport()))


def _interrupted(
    verification: Verification, gate: GateOutcome = GateOutcome.INDETERMINATE
) -> Verification:
    """The same run as a document that records it was interrupted, as a saved run may."""
    summary = replace(
        verification.manifest.result_summary, gate=gate, stopped_by=StopReason.INTERRUPTED
    )
    return replace(
        verification,
        result=replace(verification.result, stopped_by=StopReason.INTERRUPTED),
        manifest=replace(verification.manifest, result_summary=summary),
        gate=gate,
    )


def test_a_saved_run_that_records_an_interruption_reads_back_exiting_7(tmp_path: Path) -> None:
    completed = _verifier(_Asking("acme.only")).run(_endpoint(RefusingTransport()))
    assert completed.exit_code == 0
    saved = tmp_path / "run.json"
    _interrupted(completed).save(saved)

    loaded = load_verification(saved)

    assert loaded.result.stopped_by is StopReason.INTERRUPTED
    assert loaded.gate is GateOutcome.INDETERMINATE
    assert loaded.exit_code == 7


def test_a_stop_outranks_the_verdict_the_partial_counts_would_earn(tmp_path: Path) -> None:
    """Interrupting a run that had passed so far cannot leave it exiting `0`."""
    completed = _verifier(_Asking("acme.only")).run(_endpoint(RefusingTransport()))
    saved = tmp_path / "run.json"
    _interrupted(completed, GateOutcome.PASS).save(saved)

    loaded = load_verification(saved)

    assert loaded.gate is GateOutcome.PASS
    assert loaded.exit_code == 7
