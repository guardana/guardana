"""Whose failure a send ended with decides the run's outcome, and a stopped run keeps its results.

A `4xx` about one request is an error of the rule that sent it, and the run goes on. A
failure that names the target — credentials refused, a wrong address, a timeout, a rate
limit or a server error once retried, no connection, an unusable reply — stops the run
with `target_unavailable`, keeps what it graded so far, and starts no further rule. A
judge that fails is not the target's failure and still propagates.
"""

import io
import json
import threading
from collections.abc import Iterable, Mapping, Sequence
from email.message import Message
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest
from guardana.core import verify
from guardana.core.assessment import Assessment, AssessmentStatus
from guardana.core.budget import BudgetExhausted
from guardana.core.evaluator.config import JudgeUnavailableError
from guardana.core.gate import exit_code_for, gate_outcome
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile.model import FailOn, Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding, ScanResult, StopReason
from guardana.core.report.shortfall import ShortfallKind
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner, target_failures
from guardana.core.severity import Severity
from guardana.core.target import (
    AdapterConfig,
    ArtifactTarget,
    Capability,
    ChatMessage,
    EndpointError,
    EndpointTarget,
    EndpointUnreachable,
    HttpAdapterTransport,
    Target,
    TargetKind,
)
from guardana.core.target.adapter import FetchedReply
from guardana.core.target.endpoint import UrllibTransport, secrets_sent_by
from guardana.core.target.failure import FailureRemedies
from guardana.core.testing._fake_provider import FakeProvider, delayed, openai_reply
from guardana.core.verify import TargetUnavailableError, UnsupportedTargetError, Verifier

_KEY = "acme-live-0123456789abcdef"
_UNPATTERNED_KEY = "gw-live-7Q2mZp9XvR4tL8kN3bW6"
_PROFILE = Profile(name="t", policy=Policy())


def _status(code: int, body: bytes = b'{"error":"scripted"}') -> HTTPError:
    return HTTPError("http://x", code, "status", Message(), io.BytesIO(body))


class _Answers:
    """A model that answers each prompt as told: with text, or by raising."""

    def __init__(self, **by_prompt: str | Exception) -> None:
        self._by_prompt = by_prompt
        self.asked: list[str] = []
        self._lock = threading.Lock()

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """Answer the last message by its prompt."""
        prompt = messages[-1].content
        with self._lock:
            self.asked.append(prompt)
        outcome = self._by_prompt[prompt]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class _Asking(Rule):
    """Ask each prompt in turn; a reply holding `LEAK` is a finding."""

    def __init__(
        self,
        rule_id: str,
        *prompts: str,
        barrier: threading.Barrier | None = None,
        kind: TargetKind = TargetKind.ENDPOINT,
    ) -> None:
        self._prompts = prompts or (rule_id,)
        self._barrier = barrier
        self.meta = RuleMeta(
            id=rule_id,
            title=rule_id,
            severity=Severity.HIGH,
            target_kind=kind,
            taxonomy=(),
            required_capabilities=frozenset({Capability.CHAT})
            if kind is TargetKind.ENDPOINT
            else frozenset(),
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Send every prompt, reporting each reply that leaked."""
        for prompt in self._prompts:
            if self._barrier is not None:
                self._barrier.wait()
            if not isinstance(target, EndpointTarget):
                raise URLError("a local read that failed")
            reply = target.chat([ChatMessage(role="user", content=prompt)])
            if "LEAK" in reply:
                yield Finding(
                    rule_id=self.meta.id,
                    severity=Severity.HIGH,
                    title=self.meta.title,
                    taxonomy=(),
                    target_ref=target.ref,
                    evidence=Evidence(summary=f"{prompt} leaked"),
                )


class _Raising(Rule):
    """Raise what it is given, as a rule whose send met it."""

    def __init__(self, rule_id: str, error: Exception, barrier: threading.Barrier) -> None:
        self._error = error
        self._barrier = barrier
        self.meta = RuleMeta(
            id=rule_id,
            title=rule_id,
            severity=Severity.HIGH,
            target_kind=TargetKind.ENDPOINT,
            taxonomy=(),
            required_capabilities=frozenset({Capability.CHAT}),
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Wait for its peer, then fail."""
        self._barrier.wait()
        raise self._error
        yield  # pragma: no cover — keeps this a generator


def _run(transport: _Answers, *rules: Rule, concurrency: int = 1, **runner: object) -> ScanResult:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    target = EndpointTarget("http://x", "m", transport=transport)
    return Runner(
        registry=registry,
        profile=_PROFILE,
        concurrency=concurrency,
        **runner,  # type: ignore[arg-type]
    ).run(target)


def _exit(result: ScanResult) -> int:
    return exit_code_for(gate_outcome(result, _PROFILE.policy), result.stopped_by)


@pytest.mark.parametrize("code", [400, 413, 422])
def test_a_rejected_request_is_an_error_of_its_rule_and_the_run_goes_on(code: int) -> None:
    transport = _Answers(first=_status(code), second="fine", third="fine")

    result = _run(transport, _Asking("first"), _Asking("second"), _Asking("third"))

    assert result.stopped_by is None
    assert [(e.source, e.stage) for e in result.errors] == [("first", "request")]
    assert f"rejected the request (HTTP {code})" in result.errors[0].reason
    assert result.rules_run == ("second", "third")
    assert _exit(result) == 2


class _Grading(_Asking):
    """Ask each prompt in turn and record every reply as one graded case."""

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Send every prompt, recording a measured case per reply."""
        for index, prompt in enumerate(self._prompts):
            if not isinstance(target, EndpointTarget):
                return ()
            target.chat([ChatMessage(role="user", content=prompt)])
            ctx.record(
                Assessment(
                    case_id=f"case-{index}",
                    assessor="acme.test",
                    subject_ref=target.ref,
                    status=AssessmentStatus.MEASURED,
                    rule_id=self.meta.id,
                    passed=True,
                )
            )
        return ()


_LENIENT = Profile(name="t", policy=Policy(fail_on=FailOn(fail_on_error=False)))


def _ungraded(result: ScanResult) -> list[str]:
    return [g.name for g in result.coverage_shortfall if g.kind is ShortfallKind.UNGRADED_CASES]


def test_a_rule_whose_request_was_refused_graded_nothing_whatever_fail_on_error() -> None:
    transport = _Answers(guarded=_status(400), second="fine")
    registry = Registry()
    registry.register_rule(_Grading("guarded"))
    registry.register_rule(_Grading("second"))

    result = Runner(registry=registry, profile=_LENIENT).run(
        EndpointTarget("http://x", "m", transport=transport)
    )

    assert [(e.source, e.stage) for e in result.errors] == [("guarded", "request")]
    assert _ungraded(result) == ["guarded"]
    assert [a.rule_id for a in result.assessments] == ["second"]
    assert exit_code_for(gate_outcome(result, _LENIENT.policy), result.stopped_by) == 2


def test_a_rule_that_graded_a_case_before_a_refused_request_is_not_short_without_a_floor() -> None:
    transport = _Answers(early="fine", late=_status(400))
    registry = Registry()
    registry.register_rule(_Grading("half", "early", "late"))

    result = Runner(registry=registry, profile=_LENIENT).run(
        EndpointTarget("http://x", "m", transport=transport)
    )

    assert _ungraded(result) == []
    assert len(result.assessments) == 1


@pytest.mark.parametrize(
    "error",
    [
        _status(401),
        _status(403),
        _status(404),
        _status(407),
        _status(408),
        _status(425),
        _status(429),
        _status(500),
        _status(503),
        URLError("connection refused"),
        EndpointUnreachable("http://x#m did not answer within 30 seconds"),
        EndpointError("non-JSON response from http://x#m: b'<html>'"),
    ],
    ids=[
        "401",
        "403",
        "404",
        "407",
        "408",
        "425",
        "429",
        "500",
        "503",
        "no-connection",
        "timeout",
        "unusable-reply",
    ],
)
def test_a_target_failure_stops_the_run_and_no_further_rule_sends(error: Exception) -> None:
    transport = _Answers(first="fine", second=error, third="fine")

    result = _run(transport, _Asking("first"), _Asking("second"), _Asking("third"))

    assert result.stopped_by is StopReason.TARGET_UNAVAILABLE
    assert [(e.source, e.stage) for e in result.errors] == [("second", "target")]
    assert result.rules_run == ("first",)
    assert transport.asked == ["first", "second"]
    assert _exit(result) == 4


def test_what_the_run_found_before_the_target_failed_is_kept() -> None:
    transport = _Answers(early="LEAK", late="LEAK", gone=_status(503))

    result = _run(transport, _Asking("a.leaks", "early"), _Asking("b.half", "late", "gone"))

    assert result.stopped_by is StopReason.TARGET_UNAVAILABLE
    assert [f.evidence.summary for f in result.findings] == ["early leaked", "late leaked"]
    assert result.rules_run == ("a.leaks",)


def test_the_reason_names_the_status_and_quotes_the_body_within_the_run_policy() -> None:
    transport = _Answers(only=_status(503, f"maintenance for key {_KEY}".encode()))

    result = _run(transport, _Asking("only"), secrets=(_KEY,))

    assert target_failures(result) == (
        "endpoint http://x#m returned HTTP 503; its body begins: maintenance for key "
        "[redacted:credential]",
    )


def test_the_remedies_the_caller_names_reach_the_reason() -> None:
    transport = _Answers(only=_status(401))

    result = _run(
        transport, _Asking("only"), remedies=FailureRemedies(auth="set ACME_KEY", rate_limited="")
    )

    assert "set ACME_KEY" in result.errors[0].reason


def test_a_judge_that_fails_is_not_the_target_and_still_ends_the_run() -> None:
    transport = _Answers(only=JudgeUnavailableError("llm_judge", "http://judge", "down"))

    with pytest.raises(JudgeUnavailableError):
        _run(transport, _Asking("only"))


def test_a_failure_outside_an_endpoint_stays_an_error_of_the_rule(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("nothing", encoding="utf-8")
    registry = Registry()
    registry.register_rule(_Asking("local", kind=TargetKind.ARTIFACT))

    result = Runner(registry=registry, profile=_PROFILE).run(ArtifactTarget(tmp_path))

    assert result.stopped_by is None
    assert [(e.source, e.stage) for e in result.errors] == [("local", "run")]


def test_every_rule_in_flight_when_the_target_failed_records_its_own_error() -> None:
    both = threading.Barrier(2, timeout=5)
    transport = _Answers(a=_status(503), b=_status(502), c="fine", d="fine")

    result = _run(
        transport,
        _Asking("a", barrier=both),
        _Asking("b", barrier=both),
        _Asking("c"),
        _Asking("d"),
        concurrency=2,
    )

    assert result.stopped_by is StopReason.TARGET_UNAVAILABLE
    assert [(e.source, e.stage) for e in result.errors] == [("a", "target"), ("b", "target")]
    assert result.rules_run == ()
    assert sorted(transport.asked) == ["a", "b"]


@pytest.mark.parametrize("target_first", [True, False], ids=["target-first", "budget-first"])
def test_the_target_stop_outranks_a_budget_stop_in_the_same_run(target_first: bool) -> None:
    both = threading.Barrier(2, timeout=5)
    stops: list[Rule] = [
        _Raising("a.target", _status(503), both),
        _Raising("b.budget", BudgetExhausted("max_requests reached"), both),
    ]

    result = _run(_Answers(), *(stops if target_first else reversed(stops)), concurrency=2)

    assert result.stopped_by is StopReason.TARGET_UNAVAILABLE
    assert [e.source for e in result.errors] == ["a.target"]


def test_a_slow_reply_stops_the_run_as_the_target_not_answering() -> None:
    with FakeProvider(openai_reply("fine"), delayed(openai_reply("late"), 5.0)) as provider:
        registry = Registry()
        registry.register_rule(_Asking("a.fast"))
        registry.register_rule(_Asking("b.slow"))
        target = EndpointTarget(provider.url, "m", transport=UrllibTransport(timeout=0.2))

        result = Runner(registry=registry, profile=_PROFILE).run(target)

    assert result.stopped_by is StopReason.TARGET_UNAVAILABLE
    assert result.rules_run == ("a.fast",)
    assert target_failures(result) == (f"{target.ref} did not answer within 0.2 seconds",)


class _EchoesKey:
    """An application that refuses every request with `status`, quoting the key it was sent."""

    def __init__(self, status: int) -> None:
        self._status = status

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """Refuse, echoing the key."""
        raise _status(self._status, f'{{"error":"bad body for key {api_key}"}}'.encode())


def _keyed(code: int) -> EndpointTarget:
    return EndpointTarget("http://x", "m", api_key=_UNPATTERNED_KEY, transport=_EchoesKey(code))


@pytest.mark.parametrize("code", [400, 503])
def test_a_key_the_endpoint_sends_is_withheld_though_the_caller_named_none(code: int) -> None:
    registry = Registry()
    registry.register_rule(_Asking("only"))

    result = Runner(registry=registry, profile=_PROFILE).run(_keyed(code))

    assert [e.source for e in result.errors] == ["only"]
    assert _UNPATTERNED_KEY not in result.errors[0].reason
    assert "bad body for key [redacted:credential]" in result.errors[0].reason


@pytest.mark.parametrize("code", [400, 503])
def test_the_python_api_never_saves_or_says_a_key_the_target_sent(code: int) -> None:
    registry = Registry()
    registry.register_rule(_Asking("only"))
    verifier = Verifier(trust=PluginTrust(mode=PluginMode.BUILTINS), registry=registry)

    verification = verifier.run(_keyed(code))

    assert verification.result.errors
    assert _UNPATTERNED_KEY not in json.dumps(verification.document())
    assert not any(_UNPATTERNED_KEY in message for message in verification.stop_messages)


def test_the_header_values_an_adapter_sends_are_withheld_from_the_reason() -> None:
    gateway = "gw-tok-Hs8mQ2vX9pL4kR7n"
    bearer = "gw-brr-Zt5cW1yN8bD3fJ6q"

    def echoes(url: str, data: bytes, headers: Mapping[str, str]) -> FetchedReply:
        return FetchedReply(400, f"refused {gateway} and {bearer}".encode())

    adapter = HttpAdapterTransport(
        AdapterConfig(
            url="http://x/chat",
            body={"message": "{{prompt}}"},
            response_path="reply",
            headers={"X-Gateway-Token": gateway, "Authorization": f"Bearer {bearer}"},
        ),
        fetch=echoes,
    )
    registry = Registry()
    registry.register_rule(_Asking("only"))

    result = Runner(registry=registry, profile=_PROFILE).run(
        EndpointTarget("http://x", "m", transport=adapter)
    )

    reason = result.errors[0].reason
    assert gateway not in reason
    assert bearer not in reason
    assert "refused [redacted:credential] and [redacted:credential]" in reason


def test_a_failure_of_any_length_is_saved_cut_to_the_reason_limit() -> None:
    huge = EndpointError(f"unexpected response from http://x#m: {'A' * 60_000}")

    result = _run(_Answers(only=huge), _Asking("only"))

    assert result.stopped_by is StopReason.TARGET_UNAVAILABLE
    (said,) = target_failures(result)
    assert len(said) <= 500
    assert said.startswith("could not reach endpoint http://x#m: unexpected response")
    assert said.endswith("characters]")


@pytest.mark.parametrize(
    "error",
    [
        URLError(f"refused key {_UNPATTERNED_KEY} {'A' * 60_000}"),
        EndpointError(f"unusable reply for key {_UNPATTERNED_KEY} {'B' * 60_000}"),
    ],
    ids=["no-connection", "unusable-reply"],
)
def test_a_target_the_python_api_could_not_reach_is_said_without_its_key_and_bounded(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def failing(*args: object, **kwargs: object) -> object:
        raise error

    monkeypatch.setattr(verify, "run_target_probe", failing)
    verifier = Verifier(trust=PluginTrust(mode=PluginMode.BUILTINS), registry=Registry())

    with pytest.raises(TargetUnavailableError) as raised:
        verifier.run(_keyed(400))

    said = str(raised.value)
    assert _UNPATTERNED_KEY not in said
    assert "[redacted:credential]" in said
    assert len(said) <= 500
    assert said.startswith("could not reach endpoint http://x")


class _DeclaresBadly(_EchoesKey):
    """A plugin transport that refuses as `_EchoesKey` does and declares what it sends badly."""

    def __init__(self, status: int, declared: object) -> None:
        super().__init__(status)
        self._declared = declared

    def sent_secrets(self) -> tuple[str, ...]:
        """Return the declaration as given, or raise it."""
        if isinstance(self._declared, Exception):
            raise self._declared
        return self._declared  # type: ignore[return-value]


def test_a_declaration_holding_other_than_text_keeps_its_text_and_the_run_goes_on() -> None:
    registry = Registry()
    registry.register_rule(_Asking("only"))
    transport = _DeclaresBadly(400, (_UNPATTERNED_KEY, 42, None))

    result = Runner(registry=registry, profile=_PROFILE).run(
        EndpointTarget("http://x", "m", api_key=_UNPATTERNED_KEY, transport=transport)
    )

    assert "bad body for key [redacted:credential]" in result.errors[0].reason


@pytest.mark.parametrize(
    "declared",
    [(_UNPATTERNED_KEY.encode(),), _UNPATTERNED_KEY.encode()],
    ids=["bytes-item", "bytes-whole"],
)
def test_a_key_declared_as_bytes_is_withheld_as_its_text(declared: object) -> None:
    assert secrets_sent_by(_DeclaresBadly(400, declared)) == (_UNPATTERNED_KEY,)


def test_a_key_declared_as_undecodable_bytes_is_still_withheld() -> None:
    declared = (b"gw-\xffkey",)

    assert secrets_sent_by(_DeclaresBadly(400, declared)) == ("gw-\ufffdkey",)


def test_a_declaration_that_raises_gives_the_status_and_size_and_no_body() -> None:
    registry = Registry()
    registry.register_rule(_Asking("only"))
    transport = _DeclaresBadly(400, RuntimeError(f"cannot list {_UNPATTERNED_KEY}"))

    result = Runner(registry=registry, profile=_PROFILE).run(
        EndpointTarget("http://x", "m", api_key=_UNPATTERNED_KEY, transport=transport)
    )

    (error,) = result.errors
    assert error.stage == "request"
    assert error.reason == (
        "endpoint http://x#m rejected the request (HTTP 400); its body (57 bytes) is not "
        "shown under evidence mode metadata_only"
    )


def test_the_python_api_refuses_a_target_that_cannot_say_what_it_sends_before_sending() -> None:
    registry = Registry()
    registry.register_rule(_Asking("only"))
    target = EndpointTarget(
        "http://x", "m", transport=_DeclaresBadly(400, RuntimeError("no declaration"))
    )

    with pytest.raises(UnsupportedTargetError, match="could not say which values it sends"):
        Verifier(trust=PluginTrust(mode=PluginMode.BUILTINS), registry=registry).run(target)
    assert target.usage().requests == 0


class _RaisingOutside(Rule):
    """Raise `error` from a rule that examines an artifact, not an endpoint."""

    def __init__(self, error: Exception) -> None:
        self._error = error
        self.meta = RuleMeta(
            id="outside",
            title="outside",
            severity=Severity.HIGH,
            target_kind=TargetKind.ARTIFACT,
            taxonomy=(),
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Fail with the error status."""
        raise self._error
        yield  # pragma: no cover — keeps this a generator


@pytest.mark.parametrize("code", [400, 401, 503])
def test_an_error_status_the_endpoint_answered_is_closed_once_the_run_records_it(
    code: int,
) -> None:
    error = _status(code)

    result = _run(_Answers(only=error), _Asking("only"))

    assert [e.source for e in result.errors] == ["only"]
    assert error.fp.closed


def test_an_error_status_outside_an_endpoint_is_closed_once_the_run_records_it(
    tmp_path: Path,
) -> None:
    error = _status(502)
    registry = Registry()
    registry.register_rule(_RaisingOutside(error))

    result = Runner(registry=registry, profile=_PROFILE).run(ArtifactTarget(tmp_path))

    assert [(e.source, e.stage) for e in result.errors] == [("outside", "run")]
    assert error.fp.closed
