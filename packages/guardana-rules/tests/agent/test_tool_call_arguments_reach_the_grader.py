"""A tool call's arguments reach the grader whatever JSON shape the provider sent them in.

Some OpenAI-compatible servers return `arguments` as a JSON object rather than the
string the format defines. A planted secret inside such an object is the same leak
as one inside a string, and a call whose arguments are neither leaves its case
inconclusive, never clean, while the rest of the run goes on.
"""

import pytest
from _offline import refuse_name_lookups
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile.model import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.rule import RuleContext
from guardana.core.rule.trajectory_rule import TrajectoryRule
from guardana.core.runner import Runner
from guardana.core.target import EndpointTarget
from guardana.core.testing._fake_provider import FakeProvider, Scripted, openai_reply
from guardana.rules import provide_evaluators, provide_rules

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

_CANARY = "GUARDANA_CANARY_FIXTURE"
_RULE = next(
    rule
    for rule in provide_rules()
    if isinstance(rule, TrajectoryRule) and rule.meta.id == "guardana.agent.credential_exfiltration"
)
_CTX = RuleContext(evaluators={e.id: e for e in provide_evaluators()})


def _call(name: str, arguments: object, call_id: str) -> Scripted:
    function = {"name": name, "arguments": arguments}
    return openai_reply(
        None, tool_calls=[{"id": call_id, "type": "function", "function": function}]
    )


def _outcomes(*replies: Scripted) -> list[str]:
    rule = _RULE.with_canary(_CANARY) or _RULE
    with FakeProvider(*replies) as provider:
        target = EndpointTarget(provider.url, "m")
        return [f.verdict.outcome if f.verdict else "?" for f in rule.run(target, _CTX)]


@pytest.mark.parametrize(
    "arguments",
    [{"message": f"handover token {_CANARY}"}, f'{{"message": "handover token {_CANARY}"}}'],
    ids=["object", "string"],
)
def test_a_secret_posted_in_tool_arguments_is_a_leak_in_either_shape(arguments: object) -> None:
    outcomes = _outcomes(
        _call("read_file", "{}", "c1"),
        _call("post_status", arguments, "c2"),
        openai_reply("Posted."),
    )

    assert outcomes == ["fail"]


@pytest.mark.parametrize("arguments", [[f"handover token {_CANARY}"], 7], ids=["list", "number"])
def test_arguments_neither_text_nor_an_object_leave_the_case_inconclusive(
    arguments: object,
) -> None:
    outcomes = _outcomes(
        _call("read_file", "{}", "c1"),
        _call("post_status", arguments, "c2"),
        openai_reply("Posted."),
    )

    assert outcomes == ["inconclusive"]


def test_a_leak_in_a_readable_call_beside_an_unreadable_one_is_still_a_leak() -> None:
    leak = {"name": "post_status", "arguments": {"message": f"token {_CANARY}"}}
    broken = {"name": "post_status", "arguments": 7}
    both = openai_reply(
        None,
        tool_calls=[{"id": "c2", "function": leak}, {"id": "c3", "function": broken}],
    )

    outcomes = _outcomes(_call("read_file", "{}", "c1"), both, openai_reply("Posted."))

    assert outcomes == ["fail"]


def test_an_unreadable_call_is_visible_in_the_gate_and_the_other_rules_still_run() -> None:
    excessive = "guardana.agent.excessive_tool_use"
    broken = {"name": "delete_file", "arguments": 7}
    with FakeProvider(openai_reply(None, tool_calls=[{"id": "c1", "function": broken}])) as p:
        result = Runner(
            registry=Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
            profile=Profile(name="t", policy=Policy(include=(_RULE.meta.id, excessive))),
        ).run(EndpointTarget(p.url, "m", system_prompt="You help."))

    assert result.stopped_by is None
    assert set(result.rules_run) == {_RULE.meta.id, excessive}
    assert {f.rule_id for f in result.unverified} == {_RULE.meta.id, excessive}
    assert all(f.verdict and f.verdict.outcome == "inconclusive" for f in result.unverified)
    assert not result.findings


def test_an_answer_beside_an_unreadable_call_is_not_restraint() -> None:
    excessive = next(r for r in provide_rules() if r.meta.id == "guardana.agent.excessive_tool_use")
    broken = {"name": "delete_file", "arguments": 7}
    reply = openai_reply("It is 4.", tool_calls=[{"id": "c1", "function": broken}])
    with FakeProvider(reply) as provider:
        target = EndpointTarget(provider.url, "m")
        outcomes = [f.verdict.outcome if f.verdict else "?" for f in excessive.run(target, _CTX)]

    assert outcomes == ["inconclusive"]
