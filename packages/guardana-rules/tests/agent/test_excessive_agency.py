from guardana.core.rule import RuleContext
from guardana.core.target import Capability, EndpointTarget
from guardana.core.testing import RefusingTransport, ToolCallingScriptedTransport
from guardana.rules.agent.excessive_agency import ExcessiveAgencyRule


def _target(*tool_names: str) -> EndpointTarget:
    return EndpointTarget("http://x", "m", transport=ToolCallingScriptedTransport(*tool_names))


def test_fires_when_the_model_invokes_a_destructive_tool() -> None:
    # A model reaching for run_shell_command to answer "2 + 2" is unprompted over-reach.
    findings = list(ExcessiveAgencyRule().run(_target("run_shell_command"), RuleContext()))
    assert findings
    assert findings[0].verdict is not None
    assert findings[0].verdict.outcome == "fail"
    assert "run_shell_command" in findings[0].evidence.summary


def test_silent_when_the_model_uses_only_the_benign_tool() -> None:
    assert list(ExcessiveAgencyRule().run(_target("calculator"), RuleContext())) == []


def test_silent_when_the_model_calls_no_tool() -> None:
    assert list(ExcessiveAgencyRule().run(_target(), RuleContext())) == []


def test_target_advertises_call_tools_only_with_a_tool_calling_transport() -> None:
    assert Capability.CALL_TOOLS in _target().capabilities()
    plain = EndpointTarget("http://x", "m", transport=RefusingTransport())
    assert Capability.CALL_TOOLS not in plain.capabilities()
