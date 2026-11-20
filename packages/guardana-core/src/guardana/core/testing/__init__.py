"""Test doubles for writing rule tests without a network or a hand-crafted binary.

Two families, one purpose: a rule fixture (a positive *and* a negative sample) is
required for every rule Guardana ships, and the same bar applies to plugins.

**Transports** stand in for a live model, so a dynamic rule can be graded
end-to-end against a scripted one:

    from guardana.core.target import EndpointTarget
    from guardana.core.testing import RefusingTransport, ScriptedTransport

    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("Sure! Here goes..."))
    assert list(MyRule().run(target, RuleContext()))          # positive: it fires

    target = EndpointTarget("http://x", "m", transport=RefusingTransport())
    assert not list(MyRule().run(target, RuleContext()))      # negative: it stays silent

**Artifact builders** stand in for a model file, so a static rule can be driven
against a crafted artifact without checking a malicious binary into the repo:

    from guardana.core.testing import build_gguf

    (tmp_path / "m.gguf").write_bytes(build_gguf({"tokenizer.chat_template": payload}))

**Fake credentials** are assembled at run time rather than written down, so a test
about redaction does not put a secret-shaped literal in the repository:

    from guardana.core.testing import fake_aws_key

    evidence = Evidence(summary=f"the model replied with {fake_aws_key()}")

**A scripted agent run** stands in for a model with tools, so an agentic check can
be driven against a model that misuses one — and one that does not — without
either being real:

    from guardana.core.target.endpoint import ToolCall, ToolCallReply
    from guardana.core.testing import ScriptedAgentTransport

    obeys = ScriptedAgentTransport([
        ToolCallReply(text=None, tool_calls=(ToolCall("read_file", "{}", "c1"),)),
        ToolCallReply(text=None, tool_calls=(ToolCall("send_email", '{"to": "x"}', "c2"),)),
    ])

**A scripted access route** stands in for a chat route asked whether it answers a caller
presenting no credential, so the check can be driven against a route that refuses and one
that answers anybody:

    from guardana.core.target import AccessAnswer, AccessReply
    from guardana.core.testing import ScriptedAccessTransport

    refuses = ScriptedAccessTransport(AccessReply(AccessAnswer.REFUSED, 401, "refused"))
    target = EndpointTarget("http://x", "m", api_key="k", transport=refuses,
                            inference_access_check=True)

**A scripted MCP server** stands in for a live one, so a rule about how a server
authorizes a caller can be driven against a server that does — and one that does
not — without either being real:

    from guardana.core.target import McpServerTarget
    from guardana.core.testing import ScriptedMcpServer

    open_to_anyone = ScriptedMcpServer(url, tools=[{"name": "read", "description": "..."}])
    target = McpServerTarget(url, sender=open_to_anyone, discovery_sender=open_to_anyone)
    assert list(MyRule().run(target, RuleContext()))

**A scripted A2A agent** stands in for a live one, so a rule about whom an agent answers
can be driven against an agent that tells its callers apart — and one that does not:

    from guardana.core.target import A2aAgentTarget
    from guardana.core.testing import ScriptedA2aAgent

    shared = ScriptedA2aAgent(url, callers={"a": "alice", "b": "bob"},
                              tasks={"alice": ["t-1"]}, owner_bound=False)
    target = A2aAgentTarget(url, credential="a", other_credential="b", sender=shared)

**A seeded application** stands in for a team's own retrieval pipeline over a fixtures
file, so the tenant and poisoned-document checks can be driven against a filter that
holds — and one that leaks — without either being real:

    from guardana.core.testing import SeededApplication, seeded_target

    leaky = seeded_target(fixtures, SeededApplication(fixtures, leaking={"documents"}))

**A run manifest** stands in for the circumstances of a run, so a test about what
a renderer emits does not have to invent a clock, a run id and a tool version:

    from guardana.core.testing import manifest_for

    document = JsonRenderer(manifest_for(result)).render(result)

**Sample runs and a receiver** stand in for the runs and the destinations an installed
output meets, so a format or a reporter is checked against a stopped and an empty run,
and against a receiver that accepts, one that refuses and one that does not answer:

    from guardana.core.testing import receiver, sample_verifications

    with receiver() as served:
        for run in sample_verifications():
            deliver_to(served.accepting, run)
"""

from guardana.core.testing.a2a import ScriptedA2aAgent
from guardana.core.testing.artifacts import (
    build_gguf,
    build_onnx,
    build_safetensors,
    files_target,
)
from guardana.core.testing.manifests import FIXED_RUN_TIME, manifest_for
from guardana.core.testing.mcp import ScriptedMcpServer
from guardana.core.testing.receiver import ReceivedRequest, Receiver, receiver
from guardana.core.testing.samples import sample_verifications
from guardana.core.testing.secrets import (
    fake_aws_key,
    fake_github_pat,
    fake_jwt,
    fake_llm_key,
    fake_secrets,
)
from guardana.core.testing.seeded import SeededApplication, seeded_target
from guardana.core.testing.transports import (
    EchoingTransport,
    FailingTransport,
    GullibleAgentTransport,
    RefusingTransport,
    ScriptedAccessTransport,
    ScriptedAgentTransport,
    ScriptedTransport,
    ScriptExhaustedError,
    ToolCallingScriptedTransport,
)

__all__ = [
    "FIXED_RUN_TIME",
    "EchoingTransport",
    "FailingTransport",
    "GullibleAgentTransport",
    "ReceivedRequest",
    "Receiver",
    "RefusingTransport",
    "ScriptExhaustedError",
    "ScriptedA2aAgent",
    "ScriptedAccessTransport",
    "ScriptedAgentTransport",
    "ScriptedMcpServer",
    "ScriptedTransport",
    "SeededApplication",
    "ToolCallingScriptedTransport",
    "build_gguf",
    "build_onnx",
    "build_safetensors",
    "fake_aws_key",
    "fake_github_pat",
    "fake_jwt",
    "fake_llm_key",
    "fake_secrets",
    "files_target",
    "manifest_for",
    "receiver",
    "sample_verifications",
    "seeded_target",
]
