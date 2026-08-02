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

**A run manifest** stands in for the circumstances of a run, so a test about what
a renderer emits does not have to invent a clock, a run id and a tool version:

    from guardana.core.testing import manifest_for

    document = JsonRenderer(manifest_for(result)).render(result)
"""

from guardana.core.testing.artifacts import build_gguf, build_onnx, build_safetensors
from guardana.core.testing.manifests import FIXED_RUN_TIME, manifest_for
from guardana.core.testing.transports import (
    EchoingTransport,
    FailingTransport,
    GullibleAgentTransport,
    RefusingTransport,
    ScriptedTransport,
    ToolCallingScriptedTransport,
)

__all__ = [
    "FIXED_RUN_TIME",
    "EchoingTransport",
    "FailingTransport",
    "GullibleAgentTransport",
    "RefusingTransport",
    "ScriptedTransport",
    "ToolCallingScriptedTransport",
    "build_gguf",
    "build_onnx",
    "build_safetensors",
    "manifest_for",
]
