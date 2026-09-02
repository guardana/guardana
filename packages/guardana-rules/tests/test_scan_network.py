"""Every shipped artifact rule reads local files and touches no network, ever.

The sibling of `test_scan_cost`, for the safety property a cost declaration
depends on. `Rule.estimated_requests` no longer defaults to `0` for the
`artifact` target kind in `guardana-core` — that claim was too broad, because it
covered a third-party rule the engine has never read (see that property's
docstring in `guardana.core.rule.base`). What replaced it is a promise this
package makes about its *own* rules: `guardana.rules._base.ArtifactRule`
declares the zero, and this is what measures it. Every rule that inherits it
runs here, once, with outbound connections blocked at the socket layer, so a
rule that ever opens one fails loudly and by name — the point is a measurement,
not a grep for `socket`/`urllib`/`httpx` that a renamed import would slip past.
"""

import pickle
import socket
from pathlib import Path

import pytest
from guardana.core.rule import Rule, RuleContext
from guardana.core.target import ArtifactTarget, TargetKind
from guardana.rules import provide_evaluators, provide_rules

_CTX = RuleContext(evaluators={e.id: e for e in provide_evaluators()})

# Deliberately not a valid instance of any container format: every reader this
# tree exercises (GGUF, ONNX/protobuf, safetensors, HDF5, a `.keras` zip) already
# has its own fixture proving garbage bytes turn into a `FormatError` finding or
# an `unscanned` lead rather than an exception — see `onnx_graph.py`,
# `chat_template.py`, `hidden_instructions.py`, `model_format.py`, and
# `keras_lambda.py`. This tree only has to be read, not be well-formed.
_NOT_A_REAL_CONTAINER = b"not a valid model container, on purpose \x00\x01\x02\xff"


class _NetworkAttemptedError(Exception):
    """Raised in place of a real connection, so the offending rule is caught red-handed."""


def _blocked_connect(self: socket.socket, address: object) -> None:
    raise _NetworkAttemptedError(f"socket connect() to {address!r}")


def _artifact_rules() -> list[Rule]:
    return [r for r in provide_rules() if r.meta.target_kind is TargetKind.ARTIFACT]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A small tree with one file per shape a shipped artifact rule reads.

    One file per extension the 19 built-in artifact rules scan for, so each
    rule's real body runs against something that matches — not just its
    `isinstance`/`iter_files` guard on an empty tree, which would let a rule
    that only makes its network call *inside* the per-file loop pass unmeasured.
    """
    # Inert fixture text written to disk, never imported or executed: `verify=False`
    # and `os.system` are what `insecure_transport` and `code_execution` scan for,
    # the same non-executed strings `test_scan_cost.py`'s `_MODULE` fixture uses.
    (tmp_path / "model.py").write_text(
        "import os\n"
        "import requests\n"
        "from datasets import GeneratorBasedBuilder\n"
        "\n"
        "class Loader(GeneratorBasedBuilder):\n"
        "    pass\n"
        "\n"
        "def go(url):\n"
        "    requests.get(url, verify=False)\n"
        "    os.system('echo hi')\n"
        "    load_dataset('some/dataset')\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "model_card.md").write_text("# Model\n\nA card.\n", encoding="utf-8")
    (tmp_path / "tokenizer_config.json").write_text(
        '{"chat_template": "{{ messages }}"}', encoding="utf-8"
    )
    (tmp_path / "mcp_manifest.json").write_text(
        '{"tools": [{"name": "read_file", "description": "reads a file from disk"}]}',
        encoding="utf-8",
    )
    (tmp_path / "chat_template.jinja").write_text("{{ messages }}", encoding="utf-8")
    (tmp_path / "notebook.ipynb").write_text(
        '{"cells": [{"cell_type": "code", "source": "print(1)"}]}', encoding="utf-8"
    )
    (tmp_path / "export.pmml").write_text("<root></root>", encoding="utf-8")
    (tmp_path / "weights.pkl").write_bytes(pickle.dumps([1, 2, 3]))
    for name in ("model.onnx", "graph.pb", "legacy.h5", "legacy.keras", "tensors.safetensors"):
        (tmp_path / name).write_bytes(_NOT_A_REAL_CONTAINER)
    (tmp_path / "weights.gguf").write_bytes(_NOT_A_REAL_CONTAINER)
    return tmp_path


def test_no_shipped_artifact_rule_touches_the_network(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = _artifact_rules()
    assert rules, "no artifact rules are discoverable, so this gate would measure nothing"
    monkeypatch.setattr(socket.socket, "connect", _blocked_connect)
    target = ArtifactTarget(repo)
    for rule in rules:
        try:
            list(rule.run(target, _CTX))
        except _NetworkAttemptedError as exc:
            pytest.fail(f"{rule.meta.id} opened a network connection: {exc}")


def test_every_shipped_artifact_rule_declares_zero_requests() -> None:
    # The declaration `guardana plan` reports has to match what the test above
    # just measured, or the two could drift apart silently.
    undeclared = [r.meta.id for r in _artifact_rules() if r.estimated_requests != 0]
    assert not undeclared, (
        f"these shipped artifact rules do not declare zero requests: {undeclared}"
    )
