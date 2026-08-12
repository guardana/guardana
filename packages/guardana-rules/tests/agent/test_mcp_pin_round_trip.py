"""The approved MCP manifest: written by one function, read by another, in one file.

A pin is the most consequential document in this repository per byte. Everything the
rug-pull check concludes rests on it, and the check's whole proposition is "this is
not what you approved" — so a field the writer records and the reader drops does not
weaken the verdict, it invalidates it.

`server` was exactly that field until 0.20. `pin_document` recorded which server the
manifest had been approved for and `_load_pin` threw it away, so pointing
`--mcp-pin` at another server's file — a copy-paste, a wrong path in CI, a
repository holding pins for several servers — produced a full comparison against a
manifest nobody had approved for that server. Where the tool names lined up, it
produced a clean pass.
"""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from _roundtrip import Document, unread_keys
from guardana.core.rule import RuleContext
from guardana.core.target import McpServerTarget
from guardana.rules.agent.mcp_server_manifest import (
    McpServerManifestRule,
    _load_pin,
    pin_document,
)

_SERVER = "https://93.184.215.14/mcp"
_OTHER = "https://93.184.215.15/mcp"
_DESCRIPTION = "Refund an order."


class _Server:
    """An MCP transport offering one tool with whatever description the test hands it."""

    def __init__(self, description: str = _DESCRIPTION) -> None:
        self._description = description

    def speak(self, wire: object) -> None:
        pass

    def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
        if method == "initialize":
            return {"protocolVersion": "2025-11-25"}
        return {
            "tools": [
                {
                    "name": "refund",
                    "description": self._description,
                    "inputSchema": {"type": "object", "properties": {"order": {"type": "string"}}},
                }
            ]
        }

    def close(self) -> None:
        return None


def _target(url: str = _SERVER, description: str = _DESCRIPTION) -> McpServerTarget:
    return McpServerTarget(url, transport=_Server(description))


def _pin(server: str = _SERVER) -> Document:
    document: Document = pin_document(server, _target(server).list_tools())
    return document


def _outcomes(target: McpServerTarget, pin: Path) -> list[str]:
    ctx = RuleContext(config={"pin": str(pin)})
    return [
        f.verdict.outcome if f.verdict else "finding"
        for f in McpServerManifestRule().run(target, ctx)
    ]


def test_no_key_of_a_pinned_manifest_can_be_deleted_without_the_reader_noticing(
    tmp_path: Path,
) -> None:
    """Every key the writer records has to change what the reader concludes."""

    def read(document: Document) -> object:
        path = tmp_path / "pin.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        pin = _load_pin(path)
        return (pin.version, dict(pin.tools), pin.server)

    ignored = unread_keys(_pin(), read, root="pin", refusal=ValueError)

    assert not ignored, (
        "keys the approved manifest records that the reader ignores — every verdict "
        "the rug-pull check reaches rests on this document:\n  " + "\n  ".join(ignored)
    )


def test_a_pin_approved_for_another_server_is_refused_rather_than_compared(
    tmp_path: Path,
) -> None:
    """The defect this file exists for, stated as behaviour rather than as a field.

    Two servers offering the same tool compared clean against each other's pin: a
    rug-pull check reporting "nothing changed" about a server nobody approved.
    """
    path = tmp_path / "other-server.json"
    path.write_text(json.dumps(_pin(_OTHER)), encoding="utf-8")

    assert _outcomes(_target(), path) == ["inconclusive"]


def test_a_pin_that_names_no_server_is_refused_rather_than_assumed_to_match(
    tmp_path: Path,
) -> None:
    """A hand-made pin cannot be told from another server's, so it cannot speak for one."""
    document: dict[str, Any] = dict(_pin())
    del document["server"]
    path = tmp_path / "anonymous.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    assert _outcomes(_target(), path) == ["inconclusive"]


def test_the_matching_pin_still_compares_and_still_catches_drift(tmp_path: Path) -> None:
    """The refusals above must not have turned every comparison into a decline."""
    path = tmp_path / "pin.json"
    path.write_text(json.dumps(_pin()), encoding="utf-8")

    assert _outcomes(_target(), path) == []
    assert _outcomes(_target(description="Refund an order, and email the customer list"), path) == [
        "finding"
    ]
