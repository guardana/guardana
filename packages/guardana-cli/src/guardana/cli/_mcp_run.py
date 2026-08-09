"""Running the rule set against a live MCP server, and pinning its manifest.

Separate from `_probe_run` because almost nothing is shared: there is no model to
chat with, no canary to plant, and the interesting artefact is a list of tool
descriptions. What *is* shared is everything downstream — profiles, gates,
renderers, the reporter — which is why this is a target rather than a command of
its own.
"""

import json
import shlex
from dataclasses import dataclass, replace
from pathlib import Path

from guardana.core.profile import Profile
from guardana.core.registry import Registry
from guardana.core.report import ScanResult
from guardana.core.runner import Runner
from guardana.core.target import McpError, McpServerTarget
from guardana.rules.agent.mcp_server_manifest import pin_document

_PIN_RULE_ID = "guardana.agent.mcp_server_manifest"


@dataclass(frozen=True, slots=True)
class McpConnection:
    """How to reach the MCP server under test, and what to compare it against."""

    address: str
    allow_exec: bool = False
    pin: Path | None = None
    credential: str | None = None
    """A bearer token for the server, read from the environment and never from an argument.

    Without one, the checks that need a credential to say anything — whether a
    session authenticates on its own — report `inconclusive` and name the flag,
    rather than staying quiet about a question nobody asked.
    """


def build_mcp_target(connection: McpConnection) -> McpServerTarget:
    """Build the target, refusing to start a server unless that was asked for.

    An `http(s)://` address is a server already running. Anything else is a
    command, and running it is executing the thing under examination — the only
    place the engine ever does, so it takes an explicit flag.
    """
    if connection.address.startswith(("http://", "https://")):
        return McpServerTarget(connection.address, credential=connection.credential)
    return McpServerTarget(
        command=shlex.split(connection.address), allow_exec=connection.allow_exec
    )


def write_pin(connection: McpConnection, path: Path) -> int:
    """Write the server's current manifest as the approved one; return how many tools."""
    target = build_mcp_target(connection)
    try:
        tools = target.list_tools()
        path.write_text(
            json.dumps(pin_document(target.ref, tools), indent=2) + "\n", encoding="utf-8"
        )
    finally:
        target.close()
    return len(tools)


def run_mcp_probe(
    registry: Registry, profile: Profile, connection: McpConnection, write_to: Path | None
) -> ScanResult | None:
    """Examine the server, or write its manifest as the pin and return None.

    Writing a pin is an approval, not a check: it records the manifest as it is
    today, so producing a report in the same breath would say "clean" about
    something nobody compared to anything.
    """
    if write_to is not None:
        count = write_pin(connection, write_to)
        print(f"Wrote {count} approved tool description(s) to {write_to}")  # noqa: T201 — CLI output
        return None
    target = build_mcp_target(connection)
    profile = _with_pin(profile, connection.pin)
    try:
        return Runner(registry=registry, profile=profile).run(target)
    finally:
        target.close()


def _with_pin(profile: Profile, pin: Path | None) -> Profile:
    """Hand the pin path to the manifest rule through ordinary rule config.

    `replace` rather than a fresh `Profile`: listing the fields by hand drops any
    the type gains later, and a profile that quietly lost its path excludes would
    scan more than the operator asked it to.
    """
    if pin is None:
        return profile
    return replace(profile, rule_config={**profile.rule_config, _PIN_RULE_ID: {"pin": str(pin)}})


__all__ = ["McpConnection", "McpError", "build_mcp_target", "run_mcp_probe", "write_pin"]
