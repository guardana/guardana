"""Running the rule set against a live MCP server, and pinning its manifest.

Separate from `_probe_run` because almost nothing is shared: there is no model to
chat with, no canary to plant, and the interesting artefact is a list of tool
descriptions. What *is* shared is everything downstream — profiles, gates,
renderers, the reporter — which is why this is a target rather than a command of
its own.
"""

import json
import os
import shlex
from dataclasses import dataclass, replace
from pathlib import Path

import typer
from guardana.cli._run_meta import ProbeOutcome, target_identity
from guardana.core.profile import Profile
from guardana.core.registry import Registry
from guardana.core.runner import DEFAULT_ENDPOINT_CONCURRENCY, Runner
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


def require_chat_endpoint(url: str | None, model: str | None) -> tuple[str, str]:
    """Return the endpoint a chat run needs, refusing when it was not named.

    `--url` and `--model` stopped being unconditionally required when `--mcp`
    arrived: a run against an MCP server has no model to name, and the documented
    incantation had become `--url unused --model unused`. A placeholder a user is
    told to type is a field nobody reads, and the next one they mistype goes
    unnoticed.

    Returns the pair rather than checking it, so the caller gets values a type
    checker can see are present. Coercing them at the point of use would turn a
    missing `--url` into the literal string "None" and send a request to it.
    """
    if url is None or model is None:
        raise typer.BadParameter(
            "name what to examine: --url and --model for a chat endpoint, or --mcp for "
            "an MCP server"
        )
    return url, model


def credential_from(variable: str | None) -> str | None:
    """Read the MCP bearer token out of the environment, refusing a name that holds nothing.

    A typo'd variable name yielded `None`, and the run then told the operator to
    "pass --mcp-token-env" — which they had. An exported-but-empty variable was
    worse: the empty string is not `None`, so the session checks treated a
    credential as present while no `Authorization` header was ever sent, and the
    report said "the server issues no session id" about a server that was simply
    refusing an anonymous caller. Both are true sentences about the wrong thing.
    """
    if variable is None:
        return None
    value = os.environ.get(variable)
    if not value:
        raise typer.BadParameter(
            f"--mcp-token-env names {variable!r}, which is unset or empty in this "
            f"environment; export it, or drop the flag and accept that the checks "
            f"needing a credential will report inconclusive"
        )
    return value


def plan_target(address: str) -> McpServerTarget:
    """Build a target for *pricing* an MCP server, which must not start one.

    An stdio server is priced by refusing: working out what it would cost means
    running it, and a command whose whole promise is "this sends nothing" cannot
    execute the thing under examination to answer. `guardana probe --mcp …
    --allow-exec` is where that intent is stated.
    """
    if not address.startswith(("http://", "https://")):
        raise typer.BadParameter(
            "pricing an stdio MCP server would mean starting it, and this command sends "
            "nothing and starts nothing. Price a streamable-HTTP server, or run "
            "`guardana probe --mcp … --allow-exec` when you mean to execute it."
        )
    return McpServerTarget(address)


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
    registry: Registry,
    profile: Profile,
    connection: McpConnection,
    write_to: Path | None,
    *,
    concurrency: int = DEFAULT_ENDPOINT_CONCURRENCY,
) -> ProbeOutcome | None:
    """Examine the server, or write its manifest as the pin and return None.

    Writing a pin is an approval, not a check: it records the manifest as it is
    today, so producing a report in the same breath would say "clean" about
    something nobody compared to anything.

    `concurrency` is taken rather than defaulted because the manifest records it
    either way: `probe --concurrency 4 --mcp …` wrote a four into the run document
    while this ran the rules one at a time, which is a saved run stating an
    execution setting the run did not have. The shared observation is bought under
    a lock, so overlapping rules cost the server no more than sequential ones.
    """
    if write_to is not None:
        count = write_pin(connection, write_to)
        print(f"Wrote {count} approved tool description(s) to {write_to}")  # noqa: T201 — CLI output
        return None
    target = build_mcp_target(connection)
    profile = _with_pin(profile, connection.pin)
    try:
        result = Runner(registry=registry, profile=profile, concurrency=concurrency).run(target)
        return ProbeOutcome(result, target_identity(target, target.ref))
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


__all__ = [
    "McpConnection",
    "McpError",
    "build_mcp_target",
    "credential_from",
    "plan_target",
    "require_chat_endpoint",
    "run_mcp_probe",
    "write_pin",
]
