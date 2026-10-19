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
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.error import HTTPError

import typer
from guardana.cli._atomic import write_whole
from guardana.cli._errors import EndpointFlag, remedies_for
from guardana.cli._evaluators import judge_endpoint
from guardana.cli.exit_codes import ExitCode
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.calibration.store import RecordedCalibration
from guardana.core.manifest import DeploymentRef, RunSource
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import Profile
from guardana.core.profile.digest import profile_digest
from guardana.core.redaction import MessageQuoting, RedactionPolicy
from guardana.core.registry import Registry
from guardana.core.report import ShortfallKind
from guardana.core.runner import DEFAULT_ENDPOINT_CONCURRENCY
from guardana.core.target import (
    EndpointError,
    McpError,
    McpServerTarget,
    RegistryEntry,
    RegistryEntryError,
    private_url_parts,
)
from guardana.core.target.failure import describe_failure
from guardana.core.verify import Verification, Verifier
from guardana.rules.agent.mcp_server_manifest import pin_document

_PIN_RULE_ID = "guardana.agent.mcp_server_manifest"
_HTTP_PREFIXES = ("http://", "https://")
_REMEDIES = remedies_for((EndpointFlag.MCP_TOKEN_ENV, EndpointFlag.CONCURRENCY))
"""What a failure message advises: the token variable, and fewer requests at once."""


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
    registry_entry: RegistryEntry | None = None
    """The registry `server.json` the operator says this server is, read before anything is sent."""


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


def registry_entry_from(path: Path | None) -> RegistryEntry | None:
    """Read `--mcp-registry-entry` before anything is sent, refusing a file that is not an entry.

    A usage error rather than a run: the operator named the file, and a run without it
    would skip the comparison they asked for.
    """
    if path is None:
        return None
    try:
        return RegistryEntry.load(path)
    except RegistryEntryError as exc:
        raise typer.BadParameter(str(exc), param_hint="'--mcp-registry-entry'") from exc


def refuse_userinfo(address: str) -> None:
    """Refuse an MCP server URL that carries userinfo, before anything is sent.

    urllib fails on userinfo instead of sending it, and its error repeats the part
    of the address that holds the password. A query is legitimate here and is only
    redacted wherever the address is shown.
    """
    if address.startswith(_HTTP_PREFIXES) and "userinfo" in private_url_parts(address):
        raise typer.BadParameter(
            "the MCP server URL carries userinfo, which cannot be sent; pass a bearer "
            "token through --mcp-token-env instead",
            param_hint="'--mcp'",
        )


def refuse_an_unsplittable_command(address: str | None) -> None:
    """Exit `3` when an stdio server command does not split into words, before anything starts.

    The message carries shlex's reason and not the command, whose arguments may hold a secret.
    """
    if address is None or address.startswith(_HTTP_PREFIXES):
        return
    try:
        shlex.split(address)
    except ValueError as exc:
        typer.echo(
            f"error: the --mcp command cannot be split into a program and its arguments: {exc}",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc


def plan_target(address: str, registry_entry: RegistryEntry | None = None) -> McpServerTarget:
    """Build a target for *pricing* an MCP server, which must not start one.

    An stdio server is priced by refusing: working out what it would cost means
    running it, and a command whose whole promise is "this sends nothing" cannot
    execute the thing under examination to answer. `guardana probe --mcp …
    --allow-exec` is where that intent is stated.
    """
    if not address.startswith(_HTTP_PREFIXES):
        raise typer.BadParameter(
            "pricing an stdio MCP server would mean starting it, and this command sends "
            "nothing and starts nothing. Price a streamable-HTTP server, or run "
            "`guardana probe --mcp … --allow-exec` when you mean to execute it."
        )
    refuse_userinfo(address)
    return McpServerTarget(address, registry_entry=registry_entry)


def files_named_by(address: str | None) -> tuple[Path, ...]:
    """Return the existing files an stdio server command names, which the command reads or runs.

    An `http(s)://` address names none, and so does a command that does not split. An
    argument that is not an existing file is not an input.
    """
    if address is None or address.startswith(_HTTP_PREFIXES):
        return ()
    try:
        words = shlex.split(address)
    except ValueError:
        return ()
    return tuple(Path(word) for word in words if os.path.isfile(word))  # noqa: PTH113 — never raises


def build_mcp_target(connection: McpConnection) -> McpServerTarget:
    """Build the target, refusing to start a server unless that was asked for.

    An `http(s)://` address is a server already running. Anything else is a
    command, and running it is executing the thing under examination — the only
    place the engine ever does, so it takes an explicit flag.
    """
    if connection.address.startswith(_HTTP_PREFIXES):
        return McpServerTarget(
            connection.address,
            credential=connection.credential,
            registry_entry=connection.registry_entry,
        )
    return McpServerTarget(
        command=shlex.split(connection.address),
        allow_exec=connection.allow_exec,
        registry_entry=connection.registry_entry,
    )


def started(connection: McpConnection) -> McpServerTarget:
    """Build the target, ending the command before any rule when it cannot be built.

    A command that does not run exits `4`: it has no manifest to read and no run to keep.
    A command given without `--allow-exec`, or an empty one, is the operator's
    configuration and exits `3`, having started nothing.
    """
    try:
        return build_mcp_target(connection)
    except EndpointError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.TARGET_UNAVAILABLE) from exc
    except McpError as exc:
        raise typer.BadParameter(str(exc), param_hint="'--mcp'") from exc


def write_pin(connection: McpConnection, path: Path, budgets: Budgets | None = None) -> int:
    """Write the server's current manifest as the approved one; return how many tools.

    A server that cannot be read exits `TARGET_UNAVAILABLE` with one line that withholds
    the token and the session ids sent to it, and no pin is written: an approval of a
    manifest nobody received is not an approval. Reading it within `budgets` binds as a
    probe does: a ceiling reached exits `BUDGET_EXHAUSTED`, and no pin is written. A pin
    that cannot be written exits `3` and leaves the approved pin at `path` as it was.
    """
    target = started(connection)
    try:
        if budgets is not None:
            target.apply_budgets(budgets)
        try:
            tools = target.list_tools()
        except BudgetExhausted as exc:
            typer.echo(f"error: {exc}; no pin was written", err=True)
            raise typer.Exit(code=ExitCode.BUDGET_EXHAUSTED) from exc
        except (McpError, EndpointError, HTTPError) as exc:
            quoting = MessageQuoting.of(RedactionPolicy(), target.sent_secrets())
            if isinstance(exc, McpError):
                said = f"could not read the manifest of {target.ref}: {quoting.spans(str(exc))}"
            else:
                said = describe_failure(exc, target.ref, quoting, _REMEDIES)
            typer.echo(f"error: {said}", err=True)
            raise typer.Exit(code=ExitCode.TARGET_UNAVAILABLE) from exc
        try:
            document = json.dumps(pin_document(target.ref, tools), indent=2) + "\n"
            write_whole(path, document.encode("utf-8"))
        except OSError as exc:
            typer.echo(f"error: could not write the pin to {path}: {exc}", err=True)
            raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    finally:
        target.close()
    return len(tools)


def run_mcp_probe(  # noqa: PLR0913 — a connection, a destination and the run's facts
    registry: Registry,
    profile: Profile,
    connection: McpConnection,
    write_to: Path | None,
    *,
    concurrency: int = DEFAULT_ENDPOINT_CONCURRENCY,
    calibrations: Mapping[str, RecordedCalibration] | None = None,
    source: RunSource | None = None,
    deployment: DeploymentRef | None = None,
) -> Verification | None:
    """Examine the server through the verifier, or write its manifest as the pin and return None.

    Writing a pin is an approval, not a check: it records the manifest as it is
    today, so producing a report in the same breath would say "clean" about
    something nobody compared to anything.

    `concurrency` is taken rather than defaulted by the command because the manifest
    records it either way. The server this builds is closed here, whatever the run did.

    A pin given is a comparison demanded: a run whose profile leaves the manifest rule
    out, or that does not complete it, records a coverage shortfall and cannot pass.
    """
    refuse_userinfo(connection.address)
    if write_to is not None:
        count = write_pin(connection, write_to, profile.budgets)
        print(f"Wrote {count} approved tool description(s) to {write_to}")  # noqa: T201 — CLI output
        return None
    target = started(connection)
    verifier = Verifier(
        trust=registry.trust or PluginTrust(mode=PluginMode.BUILTINS),
        profile=with_pin(profile, connection.pin),
        registry=registry,
        calibrations=calibrations,
        concurrency=concurrency,
        judge_endpoint=judge_endpoint,
        remedies=_REMEDIES,
        demanded_rules=frozenset() if connection.pin is None else frozenset({_PIN_RULE_ID}),
    )
    try:
        verification = verifier.run(target, source=source, deployment=deployment)
    finally:
        target.close()
    if connection.pin is not None:
        _say_an_unchecked_pin(connection.pin, verification)
    # The pin path is where this operator keeps an approval, not a setting of the profile,
    # so the run records the digest of the profile it was given.
    configuration = replace(
        verification.manifest.configuration, profile_digest=profile_digest(profile)
    )
    return replace(
        verification, manifest=replace(verification.manifest, configuration=configuration)
    )


def _say_an_unchecked_pin(pin: Path, verification: Verification) -> None:
    """Warn that `pin` was never compared when the manifest rule did not complete.

    A rule that ran and could not compare declines in its own words; this covers the rule
    the profile left out or the run never finished.
    """
    for gap in verification.result.coverage_shortfall:
        if gap.kind is ShortfallKind.DEMANDED_CHECK and gap.name == _PIN_RULE_ID:
            if _PIN_RULE_ID not in verification.result.rules_run:
                typer.echo(
                    f"warning: --mcp-pin {pin} was given and the pinned manifest was not "
                    f"checked: {gap.detail}",
                    err=True,
                )
            return


def with_pin(profile: Profile, pin: Path | None) -> Profile:
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
    "files_named_by",
    "plan_target",
    "refuse_an_unsplittable_command",
    "refuse_userinfo",
    "registry_entry_from",
    "require_chat_endpoint",
    "run_mcp_probe",
    "started",
    "with_pin",
    "write_pin",
]
