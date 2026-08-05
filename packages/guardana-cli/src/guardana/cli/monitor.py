import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._errors import run_against_endpoint
from guardana.cli._evaluators import wire_config_evaluators
from guardana.cli._plugins import resolve_trust
from guardana.cli._probe_run import Connection, run_probe
from guardana.cli._profile import resolve_profile
from guardana.cli._reporting import check_reporter_url, submit_safely
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli._run_meta import detect_deployment
from guardana.core.manifest import DeploymentRef
from guardana.core.monitor import Alert, Monitor, MonitorConfig
from guardana.core.profile import Profile
from guardana.core.redaction import EvidenceRedactor
from guardana.core.registry import Registry
from guardana.core.runner import DEFAULT_ENDPOINT_CONCURRENCY
from guardana.report import get_renderer

_DEFAULT_INTERVAL_SECONDS = 60.0
# Matches `probe`: a monitor cycle is the same probe, so it gets the same default
# — fast enough to finish a cycle well inside the interval, polite enough for a
# single-slot local server.
_DEFAULT_CONCURRENCY = 4


def alert_handler(
    redactor: EvidenceRedactor,
    reporter_url: str | None,
    source: str,
    deployment: DeploymentRef | None = None,
) -> Callable[[Alert], None]:
    """Print each alert under the run's privacy policy, and forward it under the same one.

    Built once with the redactor rather than reaching for a default inside, because
    that default is `full`: `monitor` used to print and submit evidence the profile
    said to strip, and it is the mode that runs unattended and ships evidence off
    the machine continuously. `scan` and `probe` redact before they emit; this is
    the third emitter and it now does the same thing at the same point.

    Forwarding degrades to a warning if the collector is unreachable — a dead
    collector must not stop the monitor.
    """

    def handle(alert: Alert) -> None:
        result = redactor.redact_result(alert.result)
        typer.echo(f"--- ALERT (cycle {alert.cycle}): {alert.reason} ---")
        typer.echo(get_renderer("human", redactor=redactor).render(result))
        if reporter_url:
            submit_safely(reporter_url, result, source=source, deployment=deployment)

    return handle


def _warn_cycle_failed(cycle: int, exc: Exception) -> None:
    typer.echo(f"warning: monitor cycle {cycle} failed, continuing: {exc}", err=True)


def run_monitor(  # noqa: PLR0913 — the test seam needs every hook injectable
    registry: Registry,
    profile: Profile,
    connection: Connection,
    *,
    interval_seconds: float = _DEFAULT_INTERVAL_SECONDS,
    max_cycles: int | None = None,
    concurrency: int = DEFAULT_ENDPOINT_CONCURRENCY,
    on_alert: Callable[[Alert], None] | None = None,
    on_error: Callable[[int, Exception], None] = _warn_cycle_failed,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Sample `connection` on a loop, running the same probe `guardana probe` runs.

    A transient failure mid-run is logged and the loop continues; a never-reachable
    endpoint surfaces (via `run_against_endpoint`, exit 2) instead of spinning.

    `on_alert` defaults to printing under *this profile's* privacy policy. It is
    resolved here rather than in the signature, because a default argument would
    have to name a redactor before the profile is known — which is how the
    unredacted default got in.
    """
    handler = (
        on_alert
        if on_alert is not None
        else alert_handler(EvidenceRedactor(profile.privacy), None, connection.url)
    )
    monitor = Monitor(
        scan=lambda: run_probe(registry, profile, connection, concurrency=concurrency),
        policy=profile.policy,
        config=MonitorConfig(interval_seconds=interval_seconds, max_cycles=max_cycles),
    )
    monitor.run(handler, on_error=on_error, sleep=sleep)


def monitor(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; this is the command's surface
    url: Annotated[str, typer.Option(help="Base URL of the OpenAI-compatible endpoint")],
    model: Annotated[str, typer.Option(help="Model name")],
    api_key_env: Annotated[
        str | None, typer.Option("--api-key-env", help="Env var holding the API key")
    ] = None,
    provider: Annotated[
        str, typer.Option(help="Endpoint wire protocol: openai|ollama|tgi")
    ] = "openai",
    system_prompt_file: Annotated[
        Path | None, typer.Option("--system-prompt-file", help="File containing a system prompt")
    ] = None,
    interval: Annotated[
        float, typer.Option(help="Seconds between sampling cycles")
    ] = _DEFAULT_INTERVAL_SECONDS,
    max_cycles: Annotated[
        int | None, typer.Option("--max-cycles", help="Stop after this many cycles")
    ] = None,
    concurrency: Annotated[
        int,
        typer.Option(min=1, help="How many rules may query the model at once, per cycle"),
    ] = _DEFAULT_CONCURRENCY,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[
        str | None, typer.Option(help="Named policy preset: ci|pre-training|monitor")
    ] = None,
    rules: Annotated[
        list[Path],
        typer.Option("--rules", help="Directory or file of custom YAML rules; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    reporter: Annotated[
        str | None, typer.Option(help="Collector URL to forward alerts to, e.g. server://URL")
    ] = None,
    ai_system: Annotated[
        str | None,
        typer.Option(
            "--ai-system",
            help="Which AI system this run verifies, e.g. support-agent. Never guessed.",
        ),
    ] = None,
    environment: Annotated[
        str | None,
        typer.Option(
            "--environment",
            help="Where it runs, e.g. production. Never guessed from a branch name.",
        ),
    ] = None,
    deployment_id: Annotated[
        str | None,
        typer.Option("--deployment-id", help="Which version of it, if you have an identifier."),
    ] = None,
    plugins: Annotated[
        str,
        typer.Option(help="Which installed plugins to load: all|builtins|allowlist|disabled"),
    ] = "all",
    allow_plugin: Annotated[
        list[str],
        typer.Option("--allow-plugin", help="Distribution to trust; repeatable, needs allowlist."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Continuously sample a live endpoint and alert on new findings."""
    check_reporter_url(reporter)
    prof = resolve_profile(profile, preset)
    registry = Registry.discover(resolve_trust(plugins, allow_plugin, no_plugins=False))
    wire_config_evaluators(registry, prof)
    load_custom_rules(registry, prof, rules)

    connection = Connection(
        url=url,
        model=model,
        api_key=os.environ.get(api_key_env) if api_key_env else None,
        provider=provider,
        system_prompt=(
            system_prompt_file.read_text(encoding="utf-8") if system_prompt_file else None
        ),
    )
    on_alert = alert_handler(
        EvidenceRedactor(prof.privacy),
        reporter,
        source=f"{url}#{model}",
        deployment=detect_deployment(ai_system, environment, deployment_id),
    )

    run_against_endpoint(
        url,
        lambda: run_monitor(
            registry,
            prof,
            connection,
            interval_seconds=interval,
            max_cycles=max_cycles,
            concurrency=concurrency,
            on_alert=on_alert,
        ),
    )
