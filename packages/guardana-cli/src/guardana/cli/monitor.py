import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._errors import run_against_endpoint
from guardana.cli._evaluators import wire_config_evaluators
from guardana.cli._probe_run import Connection, run_probe
from guardana.cli._profile import resolve_profile
from guardana.cli._reporting import submit_safely
from guardana.cli._rules_loading import load_custom_rules
from guardana.core.monitor import Alert, Monitor, MonitorConfig
from guardana.core.profile import Profile
from guardana.core.registry import Registry
from guardana.report import get_renderer

_DEFAULT_INTERVAL_SECONDS = 60.0


def _print_alert(alert: Alert) -> None:
    typer.echo(f"--- ALERT (cycle {alert.cycle}): {alert.reason} ---")
    typer.echo(get_renderer("human").render(alert.result))


def _forwarding_alert_handler(reporter_url: str, source: str) -> Callable[[Alert], None]:
    """Print each alert and also forward it to the collector.

    Degrades to a warning if the collector is unreachable — a dead collector
    must not stop the monitor.
    """

    def handle(alert: Alert) -> None:
        _print_alert(alert)
        submit_safely(reporter_url, alert.result, source=source)

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
    on_alert: Callable[[Alert], None] = _print_alert,
    on_error: Callable[[int, Exception], None] = _warn_cycle_failed,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Sample `connection` on a loop, running the same probe `guardana probe` runs.

    A transient failure mid-run is logged and the loop continues; a never-reachable
    endpoint surfaces (via `run_against_endpoint`, exit 2) instead of spinning.
    """
    monitor = Monitor(
        scan=lambda: run_probe(registry, profile, connection),
        policy=profile.policy,
        config=MonitorConfig(interval_seconds=interval_seconds, max_cycles=max_cycles),
    )
    monitor.run(on_alert, on_error=on_error, sleep=sleep)


def monitor(  # noqa: PLR0913 — one typer.Option per CLI flag; this is the command's surface
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
) -> None:
    """Continuously sample a live endpoint and alert on new findings."""
    prof = resolve_profile(profile, preset)
    registry = Registry.discover()
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
    on_alert = (
        _forwarding_alert_handler(reporter, source=f"{url}#{model}") if reporter else _print_alert
    )

    run_against_endpoint(
        url,
        lambda: run_monitor(
            registry,
            prof,
            connection,
            interval_seconds=interval,
            max_cycles=max_cycles,
            on_alert=on_alert,
        ),
    )
