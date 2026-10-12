import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._connection import (
    AdapterOption,
    ApiKeyEnvOption,
    ModelOption,
    ProviderOption,
    SystemPromptFileOption,
    UrlOption,
    read_system_prompt,
    resolve_flags,
)
from guardana.cli._errors import EndpointFlag, remedies_for, run_against_endpoint
from guardana.cli._evaluators import JudgeMeters, wire_config_evaluators
from guardana.cli._exit import refuse_invalid_profile, refuse_unenforceable_budget
from guardana.cli._outputs import (
    MONITOR_REFUSAL,
    refuse_installed_reporter,
    warn_without_a_reporter,
)
from guardana.cli._plugins import (
    AllowPluginOption,
    PluginsOption,
    hint_refused_plugins,
    resolve_trust,
)
from guardana.cli._probe_run import Connection, run_probe, run_target_probe
from guardana.cli._profile import PRESET_HELP, resolve_profile
from guardana.cli._reporting import check_reporter_url, submit_safely
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli._run_meta import calibrations_or_exit, detect_deployment
from guardana.cli._target_locator import resolve_target
from guardana.cli.exit_codes import ExitCode
from guardana.core.budget import BudgetExhausted
from guardana.core.manifest import DeploymentRef
from guardana.core.manifest.records import CalibrationRecord
from guardana.core.monitor import (
    Alert,
    Monitor,
    MonitorConfig,
    MonitorSummary,
    TargetStoppedError,
)
from guardana.core.profile import Profile, ProfileError
from guardana.core.redaction import (
    EvidenceMode,
    EvidenceRedactor,
    MessageQuoting,
    RedactionPolicy,
)
from guardana.core.registry import Registry
from guardana.core.report import ScanResult
from guardana.core.runner import DEFAULT_ENDPOINT_CONCURRENCY, refuse_unmatched_includes
from guardana.core.target import Target, TargetKind, display_url
from guardana.core.target.connection import ResolvedConnection
from guardana.core.target.endpoint import secrets_sent_by
from guardana.core.target.failure import describe_failure
from guardana.report import get_renderer

_DEFAULT_INTERVAL_SECONDS = 60.0
# Matches `probe`: a monitor cycle is the same probe, so it gets the same default
# — fast enough to finish a cycle well inside the interval, polite enough for a
# single-slot local server.
_DEFAULT_CONCURRENCY = 4

_REPLACED_BY_A_FAILED_DELIVERY = frozenset(
    {ExitCode.OK, ExitCode.POLICY_FAILED, ExitCode.INDETERMINATE}
)

_ACCEPTED_FLAGS = (EndpointFlag.ADAPTER, EndpointFlag.API_KEY_ENV, EndpointFlag.CONCURRENCY)
_REMEDIES = remedies_for(_ACCEPTED_FLAGS)


@dataclass(slots=True)
class AlertDeliveries:
    """Whether the profile requires each alert's delivery, and how many went unacknowledged."""

    required: bool = False
    unacknowledged: int = 0


def alert_handler(
    redactor: EvidenceRedactor,
    reporter_url: str | None,
    source: str,
    deployment: DeploymentRef | None = None,
    deliveries: AlertDeliveries | None = None,
) -> Callable[[Alert], None]:
    """Print each alert under the run's privacy policy, and forward it under the same one.

    Built once with the redactor rather than reaching for a default inside, because
    that default is `full`: `monitor` used to print and submit evidence the profile
    said to strip, and it is the mode that runs unattended and ships evidence off
    the machine continuously. `scan` and `probe` redact before they emit; this is
    the third emitter and it now does the same thing at the same point.

    A collector that does not acknowledge never stops the monitor: it is said, and when
    `deliveries` requires acknowledgement it is counted there for the watch's exit.
    """
    counted = deliveries if deliveries is not None else AlertDeliveries()

    def handle(alert: Alert) -> None:
        result = redactor.redact_result(alert.result)
        typer.echo(f"--- ALERT (cycle {alert.cycle}): {alert.reason} ---")
        typer.echo(get_renderer("human", redactor=redactor, gate=alert.gate).render(result))
        if reporter_url:
            acknowledged = submit_safely(
                reporter_url,
                result,
                source=source,
                deployment=deployment,
                required=counted.required,
            )
            if counted.required and not acknowledged:
                counted.unacknowledged += 1

    return handle


def _withholding(
    privacy: RedactionPolicy, secrets: Callable[[], Iterable[str]]
) -> EvidenceRedactor:
    """Redact under `privacy` without `secrets`; when they cannot be read, keep no text at all."""
    try:
        return EvidenceRedactor(privacy, secrets=tuple(secrets()))
    except Exception:  # a target's declaration is plugin code
        withheld = replace(privacy, mode=EvidenceMode.METADATA_ONLY, keep_exchanges=False)
        return EvidenceRedactor(withheld)


def _sent_over(reached: ResolvedConnection) -> tuple[str, ...]:
    """Return what an endpoint built from `reached` sends: its secrets and its transport's."""
    return (*reached.secret_values, *secrets_sent_by(reached.transport))


def _cycle_failure_warning(
    ref: str, privacy: RedactionPolicy, secrets: Callable[[], Iterable[str]]
) -> Callable[[int, Exception], None]:
    """Warn of a failed cycle under `privacy`, bounded, without a value `secrets` returns.

    A cycle its target stopped is said in the words the run recorded, already withheld.
    """

    def warn(cycle: int, exc: Exception) -> None:
        if isinstance(exc, TargetStoppedError):
            said = str(exc)
        else:
            quoting = MessageQuoting(_withholding(privacy, secrets))
            said = describe_failure(exc, ref, quoting, _REMEDIES)
        typer.echo(f"warning: monitor cycle {cycle} failed, continuing: {said}", err=True)

    return warn


def run_monitor(  # noqa: PLR0913 — the test seam needs every hook injectable
    registry: Registry,
    profile: Profile,
    connection: Connection,
    *,
    interval_seconds: float = _DEFAULT_INTERVAL_SECONDS,
    max_cycles: int | None = None,
    concurrency: int = DEFAULT_ENDPOINT_CONCURRENCY,
    on_alert: Callable[[Alert], None] | None = None,
    on_error: Callable[[int, Exception], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    calibrations: Mapping[str, CalibrationRecord] | None = None,
) -> MonitorSummary:
    """Sample `connection` on a loop, running the same probe `guardana probe` runs.

    A transient failure mid-run, or a cycle its target stopped, is logged and the loop
    continues; a never-reachable endpoint surfaces (via `run_against_endpoint`, exit 4)
    instead of spinning. Each cycle's result is redacted under the profile without
    what the connection sends before anything compares, prints or forwards it.

    `on_alert` defaults to printing under *this profile's* privacy policy. It is
    resolved here rather than in the signature, because a default argument would
    have to name a redactor before the profile is known — which is how the
    unredacted default got in.
    """
    shown = display_url(connection.reached.url)
    redactor = _withholding(profile.privacy, lambda: _sent_over(connection.reached))
    handler = on_alert if on_alert is not None else alert_handler(redactor, None, shown)
    warn = (
        on_error
        if on_error is not None
        else _cycle_failure_warning(shown, profile.privacy, lambda: _sent_over(connection.reached))
    )

    def scan() -> ScanResult:
        _rearm_judges(registry, profile)
        probed = run_probe(
            registry,
            profile,
            connection,
            concurrency=concurrency,
            calibrations=calibrations,
            remedies=_REMEDIES,
        )
        return redactor.redact_result(probed.result)

    monitor = Monitor(
        scan=scan,
        policy=profile.policy,
        config=MonitorConfig(interval_seconds=interval_seconds, max_cycles=max_cycles),
    )
    return monitor.run(handler, on_error=warn, sleep=sleep)


def run_target_monitor(  # noqa: PLR0913 — mirrors the tested monitor seam
    registry: Registry,
    profile: Profile,
    target_factory: Callable[[], Target],
    *,
    source: str,
    interval_seconds: float = _DEFAULT_INTERVAL_SECONDS,
    max_cycles: int | None = None,
    concurrency: int = DEFAULT_ENDPOINT_CONCURRENCY,
    on_alert: Callable[[Alert], None] | None = None,
    on_error: Callable[[int, Exception], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    calibrations: Mapping[str, CalibrationRecord] | None = None,
) -> MonitorSummary:
    """Sample a freshly built custom endpoint target on every monitor cycle.

    Each cycle's result is redacted under the profile without what that cycle's target
    declares sending; a target that cannot say keeps no text in it.
    """
    handler = (
        on_alert
        if on_alert is not None
        else alert_handler(EvidenceRedactor(profile.privacy), None, source)
    )
    built: list[Target] = []

    def sent() -> tuple[str, ...]:
        return secrets_sent_by(built[-1]) if built else ()

    warn = (
        on_error if on_error is not None else _cycle_failure_warning(source, profile.privacy, sent)
    )

    def scan() -> ScanResult:
        _rearm_judges(registry, profile)
        built[:] = [target_factory()]
        probed = run_target_probe(
            registry,
            profile,
            built[-1],
            concurrency=concurrency,
            calibrations=calibrations,
            remedies=_REMEDIES,
        )
        return _withholding(profile.privacy, sent).redact_result(probed.result)

    monitor = Monitor(
        scan=scan,
        policy=profile.policy,
        config=MonitorConfig(interval_seconds=interval_seconds, max_cycles=max_cycles),
    )
    return monitor.run(handler, on_error=warn, sleep=sleep)


def _rearm_judges(registry: Registry, profile: Profile) -> JudgeMeters:
    """Rebuild the config-built judges on fresh meters, so the budget bounds each cycle.

    A cycle's target starts a fresh bill; a judge meter kept across cycles would run dry
    after a few and stop every later cycle on a budget no single cycle spent, and would
    report each cycle's grading as the sum of every cycle before it.
    """
    return wire_config_evaluators(registry, profile, profile.budgets)


def monitor(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; this is the command's surface
    url: UrlOption = None,
    model: ModelOption = None,
    api_key_env: ApiKeyEnvOption = None,
    provider: ProviderOption = None,
    adapter: AdapterOption = None,
    system_prompt_file: SystemPromptFileOption = None,
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
    trials: Annotated[
        int | None,
        typer.Option(
            "--trials",
            min=1,
            help="Attempts per case for rules that grade a sampled reply; overrides `trials:`.",
        ),
    ] = None,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help=PRESET_HELP)] = None,
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
    plugins: PluginsOption = None,
    allow_plugin: AllowPluginOption = None,
    target: Annotated[
        str | None,
        typer.Option("--target", help="Installed endpoint target as scheme://locator."),
    ] = None,
    target_option: Annotated[
        list[str],
        typer.Option("--target-option", help="Non-secret key=value for --target; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Continuously sample a live endpoint and alert on new findings."""
    refuse_installed_reporter(reporter, MONITOR_REFUSAL)
    check_reporter_url(reporter)
    prof = resolve_profile(profile, preset)
    warn_without_a_reporter(prof.delivery_required, reporter)
    if trials is not None:
        prof = replace(prof, trials=trials)
    if prof.privacy.keep_exchanges:
        typer.echo(
            "warning: privacy.keep_exchanges is set, and monitor keeps no exchanges; "
            "`guardana probe --format json --output` keeps them beside a saved run",
            err=True,
        )
    resolved = resolve_trust(plugins, allow_plugin, prof)
    registry = Registry.discover(resolved.trust)
    hint_refused_plugins(registry, resolved)
    try:
        wire_config_evaluators(registry, prof, prof.budgets)
    except BudgetExhausted as exc:
        raise refuse_unenforceable_budget(exc) from exc
    except ProfileError as exc:
        raise refuse_invalid_profile(exc) from exc
    load_custom_rules(registry, prof, rules)
    try:
        refuse_unmatched_includes(prof, registry)
    except ProfileError as exc:
        raise refuse_invalid_profile(exc) from exc
    registry.apply_trials(prof.trials)
    records = {key: value.as_record() for key, value in calibrations_or_exit(prof).items()}

    deployment = detect_deployment(ai_system, environment, deployment_id)
    deliveries = AlertDeliveries(required=prof.delivery_required)
    if target is not None:
        used = [
            name
            for name, value in {
                "--url": url,
                "--model": model,
                "--api-key-env": api_key_env,
                "--provider": provider,
                "--adapter": adapter,
                "--system-prompt-file": system_prompt_file,
            }.items()
            if value is not None
        ]
        if used:
            raise typer.BadParameter(
                f"--target cannot be combined with {', '.join(used)}; pass target-specific "
                "configuration through --target-option"
            )
        selected = resolve_target(
            registry,
            locator=target,
            options=target_option,
            kind=TargetKind.ENDPOINT,
            fallback=_missing_target,
        )
        on_alert = alert_handler(
            _withholding(prof.privacy, lambda: secrets_sent_by(selected)),
            reporter,
            source=selected.ref,
            deployment=deployment,
            deliveries=deliveries,
        )
        summary = run_against_endpoint(
            selected.ref,
            lambda: run_target_monitor(
                registry,
                prof,
                lambda: resolve_target(
                    registry,
                    locator=target,
                    options=target_option,
                    kind=TargetKind.ENDPOINT,
                    fallback=_missing_target,
                ),
                source=selected.ref,
                interval_seconds=interval,
                max_cycles=max_cycles,
                concurrency=concurrency,
                on_alert=on_alert,
                calibrations=records,
            ),
            privacy=prof.privacy,
            accepts=_ACCEPTED_FLAGS,
        )
        _exit_with_worst(summary, deliveries)
        return

    if target_option:
        raise typer.BadParameter("--target-option needs --target scheme://locator")
    if url is None or model is None:
        raise typer.BadParameter("pass --url and --model, or --target scheme://locator")

    reached = resolve_flags(
        url, model, provider=provider, api_key_env=api_key_env, adapter=adapter, sending=True
    )
    connection = Connection(reached, system_prompt=read_system_prompt(system_prompt_file))
    on_alert = alert_handler(
        _withholding(prof.privacy, lambda: _sent_over(reached)),
        reporter,
        source=f"{display_url(url)}#{model}",
        deployment=deployment,
        deliveries=deliveries,
    )
    summary = run_against_endpoint(
        url,
        lambda: run_monitor(
            registry,
            prof,
            connection,
            interval_seconds=interval,
            max_cycles=max_cycles,
            concurrency=concurrency,
            on_alert=on_alert,
            calibrations=records,
        ),
        privacy=prof.privacy,
        secrets=reached.secret_values,
        accepts=_ACCEPTED_FLAGS,
    )
    _exit_with_worst(summary, deliveries)


def _exit_with_worst(summary: MonitorSummary, deliveries: AlertDeliveries) -> None:
    """End a bounded watch with the worst code a cycle earned, as `probe` would have.

    A cycle that could not be sampled verified nothing, so it ends the watch as an
    unavailable target unless a sampled cycle earned something worse. An alert delivery
    the profile required and the collector did not acknowledge turns a final `0`, `1` or
    `2` into `8`; a stop's code stays.
    """
    typer.echo(
        f"monitor: {summary.cycles} cycle(s) sampled, {summary.alerts} alert(s), "
        f"{summary.unsampled} cycle(s) not sampled",
        err=True,
    )
    code = ExitCode(summary.exit_code)
    if code is ExitCode.OK and summary.unsampled:
        code = ExitCode.TARGET_UNAVAILABLE
    if deliveries.unacknowledged:
        typer.echo(
            f"monitor: {deliveries.unacknowledged} alert deliveries not acknowledged", err=True
        )
        if code in _REPLACED_BY_A_FAILED_DELIVERY:
            code = ExitCode.OUTPUT_FAILED
    if code is not ExitCode.OK:
        raise typer.Exit(code=code)


def _missing_target() -> Target:
    """Type-safe fallback that is unreachable when a custom locator is present."""
    raise typer.BadParameter("pass --target scheme://locator")
