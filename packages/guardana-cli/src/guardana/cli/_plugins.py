"""Resolve the `--plugins` flag into a trust policy, and surface what it refused.

Two helpers rather than the same lines copied into five commands: a safe mode
spelled differently by each command is a safe mode somebody sets wrongly, and a
refusal that only one command prints is a refusal the rest hide.
"""

import typer
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry


def resolve_trust(plugins: str, allow: list[str], *, no_plugins: bool) -> PluginTrust:
    """Turn the flags into a policy, refusing a mode nobody defined.

    `--no-plugins` is kept as a deprecated alias for `--plugins disabled`, because
    it is in people's pipelines. It means what it always meant — nothing is
    imported — and the new `builtins` mode is what most of those pipelines
    actually wanted.
    """
    if no_plugins:
        return PluginTrust(mode=PluginMode.DISABLED)
    try:
        mode = PluginMode(plugins)
    except ValueError as exc:
        raise typer.BadParameter(
            f"unknown plugin mode {plugins!r}; expected one of {[str(m) for m in PluginMode]}"
        ) from exc
    if allow and mode is not PluginMode.ALLOWLIST:
        # Refused rather than ignored: a user who named distributions and got a
        # mode that ignores them would believe they had restricted something.
        raise typer.BadParameter("--allow-plugin only applies with --plugins allowlist")
    return PluginTrust(mode=mode, allowed=frozenset(allow))


def warn_about_load_errors(registry: Registry, *, what: str) -> None:
    """Print a warning for every entry point `registry` refused to load.

    A restrictive `--plugins` mode changes what a command's result actually means:
    a check that never loaded looks, in its effect, exactly like one that loaded
    and stayed quiet — unless something says otherwise, in the same place the
    result appears. So this is called by every command that renders something
    built from a discovered registry, right after `Registry.discover(trust)` and
    before that render, rather than leaving the refusal reachable only through
    `registry.load_errors` for a caller who thinks to go looking.

    `what` completes "could not load ___" in the caller's own vocabulary — a
    taxonomy provider is not a rule and an evaluator is not a rule either, and
    flattening every caller into one noun would make the warning read less true,
    not more consistent.
    """
    for error in registry.load_errors:
        typer.echo(
            f"warning: could not load {what} — {error.source} ({error.stage}): {error.reason}",
            err=True,
        )
