"""Resolve the `--plugins` flag into a trust policy.

One helper rather than the same three lines in four commands: a safe mode spelled
differently by each command is a safe mode somebody sets wrongly.
"""

import typer
from guardana.core.plugins import PluginMode, PluginTrust


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
