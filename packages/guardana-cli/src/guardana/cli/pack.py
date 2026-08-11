"""`guardana pack validate` — can this build load that package, and does it do what it says.

The outer loop for an extension author: run once before publishing and once in CI.
1.0 entry criterion 8 asks in these words that a third party be able to run it
against a release candidate, which is what makes a compatibility promise checkable
rather than stated.

Two questions, and a pack is only a safe investment when both are answered. *Can
this build load it* — the declared extension API range, refused in both directions.
*Does it do what its manifest says* — every id it promises, compared against what
its entry points actually register.
"""

from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._plugins import resolve_trust
from guardana.cli.exit_codes import ExitCode
from guardana.core.pack import (
    EXTENSION_API_VERSION,
    PackCheck,
    PackError,
    check_pack,
    installed_manifests,
    load_manifest,
)
from guardana.core.registry import Registry

pack_app = typer.Typer(help="Work on an extension package: validate its manifest.")


@pack_app.command("validate")
def validate(
    manifest: Annotated[
        Path | None,
        typer.Argument(help="A guardana-pack.yaml to check. Omit to check every installed pack."),
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
    """Check a pack manifest against this build's extension API and its own registrations.

    Exit `0` every pack is loadable and accurate · `1` one is not · `2` nothing
    declared a manifest · `3` the manifest could not be read at all.
    """
    registry = Registry.discover(resolve_trust(plugins, allow_plugin, no_plugins=False))
    registered = {rule.meta.id for rule in registry.rules()} | set(registry.evaluators())

    try:
        manifests = [load_manifest(manifest)] if manifest is not None else installed_manifests()
    except PackError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc

    if not manifests:
        typer.echo(
            f"no pack declared a {'manifest' if manifest is None else 'readable manifest'} — "
            f"nothing was validated, which is not the same as nothing being wrong",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INDETERMINATE)

    checks = [check_pack(found, registered) for found in manifests]
    for line in _render(checks):
        typer.echo(line)
    raise typer.Exit(code=ExitCode.POLICY_FAILED if any(not c.ok for c in checks) else ExitCode.OK)


def _render(checks: list[PackCheck]) -> list[str]:
    lines = [f"extension API implemented by this build: {EXTENSION_API_VERSION}", ""]
    for check in checks:
        mark = "✓" if check.ok else "✖"
        lines.append(
            f"{mark} {check.manifest.name} (extension_api {check.manifest.extension_api}) — "
            f"{len(check.manifest.provides)} declared"
        )
        lines.extend(f"    {problem}" for problem in check.problems)
    lines.append("")
    failed = sum(1 for c in checks if not c.ok)
    lines.append(f"{len(checks)} pack(s) checked, {failed} with problems.")
    return lines


__all__ = ["pack_app"]
