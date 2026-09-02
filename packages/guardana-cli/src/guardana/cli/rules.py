import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._plugins import resolve_trust, warn_about_load_errors
from guardana.cli.exit_codes import ExitCode
from guardana.core.registry import Registry
from guardana.core.rule import Rule
from guardana.core.surface import Surface


class RulesFormat(StrEnum):
    """How `guardana rules` prints the catalogue."""

    human = "human"
    json = "json"


class SurfaceFilter(StrEnum):
    """Which security layer to list."""

    all = "all"
    build = "build"
    runtime = "runtime"


_SURFACE_HEADING = {
    Surface.BUILD: "Build-time  (static, artifact — dev machine, CI, training server)",
    Surface.RUNTIME: "Runtime  (dynamic, endpoint — live probe and monitor)",
}


def rules(
    format: Annotated[RulesFormat, typer.Option(help="human|json")] = RulesFormat.human,
    surface: Annotated[
        SurfaceFilter, typer.Option(help="Filter by security layer: all|build|runtime")
    ] = SurfaceFilter.all,
    plugins: Annotated[
        str,
        typer.Option(help="Which installed plugins to load: all|builtins|allowlist|disabled"),
    ] = "all",
    allow_plugin: Annotated[
        list[str],
        typer.Option("--allow-plugin", help="Distribution to trust; repeatable, needs allowlist."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    rules: Annotated[
        list[Path],
        typer.Option(
            "--rules", help="Directory or file of custom YAML rules to include; repeatable."
        ),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """List all discovered rules, grouped by the layer they secure (build vs runtime).

    Pass `--rules <dir>` to include custom YAML rules in the listing — the same
    flag `scan`/`probe` take — so you can confirm a rule pack parses and is picked
    up without launching a full probe. A file that fails to load is warned about,
    never silently dropped.

    Exit `0` at least one rule was listed · `2` nothing was — a restrictive
    `--plugins` mode or an empty `--rules` set can empty the registry, and that
    must never read as a clean, deliberately empty catalogue.
    """
    trust = resolve_trust(plugins, allow_plugin, no_plugins=False)
    registry = Registry.discover(trust)
    registry.load_yaml_rule_dirs(rules)
    # Includes entry-point failures, not just YAML: this command exists to confirm
    # a pack was picked up, so a pack that failed to import must not be an empty
    # line in the listing.
    warn_about_load_errors(registry, what="rule")
    discovered = [r for r in registry.rules() if _keep(r, surface)]
    if not discovered:
        # An empty listing produced by a refusal is not a listing — the same
        # principle `rule test` applies to an unmatched selector.
        refusal = (
            f" ({len(registry.load_errors)} extension(s) refused by plugin trust)"
            if registry.load_errors
            else ""
        )
        typer.echo(
            f"error: no rule was loaded{refusal} — nothing was listed, which is "
            f"not the same as nothing being installed",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INDETERMINATE)
    if format == RulesFormat.json:
        typer.echo(json.dumps([_as_dict(r) for r in discovered], indent=2))
        return
    for layer in (Surface.BUILD, Surface.RUNTIME):
        group = [r for r in discovered if r.meta.surface is layer]
        if not group:
            continue
        typer.echo(f"\n{_SURFACE_HEADING[layer]}")
        for r in group:
            # The reference, not the bare id: `LLM07` names two different
            # controls once a framework publishes a second edition, and a
            # listing that hid the edition would be unanswerable in an audit.
            tags = ", ".join(t.reference for t in r.meta.taxonomy)
            typer.echo(f"  {r.meta.severity.name:9} {r.meta.id}  [{tags}]")


def _keep(rule: Rule, surface: SurfaceFilter) -> bool:
    return surface == SurfaceFilter.all or rule.meta.surface.value == surface.value


def _as_dict(rule: Rule) -> dict[str, object]:
    return {
        "id": rule.meta.id,
        "severity": rule.meta.severity.name,
        "surface": rule.meta.surface.value,
        "taxonomy": [
            {"reference": t.reference, "framework": t.framework, "id": t.id, "title": t.title}
            for t in rule.meta.taxonomy
        ],
    }
