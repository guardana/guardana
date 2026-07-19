import json
from enum import StrEnum
from typing import Annotated

import typer
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
) -> None:
    """List all discovered rules, grouped by the layer they secure (build vs runtime)."""
    discovered = [r for r in Registry.discover().rules() if _keep(r, surface)]
    if format == RulesFormat.json:
        typer.echo(json.dumps([_as_dict(r) for r in discovered], indent=2))
        return
    for layer in (Surface.BUILD, Surface.RUNTIME):
        group = [r for r in discovered if r.meta.surface is layer]
        if not group:
            continue
        typer.echo(f"\n{_SURFACE_HEADING[layer]}")
        for r in group:
            tags = ", ".join(t.id for t in r.meta.taxonomy)
            typer.echo(f"  {r.meta.severity.name:9} {r.meta.id}  [{tags}]")


def _keep(rule: Rule, surface: SurfaceFilter) -> bool:
    return surface == SurfaceFilter.all or rule.meta.surface.value == surface.value


def _as_dict(rule: Rule) -> dict[str, object]:
    return {
        "id": rule.meta.id,
        "severity": rule.meta.severity.name,
        "surface": rule.meta.surface.value,
        "taxonomy": [t.id for t in rule.meta.taxonomy],
    }
