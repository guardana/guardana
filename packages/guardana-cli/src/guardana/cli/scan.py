from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._formats import OutputFormat
from guardana.cli._profile import resolve_profile
from guardana.cli._reporting import submit_safely
from guardana.cli._rules_loading import load_custom_rules
from guardana.core.registry import Registry
from guardana.core.report import BaselineError, apply_baseline, load_baseline, serialize_baseline
from guardana.core.runner import Runner, gate
from guardana.core.target import ArtifactTarget
from guardana.report import get_renderer

_BASELINE_ERROR_EXIT_CODE = 2


def scan(  # noqa: PLR0913 — one typer.Option per CLI flag; this is the command's surface
    path: Annotated[Path, typer.Argument(help="Directory to scan")],
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[
        str | None, typer.Option(help="Named policy preset: ci|pre-training|monitor")
    ] = None,
    format: Annotated[
        OutputFormat, typer.Option(help="human|json|sarif|junit")
    ] = OutputFormat.human,
    no_plugins: Annotated[bool, typer.Option("--no-plugins")] = False,
    rules: Annotated[
        list[Path],
        typer.Option("--rules", help="Directory or file of custom YAML rules; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    baseline: Annotated[
        Path | None,
        typer.Option(help="Baseline file; findings it lists are waived (reported, never gated)."),
    ] = None,
    write_baseline: Annotated[
        Path | None,
        typer.Option(
            "--write-baseline",
            help="Write a baseline waiving every current finding to this path, then exit 0.",
        ),
    ] = None,
    reporter: Annotated[
        str | None, typer.Option(help="Collector URL to forward findings to, e.g. server://URL")
    ] = None,
) -> None:
    """Statically scan a path for AI supply-chain risk (no model needed)."""
    if baseline is not None and write_baseline is not None:
        raise typer.BadParameter("pass either --baseline or --write-baseline, not both")
    prof = resolve_profile(profile, preset)
    # --no-plugins builds a bare Registry, so no entry-point code is imported or
    # run (see SECURITY.md). Custom YAML rules still load, but one whose evaluator
    # lives behind an entry point resolves to nothing at run time and is skipped —
    # safe degradation, never a crash.
    registry = Registry() if no_plugins else Registry.discover()
    load_custom_rules(registry, prof, rules)
    result = Runner(registry=registry, profile=prof).run(ArtifactTarget(path))

    if write_baseline is not None:
        write_baseline.write_text(serialize_baseline(result), encoding="utf-8")
        typer.echo(
            f"wrote baseline waiving {len(result.findings)} finding(s) to {write_baseline} "
            f"— add a reason to each before committing it.",
            err=True,
        )
        return
    if baseline is not None:
        try:
            result = apply_baseline(result, load_baseline(baseline))
        except BaselineError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=_BASELINE_ERROR_EXIT_CODE) from exc

    typer.echo(get_renderer(format.value).render(result))
    if reporter:
        submit_safely(reporter, result, source=str(path))
    if gate(result, prof.policy):
        raise typer.Exit(code=1)
