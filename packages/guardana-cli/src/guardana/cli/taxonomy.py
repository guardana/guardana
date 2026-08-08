"""List the framework catalogues this build holds, and what a reference means.

Exists because the reference syntax stopped being guessable the day a framework
published a second edition: `LLM07` is System Prompt Leakage in `OWASP-LLM-2025`
and Misinformation in `OWASP-LLM-2026`, so a rule has to name an edition and an
author has to be able to find out which ones exist without reading the source.

It answers the other half too — what a reference recorded years ago corresponds to
today — from the crosswalk, which is data with explicit relations rather than an
alias table. Nothing here rewrites anything: a stored reference is read as the
edition it names, and the correspondence is computed in memory when asked for.
"""

import json
from enum import StrEnum
from typing import Annotated

import typer
from guardana.core.registry import Registry
from guardana.core.taxonomy import (
    Correspondent,
    TaxonomyError,
    TaxonomyRef,
    catalogs,
    correspondents,
    resolve,
)

_INVALID_USAGE = 3


class TaxonomyFormat(StrEnum):
    """How `guardana taxonomy` prints what it found."""

    human = "human"
    json = "json"


def taxonomy(
    reference: Annotated[
        str | None,
        typer.Argument(help="One reference to explain, e.g. LLM07:2025 or AML.T0051"),
    ] = None,
    format: Annotated[TaxonomyFormat, typer.Option(help="human|json")] = TaxonomyFormat.human,
) -> None:
    """Show the installed framework catalogues, or explain one reference.

    With no argument it lists every catalogue with its digest — the same digest a
    run manifest pins, so a report and a build can be checked against each other
    years later. With a reference it prints that entry and what it corresponds to
    in the other editions.
    """
    # Discovery first: a company's own catalogue arrives through the
    # `guardana.taxonomies` entry point, and a listing that showed only the
    # built-ins would tell them their pack is not installed when it is.
    registry = Registry.discover()
    # And a pack that failed to load is worse than one that is absent: its
    # references are mappings the user believes they have. Warned about here for
    # the same reason `guardana rules` warns — this command exists to confirm what
    # is installed, so a silent gap defeats it.
    for error in registry.load_errors:
        typer.echo(f"warning: could not load a taxonomy provider — {error}", err=True)
    if reference is None:
        _list_catalogs(format)
        return
    _explain(reference, format)


def _list_catalogs(format: TaxonomyFormat) -> None:
    installed = catalogs()
    if format == TaxonomyFormat.json:
        typer.echo(
            json.dumps(
                [
                    {
                        "scheme": c.scheme,
                        "edition": c.edition,
                        "framework": c.framework,
                        "title": c.title,
                        "version": c.version,
                        "source": c.source,
                        "published": c.published,
                        "digest": c.digest,
                        "entries": [
                            {"reference": r.reference, "id": r.id, "rank": r.rank, "title": r.title}
                            for r in c.refs
                        ],
                    }
                    for c in installed
                ],
                indent=2,
            )
        )
        return
    for catalog in installed:
        typer.echo(f"\n{catalog.framework} — {catalog.title}")
        typer.echo(f"  {len(catalog.refs)} entries · digest {catalog.digest}")
        if catalog.version:
            typer.echo(f"  transcribed from {catalog.version}")
        if catalog.source:
            typer.echo(f"  {catalog.source}")
        for ref in catalog.refs:
            typer.echo(f"    {ref.reference:16} {ref.title}")


def _explain(reference: str, format: TaxonomyFormat) -> None:
    try:
        found = resolve(reference)
    except TaxonomyError as exc:
        # An under-specified reference, which is a different failure from a typo:
        # the message names every edition that defines the id.
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=_INVALID_USAGE) from exc
    if found is None:
        typer.echo(
            f"error: no installed catalogue defines {reference!r}; "
            f"run `guardana taxonomy` to list what is installed",
            err=True,
        )
        raise typer.Exit(code=_INVALID_USAGE)
    related = correspondents(found)
    if format == TaxonomyFormat.json:
        typer.echo(json.dumps(_as_dict(found, related), indent=2))
        return
    typer.echo(f"{found.reference}  {found.title}")
    typer.echo(f"  framework: {found.framework}")
    if found.rank is not None:
        typer.echo(f"  rank:      {found.rank}")
    if not related:
        typer.echo("  no other installed edition states a correspondence with this entry")
        return
    typer.echo("  corresponds to:")
    for correspondent in related:
        typer.echo(f"    {correspondent.describe()}")


def _as_dict(found: TaxonomyRef, related: tuple[Correspondent, ...]) -> dict[str, object]:
    return {
        "reference": found.reference,
        "scheme": found.scheme,
        "edition": found.edition,
        "framework": found.framework,
        "id": found.id,
        "title": found.title,
        "rank": found.rank,
        "corresponds_to": [
            {
                "reference": c.ref.reference,
                "framework": c.ref.framework,
                "title": c.ref.title,
                "relation": str(c.relation),
                "note": c.note,
            }
            for c in related
        ],
    }
