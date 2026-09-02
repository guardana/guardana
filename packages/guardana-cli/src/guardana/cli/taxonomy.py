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
from collections import defaultdict
from enum import StrEnum
from typing import Annotated

import typer
from guardana.cli._plugins import resolve_trust, warn_about_load_errors
from guardana.cli.exit_codes import ExitCode
from guardana.core.registry import Registry
from guardana.core.taxonomy import (
    Correspondent,
    TaxonomyError,
    TaxonomyRef,
    catalogs,
    correspondents,
    known_refs,
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
    plugins: Annotated[
        str,
        typer.Option(help="Which installed plugins to load: all|builtins|allowlist|disabled"),
    ] = "all",
    allow_plugin: Annotated[
        list[str],
        typer.Option("--allow-plugin", help="Distribution to trust; repeatable, needs allowlist."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Show the installed framework catalogues, or explain one reference.

    With no argument it lists every catalogue with its digest — the same digest a
    run manifest pins, so a report and a build can be checked against each other
    years later. With a reference it prints that entry and what it corresponds to
    in the other editions.
    """
    trust = resolve_trust(plugins, allow_plugin, no_plugins=False)
    # Discovery first: a company's own catalogue arrives through the
    # `guardana.taxonomies` entry point, and a listing that showed only the
    # built-ins would tell them their pack is not installed when it is.
    registry = Registry.discover(trust)
    # And a pack that failed to load is worse than one that is absent: its
    # references are mappings the user believes they have. Warned about here for
    # the same reason `guardana rules` warns — this command exists to confirm what
    # is installed, so a silent gap defeats it.
    warn_about_load_errors(registry, what="a taxonomy provider")
    if reference is None:
        _list_catalogs(format)
        return
    _explain(reference, format, len(registry.load_errors))


def _registered_outside_a_catalog() -> list[tuple[str, tuple[TaxonomyRef, ...]]]:
    """Group the references an installed package registered that no catalogue file holds.

    The listing did discovery and then printed `catalogs()`, which is built-ins
    only — so a company that installed their own control catalogue ran the one
    command that confirms what is installed and was told it was not. Nothing had
    ever registered through `guardana.taxonomies`, so the gap between the comment
    above and the code below had no way to be noticed.

    Reported in their own section and without a digest rather than folded in beside
    the built-ins: a package registers *references*, not a catalogue file, so there
    is nothing to pin, and inventing a digest would claim a provenance nobody has
    in the field a report is checked against years later.
    """
    catalogued = {(ref.framework, ref.id) for catalog in catalogs() for ref in catalog.refs}
    grouped: defaultdict[str, list[TaxonomyRef]] = defaultdict(list)
    for ref in known_refs():
        if (ref.framework, ref.id) not in catalogued:
            grouped[ref.framework].append(ref)
    return [(framework, tuple(refs)) for framework, refs in sorted(grouped.items())]


def _catalogs_as_json() -> list[dict[str, object]]:
    """Every installed catalogue, then every reference registered without one.

    One list rather than two keys, so a script that already walks catalogues picks
    the new entries up. `digest` is `null` on exactly the ones a package
    registered, which is how a consumer tells them apart without a flag.
    """
    listed: list[dict[str, object]] = [
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
        for c in catalogs()
    ]
    listed += [
        {
            "scheme": refs[0].scheme,
            "edition": refs[0].edition,
            "framework": framework,
            "title": "",
            "version": None,
            "source": None,
            "published": None,
            "digest": None,
            "entries": [
                {"reference": r.reference, "id": r.id, "rank": r.rank, "title": r.title}
                for r in refs
            ],
        }
        for framework, refs in _registered_outside_a_catalog()
    ]
    return listed


def _list_catalogs(format: TaxonomyFormat) -> None:
    if format == TaxonomyFormat.json:
        typer.echo(json.dumps(_catalogs_as_json(), indent=2))
        return
    for catalog in catalogs():
        typer.echo(f"\n{catalog.framework} — {catalog.title}")
        typer.echo(f"  {len(catalog.refs)} entries · digest {catalog.digest}")
        if catalog.version:
            typer.echo(f"  transcribed from {catalog.version}")
        if catalog.source:
            typer.echo(f"  {catalog.source}")
        for ref in catalog.refs:
            typer.echo(f"    {ref.reference:16} {ref.title}")
    for framework, refs in _registered_outside_a_catalog():
        typer.echo(f"\n{framework} — registered by an installed package")
        typer.echo(
            f"  {len(refs)} entr{'y' if len(refs) == 1 else 'ies'} · no catalogue digest: "
            f"a package registers references, not a catalogue file"
        )
        for ref in refs:
            typer.echo(f"    {ref.reference:16} {ref.title}")


def _explain(reference: str, format: TaxonomyFormat, refused: int) -> None:
    try:
        found = resolve(reference)
    except TaxonomyError as exc:
        # An under-specified reference, which is a different failure from a typo:
        # the message names every edition that defines the id.
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=_INVALID_USAGE) from exc
    if found is None:
        if refused:
            # `resolve` searches built-ins (always loaded) plus whatever
            # `guardana.taxonomies` registered — and plugin trust just refused
            # `refused` of those providers. A reference they would have defined
            # is unproven, not absent, so "no installed catalogue" would say more
            # than this build actually knows.
            typer.echo(
                f"error: no loaded catalogue defines {reference!r} — {refused} "
                f"provider(s) were refused by plugin trust, so this may be theirs "
                f"rather than missing; see the warning(s) above",
                err=True,
            )
            raise typer.Exit(code=ExitCode.INDETERMINATE)
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
