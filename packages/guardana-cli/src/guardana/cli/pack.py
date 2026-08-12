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

from collections import defaultdict
from pathlib import Path
from typing import Annotated

import typer
import yaml
from guardana.cli._plugins import resolve_trust
from guardana.cli.exit_codes import ExitCode
from guardana.core.pack import (
    EXTENSION_API_VERSION,
    PackCheck,
    PackError,
    PackManifest,
    check_packs,
    installed_manifests,
    installed_packs,
    load_manifest,
)
from guardana.core.pack.lock import (
    LOCK_NAME,
    Installed,
    Lock,
    catalogue_digest,
    compare,
    lock_from_dict,
    lock_of,
    lock_to_dict,
)
from guardana.core.registry import Registry
from guardana.core.taxonomy import TaxonomyRef, catalogs, known_refs

_NAMED_IN_A_WARNING = 5
"""How many unpinnable extensions a warning names before it says "and more".

Bounded because the count is the actionable part and a wall of ids is a line nobody
finishes reading — the whole point of the warning is that it stays read.
"""

pack_app = typer.Typer(
    help="Work on an extension package: validate its manifest, pin what is installed."
)


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
    # All four groups a manifest may declare. Leaving targets out made every pack
    # shipping one accused of not registering it — a false red, which this project
    # treats exactly as seriously as a false green: a validator that accuses a pack
    # of a fault it does not have is a validator somebody turns off. Taxonomies were
    # the same hole one release later, and worse: a manifest could not even name one.
    #
    # Catalogues are compared by **framework**, which is the unit a pack registers
    # and the unit `provides.taxonomies` declares. `known_refs()` rather than a
    # registry method: taxonomies are registered into the taxonomy module during
    # discovery, before rules, so a YAML rule can resolve the ids it names.
    registered = (
        {rule.meta.id for rule in registry.rules()}
        | set(registry.evaluators())
        | {target.__name__ for target in registry.targets()}
        | {ref.framework for ref in known_refs()}
    )

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

    checks = check_packs(manifests, registered)
    for line in _render(checks):
        typer.echo(line)
    raise typer.Exit(code=ExitCode.POLICY_FAILED if any(not c.ok for c in checks) else ExitCode.OK)


@pack_app.command("lock")
def lock(
    path: Annotated[
        Path,
        typer.Argument(help=f"Where the lock lives. Defaults to ./{LOCK_NAME}."),
    ] = Path(LOCK_NAME),
    check: Annotated[
        bool,
        typer.Option("--check", help="Compare against the lock and write nothing."),
    ] = False,
    plugins: Annotated[
        str,
        typer.Option(help="Which installed plugins to load: all|builtins|allowlist|disabled"),
    ] = "all",
    allow_plugin: Annotated[
        list[str],
        typer.Option("--allow-plugin", help="Distribution to trust; repeatable, needs allowlist."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Pin every installed extension by what it is, and fail when the build has drifted.

    Rules are pinned by digest, so a pack that sharpens a corpus inside a patch
    release is visible — which a version pin is not. Evaluators and targets are
    pinned by id, because Python has no declaration to hash; catalogues by a digest
    over the references they register.

    Exit `0` the build matches the lock · `1` it has drifted · `2` nothing was
    installed to pin · `3` the lock could not be read.
    """
    registry = Registry.discover(resolve_trust(plugins, allow_plugin, no_plugins=False))
    packs = installed_packs()
    if not packs:
        typer.echo(
            "no installed pack declares a manifest, so there is nothing to pin — which "
            "is not the same as nothing being installed",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INDETERMINATE)
    present = lock_of(packs, _installed(registry))

    if not check:
        path.write_text(yaml.safe_dump(lock_to_dict(present), sort_keys=False), encoding="utf-8")
        typer.echo(f"pinned {len(present.packs)} pack(s) to {path}")
        _warn_about_unpinnable(present)
        raise typer.Exit(code=ExitCode.OK)

    try:
        locked = lock_from_dict(yaml.safe_load(path.read_text(encoding="utf-8")), str(path))
    except (PackError, OSError, yaml.YAMLError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc

    drift = compare(locked, present)
    for entry in drift:
        typer.echo(entry.describe())
    if drift:
        typer.echo(f"\n{len(drift)} difference(s) from {path}.")
        raise typer.Exit(code=ExitCode.POLICY_FAILED)
    typer.echo(f"{len(present.packs)} pack(s) match {path}.")
    _warn_about_unpinnable(present)


def _installed(registry: Registry) -> Installed:
    """Collect what this build registers, in the vocabulary a lock pins.

    The engine's own catalogues are left out. They ship inside `guardana-core` as
    catalogue files, are pinned by its version and its recorded digest, and belong to
    no pack — listing them here would report seven frameworks as extensions nobody
    declared on every single run, which is how a warning stops being read.
    """
    builtin = {ref.framework for catalog in catalogs() for ref in catalog.refs}
    frameworks: dict[str, list[TaxonomyRef]] = defaultdict(list)
    for ref in known_refs():
        if ref.framework not in builtin:
            frameworks[ref.framework].append(ref)
    return Installed(
        rules={rule.meta.id: rule.digest() for rule in registry.rules()},
        evaluators=tuple(sorted(registry.evaluators())),
        targets=tuple(sorted(target.__name__ for target in registry.targets())),
        catalogues={name: catalogue_digest(refs) for name, refs in frameworks.items()},
    )


def _warn_about_unpinnable(present: Lock) -> None:
    """Say out loud what the lock could not pin, rather than letting the file imply it did.

    An extension registered by a package with no manifest cannot be attributed to a
    pack, so it is listed and not pinned. A lock that stayed silent about it would
    read as full coverage of a build running something nobody declared.
    """
    if not present.unlocked:
        return
    shown = present.unlocked[:_NAMED_IN_A_WARNING]
    typer.echo(
        f"note: {len(present.unlocked)} extension(s) are registered by packages that declare "
        f"no manifest, so they are recorded but not attributed to a pack: "
        f"{', '.join(shown)}" + (" …" if len(present.unlocked) > len(shown) else ""),
        err=True,
    )


def _read_as(manifest: PackManifest) -> str:
    """Say when a manifest was read as an older schema than this build writes.

    Printed rather than kept internal: the migration happens in memory and never
    touches the author's file, so without this line the only evidence that a
    manifest was carried forward is that it did not fail — and an author who cannot
    see the migration cannot tell whether the newer keys are reaching anything.
    """
    if manifest.migrated_from is None:
        return ""
    return (
        f" · read as schema {manifest.migrated_from}, migrated to "
        f"{manifest.schema_version} in memory"
    )


def _render(checks: list[PackCheck]) -> list[str]:
    lines = [f"extension API implemented by this build: {EXTENSION_API_VERSION}", ""]
    for check in checks:
        mark = "✓" if check.ok else "✖"
        lines.append(
            f"{mark} {check.manifest.name} (extension_api {check.manifest.extension_api}) — "
            f"{len(check.manifest.provides)} declared{_read_as(check.manifest)}"
        )
        lines.extend(f"    {problem}" for problem in check.problems)
    lines.append("")
    failed = sum(1 for c in checks if not c.ok)
    lines.append(f"{len(checks)} pack(s) checked, {failed} with problems.")
    return lines


__all__ = ["pack_app"]
