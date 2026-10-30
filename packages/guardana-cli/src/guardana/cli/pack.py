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
import yaml
from guardana.cli._atomic import write_whole
from guardana.cli._plugins import (
    AllowPluginOption,
    PluginsOption,
    ResolvedTrust,
    admission_forms,
    hint_refused_plugins,
    refused_distributions,
    resolve_trust,
    warn_about_load_errors,
)
from guardana.cli._profile import resolve_profile
from guardana.cli.exit_codes import ExitCode
from guardana.core._yaml import load_yaml
from guardana.core.entrypoints import RENDERER_GROUP, REPORTER_GROUP
from guardana.core.output import OutputDiscovery, discover_outputs
from guardana.core.pack import (
    EXTENSION_API_VERSION,
    SUPPORTED_EXTENSION_API_VERSIONS,
    PackCheck,
    PackError,
    PackManifest,
    check_packs,
    discover_packs,
    load_manifest,
)
from guardana.core.pack.discover import Registered
from guardana.core.pack.lock import (
    LOCK_NAME,
    Installed,
    Lock,
    catalogue_digest,
    compare,
    incomparable,
    lock_from_dict,
    lock_of,
    lock_to_dict,
)
from guardana.core.registry import Registry
from guardana.core.taxonomy import extensions, known_refs

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
    plugins: PluginsOption = None,
    allow_plugin: AllowPluginOption = None,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
) -> None:
    """Check a pack manifest against this build's extension API and its own registrations.

    Exit `0` every pack is loadable and accurate · `1` one is not · `2` nothing
    declared a manifest, some installed package registers extensions and declares
    none, or plugin trust refused an extension or an output (or one failed to load,
    or several distributions install one output name) so this build's own
    registrations are unproven and no manifest can be checked against them · `3` the
    manifest could not be read at all.
    """
    resolved = resolve_trust(plugins, allow_plugin, resolve_profile(profile, None))
    registry, outputs = _discover_completely(
        resolved,
        consequence="a manifest cannot be checked against a registry this build did not fully load",
    )
    # All six groups a manifest may declare. Leaving targets out made every pack
    # shipping one accused of not registering it — a false red, which this project
    # treats exactly as seriously as a false green: a validator that accuses a pack
    # of a fault it does not have is a validator somebody turns off. Taxonomies were
    # the same hole one release later, and worse: a manifest could not even name one.
    #
    # Catalogues are compared by **framework**, which is the unit a pack registers
    # and the unit `provides.taxonomies` declares. `known_refs()` rather than a
    # registry method: taxonomies are registered into the taxonomy module during
    # discovery, before rules, so a YAML rule can resolve the ids it names.
    registered = _registered(registry, outputs)

    try:
        if manifest is not None:
            manifests = [load_manifest(manifest)]
            distributions: list[str | None] = [None]
            silent: tuple[str, ...] = ()
        else:
            discovery = discover_packs(resolved.trust)
            manifests = list(discovery.manifests)
            distributions = [distribution for distribution, _, _ in discovery.packs]
            silent = discovery.unmanifested
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

    checks = check_packs(manifests, registered, distributions)
    for line in _render(checks):
        typer.echo(line)
    if any(not c.ok for c in checks):
        raise typer.Exit(code=ExitCode.POLICY_FAILED)
    if silent:
        # Those packages register rules, evaluators, targets, catalogues, renderers or
        # reporters that are live in this build, and no manifest says which API they
        # were written against. Counting only the manifests found would report a
        # clean bill of health over a subset whose size the reader cannot see.
        shown = ", ".join(silent[:_NAMED_IN_A_WARNING])
        typer.echo(
            f"{len(silent)} installed package(s) register extensions (rules, evaluators, "
            f"targets, catalogues, renderers or reporters) and declare no manifest, so "
            f"nothing here says whether this build can load them: "
            f"{shown}" + (" …" if len(silent) > _NAMED_IN_A_WARNING else ""),
            err=True,
        )
        raise typer.Exit(code=ExitCode.INDETERMINATE)
    raise typer.Exit(code=ExitCode.OK)


def _write_lock(path: Path, present: Lock) -> None:
    """Write `present` to `path` whole or not at all; a lock that cannot be written exits `3`."""
    document = yaml.safe_dump(lock_to_dict(present), sort_keys=False)
    try:
        write_whole(path, document.encode("utf-8"))
    except OSError as exc:
        typer.echo(f"error: could not write the lock to {path}: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc


def _read_lock(path: Path) -> Lock:
    """Read the lock at `path`; text that is not a YAML document is a `PackError` naming it."""
    try:
        return lock_from_dict(load_yaml(path.read_text(encoding="utf-8")), str(path))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PackError(f"invalid lock file {path}: {exc}") from exc


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
    plugins: PluginsOption = None,
    allow_plugin: AllowPluginOption = None,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
) -> None:
    """Pin every installed extension by what it is, and fail when the build has drifted.

    Rules are pinned by digest, so a pack that sharpens a corpus inside a patch
    release is visible — which a version pin is not. Evaluators, targets and outputs
    are pinned by id, because Python has no declaration to hash, and only when the
    pack's own distribution registers them; catalogues by a digest over the
    references they register.

    Exit `0` the build matches the lock · `1` it has drifted, an id the lock pins
    another distribution now registering included · `2` nothing was installed to
    pin, a pack declares something nothing or another distribution registers, or
    plugin trust refused an extension or an output (or one failed to load, or
    several distributions install one output name) so what this build registers is
    unproven · `3` the lock could not be read.
    """
    resolved = resolve_trust(plugins, allow_plugin, resolve_profile(profile, None))
    # `_installed(registry)` reads this registry. Writing a lock from one that trust
    # emptied would persist a false "rules: {}" for a pack that registers plenty;
    # checking against it would call a refused extension "gone" when it was never
    # absent. A lock is a document a team keeps and reads on every CI run.
    registry, outputs = _discover_completely(
        resolved,
        consequence="a lock written or checked against it could call something 'gone' "
        "that was only refused",
    )
    packs = discover_packs(resolved.trust).packs
    if not packs:
        typer.echo(
            "no installed pack declares a manifest, so there is nothing to pin — which "
            "is not the same as nothing being installed",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INDETERMINATE)
    try:
        present = lock_of(packs, _installed(registry, outputs), writing=not check)
    except PackError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INDETERMINATE) from exc

    if not check:
        _write_lock(path, present)
        typer.echo(f"pinned {len(present.packs)} pack(s) to {path}")
        _warn_about_unpinnable(present)
        raise typer.Exit(code=ExitCode.OK)

    try:
        locked = _read_lock(path)
    except (PackError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc

    refusal = incomparable(locked, present)
    if refusal is not None:
        typer.echo(f"error: {refusal}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE)
    if locked.migrated_from is not None:
        typer.echo(
            f"note: {path} is lock schema {locked.migrated_from}, whose `<id>: <digest>` "
            f"lines trip secret scanners — rewrite it with `guardana pack lock` once this "
            f"check is clean",
            err=True,
        )
    elif locked.schema_version < present.schema_version:
        typer.echo(
            f"note: {path} is lock schema {locked.schema_version}, which pins no outputs, "
            f"and this build has outputs to pin — rewrite it with `guardana pack lock`",
            err=True,
        )

    drift = compare(locked, present)
    for entry in drift:
        typer.echo(entry.describe())
    if drift:
        typer.echo(f"\n{len(drift)} difference(s) from {path}.")
        raise typer.Exit(code=ExitCode.POLICY_FAILED)
    typer.echo(f"{len(present.packs)} pack(s) match {path}.")
    _warn_about_unpinnable(present)


def _discover_completely(
    resolved: ResolvedTrust, *, consequence: str
) -> tuple[Registry, OutputDiscovery]:
    """Discover under `resolved`, and stop with exit 2 unless everything installed loaded.

    Runs before any manifest is read, because reading one imports its module: a pack
    trust refused must not execute through the command that reports the refusal. An
    output is refused from its metadata before anything imports it, and an output
    name several distributions install counts as unaccounted, because no run can
    select it.
    """
    registry = Registry.discover(resolved.trust)
    warn_about_load_errors(registry, resolved, what="an extension")
    hint_refused_plugins(registry, resolved)
    outputs = discover_outputs(resolved.trust)
    unaccounted = _warn_about_outputs(outputs, resolved)
    if registry.load_errors or unaccounted:
        typer.echo(
            f"error: {len(registry.load_errors) + unaccounted} extension(s) were refused "
            f"by plugin trust, failed to load or are installed by more than one "
            f"distribution, so what this build actually registers is unproven — "
            f"{consequence}; see the warning(s) above",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INDETERMINATE)
    return registry, outputs


_OUTPUT_NOUNS = {"renderer": "format", "reporter": "reporter"}
_GROUP_NOUNS = {RENDERER_GROUP: "format", REPORTER_GROUP: "reporter"}


def _warn_about_outputs(outputs: OutputDiscovery, resolved: ResolvedTrust) -> int:
    """Warn about every output trust refused, that failed or that collides; return how many."""
    for entry_point in outputs.refused:
        noun = _GROUP_NOUNS[entry_point.group]
        typer.echo(
            f"warning: the {noun} {entry_point.name} comes from "
            f"{_described(entry_point.distribution, entry_point.version)}, which plugin "
            f"trust {resolved.trust.describe()} does not admit",
            err=True,
        )
    if outputs.refused and not resolved.stated:
        first, *rest = admission_forms(list(refused_distributions(outputs.refused)))
        lines = [f"  to load them, state the trust, narrowest first: {first}"]
        lines.extend(f"    or {form}" for form in rest)
        typer.echo("\n".join(lines), err=True)
    for entry_point, reason in outputs.failed:
        noun = _GROUP_NOUNS[entry_point.group]
        typer.echo(
            f"warning: the {noun} {entry_point.name} from "
            f"{_described(entry_point.distribution, entry_point.version)} could not be "
            f"loaded: {reason}",
            err=True,
        )
    for key, distributions in sorted(outputs.collisions.items()):
        kind, _, name = key.partition(":")
        typer.echo(
            f"warning: the {_OUTPUT_NOUNS[kind]} {name} is installed by "
            f"{len(distributions)} distributions ({', '.join(distributions)}); selecting it "
            f"is refused",
            err=True,
        )
    return len(outputs.refused) + len(outputs.failed) + len(outputs.collisions)


def _described(distribution: str | None, version: str | None) -> str:
    if distribution is None:
        return "an unnamed distribution"
    return f"{distribution} {version}" if version else distribution


def _registered(registry: Registry, outputs: OutputDiscovery) -> Registered:
    """Collect what this build registers, by kind, naming the distribution where it can.

    Rules, evaluators and targets carry the distribution discovery loaded them from;
    a framework carries every distribution that registered a reference into it, the
    one shipping the built-in catalogues included; an output carries the distribution
    whose entry point names it.
    """
    return Registered(
        rules={
            rule.meta.id: registry.origin_of(rule.meta.id).distribution for rule in registry.rules()
        },
        evaluators={
            evaluator_id: registry.evaluator_origin(evaluator_id).distribution
            for evaluator_id in registry.evaluators()
        },
        targets={
            target.__name__: registry.target_origin(target).distribution
            for target in registry.targets()
        },
        taxonomies=dict.fromkeys(ref.framework for ref in known_refs()),
        taxonomy_owners=registry.taxonomy_owners(),
        renderers={name: origin.distribution for name, origin in outputs.renderers.items()},
        reporters={name: origin.distribution for name, origin in outputs.reporters.items()},
        output_collisions=outputs.collisions,
    )


def _installed(registry: Registry, outputs: OutputDiscovery) -> Installed:
    """Collect what this build registers, in the vocabulary a lock pins.

    The engine's own references are left out. They ship inside `guardana-core` as
    catalogue files, are pinned by its version and its recorded digest, and belong to
    no pack — listing them here would report seven frameworks as extensions nobody
    declared on every single run, which is how a warning stops being read. A control a
    package adds to a built-in framework is an extension and is pinned.

    Evaluators, targets and outputs carry the distribution registering each, so a pack
    pins only the ones its own distribution ships.
    """
    return Installed(
        rules={rule.meta.id: rule.digest() for rule in registry.rules()},
        evaluators={
            evaluator_id: registry.evaluator_origin(evaluator_id).distribution
            for evaluator_id in sorted(registry.evaluators())
        },
        targets={
            target.__name__: registry.target_origin(target).distribution
            for target in sorted(registry.targets(), key=lambda target: target.__name__)
        },
        catalogues={name: catalogue_digest(refs) for name, refs in extensions().items()},
        renderers={
            name: outputs.renderers[name].distribution for name in sorted(outputs.renderers)
        },
        reporters={
            name: outputs.reporters[name].distribution for name in sorted(outputs.reporters)
        },
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
    supported = ", ".join(str(api) for api in sorted(SUPPORTED_EXTENSION_API_VERSIONS))
    lines = [
        f"extension APIs implemented by this build: {supported} (newest {EXTENSION_API_VERSION})",
        "",
    ]
    for check in checks:
        mark = "✓" if check.ok else "✖"
        output_api = (
            f", output_api {check.manifest.output_api}" if check.manifest.output_api else ""
        )
        lines.append(
            f"{mark} {check.manifest.name} (extension_api {check.manifest.extension_api}"
            f"{output_api}) — {len(check.manifest.provides)} declared{_read_as(check.manifest)}"
        )
        lines.extend(f"    {problem}" for problem in check.problems)
    lines.append("")
    failed = sum(1 for c in checks if not c.ok)
    lines.append(f"{len(checks)} pack(s) checked, {failed} with problems.")
    return lines


__all__ = ["pack_app"]
