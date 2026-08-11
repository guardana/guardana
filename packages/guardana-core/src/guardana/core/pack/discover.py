"""Find installed pack manifests, and check each against what its package registers.

A manifest is a claim; this is where the claim meets the registry. The direction
that matters is the *missing* one: a pack promising `acme.agent.customer_data` and
not registering it leaves a team believing a check runs that never does — which is
the same false green the engine refuses everywhere else, arriving through
documentation instead of through code.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from importlib import metadata, resources

from guardana.core.pack.load import MANIFEST_NAME, load_manifest
from guardana.core.pack.model import EXTENSION_API_VERSION, PackError, PackManifest

_ENTRY_POINT_GROUPS = ("guardana.rules", "guardana.evaluators", "guardana.targets")


@dataclass(frozen=True, slots=True)
class PackCheck:
    """One pack, and everything wrong with it — or nothing."""

    manifest: PackManifest
    problems: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """Whether this pack is loadable and describes itself accurately."""
        return not self.problems


def installed_manifests() -> list[PackManifest]:
    """Read the manifest of every installed package that registers a Guardana extension.

    **Located from the entry point, not from the distribution's file list.** An
    editable install lists no files, so walking them found nothing for a package
    sitting right there — and a discovery that silently finds nothing is
    indistinguishable from a package that declared nothing. The entry point already
    names the module that provides the extension, and that module's package is
    exactly the one that owns the manifest.
    """
    manifests: dict[str, PackManifest] = {}
    for package in sorted(_extension_packages()):
        found = _manifest_in(package)
        if found is not None:
            manifests.setdefault(found.name, found)
    return list(manifests.values())


def check_pack(manifest: PackManifest, registered: Iterable[str]) -> PackCheck:
    """Compare one manifest against the ids actually registered, and against this build.

    Two questions, and both have to be answered before a pack is a safe investment:
    *can this build load it at all*, and *does it do what its manifest says*.
    """
    problems: list[str] = []
    if not manifest.loadable_by(EXTENSION_API_VERSION):
        problems.append(manifest.extension_api.why_not(EXTENSION_API_VERSION))
    available = set(registered)
    missing = [declared for declared in manifest.provides if declared not in available]
    if missing:
        problems.append(
            f"declares {', '.join(missing)} and does not register "
            f"{'it' if len(missing) == 1 else 'them'} — a team reading this manifest "
            f"believes a check runs that does not"
        )
    return PackCheck(manifest, tuple(problems))


def _extension_packages() -> set[str]:
    """Every package that registers through a Guardana entry-point group.

    The module, not the distribution: `guardana` is a PEP 420 namespace shared by
    five distributions, so looking for a manifest beside the namespace root would
    find whichever happened to be first on the path.
    """
    packages: set[str] = set()
    for group in _ENTRY_POINT_GROUPS:
        for entry_point in metadata.entry_points(group=group):
            module = entry_point.value.split(":", 1)[0].strip()
            if module:
                packages.add(module)
    return packages


def _manifest_in(package: str) -> PackManifest | None:
    """Read the manifest a package ships, or None when it ships none.

    Absent is allowed. Requiring one would make every pack written before this
    existed unloadable — breaking somebody's package to enforce a bar it could not
    have known about — so `pack validate` reports the absence instead of refusing.
    """
    try:
        candidate = resources.files(package).joinpath(MANIFEST_NAME)
        if not candidate.is_file():
            return None
        with resources.as_file(candidate) as path:
            return load_manifest(path)
    except (ModuleNotFoundError, TypeError, OSError):
        return None
    except PackError:
        # A manifest that is present and unreadable is a real problem, and swallowing
        # it here would report the pack as having declared nothing. Raised so the
        # command exits `3` naming the file, exactly as a malformed contract does.
        raise
