"""What was installed, pinned by what each thing *is* rather than by what it is called.

A lock over distribution versions is not a lock for this project, and the reason is
already in the codebase: `Rule.digest()` exists precisely so that "the same rule"
means more than "the same package version". A pack can sharpen a corpus, widen a
prompt set or swap an evaluator inside one patch release, and every one of those
changes what a run tests while the version string it is pinned by says nothing
moved. A comparison against last week's run would then blame the model.

So this pins three different things with three different strengths, and says which
is which rather than presenting one confidence:

- **rules** by digest — their declaration, hashed. A changed corpus is visible;
- **evaluators and targets** by id only. An `Evaluator` is Python and has no
  declaration to hash, and inventing a digest from a class name would claim to
  detect a change it cannot see. `_run_meta` made that call for the run manifest
  and it is the same call here;
- **catalogues** by a digest over the references a pack registers. A third-party
  catalogue has no *file* to pin — a pack registers refs through an entry point —
  but what it registered is content, and content hashes.

The distribution version is recorded beside all of it as the coarse pin that covers
what none of the above can: the Python implementation behind a rule whose
declaration did not move.
"""

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from guardana.core.fingerprint import digest_of
from guardana.core.pack.model import EXTENSION_API_VERSION, PackError

LOCK_SCHEMA_VERSION = 1
"""Version of `guardana-lock.yaml`, moved independently of everything it pins.

A lock is a document a team keeps in their repository and reads on every CI run, so
principle 11 applies to it exactly as it does to a saved run.
"""

LOCK_NAME = "guardana-lock.yaml"
"""The conventional filename, at the root of the repository being gated."""


class DriftKind(StrEnum):
    """How what is installed differs from what was locked.

    Six kinds rather than one "mismatch", because they are six different things to
    do about it. A rule whose digest moved is a review; a pack nobody pinned is a
    supply-chain question; a rule that vanished is coverage a team still believes
    they have.
    """

    PACK_MISSING = "pack_missing"
    PACK_UNLOCKED = "pack_unlocked"
    VERSION_CHANGED = "version_changed"
    REMOVED = "removed"
    ADDED = "added"
    CHANGED = "changed"


@dataclass(frozen=True, slots=True)
class Drift:
    """One difference between the lock and what is installed."""

    kind: DriftKind
    subject: str
    detail: str

    def describe(self) -> str:
        """One line, naming the thing and what happened to it."""
        return f"{self.kind}: {self.subject} — {self.detail}"


@dataclass(frozen=True, slots=True)
class LockedPack:
    """One pack as it was when the lock was written."""

    name: str
    distribution: str
    version: str
    rules: Mapping[str, str] = field(default_factory=dict)
    evaluators: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    taxonomies: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Lock:
    """Everything a build had installed, pinned."""

    packs: tuple[LockedPack, ...] = ()
    unlocked: tuple[str, ...] = ()
    """Ids registered by no pack that declares a manifest.

    Recorded rather than dropped. An extension nobody can pin is the single thing a
    lock file exists to make visible, and leaving it out of the document would make
    a repository with an unpinnable pack look fully pinned.
    """

    schema_version: int = LOCK_SCHEMA_VERSION
    extension_api: int = EXTENSION_API_VERSION


def catalogue_digest(refs: Iterable[Any]) -> str:
    """Digest the references a pack registers under one framework.

    Covers identity and display data both: a catalogue that silently re-titles a
    control has changed what every finding mapping to it says in somebody's audit,
    which is a change worth seeing even though it moves no rule.
    """
    entries = sorted(
        (ref.scheme, ref.id, ref.title, ref.edition or "", str(ref.rank or "")) for ref in refs
    )
    return digest_of(json.dumps(entries, sort_keys=True, ensure_ascii=False))


@dataclass(frozen=True, slots=True)
class Installed:
    """What this build has registered, in the vocabulary a lock pins.

    Assembled by the caller from a `Registry` rather than read here, so this module
    stays a document format with no opinion about how extensions are discovered —
    which is also what lets a test build one without installing anything.
    """

    rules: Mapping[str, str] = field(default_factory=dict)
    evaluators: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    catalogues: Mapping[str, str] = field(default_factory=dict)

    def ids(self) -> set[str]:
        """Every id this build registers, in one set."""
        return {*self.rules, *self.evaluators, *self.targets, *self.catalogues}


def lock_of(packs: Sequence[tuple[str, str, Any]], installed: Installed) -> Lock:
    """Pin what is installed, attributing each id to the pack whose manifest declares it.

    `packs` is `(distribution, version, manifest)` per installed pack.

    An id declared by no manifest lands in `unlocked`. That is the case worth
    designing for rather than dropping: a package registering rules without a
    manifest cannot be pinned by name, and a lock that silently omitted it would
    report a fully pinned repository while an unpinned pack ran in it.
    """
    locked = [
        LockedPack(
            name=manifest.name,
            distribution=distribution,
            version=version,
            rules={i: installed.rules[i] for i in manifest.rules if i in installed.rules},
            evaluators=tuple(i for i in manifest.evaluators if i in installed.evaluators),
            targets=tuple(i for i in manifest.targets if i in installed.targets),
            taxonomies={
                i: installed.catalogues[i] for i in manifest.taxonomies if i in installed.catalogues
            },
        )
        for distribution, version, manifest in packs
    ]
    declared = {name for _, _, manifest in packs for name in manifest.provides}
    return Lock(packs=tuple(locked), unlocked=tuple(sorted(installed.ids() - declared)))


def lock_to_dict(lock: Lock) -> dict[str, Any]:
    """Render a lock as the document written to disk."""
    return {
        "schema_version": lock.schema_version,
        "extension_api": lock.extension_api,
        "packs": [
            {
                "name": pack.name,
                "distribution": pack.distribution,
                "version": pack.version,
                "rules": dict(sorted(pack.rules.items())),
                "evaluators": list(pack.evaluators),
                "targets": list(pack.targets),
                "taxonomies": dict(sorted(pack.taxonomies.items())),
            }
            for pack in sorted(lock.packs, key=lambda p: p.name)
        ],
        "unlocked": list(lock.unlocked),
    }


def lock_from_dict(raw: object, source: str) -> Lock:
    """Read a lock, refusing anything it cannot read exactly.

    Refused rather than partially read, for the reason every other loader here
    refuses: a lock understood in part is a gate that passes on the part it
    understood, and a gate that passes for the wrong reason is worse than no gate.
    """
    if not isinstance(raw, dict):
        raise PackError(f"invalid lock {source}: the file must be a mapping")
    version = raw.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise PackError(f"invalid lock {source}: schema_version is required and must be an integer")
    if version != LOCK_SCHEMA_VERSION:
        raise PackError(
            f"invalid lock {source}: schema_version {version} is not the version this "
            f"build reads ({LOCK_SCHEMA_VERSION}) — regenerate it with `guardana pack lock`"
        )
    packs = raw.get("packs")
    if not isinstance(packs, list):
        raise PackError(f"invalid lock {source}: 'packs' must be a list")
    return Lock(
        packs=tuple(_pack(entry, source) for entry in packs),
        unlocked=_strings(raw.get("unlocked"), "unlocked", source),
        schema_version=version,
        extension_api=_api(raw.get("extension_api"), source),
    )


def incomparable(locked: Lock, installed: Lock) -> str | None:
    """Why these two locks cannot be compared at all, or None when they can.

    Asked before `compare`, because this is not a difference between two builds —
    it is the two builds not sharing the vocabulary a difference would be expressed
    in. `Rule.digest()` covers the fields of `RuleMeta`, and `extension_api` moving
    is precisely what changes those fields, so a digest taken under one contract and
    one taken under another are not the same measurement even when they are equal.

    This is the comparison `_api` refuses a lock without the field *for*. It was
    required on read from the first release and read by nothing, so a lock taken
    against another contract reported every pack as matching.

    Reported as a refusal rather than as drift: every rule would come back `changed`
    with a detail naming the wrong cause, and the answer to all of them is the one
    sentence below.
    """
    if locked.extension_api != installed.extension_api:
        return (
            f"the lock was taken against extension_api {locked.extension_api} and this "
            f"build implements {installed.extension_api}, so what it pins was measured "
            f"under a different contract — regenerate it with `guardana pack lock`"
        )
    return None


def compare(locked: Lock, installed: Lock) -> tuple[Drift, ...]:
    """Every way what is installed differs from what was locked.

    Both directions, always. A missing rule is coverage a team still believes they
    have; an added one is a check nobody reviewed running against production. Only
    reporting the first would make the lock a floor rather than a pin.
    """
    drift: list[Drift] = []
    by_name = {pack.name: pack for pack in installed.packs}
    for pack in locked.packs:
        present = by_name.get(pack.name)
        if present is None:
            drift.append(
                Drift(
                    DriftKind.PACK_MISSING,
                    pack.name,
                    f"locked at {pack.distribution} {pack.version} and not installed, so every "
                    f"check it provides is missing from this run",
                )
            )
            continue
        drift.extend(_pack_drift(pack, present))
    for name in sorted(set(by_name) - {pack.name for pack in locked.packs}):
        pack = by_name[name]
        drift.append(
            Drift(
                DriftKind.PACK_UNLOCKED,
                name,
                f"{pack.distribution} {pack.version} is installed and the lock does not "
                f"mention it — a pack nobody pinned is running here",
            )
        )
    drift.extend(_membership(locked.unlocked, installed.unlocked, "extension outside any pack"))
    return tuple(drift)


def _pack_drift(locked: LockedPack, installed: LockedPack) -> list[Drift]:
    drift: list[Drift] = []
    if locked.version != installed.version:
        drift.append(
            Drift(
                DriftKind.VERSION_CHANGED,
                locked.name,
                f"locked at {locked.version}, installed {installed.version}",
            )
        )
    drift.extend(_digests(locked.name, locked.rules, installed.rules, "rule"))
    drift.extend(_digests(locked.name, locked.taxonomies, installed.taxonomies, "catalogue"))
    drift.extend(_membership(locked.evaluators, installed.evaluators, "evaluator"))
    drift.extend(_membership(locked.targets, installed.targets, "target"))
    return drift


def _digests(
    pack: str, locked: Mapping[str, str], installed: Mapping[str, str], what: str
) -> list[Drift]:
    return [
        *_membership(tuple(locked), tuple(installed), what, pack),
        *(
            Drift(
                DriftKind.CHANGED,
                name,
                f"{what} is pinned at {locked[name]} and this build has "
                f"{installed[name]} — it is not the same check any more",
            )
            for name in sorted(set(locked) & set(installed))
            if locked[name] != installed[name]
        ),
    ]


def _membership(
    locked: Sequence[str], installed: Sequence[str], what: str, pack: str = ""
) -> list[Drift]:
    owner = f" by {pack}" if pack else ""
    return [
        *(
            Drift(DriftKind.REMOVED, name, f"{what} was locked{owner} and is gone")
            for name in sorted(set(locked) - set(installed))
        ),
        *(
            Drift(DriftKind.ADDED, name, f"{what} is installed and was never locked")
            for name in sorted(set(installed) - set(locked))
        ),
    ]


def _pack(raw: object, source: str) -> LockedPack:
    if not isinstance(raw, dict):
        raise PackError(f"invalid lock {source}: every entry in 'packs' must be a mapping")
    return LockedPack(
        name=_text(raw, "name", source),
        distribution=_text(raw, "distribution", source),
        version=_text(raw, "version", source),
        rules=_digest_map(raw.get("rules"), "rules", source),
        evaluators=_strings(raw.get("evaluators"), "evaluators", source),
        targets=_strings(raw.get("targets"), "targets", source),
        taxonomies=_digest_map(raw.get("taxonomies"), "taxonomies", source),
    )


def _digest_map(raw: object, key: str, source: str) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict) or not all(
        isinstance(name, str) and isinstance(value, str) for name, value in raw.items()
    ):
        raise PackError(f"invalid lock {source}: '{key}' must map every id to a digest string")
    return dict(raw)


def _strings(raw: object, key: str, source: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise PackError(f"invalid lock {source}: '{key}' must be a list of strings")
    return tuple(raw)


def _text(raw: dict[str, Any], key: str, source: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PackError(f"invalid lock {source}: every pack needs a non-empty '{key}'")
    return value


def _api(raw: object, source: str) -> int:
    if not isinstance(raw, int) or isinstance(raw, bool):
        raise PackError(
            f"invalid lock {source}: 'extension_api' is required and must be an integer — "
            f"a lock that does not say which contract it was taken against cannot be "
            f"compared against a build that implements a different one"
        )
    return raw
