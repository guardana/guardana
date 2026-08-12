"""Schema 2: the fourth extension group can be declared, and a v1 manifest still loads.

Two failures this closes, and the second is the sharper one.

`pack validate` was blind to a whole category: a pack could register a control
catalogue through `guardana.taxonomies` and its manifest had nowhere to say so, so
the one command that compares a pack's claims against its registrations had nothing
to compare for catalogues. Worse, a pack whose *only* extension was a catalogue
could not write a valid manifest at all — `provides:` had to list something, and
none of the three things it could list were what that pack shipped. It was also not
discovered, because the group was missing from the discovery list.

The migration is read against the real v1 manifest this repository shipped in
0.19.1, kept in `pack_manifests/` for the reason `saved_runs/` keeps a real saved
run: a migration tested only against a document written by the test is a migration
tested against the writer's idea of the old format.
"""

from pathlib import Path

import pytest
from guardana.core.pack import (
    PACK_SCHEMA_VERSION,
    PackError,
    check_pack,
    load_manifest,
)

_CORPUS = Path(__file__).resolve().parent / "pack_manifests"

_TAXONOMY_ONLY = """
schema_version: 2
name: acme-controls
extension_api: ">=1,<2"
description: Acme's control catalogue, and nothing else.
provides:
  taxonomies: [ACME-CONTROLS]
"""


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "guardana-pack.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_a_pack_that_ships_only_a_catalogue_can_describe_itself(tmp_path: Path) -> None:
    """The manifest that could not be written before, written."""
    manifest = load_manifest(_write(tmp_path, _TAXONOMY_ONLY))

    assert manifest.taxonomies == ("ACME-CONTROLS",)
    assert manifest.provides == ("ACME-CONTROLS",)
    assert manifest.schema_version == PACK_SCHEMA_VERSION
    assert manifest.migrated_from is None


def test_a_taxonomy_only_pack_validates_clean_against_the_catalogue_it_registers(
    tmp_path: Path,
) -> None:
    """Exit `0` and say something true: the pack declares a catalogue and registers it."""
    manifest = load_manifest(_write(tmp_path, _TAXONOMY_ONLY))

    check = check_pack(manifest, ["ACME-CONTROLS", "guardana.prompt.injection"])

    assert check.ok
    assert check.problems == ()


def test_a_catalogue_declared_and_not_registered_is_still_caught(tmp_path: Path) -> None:
    """The direction that matters, extended to the group that had no way to be checked.

    A team reading `taxonomies: [ACME-CONTROLS]` believes their rules' framework
    references resolve. If the entry point does not register the catalogue, every
    one of those references is unresolvable and the manifest said otherwise.
    """
    manifest = load_manifest(_write(tmp_path, _TAXONOMY_ONLY))

    check = check_pack(manifest, ["guardana.prompt.injection"])

    assert not check.ok
    assert "ACME-CONTROLS" in check.problems[0]


def test_the_real_v1_manifest_this_project_shipped_still_loads() -> None:
    """The compatibility corpus, read rather than described.

    `acme-guardana-pack-0.19.1.yaml` is the file `examples/custom_rule` shipped
    before this change — comments, ordering and all. A migration proved only against
    a document the test wrote is a migration proved against the writer's memory of
    the old format.
    """
    manifest = load_manifest(_CORPUS / "acme-guardana-pack-0.19.1.yaml")

    assert manifest.migrated_from == 1
    assert manifest.schema_version == PACK_SCHEMA_VERSION
    assert manifest.rules[0] == "acme.supply_chain.hardcoded_key"
    assert manifest.evaluators == ("acme.strict_refusal",)
    assert manifest.targets == ("AcmePromptLibraryTarget",)
    # It could not name one, so it names none — which is what it meant, not a guess.
    assert manifest.taxonomies == ()


def test_a_v1_manifest_may_not_declare_a_key_its_own_version_did_not_have(
    tmp_path: Path,
) -> None:
    """The migration refuses forward-dated keys rather than reading them optimistically.

    A document claiming schema 1 and carrying a schema 2 key is a document whose
    `schema_version` no longer describes it. Accepting it would make the version a
    decoration — and the next reader, which may be an older build, would silently
    drop the key while this one honoured it.
    """
    body = _TAXONOMY_ONLY.replace("schema_version: 2", "schema_version: 1")

    with pytest.raises(PackError, match="taxonomies"):
        load_manifest(_write(tmp_path, body))


def test_a_manifest_from_a_newer_schema_is_refused(tmp_path: Path) -> None:
    """Both directions, as everywhere else: a build may not guess at a format it postdates."""
    body = _TAXONOMY_ONLY.replace("schema_version: 2", f"schema_version: {PACK_SCHEMA_VERSION + 1}")

    with pytest.raises(PackError, match="newer than this build reads"):
        load_manifest(_write(tmp_path, body))


def test_a_provides_block_that_names_nothing_is_still_refused(tmp_path: Path) -> None:
    """Adding a fourth group must not have created a way to declare an empty pack."""
    body = _TAXONOMY_ONLY.replace("  taxonomies: [ACME-CONTROLS]", "  taxonomies: []")

    with pytest.raises(PackError, match="lists nothing at all"):
        load_manifest(_write(tmp_path, body))
