"""A catalogue this build cannot read exactly is an error, never a partial load.

Framework data is a file now, which moves a class of mistake from Python into YAML —
a mistyped key, an unquoted edition, a relation nobody defined. Every one of them has
to fail at import with the file named, because the alternative is a registry missing
entries and one load-time error per rule that maps to them, a directory away from the
cause. Mapping is mandatory for a rule; a half-loaded catalogue breaks all of them.
"""

from pathlib import Path

import pytest
from guardana.core.taxonomy import Relation, TaxonomyError, TaxonomyRef
from guardana.core.taxonomy._catalog import Correspondence, load_catalog, load_catalogs

_MINIMAL = """\
scheme: ACME
edition: "1"
title: Acme Controls
entries:
  - id: ACME-1
    rank: 1
    title: Change control
"""


def _write(tmp_path: Path, text: str, name: str = "acme.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_a_catalogue_loads_into_references_with_a_digest(tmp_path: Path) -> None:
    catalog = load_catalog(_write(tmp_path, _MINIMAL))

    assert catalog.framework == "ACME-1"
    assert catalog.digest.startswith("sha256:")
    (ref,) = catalog.refs
    assert ref == TaxonomyRef(
        scheme="ACME", id="ACME-1", title="Change control", edition="1", rank=1
    )


def test_the_digest_follows_the_content_and_not_the_formatting(tmp_path: Path) -> None:
    # Hashing bytes would make the digest depend on which line endings a checkout
    # produced, and would call a new comment a changed catalogue.
    reformatted = _MINIMAL.replace("entries:", "# a comment\nentries:") + "\n"
    reworded = _MINIMAL.replace("Change control", "Change management")

    same = load_catalog(_write(tmp_path, reformatted, "a.yaml"))
    different = load_catalog(_write(tmp_path, reworded, "b.yaml"))

    assert same.digest == load_catalog(_write(tmp_path, _MINIMAL, "c.yaml")).digest
    assert different.digest != same.digest


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (_MINIMAL.replace("title: Acme Controls", "titel: Acme Controls"), "unknown catalogue"),
        (_MINIMAL.replace("    rank: 1", "    rnak: 1"), "unknown entry"),
        (_MINIMAL.replace('edition: "1"', "edition: 1"), "quote it"),
        (_MINIMAL.replace("    rank: 1", "    rank: one"), "'rank' must be an integer"),
        ('scheme: ACME\nedition: "1"\ntitle: Acme\nentries: []\n', "non-empty list"),
        ("- not a mapping\n", "must be a mapping"),
        (_MINIMAL + "  - id: ACME-1\n    title: Twice\n", "declared twice"),
    ],
)
def test_a_catalogue_this_build_cannot_read_exactly_is_refused(
    tmp_path: Path, text: str, message: str
) -> None:
    with pytest.raises(TaxonomyError, match=message):
        load_catalog(_write(tmp_path, text))


def test_an_unquoted_edition_is_refused_rather_than_stringified(tmp_path: Path) -> None:
    # `edition: 2026` is an integer in YAML. Coercing it here would let one catalogue
    # say "2026" and another 2026 for the same edition — two identities for one
    # control, which is the entire failure this module exists to prevent.
    with pytest.raises(TaxonomyError, match='edition: "2026"'):
        load_catalog(_write(tmp_path, _MINIMAL.replace('edition: "1"', "edition: 2026")))


def test_a_relation_nobody_defined_is_refused(tmp_path: Path) -> None:
    text = _MINIMAL + "    supersedes:\n      - ref: ACME-0:0\n        relation: sortof\n"

    with pytest.raises(TaxonomyError, match="unknown relation 'sortof'"):
        load_catalog(_write(tmp_path, text))


def test_an_empty_supersedes_block_is_refused(tmp_path: Path) -> None:
    with pytest.raises(TaxonomyError, match="'supersedes' must be a non-empty list"):
        load_catalog(_write(tmp_path, _MINIMAL + "    supersedes: []\n"))


def test_a_crosswalk_entry_is_parsed_with_its_note(tmp_path: Path) -> None:
    text = _MINIMAL + (
        "    supersedes:\n      - ref: ACME-9:0\n        relation: broader\n        note: widened\n"
    )

    catalog = load_catalog(_write(tmp_path, text))

    assert catalog.correspondences == (
        Correspondence(
            subject="ACME-1:1", other="ACME-9:0", relation=Relation.BROADER, note="widened"
        ),
    )


def test_a_directory_with_no_catalogue_is_an_error_not_an_empty_registry(tmp_path: Path) -> None:
    # A build that shipped without its catalogues can resolve no reference at all, so
    # every rule's mapping fails to load. It has to say that once, here.
    with pytest.raises(TaxonomyError, match="cannot resolve any framework reference"):
        load_catalogs(tmp_path)


def test_an_unreadable_file_is_refused_with_its_name(tmp_path: Path) -> None:
    path = _write(tmp_path, "scheme: [unclosed\n")

    with pytest.raises(TaxonomyError, match="cannot read taxonomy catalogue"):
        load_catalog(path)


def test_a_relation_reads_the_same_from_both_sides() -> None:
    assert Relation.BROADER.inverse is Relation.NARROWER
    assert Relation.NARROWER.inverse is Relation.BROADER
    assert Relation.EXACT.inverse is Relation.EXACT
    assert Relation.RELATED.inverse is Relation.RELATED
