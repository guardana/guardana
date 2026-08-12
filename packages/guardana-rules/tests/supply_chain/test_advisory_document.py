"""The advisory dataset: a document Guardana ships and a team may replace.

`load_advisories(path)` takes anyone's file, so this is a schema with third-party
writers even though the only one today is us. A key it silently ignores is a
statement an advisory author made about a package and Guardana did not act on —
which, for a dataset whose whole job is to say "this release is malicious", is the
quiet direction.

There is no writer to compare against, so the trip is one-way and the question is
the one that found the last two document defects: can a key be removed with nothing
changing.
"""

import json
from pathlib import Path
from typing import Any

from _roundtrip import Document, unread_keys
from guardana.core.rule import RuleLoadError
from guardana.rules.supply_chain._advisories import (
    SCHEMA_VERSION,
    load_advisories,
)


def _dataset() -> Document:
    """One advisory carrying every field the parser requires."""
    return {
        "schema_version": SCHEMA_VERSION,
        "advisories": [
            {
                "id": "ACME-ADV-2026-0001",
                "package": "acme-ml",
                "kind": "malicious_release",
                "versions": ["1.4.2", ">=2.0,<2.1"],
                "severity": "critical",
                "summary": "a post-install hook exfiltrates the training corpus",
                "reference": "https://acme.example/advisories/0001",
            }
        ],
    }


def test_the_bundled_dataset_declares_the_version_the_parser_requires() -> None:
    """Read through the shipped path, so the file that actually ships is the one checked."""
    assert load_advisories()


def test_no_key_of_an_advisory_dataset_can_be_deleted_without_the_loader_noticing(
    tmp_path: Path,
) -> None:
    def read(document: Document) -> object:
        path = tmp_path / "advisories.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return load_advisories(path)

    ignored = unread_keys(_dataset(), read, root="advisories", refusal=RuleLoadError)

    assert not ignored, (
        "keys an advisory dataset carries that the loader ignores, so an author's "
        "statement about a package never reaches a finding:\n  " + "\n  ".join(ignored)
    )


def test_an_advisory_reaches_the_rule_with_every_field_it_declared(tmp_path: Path) -> None:
    """The other half: parsed is not the same as carried into what a reader sees."""
    document: dict[str, Any] = dict(_dataset())
    path = tmp_path / "advisories.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    declared = document["advisories"][0]

    (advisory,) = load_advisories(path)

    assert advisory.id == declared["id"]
    assert advisory.package == declared["package"]
    assert advisory.kind == declared["kind"]
    assert advisory.versions == tuple(declared["versions"])
    assert advisory.severity.name == declared["severity"].upper()
    assert advisory.summary == declared["summary"]
    assert advisory.reference == declared["reference"]
    assert advisory.matches("1.4.2")
    assert advisory.matches("2.0.7")
    assert not advisory.matches("2.1.0")
