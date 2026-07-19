"""The dashboard shows a human name/description per rule from the server's
`catalog/en.json`; a rule that ships without an entry would appear there as a bare
id. Pin the catalog to the registry — like `test_features_doc` pins FEATURES.md —
so the two cannot drift."""

import json
from pathlib import Path

from guardana.rules import provide_rules

_CATALOG_REL = Path("packages/guardana-server/src/guardana/server/catalog/en.json")


def _catalog() -> dict[str, dict[str, str]]:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / _CATALOG_REL
        if candidate.is_file():
            rules: dict[str, dict[str, str]] = json.loads(candidate.read_text(encoding="utf-8"))[
                "rules"
            ]
            return rules
    raise AssertionError("could not locate the server rule catalog en.json")


def test_every_builtin_rule_has_a_catalog_entry() -> None:
    catalog = _catalog()
    missing = [rule.meta.id for rule in provide_rules() if rule.meta.id not in catalog]
    assert not missing, f"catalog/en.json does not describe rule(s): {missing}"


def test_every_catalog_entry_has_a_name_and_description() -> None:
    catalog = _catalog()
    for rule in provide_rules():
        entry = catalog[rule.meta.id]
        assert entry.get("name"), f"{rule.meta.id}: missing name"
        assert entry.get("description"), f"{rule.meta.id}: missing description"
