"""`rules.json` and `rule-catalog.md` are one registry walk, so they must agree.

The site's rule explorer is built from the JSON and the documentation table is
rendered from the markdown. Two renderings of one walk is the cheap arrangement;
what it buys is that neither can quietly stop describing what ships. The landing
page drifting from the registry is this project's own worked example, and an
explorer is a bigger surface to drift on — it states a severity, a cost and a
framework entry for every rule rather than one total.

The comparison is deliberately across *both* generated files rather than each one
against the registry separately. Checked separately, both pass while a reader is
shown two different catalogues.
"""

import json
import re
from pathlib import Path
from typing import cast

from guardana.core.surface import Surface
from guardana.rules import provide_rules

_ROW = re.compile(r"^\| `([^`]+)` \| (\w+) \| (\w+) \| (.+) \|$", re.MULTILINE)


def _generated(name: str) -> str:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "docs" / "generated" / name
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise AssertionError(f"could not locate docs/generated/{name}")


def _catalog_rows() -> dict[str, tuple[str, str, str]]:
    rows = _ROW.findall(_generated("rule-catalog.md"))
    assert rows, "rule-catalog.md no longer has rows in the form this test reads"
    return {rule_id: (severity, surface, maps_to) for rule_id, severity, surface, maps_to in rows}


def _rules_json() -> dict[str, dict[str, object]]:
    document = json.loads(_generated("rules.json"))
    return {str(entry["id"]): entry for entry in document["rules"]}


def test_both_generated_files_describe_the_same_set_of_rules() -> None:
    catalogued = set(_catalog_rows())
    in_json = set(_rules_json())

    assert catalogued == in_json, (
        f"only in rule-catalog.md: {sorted(catalogued - in_json)}; "
        f"only in rules.json: {sorted(in_json - catalogued)}"
    )


def test_severity_surface_and_framework_mapping_agree_between_the_two() -> None:
    rows = _catalog_rows()
    disagreements = []
    for rule_id, entry in _rules_json().items():
        severity, surface, maps_to = rows[rule_id]
        listed = {reference.strip(" `") for reference in maps_to.split(",")}
        taxonomy = cast("list[dict[str, object]]", entry["taxonomy"])
        stated = {str(ref["reference"]) for ref in taxonomy}
        if (severity, surface) != (entry["severity"], entry["surface"]) or listed != stated:
            disagreements.append(
                f"{rule_id}: table says {severity}/{surface}/{sorted(listed)}, "
                f"json says {entry['severity']}/{entry['surface']}/{sorted(stated)}"
            )

    assert not disagreements, "\n  ".join(disagreements)


def test_the_json_describes_the_registry_that_is_installed() -> None:
    """The half a comparison between two generated files cannot catch.

    Both are written by one script, so both stay wrong together if the script is
    wrong. This asks the registry, which is what the explorer claims to describe.
    """
    entries = _rules_json()
    installed = {rule.meta.id: rule for rule in provide_rules()}

    assert set(entries) == set(installed)
    for rule_id, rule in installed.items():
        entry = entries[rule_id]
        assert entry["severity"] == rule.meta.severity.name
        assert entry["surface"] == rule.meta.surface.value
        assert entry["impact"] == str(rule.meta.impact)
        assert entry["destructive"] == rule.meta.destructive
        assert entry["maturity"] == str(rule.meta.maturity)
        assert entry["evaluator"] == rule.meta.evaluator
        assert entry["estimated_requests"] == rule.estimated_requests
        assert entry["requires"] == sorted(str(c) for c in rule.meta.required_capabilities)


def test_the_surface_split_in_the_json_matches_the_one_the_summary_states() -> None:
    """The count the landing page and llms.txt both quote, reaching the explorer intact."""
    entries = list(_rules_json().values())
    build = sum(1 for entry in entries if entry["surface"] == Surface.BUILD.value)
    runtime = sum(1 for entry in entries if entry["surface"] == Surface.RUNTIME.value)

    summary = _generated("rule-summary.md")

    assert f"| Build-time (`scan`) | {build} |" in summary
    assert f"| Runtime (`probe`, `monitor`) | {runtime} |" in summary
    assert f"**{build + runtime} built-in rules**" in summary
