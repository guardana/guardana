import json
from pathlib import Path

import pytest
from guardana.core.rule import RuleLoadError
from guardana.core.severity import Severity
from guardana.rules.supply_chain._advisories import ADVISORY_KINDS, load_advisories, version_matches


def _write(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "advisories.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_the_bundled_dataset_loads() -> None:
    advisories = load_advisories()
    assert advisories
    assert {advisory.package for advisory in advisories} >= {"ultralytics", "transformers"}


def test_every_bundled_advisory_is_sourced_and_typed() -> None:
    # An advisory nobody can check is an assertion, not evidence.
    for advisory in load_advisories():
        assert advisory.reference.startswith("https://"), advisory.id
        assert advisory.kind in ADVISORY_KINDS, advisory.id
        assert advisory.versions, advisory.id


@pytest.mark.parametrize(
    ("spec", "version", "expected"),
    [
        ("8.3.41", "8.3.41", True),
        ("8.3.41", "8.3.410", False),
        ("<5.3.0", "4.57.0", True),
        ("<5.3.0", "5.3.0", False),
        ("<5.3.0", "5.4.1", False),
        (">=3.0.0,<3.11.3", "3.10.0", True),
        (">=3.0.0,<3.11.3", "2.15.0", False),
        (">=3.0.0,<3.11.3", "3.11.3", False),
        ("*", "0.0.1", True),
        ("<2.6.0", "2.6.0rc1", False),
        ("<5.3.0", "not-a-version", False),
    ],
)
def test_version_matching(spec: str, version: str, expected: bool) -> None:
    assert version_matches(spec, version) is expected


def test_a_malformed_dataset_fails_loudly(tmp_path: Path) -> None:
    # A dataset that silently loads as empty would turn a blocklist into a
    # rubber stamp — exactly the gate-you-think-you-configured failure.
    path = tmp_path / "advisories.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(RuleLoadError, match="advisor"):
        load_advisories(path)


def test_an_unknown_key_is_rejected(tmp_path: Path) -> None:
    document = {
        "schema_version": 1,
        "advisories": [
            {
                "id": "X",
                "package": "p",
                "kind": "malicious_release",
                "versions": ["1.0"],
                "severity": "high",
                "summary": "s",
                "reference": "https://example.invalid",
                "typo": 1,
            }
        ],
    }
    with pytest.raises(RuleLoadError, match="typo"):
        load_advisories(_write(tmp_path, document))


def test_an_unknown_kind_is_rejected(tmp_path: Path) -> None:
    document = {
        "schema_version": 1,
        "advisories": [
            {
                "id": "X",
                "package": "p",
                "kind": "rumour",
                "versions": ["1.0"],
                "severity": "high",
                "summary": "s",
                "reference": "https://example.invalid",
            }
        ],
    }
    with pytest.raises(RuleLoadError, match="kind"):
        load_advisories(_write(tmp_path, document))


def test_a_future_schema_version_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(RuleLoadError, match="schema_version"):
        load_advisories(_write(tmp_path, {"schema_version": 99, "advisories": []}))


def test_a_bad_severity_is_rejected(tmp_path: Path) -> None:
    document = {
        "schema_version": 1,
        "advisories": [
            {
                "id": "X",
                "package": "p",
                "kind": "malicious_release",
                "versions": ["1.0"],
                "severity": "apocalyptic",
                "summary": "s",
                "reference": "https://example.invalid",
            }
        ],
    }
    with pytest.raises(RuleLoadError, match="severity"):
        load_advisories(_write(tmp_path, document))


def test_a_valid_custom_dataset_loads(tmp_path: Path) -> None:
    document = {
        "schema_version": 1,
        "advisories": [
            {
                "id": "ACME-1",
                "package": "acme-ml",
                "kind": "malicious_release",
                "versions": ["1.0"],
                "severity": "critical",
                "summary": "s",
                "reference": "https://example.invalid",
            }
        ],
    }
    advisories = load_advisories(_write(tmp_path, document))
    assert advisories[0].severity is Severity.CRITICAL


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "not a JSON object"),
        ({"schema_version": 1, "advisories": {}}, "must be a list"),
        ({"schema_version": 1, "advisories": [42]}, "must be an object"),
        ({"schema_version": 1, "advisories": [{"id": "X", "package": "p"}]}, "missing"),
        (
            {
                "schema_version": 1,
                "advisories": [
                    {
                        "id": "X",
                        "package": "p",
                        "kind": "malicious_release",
                        "versions": [],
                        "severity": "high",
                        "summary": "s",
                        "reference": "https://example.invalid",
                    }
                ],
            },
            "non-empty list",
        ),
    ],
)
def test_a_dataset_we_cannot_fully_understand_is_refused(
    tmp_path: Path, document: object, message: str
) -> None:
    with pytest.raises(RuleLoadError, match=message):
        load_advisories(_write(tmp_path, document))


def test_an_unparseable_comparator_bound_never_matches() -> None:
    assert version_matches("<not.a.version", "1.0.0") is False
    assert version_matches("~=1.0", "1.0") is False
