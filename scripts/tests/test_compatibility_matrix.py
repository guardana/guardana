"""The compatibility matrix shows what releases were recorded writing, and says when none were.

A row for a release nobody captured would be a claim about documents nobody read, so the page
holds this tree's row alone until the record exists, and a cell the record leaves empty stays
visibly empty.
"""

import json
from pathlib import Path

import pytest

import generate_docs

_THIS_TREE = "| this tree | 3.11, 3.12, 3.13 | "


def _kind(version: int | None, *, produced: bool = True) -> dict[str, object]:
    if not produced:
        return {"produced": False, "why": "no such command"}
    return {"produced": True, "schema_version": version, "stored": None}


def _release(run: int | None, *, extension: int | None, produced: bool = True) -> dict[str, object]:
    return {
        "kinds": {
            "run": _kind(run, produced=produced),
            "envelope": _kind(8),
            "pack-manifest": _kind(2, produced=produced),
            "pack-lock": _kind(1, produced=produced),
            "profile": _kind(None),
        },
        "extension_api_version": extension,
        "output_api_version": None,
        "python_classifiers": ["3.11", "3.12"],
    }


def _history(tmp_path: Path, releases: dict[str, object]) -> Path:
    path = tmp_path / "releases.json"
    path.write_text(json.dumps(releases), encoding="utf-8")
    return path


def test_without_a_record_only_this_tree_has_a_row(tmp_path: Path) -> None:
    page = generate_docs._compatibility_matrix([], tmp_path / "releases.json")
    rows = [line for line in page.splitlines() if line.startswith("| ") and "Release" not in line]

    assert "**Not generated yet.**" in page
    assert len(rows) == 1
    assert rows[0].startswith(_THIS_TREE)


def test_each_minor_release_shows_its_newest_patch_newest_first(tmp_path: Path) -> None:
    history = _history(
        tmp_path,
        {
            "0.17.0": _release(4, extension=None),
            "0.17.1": _release(5, extension=None),
            "0.20.0": _release(6, extension=1),
            "0.5.0": _release(None, extension=None, produced=False),
        },
    )

    page = generate_docs._compatibility_matrix([], history)
    rows = [line for line in page.splitlines() if line.startswith("| ") and "Release" not in line]

    assert "Not generated yet" not in page
    assert rows[0].startswith(_THIS_TREE)
    assert rows[1:] == [
        "| 0.20.0 | 3.11, 3.12 | 6 | 8 | 2 | 1 | — | 1 | — |",
        "| 0.17.1 | 3.11, 3.12 | 5 | 8 | 2 | 1 | — | — | — |",
        "| 0.5.0 | 3.11, 3.12 | — | 8 | — | — | — | — | — |",
    ]


def test_a_candidate_stands_for_its_minor_until_the_final_release_is_recorded(
    tmp_path: Path,
) -> None:
    candidates: dict[str, object] = {
        "0.41.0": _release(17, extension=2),
        "1.0.0rc2": _release(17, extension=2),
        "1.0.0rc10": _release(18, extension=2),
    }
    final: dict[str, object] = {**candidates, "1.0.0": _release(19, extension=2)}

    def rows(history: dict[str, object]) -> list[str]:
        page = generate_docs._compatibility_matrix([], _history(tmp_path, history))
        return [
            line for line in page.splitlines() if line.startswith("| ") and "Release" not in line
        ]

    assert [row.split(" | ")[0] for row in rows(candidates)[1:]] == ["| 1.0.0rc10", "| 0.41.0"]
    assert [row.split(" | ")[0] for row in rows(final)[1:]] == ["| 1.0.0", "| 0.41.0"]


@pytest.mark.parametrize(
    "broken",
    [
        {"0.20.0": {"kinds": {}}},
        {"0.20": _release(6, extension=1)},
        {"0.20.0": {**_release(6, extension=1), "extension_api_version": "2"}},
    ],
)
def test_a_record_the_page_cannot_read_stops_the_generator(
    tmp_path: Path, broken: dict[str, object]
) -> None:
    with pytest.raises(ValueError, match=r"releases\.json: 0\.20\.0|0\.20 is not"):
        generate_docs._compatibility_matrix([], _history(tmp_path, broken))
