"""Documents written by published releases still read with today's readers.

`historical/` holds what each release from 0.2.0 on wrote when it was fed synthetic
inputs, captured by `scripts/capture_historical_documents.py` and kept whenever a
kind's shape changed, and the profile examples each release's own documentation showed
and that release loaded. The in-code builders in `_documents.py` test single fields;
this tests what an older writer actually wrote or accepted. The envelopes are read by
the collector's own suite.
"""

import json
import re
from collections.abc import Iterator
from itertools import pairwise
from pathlib import Path

import pytest
import yaml
from guardana.cli.main import app
from guardana.core.dataset import READ_FORMATS, read_dataset
from guardana.core.pack import LOCK_SCHEMA_VERSION, lock_from_dict
from guardana.core.pack.load import load_manifest
from guardana.core.pack.model import PACK_SCHEMA_VERSION
from guardana.core.profile.loader import PROFILE_SCHEMA_VERSION, load_profile
from guardana.core.report import REPORT_SCHEMA_VERSION, ReportLoadError, load_report
from guardana.core.report.load import MIGRATABLE_VERSIONS
from guardana.core.reporter import ENVELOPE_SCHEMA_VERSION
from guardana.core.verify import load_verification
from typer.testing import CliRunner

HISTORICAL = Path(__file__).parent / "historical"
RELEASES = HISTORICAL / "releases.json"

_RUN_KINDS = ("run", "probe-run")
_KINDS = ("run", "probe-run", "envelope", "profile", "pack-manifest", "pack-lock", "dataset")
_PERSISTED = ("run", "envelope", "pack-manifest", "pack-lock", "dataset", "profile")

_LEAK_MARKERS = ("/Users/", "/home/", "C:\\", "/private/", "/tmp/", "/var/")  # noqa: S108
_RULE_TEXT_PATHS = ("/tmp/session-42.log",)  # noqa: S108
"""Paths a built-in rule writes into the prompts it sends, quoted back in evidence."""

_OLDEST_ENVELOPE = 2
"""The oldest envelope a collector accepts; every one from it up to the current is read."""

_ACCEPTED: dict[str, frozenset[int]] = {
    "run": frozenset(MIGRATABLE_VERSIONS) | {REPORT_SCHEMA_VERSION},
    "envelope": frozenset(range(_OLDEST_ENVELOPE, ENVELOPE_SCHEMA_VERSION + 1)),
    "pack-manifest": frozenset(range(1, PACK_SCHEMA_VERSION + 1)),
    "pack-lock": frozenset(range(1, LOCK_SCHEMA_VERSION + 1)),
    "dataset": frozenset(READ_FORMATS),
    "profile": frozenset(range(1, PROFILE_SCHEMA_VERSION + 1)),
}
"""Every version each persisted kind's reader accepts."""

NOT_EXERCISED: dict[tuple[str, int], str] = {
    ("envelope", 6): "no release on PyPI wrote it: 0.8.0 writes 5 and 0.9.1 writes 7",
    ("pack-manifest", 1): (
        "no release with schema 1 has `pack lock` to accept a pack; the hand-written 0.19.1 "
        "manifest in pack_manifests/ is that version"
    ),
    ("pack-manifest", 3): (
        "written only for a pack that declares an output; neither the captured hand-written "
        "pack nor the one `new-pack` scaffolds declares one"
    ),
    ("pack-lock", 3): (
        "written only when a pack pins an output; no captured pack declares one, so every "
        "release writes 1 or 2"
    ),
}
"""Versions a reader accepts that no stored document declares, each with the reason."""

_MIGRATED_NOTE = "migrated from an older saved-run schema"

runner = CliRunner()


def _releases() -> dict[str, dict[str, object]]:
    loaded = json.loads(RELEASES.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise TypeError(f"{RELEASES} is not an object")
    return loaded


def _release_order(path: Path) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", path.stem))


def _stored(kind: str) -> list[Path]:
    return sorted((HISTORICAL / kind).glob("*"), key=_release_order)


def _documents() -> Iterator[Path]:
    for kind in _KINDS:
        yield from _stored(kind)


def _declared(kind: str, path: Path) -> int | None:
    text = path.read_text(encoding="utf-8")
    if kind == "dataset":
        header = json.loads(text.splitlines()[0])
        value = header.get("guardana_dataset")
    else:
        document = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
        value = document.get("schema_version") if isinstance(document, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _plain(text: str) -> str:
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", text).split())


def _ci_fields(node: object, at: str = "") -> Iterator[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{at}.{key}" if at else str(key)
            if key in ("ci", "run_url") and value is not None:
                yield here
            if key == "source" and isinstance(value, dict) and value.get("kind") == "ci":
                yield here
            yield from _ci_fields(value, here)
    elif isinstance(node, list):
        for item in node:
            yield from _ci_fields(item, f"{at}[]")


def test_the_corpus_holds_documents_of_every_kind() -> None:
    """An empty or half-written corpus would make every test below pass on nothing."""
    for kind in _KINDS:
        assert _stored(kind), f"historical/{kind}/ holds no document"


def _profile_examples(release: dict[str, object]) -> list[dict[str, object]]:
    entry = release["profile_examples"]
    assert isinstance(entry, dict)
    if entry["tried"] is False:
        return []
    examples = entry["examples"]
    assert isinstance(examples, list)
    return examples


def test_the_release_record_names_exactly_the_stored_documents() -> None:
    named: set[str] = set()
    for release in _releases().values():
        kinds = release["kinds"]
        assert isinstance(kinds, dict)
        named |= {
            str(e["stored"]) for e in kinds.values() if isinstance(e, dict) and e.get("stored")
        }
        named |= {str(e["stored"]) for e in _profile_examples(release) if e.get("stored")}
    on_disk = {str(path.relative_to(HISTORICAL)) for path in _documents()}

    assert named == on_disk


def test_every_release_says_for_each_kind_what_it_produced_or_why_not() -> None:
    for version, release in _releases().items():
        kinds = release["kinds"]
        assert isinstance(kinds, dict)
        assert set(kinds) == set(_KINDS), version
        for kind, entry in kinds.items():
            assert isinstance(entry, dict)
            if entry["produced"] is False:
                assert str(entry["why"]).strip(), f"{version} {kind}: no document and no why"
        assert isinstance(release["exclude_newer"], str)


@pytest.mark.parametrize("path", list(_documents()), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_no_stored_document_holds_a_local_path_or_a_ci_field(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for quoted in _RULE_TEXT_PATHS:
        text = text.replace(quoted, "")

    assert [marker for marker in _LEAK_MARKERS if marker in text] == []
    if path.suffix == ".json":
        assert list(_ci_fields(json.loads(text))) == []


def test_every_release_says_where_each_profile_example_came_from_and_what_it_did() -> None:
    for version, release in _releases().items():
        entry = release["profile_examples"]
        assert isinstance(entry, dict)
        if entry["tried"] is False:
            assert str(entry["why"]).strip(), f"{version}: no example tried and no why"
        for example in _profile_examples(release):
            where = f"{version} example {example['n']}"
            assert example["tag"] == f"v{version}", where
            assert str(example["doc"]).startswith("docs/"), where
            assert isinstance(example["block"], int), where
            assert example["block"] >= 1, where
            loaded = example["loaded"]
            assert loaded is None or isinstance(loaded, bool), f"{where}: loaded is {loaded!r}"
            if loaded is None:
                assert str(example["why"]).strip(), f"{where}: not tried with no reason"
                assert "stored" not in example, f"{where}: an example not tried was stored"
                assert "loaded_by" not in example, f"{where}: an example not tried was loaded"
                continue
            if loaded is False:
                assert str(example["why"]).strip(), f"{where}: refused with no reason"
                assert "stored" not in example, f"{where}: a refused example was stored"
                continue
            assert example["loaded_by"] in {"scan", "probe"}, where
            if example["stored"]:
                assert example["stored"] == f"profile/{version}-{example['n']}.yaml", where


def test_the_corpus_holds_profile_examples_a_release_loaded_and_one_it_refused() -> None:
    """Without both, the example capture could have tried nothing and still read as green."""
    examples = [e for release in _releases().values() for e in _profile_examples(release)]

    assert [e for e in examples if e.get("stored")]
    assert [e for e in examples if e["loaded"] is False]


@pytest.mark.parametrize(
    "path",
    [path for kind in _RUN_KINDS for path in _stored(kind)],
    ids=lambda p: f"{p.parent.name}/{p.name}",
)
def test_every_stored_run_loads_migrates_and_yields_its_recorded_verdict(
    path: Path, tmp_path: Path
) -> None:
    declared = _declared(path.parent.name, path)

    report = load_report(path)
    migrated = tmp_path / "migrated.json"
    result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(migrated)])

    assert result.exit_code == 0, result.output
    current = declared == REPORT_SCHEMA_VERSION
    assert report.manifest.migrated_from == (None if current else declared)
    if not current:
        assert json.loads(migrated.read_text(encoding="utf-8"))["schema_version"] == (
            REPORT_SCHEMA_VERSION
        )
        load_report(migrated)
    if declared == 1:
        with pytest.raises(ReportLoadError, match="records no gate"):
            load_verification(path)
    else:
        assert load_verification(path).gate is not None


def _consecutive(kind: str) -> list[tuple[Path, Path]]:
    return list(pairwise(_stored(kind)))


@pytest.mark.parametrize(
    ("before", "after"),
    [pair for kind in _RUN_KINDS for pair in _consecutive(kind)],
    ids=lambda p: f"{p.parent.name}/{p.name}",
)
def test_each_pair_of_consecutive_runs_compares(before: Path, after: Path) -> None:
    result = runner.invoke(app, ["diff", str(before), str(after)])

    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    assert result.exit_code in {0, 1, 2}, result.output
    assert "cannot compare these runs" not in result.output
    migrated = any(
        _declared(path.parent.name, path) != REPORT_SCHEMA_VERSION for path in (before, after)
    )
    assert (_MIGRATED_NOTE in _plain(result.output)) is migrated, result.output


@pytest.mark.parametrize("path", _stored("profile"), ids=lambda p: p.name)
def test_every_stored_profile_loads(path: Path) -> None:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))

    profile = load_profile(path)

    assert profile.name == str(document.get("name", "custom"))


@pytest.mark.parametrize("path", _stored("pack-manifest"), ids=lambda p: p.name)
def test_every_stored_pack_manifest_loads(path: Path) -> None:
    manifest = load_manifest(path)

    assert manifest.rules


@pytest.mark.parametrize("path", _stored("pack-lock"), ids=lambda p: p.name)
def test_every_stored_lock_loads(path: Path) -> None:
    lock = lock_from_dict(yaml.safe_load(path.read_text(encoding="utf-8")), str(path))

    assert lock.packs


@pytest.mark.parametrize("path", _stored("dataset"), ids=lambda p: p.name)
def test_every_stored_dataset_loads_in_the_format_it_declares(path: Path) -> None:
    dataset = read_dataset(path)

    assert dataset.format == _declared("dataset", path)
    assert dataset.cases


def _stored_versions(kind: str) -> set[int]:
    kinds = _RUN_KINDS if kind == "run" else (kind,)
    return {
        version
        for each in kinds
        for path in _stored(each)
        if (version := _declared(each, path)) is not None
    }


@pytest.mark.parametrize("kind", _PERSISTED)
def test_every_version_a_reader_accepts_has_a_stored_document_or_a_reason(kind: str) -> None:
    stored = _stored_versions(kind)
    excused = {version for (excused_kind, version) in NOT_EXERCISED if excused_kind == kind}

    assert sorted(_ACCEPTED[kind] - stored - excused) == []
    assert sorted(excused & stored) == [], "NOT_EXERCISED excuses a version a document declares"
    assert sorted(excused - _ACCEPTED[kind]) == [], "NOT_EXERCISED names a version nobody reads"
