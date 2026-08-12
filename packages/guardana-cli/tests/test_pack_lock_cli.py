"""`guardana pack lock` against the build that is actually installed.

The unit tests build a `Lock` from fixtures, which proves the comparison and proves
nothing about whether the command can pin this machine. That distinction has cost
this project real defects twice: a seam nothing runs is a seam nobody has run, and
the pack-manifest work found its own version of it — a distribution resolved through
the PEP 420 namespace, which named the wrong package and read an empty version, and
looked entirely fine until somebody read the file.

So these tests write a lock from the live registry and read the file.
"""

from pathlib import Path

import yaml
from guardana.cli.main import app
from guardana.core.pack.lock import LOCK_SCHEMA_VERSION
from typer.testing import CliRunner

runner = CliRunner()


def _lock(tmp_path: Path) -> Path:
    path = tmp_path / "guardana-lock.yaml"
    result = runner.invoke(app, ["pack", "lock", str(path)])
    assert result.exit_code == 0, result.output
    return path


def test_a_lock_written_here_names_the_distribution_that_ships_the_pack(tmp_path: Path) -> None:
    """The trap the namespace sets: `guardana` is five distributions, not one.

    Resolving the owner by top-level import name answers with whichever distribution
    sorts first, so every built-in rule was pinned to a package that does not ship
    it, at a version that could not be read. The file said so; nothing else did.
    """
    document = yaml.safe_load(_lock(tmp_path).read_text(encoding="utf-8"))

    (builtin,) = [pack for pack in document["packs"] if pack["name"] == "guardana-rules"]
    assert builtin["distribution"] == "guardana-rules"
    assert builtin["version"], "the lock recorded no version for the pack shipping the built-ins"


def test_a_lock_pins_the_built_in_rules_by_digest(tmp_path: Path) -> None:
    document = yaml.safe_load(_lock(tmp_path).read_text(encoding="utf-8"))

    (builtin,) = [pack for pack in document["packs"] if pack["name"] == "guardana-rules"]
    assert builtin["rules"]["guardana.prompt.system_prompt_leak.canary"]
    assert document["schema_version"] == LOCK_SCHEMA_VERSION


def test_an_unchanged_build_checks_clean(tmp_path: Path) -> None:
    path = _lock(tmp_path)

    result = runner.invoke(app, ["pack", "lock", str(path), "--check"])

    assert result.exit_code == 0, result.output
    assert "match" in result.output


def test_a_rule_whose_digest_moved_fails_the_check(tmp_path: Path) -> None:
    """The behaviour the whole feature is for, exercised through the command.

    Edited in the lock rather than in a rule, because the point is what the *check*
    concludes when the two disagree — and a build whose rules were really edited
    could not then be restored for the next test.
    """
    path = _lock(tmp_path)
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["packs"][0]["rules"]["guardana.prompt.system_prompt_leak.canary"] = "0000000000000000"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    result = runner.invoke(app, ["pack", "lock", str(path), "--check"])

    assert result.exit_code == 1, result.output
    assert "not the same check any more" in result.output


def test_a_pack_the_lock_names_and_this_build_lacks_fails_the_check(tmp_path: Path) -> None:
    path = _lock(tmp_path)
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["packs"].append(
        {"name": "acme-guardana-rules", "distribution": "acme-guardana-rules", "version": "0.3.1"}
    )
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    result = runner.invoke(app, ["pack", "lock", str(path), "--check"])

    assert result.exit_code == 1, result.output
    assert "pack_missing" in result.output


def test_an_unreadable_lock_is_refused_rather_than_treated_as_empty(tmp_path: Path) -> None:
    """An empty lock would match nothing and report every pack as unlocked — or, worse
    for a build with no packs, match everything. Refused with its own code instead."""
    path = tmp_path / "guardana-lock.yaml"
    path.write_text("schema_version: 99\npacks: []\n", encoding="utf-8")

    result = runner.invoke(app, ["pack", "lock", str(path), "--check"])

    assert result.exit_code == 3, result.output
    assert "regenerate it" in result.output


def test_a_missing_lock_is_refused_rather_than_written_silently(tmp_path: Path) -> None:
    """`--check` never writes. A check that created what it was asked to compare against
    would pass on every first run, which is the one run nobody looks at."""
    result = runner.invoke(app, ["pack", "lock", str(tmp_path / "absent.yaml"), "--check"])

    assert result.exit_code == 3, result.output
    assert not (tmp_path / "absent.yaml").exists()
