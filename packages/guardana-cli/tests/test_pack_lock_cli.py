"""`guardana pack lock` against the build that is actually installed.

The unit tests build a `Lock` from fixtures, which proves the comparison and proves
nothing about whether the command can pin this machine. That distinction has cost
this project real defects twice: a seam nothing runs is a seam nobody has run, and
the pack-manifest work found its own version of it — a distribution resolved through
the PEP 420 namespace, which named the wrong package and read an empty version, and
looked entirely fine until somebody read the file.

So these tests write a lock from the live registry and read the file.
"""

import re
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
import yaml
from guardana.cli import pack as pack_command
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.pack import PackDiscovery, discover_packs
from guardana.core.pack.lock import LOCK_SCHEMA_VERSION
from guardana.core.pack.model import EXTENSION_API_VERSION, ApiRange, PackManifest
from guardana.core.plugins import PluginTrust
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
    assert builtin["rules"]["guardana.prompt.system_prompt_leak.canary"]["digest"]
    # Nothing installed pins an output, so the lock stays at the schema older builds read.
    assert document["schema_version"] == 2


_ID_BESIDE_A_DIGEST = re.compile(
    r"^\s*(?!digest:)[^\s:]+:\s+['\"]?(sha256:)?[0-9a-f]{12,}['\"]?\s*$"
)


def test_a_lock_written_here_puts_no_id_on_the_same_line_as_a_digest(tmp_path: Path) -> None:
    """Built-in ids say `secret` and `token`; beside a hex value a secret scanner fires."""
    text = _lock(tmp_path).read_text(encoding="utf-8")

    offending = [line for line in text.splitlines() if _ID_BESIDE_A_DIGEST.match(line)]

    assert re.search(r"secret|token", text), "the live build pins no id the scanner keys on"
    assert not offending, "lines a secret scanner reads as a credential:\n" + "\n".join(offending)


def _as_schema_1(path: Path) -> None:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["schema_version"] = 1
    for pack in document["packs"]:
        for group in ("rules", "taxonomies"):
            pack[group] = {name: entry["digest"] for name, entry in pack[group].items()}
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def test_a_schema_1_lock_still_verifies_and_says_to_rewrite_it(tmp_path: Path) -> None:
    """A teammate's older lock keeps gating; the hint is the only change it sees."""
    path = _lock(tmp_path)
    _as_schema_1(path)

    result = runner.invoke(app, ["pack", "lock", str(path), "--check"])

    assert result.exit_code == 0, result.output
    assert "match" in result.stdout
    assert "lock schema 1" in result.stderr
    assert "guardana pack lock" in result.stderr
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["schema_version"] == 1


def test_a_schema_1_lock_that_drifted_still_fails_the_check(tmp_path: Path) -> None:
    path = _lock(tmp_path)
    _as_schema_1(path)
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["packs"][0]["rules"]["guardana.prompt.system_prompt_leak.canary"] = "0000000000000000"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    result = runner.invoke(app, ["pack", "lock", str(path), "--check"])

    assert result.exit_code == 1, result.output
    assert "not the same check any more" in result.output


def test_a_current_lock_gets_no_rewrite_hint(tmp_path: Path) -> None:
    result = runner.invoke(app, ["pack", "lock", str(_lock(tmp_path)), "--check"])

    assert result.exit_code == 0, result.output
    assert "lock schema 1" not in result.output


def test_an_unchanged_build_checks_clean(tmp_path: Path) -> None:
    path = _lock(tmp_path)

    result = runner.invoke(app, ["pack", "lock", str(path), "--check"])

    assert result.exit_code == 0, result.output
    assert "match" in result.output


def _a_pack_promising(monkeypatch: pytest.MonkeyPatch, manifest: PackManifest) -> None:
    """Make discovery report one more installed pack, declaring `manifest`."""

    def discovered(trust: PluginTrust) -> PackDiscovery:
        found = discover_packs(trust)
        return replace(found, packs=(*found.packs, ("acme-guardana-rules", "0.3.1", manifest)))

    monkeypatch.setattr(pack_command, "discover_packs", discovered)


_PROMISING = PackManifest(
    "acme-guardana-rules", ApiRange(1, 3), "x", rules=("acme.never_registered",)
)


def test_a_lock_is_not_written_while_a_pack_declares_a_rule_nothing_registers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _a_pack_promising(monkeypatch, _PROMISING)
    path = tmp_path / "guardana-lock.yaml"

    result = runner.invoke(app, ["pack", "lock", str(path)])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert not path.exists(), "a partial lock was written"
    assert "acme.never_registered" in result.stderr


def test_a_check_is_refused_while_a_pack_declares_a_rule_nothing_registers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The lock on disk omits the rule too, so comparing would report a match."""
    path = _lock(tmp_path)
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["packs"].append(
        {
            "name": "acme-guardana-rules",
            "distribution": "acme-guardana-rules",
            "version": "0.3.1",
            "rules": {},
            "evaluators": [],
            "targets": [],
            "taxonomies": {},
        }
    )
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    _a_pack_promising(monkeypatch, _PROMISING)

    result = runner.invoke(app, ["pack", "lock", str(path), "--check"])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert "match" not in result.stdout
    assert "acme.never_registered" in result.stderr


def test_a_rule_whose_digest_moved_fails_the_check(tmp_path: Path) -> None:
    """The behaviour the whole feature is for, exercised through the command.

    Edited in the lock rather than in a rule, because the point is what the *check*
    concludes when the two disagree — and a build whose rules were really edited
    could not then be restored for the next test.
    """
    path = _lock(tmp_path)
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["packs"][0]["rules"]["guardana.prompt.system_prompt_leak.canary"] = {
        "digest": "0000000000000000"
    }
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


def test_a_lock_taken_against_another_extension_contract_is_refused(tmp_path: Path) -> None:
    """The field is required on read for exactly this comparison, and was never made.

    `extension_api` is the one thing in the file that says which `Rule` shape the
    digests beside it were computed from. A build implementing a different one
    cannot compare them — `Rule.digest()` covers the fields of `RuleMeta`, and the
    contract moving is what changes those fields. The released build read the number,
    dropped it, and reported "1 pack(s) match" over a lock taken from another
    contract entirely.

    Refused rather than reported as drift: every rule would come back `changed` with
    a reason that names the wrong cause, and the fix is the same one line either way.
    """
    path = _lock(tmp_path)
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["extension_api"] = EXTENSION_API_VERSION + 1
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    result = runner.invoke(app, ["pack", "lock", str(path), "--check"])

    assert result.exit_code == 3, result.output
    assert "extension_api" in result.output


def test_a_lock_taken_against_this_contract_still_checks_clean(tmp_path: Path) -> None:
    """The inversion, so the refusal above cannot be satisfied by refusing every lock."""
    path = _lock(tmp_path)
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert document["extension_api"] == EXTENSION_API_VERSION

    result = runner.invoke(app, ["pack", "lock", str(path), "--check"])

    assert result.exit_code == 0, result.output


def test_an_unreadable_lock_is_refused_rather_than_treated_as_empty(tmp_path: Path) -> None:
    """An empty lock would match nothing and report every pack as unlocked — or, worse
    for a build with no packs, match everything. Refused with its own code instead."""
    path = tmp_path / "guardana-lock.yaml"
    path.write_text("schema_version: 0\npacks: []\n", encoding="utf-8")

    result = runner.invoke(app, ["pack", "lock", str(path), "--check"])

    assert result.exit_code == 3, result.output
    assert "regenerate it" in result.output


@pytest.mark.parametrize(
    "content",
    [b"schema_version: !!int high\npacks: []\n", b"\xff\xfeschema_version: 2\n"],
    ids=["unbuildable-scalar", "not-utf-8"],
)
def test_a_lock_that_is_not_a_yaml_document_is_refused_naming_it(
    tmp_path: Path, content: bytes
) -> None:
    path = tmp_path / "guardana-lock.yaml"
    path.write_bytes(content)

    result = runner.invoke(app, ["pack", "lock", str(path), "--check"])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert f"invalid lock file {path}:" in " ".join(result.output.split())


def test_a_lock_from_a_newer_guardana_is_refused_with_upgrade_not_regenerate(
    tmp_path: Path,
) -> None:
    """Regenerating would overwrite a teammate's newer lock with this build's older layout."""
    path = tmp_path / "guardana-lock.yaml"
    path.write_text(f"schema_version: {LOCK_SCHEMA_VERSION + 1}\npacks: []\n", encoding="utf-8")

    result = runner.invoke(app, ["pack", "lock", str(path), "--check"])

    assert result.exit_code == 3, result.output
    assert "newer Guardana" in result.output
    assert "upgrade" in result.output
    assert "regenerate" not in result.output


def test_a_missing_lock_is_refused_rather_than_written_silently(tmp_path: Path) -> None:
    """`--check` never writes. A check that created what it was asked to compare against
    would pass on every first run, which is the one run nobody looks at."""
    result = runner.invoke(app, ["pack", "lock", str(tmp_path / "absent.yaml"), "--check"])

    assert result.exit_code == 3, result.output
    assert not (tmp_path / "absent.yaml").exists()


def test_a_restrictive_plugin_mode_refuses_to_write_a_false_lock(tmp_path: Path) -> None:
    """A refused entry point used to leave the lock pinning an emptied pack in silence:
    `_installed` reads straight from the registry, so a distribution `--plugins`
    refused was pinned with zero rules, indistinguishable from one that genuinely
    ships none — and the command still said "pinned" and exited `0`. A lock is a
    document a team keeps and reads on every CI run, so writing a false one is
    worse than refusing to write at all: the command must refuse, and the file
    must not exist afterwards.
    """
    path = tmp_path / "guardana-lock.yaml"

    result = runner.invoke(app, ["pack", "lock", str(path), "--plugins", "disabled"])

    assert result.exit_code == 2, result.output
    assert "could not load an extension" in result.stderr
    assert "plugin trust is disabled" in result.stderr
    assert "refused by plugin trust" in result.stderr
    assert "pinned" not in result.stdout
    assert not path.exists()


def test_a_restrictive_plugin_mode_refuses_the_check_too_rather_than_call_it_gone(
    tmp_path: Path,
) -> None:
    """`--check` against a registry with refusals must not report a refused
    extension as `removed` ("is gone") — it is exactly as unproven for a check as
    it is for a fresh write, so the whole comparison is refused the same way.
    """
    path = _lock(tmp_path)

    result = runner.invoke(app, ["pack", "lock", str(path), "--check", "--plugins", "disabled"])

    assert result.exit_code == 2, result.output
    assert "is gone" not in result.output
    assert "removed" not in result.output
    assert "refused by plugin trust" in result.stderr


def test_full_trust_still_checks_clean_after_the_refusal_fix(tmp_path: Path) -> None:
    """The inversion target: refusing on load errors must not become refusing always."""
    path = _lock(tmp_path)

    result = runner.invoke(app, ["pack", "lock", str(path), "--check"])

    assert result.exit_code == 0, result.output
    assert "match" in result.output


@pytest.mark.parametrize("unwritable", ["read-only directory", "directory", "read-only file"])
def test_a_lock_that_cannot_be_written_is_a_usage_error_that_changes_nothing(
    tmp_path: Path, unwritable: str
) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    path = locked if unwritable == "directory" else locked / "guardana-lock.yaml"
    if unwritable == "read-only file":
        path.write_text("an earlier lock\n", encoding="utf-8")
        path.chmod(0o444)
    else:
        locked.chmod(0o500)
    before = {kept.name: kept.read_bytes() for kept in locked.iterdir()}
    try:
        result = runner.invoke(app, ["pack", "lock", str(path)])
    finally:
        locked.chmod(0o700)
        if path.is_file():
            path.chmod(0o644)

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert f"error: could not write the lock to {path}: " in " ".join(result.output.split())
    assert not isinstance(result.exception, OSError)
    assert {kept.name: kept.read_bytes() for kept in locked.iterdir()} == before


def test_a_lock_replaces_an_earlier_one_whole_and_keeps_its_mode(tmp_path: Path) -> None:
    folder = tmp_path / "out"
    folder.mkdir()
    path = folder / "guardana-lock.yaml"
    path.write_text("# an earlier lock\n" * 2000, encoding="utf-8")
    path.chmod(0o640)

    result = runner.invoke(app, ["pack", "lock", str(path)])

    assert result.exit_code == ExitCode.OK, result.output
    assert "# an earlier lock" not in path.read_text(encoding="utf-8")
    assert path.stat().st_mode & 0o777 == 0o640
    assert list(folder.iterdir()) == [path]
    assert runner.invoke(app, ["pack", "lock", str(path), "--check"]).exit_code == ExitCode.OK


_UNDER_A_FILE_SIZE_LIMIT = """
import resource, sys
from guardana.cli.main import app

limit = int(sys.argv[1])
resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
app(sys.argv[2:])
"""


def test_a_lock_whose_write_fails_part_way_leaves_the_earlier_lock_as_it_was(
    tmp_path: Path,
) -> None:
    folder = tmp_path / "out"
    folder.mkdir()
    path = folder / "guardana-lock.yaml"
    path.write_text("# an earlier lock\n", encoding="utf-8")
    before = path.read_bytes()
    command = ["pack", "lock", str(path)]

    # The limit lets the lock start to land and stops it part-way.
    result = subprocess.run(  # noqa: S603 — this interpreter, a script defined above
        [sys.executable, "-c", _UNDER_A_FILE_SIZE_LIMIT, str(len(before)), *command],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == ExitCode.INVALID_USAGE, result.stdout + result.stderr
    assert f"error: could not write the lock to {path}: " in " ".join(result.stderr.split())
    assert path.read_bytes() == before
    assert list(folder.iterdir()) == [path]
