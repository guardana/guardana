"""The release script refuses twice: it tags only what CI passed, and commits only what it wrote.

Pushing the branch and the tag together races CI against the publish, and a red run
then leaves a publish waiting on the `pypi` approval — a second click, and a cancelled
run in the history that reads as a failed release.

The direction that matters is the refusal. A gate that pushed the tag anyway when it
could not check is the same defect wearing a different hat, so both ways of being unable
to check — no `gh`, and no run to look at — stop before the tag.
"""

import subprocess
import sys
from pathlib import Path

import pytest

import bump_version
import release


def test_a_tag_is_not_pushed_when_ci_cannot_be_reached(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without `gh` there is no way to know, and an unverified tag is the thing avoided."""

    def _no_gh(cmd: list[str], **_: bool) -> str:
        if cmd[0] == "gh":
            raise FileNotFoundError(cmd[0])
        return "cafebabe1234\n"

    monkeypatch.setattr(release, "_run", _no_gh)

    with pytest.raises(SystemExit) as exit_info:
        release._await_green_ci()

    assert exit_info.value.code == 1


def test_a_stop_before_tagging_spells_out_the_tag_commands(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The release commit is pushed and untagged, so the message is all a hand has to go on."""
    with pytest.raises(SystemExit):
        release._stop_before_tagging("CI run 42 is not green")

    err = capsys.readouterr().err
    assert all(command in err for command in release._TAG_BY_HAND), err


def test_a_tag_is_not_pushed_when_no_ci_run_exists_yet(monkeypatch: pytest.MonkeyPatch) -> None:
    """A commit CI has not started on is a commit CI has not passed."""

    def _no_run(cmd: list[str], **_: bool) -> str:
        return "" if cmd[0] == "gh" else "cafebabe1234\n"

    monkeypatch.setattr(release, "_run", _no_run)

    with pytest.raises(SystemExit):
        release._await_green_ci()


def test_a_tag_is_not_pushed_when_ci_is_red(monkeypatch: pytest.MonkeyPatch) -> None:
    """`gh run watch --exit-status` failing is the whole check, so it has to stop here."""

    def _red(cmd: list[str], **_: bool) -> str:
        if cmd[:3] == ["gh", "run", "watch"]:
            raise subprocess.CalledProcessError(1, cmd)
        return "42\n" if cmd[0] == "gh" else "cafebabe1234\n"

    monkeypatch.setattr(release, "_run", _red)

    with pytest.raises(SystemExit):
        release._await_green_ci()


def test_a_green_run_lets_the_release_continue(monkeypatch: pytest.MonkeyPatch) -> None:
    """The inversion: the same path, green, returns rather than stopping.

    Without this the three refusals above would pass against a gate that refused
    everything, which is a gate nobody could cut a release with.
    """
    watched: list[list[str]] = []

    def _green(cmd: list[str], **_: bool) -> str:
        if cmd[0] == "gh":
            watched.append(cmd)
            return "42\n"
        return "cafebabe1234\n"

    monkeypatch.setattr(release, "_run", _green)

    release._await_green_ci()

    assert ["gh", "run", "watch", "42", "--exit-status"] in watched


_BUMP_PLAN = (
    "0.1.0 -> 0.1.1  (siblings pin ==0.1.1)\n"
    "  would update packages/guardana-core/pyproject.toml\n"
    "  would update docs/install.md\n"
    "dry run: uv.lock not re-locked; no files written.\n"
)
_RELEASED = (
    " M packages/guardana-core/pyproject.toml",
    " M docs/install.md",
    " M CHANGELOG.md",
    " M uv.lock",
    " M site/index.html",
    "?? site/docs/new-page.html",
    " D site/docs/old-page.html",
)


def _cut(
    monkeypatch: pytest.MonkeyPatch,
    status: tuple[str, ...],
    calls: list[list[str]],
    *,
    ci_green: bool = True,
) -> None:
    """Run `release.main`, recording into `calls` every side effect instead of performing it."""

    def _fake(cmd: list[str], **_: bool) -> str:
        calls.append(cmd)
        if "scripts/bump_version.py" in cmd and "--dry-run" in cmd:
            return _BUMP_PLAN
        if cmd[:2] == ["git", "status"]:
            return "".join(f"{line}\0" for line in status)
        return ""

    def _ci() -> None:
        calls.append(["<ci>"])
        if not ci_green:
            raise SystemExit(1)

    monkeypatch.setattr(release, "_run", _fake)
    monkeypatch.setattr(release, "_current_version", lambda: "0.1.0")
    monkeypatch.setattr(release, "_preflight", lambda: None)
    monkeypatch.setattr(release, "_gate", lambda: None)
    monkeypatch.setattr(release, "_check_reference_pack", lambda: None)
    monkeypatch.setattr(release, "_roll_changelog", lambda version, dry_run: None)
    monkeypatch.setattr(release, "_await_green_ci", _ci)
    monkeypatch.setattr(release, "_move_marketplace_tag", lambda version, tag: None)
    release.main(["patch"])


def _position(calls: list[list[str]], head: list[str]) -> int:
    return next(i for i, cmd in enumerate(calls) if cmd[: len(head)] == head)


def test_the_tag_is_created_only_after_ci_is_green(monkeypatch: pytest.MonkeyPatch) -> None:
    """A tag that exists before CI is green leaves with any push that follows tags."""
    calls: list[list[str]] = []
    _cut(monkeypatch, _RELEASED, calls)

    push_main = calls[_position(calls, ["git", "push"])]
    assert "--no-follow-tags" in push_main
    assert push_main[-1] == "main"
    assert _position(calls, ["git", "push"]) < _position(calls, ["<ci>"])
    assert _position(calls, ["<ci>"]) < _position(calls, ["git", "tag", "-a"])
    assert calls[-1] == ["git", "push", "origin", "refs/tags/v0.1.1"]


def test_a_red_ci_leaves_no_tag_behind(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    with pytest.raises(SystemExit):
        _cut(monkeypatch, _RELEASED, calls, ci_green=False)

    assert ["<ci>"] in calls
    assert not [cmd for cmd in calls if cmd[:2] == ["git", "tag"]]


def test_the_release_stages_exactly_the_paths_it_wrote(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    _cut(monkeypatch, _RELEASED, calls)

    (stage,) = [cmd for cmd in calls if cmd[:2] == ["git", "add"]]
    assert stage[:3] == ["git", "add", "--"]
    assert sorted(stage[3:]) == sorted(line[3:] for line in _RELEASED)
    assert _position(calls, ["git", "add"]) < _position(calls, ["git", "commit"])


@pytest.mark.parametrize(
    "stray",
    [
        " M packages/guardana-core/src/guardana/core/gate.py",
        "?? notes.txt",
        "M  docs/how-it-works.md",
        "R  docs/a.md\0docs/generated/b.md",
    ],
)
def test_a_change_the_release_did_not_write_stops_it_before_the_commit(
    monkeypatch: pytest.MonkeyPatch, stray: str
) -> None:
    """Another session's edit made during the gate is not part of the release."""
    calls: list[list[str]] = []
    with pytest.raises(SystemExit) as exit_info:
        _cut(monkeypatch, (*_RELEASED, stray), calls)

    assert "did not write" in str(exit_info.value.code)
    assert calls[-1][:2] == ["git", "status"]
    assert not [cmd for cmd in calls if cmd[:2] in (["git", "add"], ["git", "commit"])]


def test_the_real_bump_plan_names_every_file_the_bump_rewrites(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The two scripts agree on the plan's format, or the release refuses its own bump."""
    # An explicit final version, so the Action pins are rewritten (a candidate leaves them)
    # and the assertion holds whether or not the tree is itself a release candidate.
    major, minor, patch = bump_version._core(bump_version._current_version())
    target = f"{major}.{minor}.{patch + 1}"
    monkeypatch.setattr(sys, "argv", ["bump_version.py", target, "--dry-run"])
    assert bump_version.main() == 0

    named = release._bump_writes(capsys.readouterr().out)

    assert {f"packages/{p}/pyproject.toml" for p in bump_version._PACKAGES} <= named
    assert bump_version._DUNDER_PATH.as_posix() in named
    assert {"action.yml", "README.md", "docs/install.md"} <= named


def test_a_bump_plan_names_the_files_the_bump_writes() -> None:
    assert release._bump_writes(_BUMP_PLAN) == frozenset(
        {"packages/guardana-core/pyproject.toml", "docs/install.md"}
    )


def test_the_tag_by_hand_moves_the_minor_tag_the_way_the_script_does(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The moving tag is a lightweight pointer at the release commit, by hand or by script."""
    calls: list[list[str]] = []

    def _record(cmd: list[str], **_: bool) -> str:
        calls.append(cmd)
        return ""

    monkeypatch.setattr(release, "_run", _record)
    release._move_marketplace_tag("0.1.1", "v0.1.1")
    by_hand = [
        line for line in release._TAG_BY_HAND if line.startswith("git tag") and " vX.Y " in line
    ]

    assert calls[0] == ["git", "tag", "-f", "v0.1", "v0.1.1^{commit}"]
    assert by_hand
    assert all(" -a " not in line and "^{commit}" in line for line in by_hand), by_hand


_SURFACE = '{"facade": {}}\n'
_CHANGED_SURFACE = '{"facade": {"guardana.core.verify.Verifier": {}}}\n'


def _candidate(  # noqa: PLR0913 — each keyword is one answer the fake git gives
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    unreleased: str,
    previous: str | None,
    tag: str | None = "v1.0.0rc1",
    tags: str = "",
) -> list[list[str]]:
    """Point the surface check at a changelog and a surface in `tmp_path`, and record git calls."""
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        f"# Changelog\n\n## [Unreleased]\n{unreleased}\n## [0.41.0] - 2026-10-05\n\n"
        "### Removed\n\n- something older\n",
        encoding="utf-8",
    )
    surface = tmp_path / "api-surface.json"
    surface.write_text(_SURFACE, encoding="utf-8")
    calls: list[list[str]] = []

    def _git(cmd: list[str], **_: bool) -> str:
        calls.append(cmd)
        if cmd[:2] == ["git", "describe"]:
            if tag is None:
                raise subprocess.CalledProcessError(128, cmd)
            return f"{tag}\n"
        if cmd[:2] == ["git", "show"]:
            if previous is None:
                raise subprocess.CalledProcessError(128, cmd)
            return previous
        if cmd[:2] == ["git", "for-each-ref"]:
            return tags
        return ""

    monkeypatch.setattr(release, "_run", _git)
    monkeypatch.setattr(release, "_CHANGELOG", changelog)
    monkeypatch.setattr(release, "_SURFACE_PATH", surface)
    return calls


def test_a_candidate_whose_surface_moved_without_a_changelog_section_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _candidate(
        monkeypatch, tmp_path, unreleased="\n### Added\n\n- a flag\n", previous=_CHANGED_SURFACE
    )

    with pytest.raises(SystemExit) as refused:
        release._check_surface("1.0.0rc2")

    assert "supported surface" in str(refused.value.code)
    assert "v1.0.0rc1" in str(refused.value.code)


@pytest.mark.parametrize("section", ["Changed", "Changed — breaking", "Deprecated", "Removed"])
def test_a_candidate_whose_surface_moved_with_a_changelog_section_continues(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, section: str
) -> None:
    _candidate(
        monkeypatch,
        tmp_path,
        unreleased=f"\n### {section}\n\n- a name\n",
        previous=_CHANGED_SURFACE,
    )

    release._check_surface("1.0.0rc2")


def test_a_section_of_an_earlier_release_does_not_announce_this_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Only `[Unreleased]` speaks for the candidate; the release below it already shipped."""
    _candidate(monkeypatch, tmp_path, unreleased="", previous=_CHANGED_SURFACE)

    with pytest.raises(SystemExit):
        release._check_surface("1.0.0rc2")


def test_a_candidate_with_an_unchanged_surface_continues_without_a_section(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = _candidate(monkeypatch, tmp_path, unreleased="", previous=_SURFACE)

    release._check_surface("1.0.0rc2")

    assert ["git", "show", "v1.0.0rc1:docs/generated/api-surface.json"] in calls


def test_a_previous_tag_without_a_surface_counts_as_a_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A tag older than the snapshot cannot show the surface stayed put."""
    _candidate(monkeypatch, tmp_path, unreleased="", previous=None)

    with pytest.raises(SystemExit):
        release._check_surface("1.0.0rc1")


def test_a_candidate_with_no_earlier_tag_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _candidate(monkeypatch, tmp_path, unreleased="\n### Changed\n\n- x\n", previous=None, tag=None)

    with pytest.raises(SystemExit) as refused:
        release._check_surface("1.0.0rc1")

    assert "no earlier release tag" in str(refused.value.code)


@pytest.mark.parametrize(
    ("version", "tag"),
    [
        ("1.1.0", "v1.0.0"),
        ("0.41.1", "v0.41.0"),
        ("1.0.0", "v0.41.0"),
        ("1.1.0", "v1.0.0rc2"),
        ("0.41.0", None),
    ],
)
def test_a_final_release_after_a_final_is_not_held_by_the_surface_check(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, version: str, tag: str | None
) -> None:
    """Only a candidate of the same version pins a final's surface; a first release has no tag."""
    calls = _candidate(monkeypatch, tmp_path, unreleased="", previous=_CHANGED_SURFACE, tag=tag)

    release._check_surface(version)

    assert not [cmd for cmd in calls if cmd[:2] == ["git", "show"]]


@pytest.mark.parametrize("nearest", ["v0.41.0", None])
def test_a_final_whose_candidates_are_not_behind_head_is_refused_rather_than_unchecked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, nearest: str | None
) -> None:
    """Unfetched tags, or a cut that skips the candidate, would otherwise compare nothing."""
    _candidate(
        monkeypatch,
        tmp_path,
        unreleased="",
        previous=_SURFACE,
        tag=nearest,
        tags="v1.0.0rc1\nv1.0.0rc2\n",
    )

    with pytest.raises(SystemExit) as refused:
        release._check_surface("1.0.0")

    assert "v1.0.0rc1, v1.0.0rc2" in str(refused.value.code)


def test_a_final_whose_surface_moved_since_its_candidate_without_a_section_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _candidate(
        monkeypatch,
        tmp_path,
        unreleased="\n### Fixed\n\n- a fix\n",
        previous=_CHANGED_SURFACE,
        tag="v1.0.0rc2",
    )

    with pytest.raises(SystemExit) as refused:
        release._check_surface("1.0.0")

    assert "supported surface" in str(refused.value.code)
    assert "v1.0.0rc2" in str(refused.value.code)


@pytest.mark.parametrize("section", ["Changed", "Deprecated", "Removed"])
def test_a_final_whose_surface_moved_since_its_candidate_is_refused_whatever_the_changelog_says(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, section: str
) -> None:
    """The final ships what its last candidate was tested as; a section cannot excuse a move."""
    _candidate(
        monkeypatch,
        tmp_path,
        unreleased=f"\n### {section}\n\n- a name\n",
        previous=_CHANGED_SURFACE,
        tag="v1.0.0rc2",
    )

    with pytest.raises(SystemExit) as refused:
        release._check_surface("1.0.0")

    assert "v1.0.0rc2" in str(refused.value.code)
    assert "supported surface" in str(refused.value.code)


def test_a_final_with_the_surface_of_its_candidate_continues_without_a_section(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = _candidate(monkeypatch, tmp_path, unreleased="", previous=_SURFACE, tag="v1.0.0rc2")

    release._check_surface("1.0.0")

    assert ["git", "show", "v1.0.0rc2:docs/generated/api-surface.json"] in calls


def test_a_final_whose_candidate_tag_has_no_surface_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _candidate(monkeypatch, tmp_path, unreleased="", previous=None, tag="v1.0.0rc2")

    with pytest.raises(SystemExit):
        release._check_surface("1.0.0")


def test_the_surface_check_runs_before_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    monkeypatch.setattr(release, "_current_version", lambda: "1.0.0rc1")
    monkeypatch.setattr(release, "_preflight", lambda: order.append("preflight"))
    monkeypatch.setattr(release, "_check_surface", order.append)
    monkeypatch.setattr(release, "_check_reference_pack", lambda: None)

    def _gate() -> None:
        order.append("gate")
        raise SystemExit(0)

    monkeypatch.setattr(release, "_gate", _gate)

    with pytest.raises(SystemExit):
        release.main(["1.0.0rc2"])

    assert order == ["preflight", "1.0.0rc2", "gate"]


_PRE_1_POLICY = (
    "# Compatibility\n\n## Versioning\n\nGuardana follows SemVer. The twist is that it\n"
    "is **pre-1.0**, and 0.x has its own rules.\n\n| Pre-1.0 (`0.y.z`) | Post-1.0 |\n"
)
_POST_1_POLICY = (
    "# Compatibility\n\n## Versioning\n\nGuardana follows SemVer and is past 1.0.\n\n"
    "| Pre-1.0 (`0.y.z`) | Post-1.0 |\n\nBut pre-1.0 with a single active line, patch it.\n"
)
_POLICY_PAGE = "docs/compatibility.md"


def _policy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str | None) -> None:
    """Point the pre-1.0 check at a policy page under `tmp_path`; `None` leaves it unreadable."""
    page = tmp_path / _POLICY_PAGE
    if text is not None:
        page.parent.mkdir(parents=True)
        page.write_text(text, encoding="utf-8")
    monkeypatch.setattr(release, "_ROOT", tmp_path)
    monkeypatch.setattr(release, "_VERSIONING", page)


def test_the_pre_1_0_statement_is_read_from_the_public_versioning_policy() -> None:
    """The release must read the page users read, and that page must carry the policy."""
    assert release._VERSIONING == release._ROOT / _POLICY_PAGE
    assert "\n## Versioning\n" in release._VERSIONING.read_text(encoding="utf-8")


@pytest.mark.parametrize("version", ["1.0.0", "1.2.3", "2.0.0"])
def test_a_final_1x_release_is_refused_while_the_policy_says_pre_1_0(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, version: str
) -> None:
    _policy(monkeypatch, tmp_path, _PRE_1_POLICY)

    with pytest.raises(SystemExit) as refused:
        release._check_pre_1_statement(version)

    assert f"{_POLICY_PAGE}:6" in str(refused.value.code)
    assert "pre-1.0" in str(refused.value.code)


def test_the_pre_1_0_statement_is_found_across_a_line_break(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _policy(monkeypatch, tmp_path, "# Compatibility\n\nThe twist is that it is\n**pre-1.0**.\n")

    with pytest.raises(SystemExit) as refused:
        release._check_pre_1_statement("1.0.0")

    assert f"{_POLICY_PAGE}:4" in str(refused.value.code)


@pytest.mark.parametrize("version", ["1.0.0rc2", "0.42.0", "0.41.1"])
def test_a_candidate_or_a_0x_release_is_not_held_by_the_pre_1_0_statement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, version: str
) -> None:
    _policy(monkeypatch, tmp_path, _PRE_1_POLICY)

    release._check_pre_1_statement(version)


def test_a_final_1x_release_continues_once_the_policy_is_rewritten(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _policy(monkeypatch, tmp_path, _POST_1_POLICY)

    release._check_pre_1_statement("1.0.0")


def test_the_versioning_policy_may_keep_naming_pre_1_0_once_the_status_is_rewritten(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The table and the advice that describe 0.x releases stay true after 1.0."""
    policy = (
        "# Compatibility\n\nGuardana follows Semantic Versioning and is stable since 1.0.0.\n\n"
        "| You're releasing… | Bump | Pre-1.0 (`0.y.z`) | Post-1.0 (`x.y.z`) |\n"
        "|---|---|---|---|\n"
        "| An incompatible change | **minor** pre-1.0, **major** post-1.0 | `0.1.4 → 0.2.0` "
        "| `1.4.2 → 2.0.0` |\n"
        "| A compatible feature | **minor** post-1.0, **patch**-or-minor pre-1.0 "
        "| `0.1.4 → 0.2.0` | `1.4.2 → 1.5.0` |\n\n"
        'Practical pre-1.0 rule of thumb: **patch = "safe to upgrade blindly"**.\n\n'
        "release `0.1.5` from there — but pre-1.0 with a single active line, you'll almost\n"
    )
    _policy(monkeypatch, tmp_path, policy)

    release._check_pre_1_statement("1.0.0")


def test_a_final_1x_release_is_refused_when_the_policy_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _policy(monkeypatch, tmp_path, None)

    with pytest.raises(SystemExit) as refused:
        release._check_pre_1_statement("1.0.0")

    assert f"cannot read {_POLICY_PAGE}" in str(refused.value.code)


def test_the_pre_1_0_statement_refuses_a_dry_run_before_the_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _policy(monkeypatch, tmp_path, _PRE_1_POLICY)
    ran: list[str] = []
    monkeypatch.setattr(release, "_current_version", lambda: "1.0.0rc2")
    monkeypatch.setattr(release, "_preflight", lambda: None)
    monkeypatch.setattr(release, "_check_surface", lambda version: None)
    monkeypatch.setattr(release, "_check_reference_pack", lambda: None)
    monkeypatch.setattr(release, "_gate", lambda: ran.append("gate"))

    with pytest.raises(SystemExit) as refused:
        release.main(["1.0.0", "--dry-run"])

    assert f"{_POLICY_PAGE}:6" in str(refused.value.code)
    assert ran == []


def _pack_pyproject(version: str) -> str:
    return f'[project]\nname = "guardana-reference-pack"\nversion = "{version}"\n'


def _pack_release(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    current: str,
    previous: str | None,
    diff: str,
) -> list[list[str]]:
    """Point the reference pack check at a pyproject in `tmp_path`, and record git calls."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(_pack_pyproject(current), encoding="utf-8")
    calls: list[list[str]] = []

    def _git(cmd: list[str], **_: bool) -> str:
        calls.append(cmd)
        if cmd[:2] == ["git", "describe"]:
            return "v0.41.0\n"
        if cmd[:2] == ["git", "show"]:
            if previous is None:
                raise subprocess.CalledProcessError(128, cmd)
            return _pack_pyproject(previous)
        if cmd[:2] == ["git", "diff"]:
            return diff
        return ""

    monkeypatch.setattr(release, "_run", _git)
    monkeypatch.setattr(release, "_PACK_PYPROJECT", pyproject)
    return calls


_PACK_DIFF = "diff --git a/examples/reference_pack/README.md b/examples/reference_pack/README.md\n"


def test_a_changed_reference_pack_under_the_released_version_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The index refuses a second upload of the version, so the change would never ship."""
    calls = _pack_release(monkeypatch, tmp_path, current="0.1.0", previous="0.1.0", diff=_PACK_DIFF)

    with pytest.raises(SystemExit) as refused:
        release._check_reference_pack()

    assert "examples/reference_pack" in str(refused.value.code)
    assert "0.1.0" in str(refused.value.code)
    assert "v0.41.0" in str(refused.value.code)
    assert ["git", "diff", "v0.41.0", "--", "examples/reference_pack"] in calls


def test_a_changed_reference_pack_with_a_new_version_continues(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _pack_release(monkeypatch, tmp_path, current="0.1.1", previous="0.1.0", diff=_PACK_DIFF)

    release._check_reference_pack()


def test_an_unchanged_reference_pack_keeps_its_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _pack_release(monkeypatch, tmp_path, current="0.1.0", previous="0.1.0", diff="")

    release._check_reference_pack()


def test_a_reference_pack_absent_at_the_previous_tag_continues(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A pack that never shipped has no published version to collide with."""
    calls = _pack_release(monkeypatch, tmp_path, current="0.1.0", previous=None, diff=_PACK_DIFF)

    release._check_reference_pack()

    assert ["git", "show", "v0.41.0:examples/reference_pack/pyproject.toml"] in calls


def test_the_reference_pack_check_refuses_without_an_earlier_tag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _pack_release(monkeypatch, tmp_path, current="0.1.0", previous="0.1.0", diff="")
    answered = release._run

    def _no_tag(cmd: list[str], **kwargs: bool) -> str:
        if cmd[:2] == ["git", "describe"]:
            raise subprocess.CalledProcessError(128, cmd)
        return answered(cmd, **kwargs)

    monkeypatch.setattr(release, "_run", _no_tag)

    with pytest.raises(SystemExit) as refused:
        release._check_reference_pack()

    assert "no earlier release tag" in str(refused.value.code)


def test_the_reference_pack_check_runs_before_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    monkeypatch.setattr(release, "_current_version", lambda: "0.41.0")
    monkeypatch.setattr(release, "_preflight", lambda: None)
    monkeypatch.setattr(release, "_check_surface", lambda version: None)
    monkeypatch.setattr(release, "_check_reference_pack", lambda: order.append("pack"))

    def _gate() -> None:
        order.append("gate")
        raise SystemExit(0)

    monkeypatch.setattr(release, "_gate", _gate)

    with pytest.raises(SystemExit):
        release.main(["patch"])

    assert order == ["pack", "gate"]


# Records and prose that name the command without running it.
_DOGFOOD_DESCRIBED = frozenset(
    {"CHANGELOG.md", "SECURITY.md", "scripts/tests/test_release_script.py"}
)


def test_every_dogfood_run_passes_the_dogfood_profile() -> None:
    """Without the profile a dogfood run gates at the default HIGH bar and passes lower findings."""
    root = release._ROOT
    command = "guardana scan packages"
    with_profile = f"{command} --profile {release.DOGFOOD_PROFILE}"
    listed = subprocess.run(
        ["git", "ls-files", "-z"],  # noqa: S607 — git on this clone
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split("\0")
    running = []
    for name in listed:
        if name in _DOGFOOD_DESCRIBED or name.startswith("site/"):
            continue
        if not name:
            continue
        try:
            text = (root / name).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if command in text:
            running.append(name)
            assert text.count(command) == text.count(with_profile), name
    assert {".github/workflows/ci.yml", "scripts/ci_local.sh", ".pre-commit-config.yaml"} <= set(
        running
    )
    assert release._DOGFOOD[-2:] == ["--profile", release.DOGFOOD_PROFILE]
    source = (root / "scripts" / "release.py").read_text(encoding="utf-8")
    assert source.count('"scan", "packages"') == 1
    assert (root / release.DOGFOOD_PROFILE).is_file()
