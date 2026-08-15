"""The release script's one fail-closed moment: it will not tag what CI has not passed.

Pushing the branch and the tag together races CI against the publish, and a red run
then leaves a publish waiting on the `pypi` approval — a second click, and a cancelled
run in the history that reads as a failed release. Every release from 0.19.0 to 0.21.0
paid that once and 0.20.0 paid it twice, which is why the wait is in the script and not
only in the runbook.

The direction that matters is the refusal. A gate that pushed the tag anyway when it
could not check is the same defect wearing a different hat, so both ways of being unable
to check — no `gh`, and no run to look at — stop before the tag.
"""

import subprocess

import pytest

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
