"""The release script refuses at every step it cannot check, and commits only what it wrote.

The release commit reaches `main` through a pull request that merges only once its required
checks pass, and the tag follows only once CI is green on the merge commit and the tag's
signature verifies. Pushing the branch and the tag together races CI against the publish,
and a red run then leaves a publish waiting on the `pypi` approval — a second click, and a
cancelled run in the history that reads as a failed release.

The direction that matters is the refusal. A gate that pushed the tag anyway when it
could not check is the same defect wearing a different hat, so every way of being unable
to check — no `gh`, no run to look at, a signature that does not verify — stops before the tag.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

import bump_version
import release

_COMMIT = "cafebabe1234"


class _Clock:
    """Time that moves only when the code under test sleeps."""

    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    fake = _Clock()
    monkeypatch.setattr(release, "_monotonic", fake.monotonic)
    monkeypatch.setattr(release, "_sleep", fake.sleep)
    return fake


def test_a_tag_is_not_pushed_when_ci_cannot_be_reached(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    """Without `gh` there is no way to know, and an unverified tag is the thing avoided."""

    def _no_gh(cmd: list[str], **_: bool) -> str:
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(release, "_run", _no_gh)

    with pytest.raises(SystemExit) as exit_info:
        release._await_green_ci(_COMMIT)

    assert exit_info.value.code == 1
    assert clock.slept == []


def test_a_stop_before_tagging_spells_out_the_tag_commands(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The release commit is merged and untagged, so the message is all a hand has to go on."""
    with pytest.raises(SystemExit):
        release._stop_before_tagging("CI run 42 is not green")

    err = capsys.readouterr().err
    assert all(command in err for command in release._TAG_BY_HAND), err


def test_a_stop_before_merging_spells_out_the_rest_of_the_release(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        release._stop_before_merge("the required checks of pull request #190 did not pass", "190")

    err = capsys.readouterr().err
    assert "pull request #190" in err
    assert "Nothing reached `main`" in err
    assert all(command in err for command in release._TAG_BY_HAND), err


def test_the_hand_written_tag_is_signed_and_verified_before_it_is_pushed() -> None:
    lines = list(release._TAG_BY_HAND)
    create = next(i for i, line in enumerate(lines) if line.startswith("git tag -s vX.Y.Z "))
    verify = lines.index("git tag -v vX.Y.Z")
    push = lines.index("git push origin refs/tags/vX.Y.Z")

    assert create < verify < push
    assert not any(" -a " in line for line in lines)


def test_a_tag_is_not_pushed_when_no_ci_run_ever_starts(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    """A commit CI has not started on is a commit CI has not passed, once the wait is over."""
    listed: list[list[str]] = []

    def _no_run(cmd: list[str], **_: bool) -> str:
        listed.append(cmd)
        return ""

    monkeypatch.setattr(release, "_run", _no_run)

    with pytest.raises(SystemExit):
        release._await_green_ci(_COMMIT)

    assert clock.now >= release._CI_APPEARS_WITHIN_S
    assert not [cmd for cmd in listed if cmd[:3] == ["gh", "run", "watch"]]


def test_a_run_listed_after_the_push_is_waited_for_rather_than_refused(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    """Seconds after a push the run is not listed yet; that is "not yet", not "red"."""
    answers = iter(["", "", "42\n"])
    calls: list[list[str]] = []

    def _late(cmd: list[str], **_: bool) -> str:
        calls.append(cmd)
        return next(answers) if cmd[:3] == ["gh", "run", "list"] else ""

    monkeypatch.setattr(release, "_run", _late)

    release._await_green_ci(_COMMIT)

    assert clock.slept == [release._CI_POLL_S, release._CI_POLL_S]
    assert calls[-1] == ["gh", "run", "watch", "42", "--exit-status"]


def test_the_ci_run_awaited_before_the_tag_is_the_push_run_release_yml_requires(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    calls: list[list[str]] = []

    def _green(cmd: list[str], **_: bool) -> str:
        calls.append(cmd)
        return "42\n"

    monkeypatch.setattr(release, "_run", _green)

    release._await_green_ci(_COMMIT)

    (listing,) = [cmd for cmd in calls if cmd[:3] == ["gh", "run", "list"]]
    assert f"--commit={_COMMIT}" in listing
    assert "--event=push" in listing
    assert "--workflow=CI" in listing


def test_a_tag_is_not_pushed_when_ci_is_red(monkeypatch: pytest.MonkeyPatch, clock: _Clock) -> None:
    """`gh run watch --exit-status` failing is the whole check, so it has to stop here."""

    def _red(cmd: list[str], **_: bool) -> str:
        if cmd[:3] == ["gh", "run", "watch"]:
            raise subprocess.CalledProcessError(1, cmd)
        return "42\n"

    monkeypatch.setattr(release, "_run", _red)

    with pytest.raises(SystemExit):
        release._await_green_ci(_COMMIT)


def test_a_green_run_lets_the_release_continue(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    """The inversion: the same path, green, returns rather than stopping.

    Without this the refusals above would pass against a gate that refused
    everything, which is a gate nobody could cut a release with.
    """
    watched: list[list[str]] = []

    def _green(cmd: list[str], **_: bool) -> str:
        watched.append(cmd)
        return "42\n"

    monkeypatch.setattr(release, "_run", _green)

    release._await_green_ci(_COMMIT)

    assert ["gh", "run", "watch", "42", "--exit-status"] in watched
    assert clock.slept == []


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


_HEAD = "1" * 40
_MERGED = "2" * 40
_PR_URL = "https://github.com/guardana/guardana/pull/190\n"
_TAG_PUSH = ["git", "push", "origin", "refs/tags/v0.1.1"]


def _cut(  # noqa: PLR0913 — each keyword is one answer the fake world gives
    monkeypatch: pytest.MonkeyPatch,
    status: tuple[str, ...],
    calls: list[list[str]],
    *,
    ci_green: bool = True,
    checks_green: bool = True,
    merged_tree: str = "tree-of-head",
    pr_state: str = "MERGED",
    failing: tuple[tuple[str, ...], ...] = (),
) -> None:
    """Run `release.main`, recording into `calls` every side effect instead of performing it.

    `failing` names command prefixes that exit non-zero, as git and gh do when they refuse.
    """
    exact: dict[tuple[str, ...], str] = {
        ("git", "rev-parse", "HEAD"): f"{_HEAD}\n",
        ("git", "rev-parse", f"{_HEAD}^{{tree}}"): "tree-of-head\n",
        ("git", "rev-parse", f"{_MERGED}^{{tree}}"): f"{merged_tree}\n",
    }
    by_prefix: dict[tuple[str, ...], str] = {
        ("git", "status"): "".join(f"{line}\0" for line in status),
        ("gh", "pr", "create"): _PR_URL,
        ("gh", "pr", "view"): f"{pr_state}\n{_MERGED if pr_state == 'MERGED' else ''}\n",
    }

    def _fake(cmd: list[str], **_: bool) -> str:
        calls.append(cmd)
        if any(tuple(cmd[: len(prefix)]) == prefix for prefix in failing):
            raise subprocess.CalledProcessError(1, cmd)
        if "scripts/bump_version.py" in cmd and "--dry-run" in cmd:
            return _BUMP_PLAN
        if tuple(cmd) in exact:
            return exact[tuple(cmd)]
        return next((out for head, out in by_prefix.items() if tuple(cmd[: len(head)]) == head), "")

    def _checks(pr: str, head: str) -> None:
        calls.append(["<checks>", pr, head])
        if not checks_green:
            raise SystemExit(1)

    def _ci(commit: str) -> None:
        calls.append(["<ci>", commit])
        if not ci_green:
            raise SystemExit(1)

    monkeypatch.setattr(release, "_run", _fake)
    monkeypatch.setattr(release, "_current_version", lambda: "0.1.0")
    monkeypatch.setattr(release, "_preflight", lambda branch: calls.append(["<preflight>", branch]))
    monkeypatch.setattr(release, "_gate", lambda: None)
    monkeypatch.setattr(release, "_check_reference_pack", lambda: None)
    monkeypatch.setattr(release, "_roll_changelog", lambda version, dry_run: None)
    monkeypatch.setattr(release, "_await_required_checks", _checks)
    monkeypatch.setattr(release, "_await_green_ci", _ci)
    monkeypatch.setattr(release, "_move_marketplace_tag", lambda version, tag: None)
    release.main(["patch"])


def _position(calls: list[list[str]], head: list[str]) -> int:
    return next(i for i, cmd in enumerate(calls) if cmd[: len(head)] == head)


def _pushes(calls: list[list[str]]) -> list[list[str]]:
    return [cmd for cmd in calls if cmd[:2] == ["git", "push"]]


def test_the_release_commit_reaches_main_only_through_a_pull_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nothing is pushed to `main`; the commit rides a release branch merged once checks pass."""
    calls: list[list[str]] = []
    _cut(monkeypatch, _RELEASED, calls)

    assert ["<preflight>", "release/v0.1.1"] in calls
    assert _position(calls, ["git", "switch", "--create", "release/v0.1.1"]) < _position(
        calls, ["git", "add"]
    )
    branch_push = _pushes(calls)[0]
    assert branch_push == [
        "git",
        "push",
        "--no-follow-tags",
        "--set-upstream",
        "origin",
        "release/v0.1.1",
    ]
    assert not [cmd for cmd in _pushes(calls) if "main" in cmd]
    create = calls[_position(calls, ["gh", "pr", "create"])]
    assert create[create.index("--base") + 1] == "main"
    assert create[create.index("--head") + 1] == "release/v0.1.1"
    merge = calls[_position(calls, ["gh", "pr", "merge"])]
    assert merge == ["gh", "pr", "merge", "190", "--squash", "--match-head-commit", _HEAD]
    assert (
        _position(calls, ["git", "push", "--no-follow-tags"])
        < _position(calls, ["gh", "pr", "create"])
        < _position(calls, ["<checks>", "190", _HEAD])
        < _position(calls, ["gh", "pr", "merge"])
    )


def test_the_tag_is_signed_on_the_merge_commit_after_ci_and_verified_before_the_push(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tag that exists before CI is green leaves with any push that follows tags."""
    calls: list[list[str]] = []
    _cut(monkeypatch, _RELEASED, calls)

    sign = ["git", "tag", "-s", "v0.1.1", "-m", "Guardana v0.1.1", _MERGED]
    assert (
        _position(calls, ["gh", "pr", "merge"])
        < _position(calls, ["<ci>", _MERGED])
        < calls.index(sign)
        < calls.index(["git", "tag", "-v", "v0.1.1"])
        < calls.index(_TAG_PUSH)
    )
    assert not [cmd for cmd in calls if cmd[:3] == ["git", "tag", "-a"]]
    assert _TAG_PUSH in _pushes(calls)


def test_a_red_required_check_leaves_the_pull_request_unmerged_and_untagged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    with pytest.raises(SystemExit):
        _cut(monkeypatch, _RELEASED, calls, checks_green=False)

    assert ["<checks>", "190", _HEAD] in calls
    assert not [cmd for cmd in calls if cmd[:3] == ["gh", "pr", "merge"]]
    assert not [cmd for cmd in calls if cmd[:2] == ["git", "tag"]]


def test_a_red_ci_on_the_merge_commit_leaves_no_tag_behind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    with pytest.raises(SystemExit):
        _cut(monkeypatch, _RELEASED, calls, ci_green=False)

    assert ["<ci>", _MERGED] in calls
    assert not [cmd for cmd in calls if cmd[:2] == ["git", "tag"]]


def test_a_merge_github_refuses_stops_before_any_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unresolved review threads or a stale branch make GitHub refuse; the script stops there."""
    calls: list[list[str]] = []
    with pytest.raises(SystemExit):
        _cut(monkeypatch, _RELEASED, calls, failing=(("gh", "pr", "merge"),), pr_state="OPEN")

    assert not [cmd for cmd in calls if cmd[:2] == ["git", "tag"] or cmd == ["<ci>", _MERGED]]
    assert _TAG_PUSH not in calls


def test_a_merge_commit_holding_another_tree_is_never_tagged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The tag must name what the gate and the checks saw, not whatever `main` merged."""
    calls: list[list[str]] = []
    with pytest.raises(SystemExit):
        _cut(monkeypatch, _RELEASED, calls, merged_tree="tree-of-something-else")

    assert not [cmd for cmd in calls if cmd[:2] == ["git", "tag"] or cmd[0] == "<ci>"]


def test_a_tag_whose_signature_does_not_verify_is_deleted_and_never_pushed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    with pytest.raises(SystemExit):
        _cut(monkeypatch, _RELEASED, calls, failing=(("git", "tag", "-v"),))

    assert ["git", "tag", "-d", "v0.1.1"] in calls
    assert _TAG_PUSH not in calls


def test_a_tag_git_cannot_sign_is_never_pushed(monkeypatch: pytest.MonkeyPatch) -> None:
    """No signing key, or one git cannot use, must not fall back to an unsigned tag."""
    calls: list[list[str]] = []
    with pytest.raises(SystemExit):
        _cut(monkeypatch, _RELEASED, calls, failing=(("git", "tag", "-s"),))

    assert not [cmd for cmd in calls if cmd[:3] in (["git", "tag", "-a"], ["git", "tag", "-v"])]
    assert _TAG_PUSH not in calls


def _pr_world(
    monkeypatch: pytest.MonkeyPatch, answers: dict[tuple[str, ...], str | Exception]
) -> list[list[str]]:
    """Fake `_run` answering by command prefix; an exception answer is raised."""
    calls: list[list[str]] = []

    def _fake(cmd: list[str], **_: bool) -> str:
        calls.append(cmd)
        for prefix, answer in answers.items():
            if tuple(cmd[: len(prefix)]) == prefix:
                if isinstance(answer, Exception):
                    raise answer
                return answer
        return ""

    monkeypatch.setattr(release, "_run", _fake)
    return calls


def test_the_required_checks_are_awaited_on_the_pull_request_run(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    calls = _pr_world(monkeypatch, {("gh", "run", "list"): "77\n"})

    release._await_required_checks("190", _HEAD)

    (listing,) = [cmd for cmd in calls if cmd[:3] == ["gh", "run", "list"]]
    assert "--event=pull_request" in listing
    assert f"--commit={_HEAD}" in listing
    assert calls[-1] == ["gh", "pr", "checks", "190", "--required", "--watch", "--fail-fast"]


def test_a_failed_required_check_stops_before_the_merge(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    _pr_world(
        monkeypatch,
        {
            ("gh", "run", "list"): "77\n",
            ("gh", "pr", "checks"): subprocess.CalledProcessError(1, ["gh"]),
        },
    )

    with pytest.raises(SystemExit) as stopped:
        release._await_required_checks("190", _HEAD)

    assert stopped.value.code == 1


_DROPPED = subprocess.CalledProcessError(1, ["gh"])
_CHECKS_WATCH = ("gh", "pr", "checks", "190", "--required", "--watch", "--fail-fast")
_CHECKS_READ = ("gh", "pr", "checks", "190", "--required", "--json", "name,bucket")
_RUN_WATCH = ("gh", "run", "watch", "42", "--exit-status")
_RUN_READ = ("gh", "run", "view", "42", "--json", "status,conclusion")


def _checks(*buckets: str) -> str:
    return json.dumps([{"name": f"check-{i}", "bucket": b} for i, b in enumerate(buckets)])


def _run_state(status: str, conclusion: str) -> str:
    return json.dumps({"status": status, "conclusion": conclusion})


def _scripted(
    monkeypatch: pytest.MonkeyPatch, script: dict[tuple[str, ...], list[str | Exception]]
) -> list[list[str]]:
    """Fake `_run` answering by command prefix from a queue whose last answer repeats."""
    calls: list[list[str]] = []

    def _fake(cmd: list[str], **_: bool) -> str:
        calls.append(cmd)
        for prefix, answers in script.items():
            if tuple(cmd[: len(prefix)]) == prefix:
                answer = answers.pop(0) if len(answers) > 1 else answers[0]
                if isinstance(answer, Exception):
                    raise answer
                return answer
        return ""

    monkeypatch.setattr(release, "_run", _fake)
    return calls


def _publish_world(
    monkeypatch: pytest.MonkeyPatch, script: dict[tuple[str, ...], list[str | Exception]]
) -> list[list[str]]:
    """Script `_publish` up to the waits: a pushed branch, pull request #190, a clean merge."""
    return _scripted(
        monkeypatch,
        {
            ("git", "rev-parse", "HEAD"): [f"{_HEAD}\n"],
            ("git", "rev-parse"): ["same-tree\n"],
            ("gh", "pr", "create"): [_PR_URL],
            ("gh", "run", "list"): ["42\n"],
            ("gh", "pr", "view"): [f"MERGED\n{_MERGED}\n"],
            **script,
        },
    )


def _count(calls: list[list[str]], prefix: tuple[str, ...]) -> int:
    return sum(tuple(cmd[: len(prefix)]) == prefix for cmd in calls)


def test_a_dropped_checks_watch_goes_on_when_every_required_check_reads_passed(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    """A watch that lost its connection says nothing; the state read afterwards does."""
    calls = _scripted(
        monkeypatch,
        {
            ("gh", "run", "list"): ["77\n"],
            _CHECKS_WATCH: [_DROPPED],
            _CHECKS_READ: [_checks("pass", "pass")],
        },
    )

    release._await_required_checks("190", _HEAD)

    assert _count(calls, _CHECKS_WATCH) == 1
    assert _count(calls, _CHECKS_READ) == 1


@pytest.mark.parametrize("bucket", ["fail", "cancel"])
def test_a_dropped_checks_watch_stops_as_failed_when_a_required_check_reads_failed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], clock: _Clock, bucket: str
) -> None:
    calls = _scripted(
        monkeypatch,
        {
            ("gh", "run", "list"): ["77\n"],
            _CHECKS_WATCH: [_DROPPED],
            _CHECKS_READ: [_checks("pass", bucket, "pending")],
        },
    )

    with pytest.raises(SystemExit):
        release._await_required_checks("190", _HEAD)

    assert "the required checks of pull request #190 did not pass" in capsys.readouterr().err
    assert _count(calls, _CHECKS_WATCH) == 1


_UNSHOWN_CHECKS: list[str | Exception] = [
    _checks("pass", "pending"),
    _checks("pass", "skipping"),
    _checks(),
    "",
    "not json",
    '{"bucket": "pass"}',
    '["pass"]',
    '[{"name": "check-0"}]',
    _DROPPED,
]


@pytest.mark.parametrize(
    "state",
    _UNSHOWN_CHECKS,
    ids=[
        "pending",
        "skipping",
        "empty-list",
        "empty",
        "not-json",
        "object",
        "strings",
        "no-bucket",
        "read-failed",
    ],
)
def test_a_checks_watch_dropped_twice_on_an_unshown_state_stops_without_merging(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    clock: _Clock,
    state: str | Exception,
) -> None:
    """Checks never shown to pass are not called passed, nor called failed."""
    calls = _publish_world(monkeypatch, {_CHECKS_WATCH: [_DROPPED], _CHECKS_READ: [state]})

    with pytest.raises(SystemExit):
        release._publish("release/v0.1.1", "v0.1.1", "0.1.1")

    err = capsys.readouterr().err
    assert "the required checks of pull request #190 could not be watched to the end" in err
    assert "were not shown to pass" in err
    assert "did not pass" not in err
    assert _count(calls, _CHECKS_WATCH) == 2
    assert not [
        cmd for cmd in calls if cmd[:3] == ["gh", "pr", "merge"] or cmd[:2] == ["git", "tag"]
    ]


def test_a_checks_watch_dropped_once_goes_on_when_the_retry_finishes(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    calls = _scripted(
        monkeypatch,
        {
            ("gh", "run", "list"): ["77\n"],
            _CHECKS_WATCH: [_DROPPED, ""],
            _CHECKS_READ: [_checks("pass", "pending")],
        },
    )

    release._await_required_checks("190", _HEAD)

    assert _count(calls, _CHECKS_WATCH) == 2
    assert calls[-1] == list(_CHECKS_WATCH)


def test_a_dropped_ci_watch_goes_on_when_the_run_reads_green(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    calls = _scripted(
        monkeypatch,
        {
            ("gh", "run", "list"): ["42\n"],
            _RUN_WATCH: [_DROPPED],
            _RUN_READ: [_run_state("completed", "success")],
        },
    )

    release._await_green_ci(_COMMIT)

    assert _count(calls, _RUN_WATCH) == 1
    assert _count(calls, _RUN_READ) == 1


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "timed_out", ""])
def test_a_dropped_ci_watch_stops_as_red_when_the_run_reads_concluded_otherwise(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    clock: _Clock,
    conclusion: str,
) -> None:
    calls = _scripted(
        monkeypatch,
        {
            ("gh", "run", "list"): ["42\n"],
            _RUN_WATCH: [_DROPPED],
            _RUN_READ: [_run_state("completed", conclusion)],
        },
    )

    with pytest.raises(SystemExit):
        release._await_green_ci(_COMMIT)

    assert "CI run 42 is not green" in capsys.readouterr().err
    assert _count(calls, _RUN_WATCH) == 1


_UNSHOWN_RUNS: list[str | Exception] = [
    _run_state("in_progress", ""),
    _run_state("queued", ""),
    '{"conclusion": "success"}',
    "",
    "not json",
    "[]",
    _DROPPED,
]


@pytest.mark.parametrize(
    "state",
    _UNSHOWN_RUNS,
    ids=["in-progress", "queued", "no-status", "empty", "not-json", "list", "read-failed"],
)
def test_a_ci_watch_dropped_twice_on_an_unshown_state_stops_without_a_tag(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    clock: _Clock,
    state: str | Exception,
) -> None:
    """A run never shown to be green is not called green, nor called red."""
    calls = _publish_world(monkeypatch, {_RUN_WATCH: [_DROPPED], _RUN_READ: [state]})

    with pytest.raises(SystemExit):
        release._publish("release/v0.1.1", "v0.1.1", "0.1.1")

    err = capsys.readouterr().err
    assert "CI run 42 could not be watched to the end; it was not shown to be green" in err
    assert "is not green" not in err
    assert _count(calls, ("gh", "pr", "merge")) == 1
    assert _count(calls, _RUN_WATCH) == 2
    assert not [cmd for cmd in calls if cmd[:2] == ["git", "tag"]]
    assert _TAG_PUSH not in calls


def test_a_ci_watch_dropped_once_goes_on_when_the_retry_finishes(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    calls = _scripted(
        monkeypatch,
        {
            ("gh", "run", "list"): ["42\n"],
            _RUN_WATCH: [_DROPPED, ""],
            _RUN_READ: [_run_state("in_progress", "")],
        },
    )

    release._await_green_ci(_COMMIT)

    assert _count(calls, _RUN_WATCH) == 2
    assert calls[-1] == list(_RUN_WATCH)


@pytest.mark.parametrize("answer", ["", "OPEN\n\n"], ids=["unreadable", "open"])
def test_a_merge_github_did_not_confirm_is_neither_tagged_nor_called_unmerged(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], answer: str
) -> None:
    """The merge call said yes but the state does not: the operator has to look, not guess."""
    calls = _pr_world(monkeypatch, {("gh", "pr", "view"): answer})

    with pytest.raises(SystemExit):
        release._merge("190", _HEAD)

    assert not [cmd for cmd in calls if cmd[:2] == ["git", "tag"]]
    assert "could not tell whether pull request #190 merged" in capsys.readouterr().err


def test_a_merge_call_that_failed_after_github_merged_goes_on_to_the_tree_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A timeout on the response can hide a merge that happened; the state says which."""
    _pr_world(
        monkeypatch,
        {
            ("gh", "pr", "merge"): subprocess.CalledProcessError(1, ["gh"]),
            ("gh", "pr", "view"): f"MERGED\n{_MERGED}\n",
            ("git", "rev-parse"): "same-tree\n",
        },
    )

    assert release._merge("190", _HEAD) == _MERGED


def test_a_merge_call_that_failed_on_an_open_pull_request_says_nothing_reached_main(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _pr_world(
        monkeypatch,
        {
            ("gh", "pr", "merge"): subprocess.CalledProcessError(1, ["gh"]),
            ("gh", "pr", "view"): "OPEN\n\n",
        },
    )

    with pytest.raises(SystemExit):
        release._merge("190", _HEAD)

    err = capsys.readouterr().err
    assert "GitHub did not merge pull request #190 (OPEN)" in err
    assert "Nothing reached `main`" in err


def test_a_merge_commit_holding_another_tree_tells_the_operator_not_to_tag_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Spelling out the tag commands here would hand the rejected commit a tag by hand."""
    trees = iter(["tree-of-merge\n", "tree-of-head\n"])
    calls = _pr_world(monkeypatch, {("gh", "pr", "view"): f"MERGED\n{_MERGED}\n"})

    def _fake(cmd: list[str], **_: bool) -> str:
        calls.append(cmd)
        if cmd[:2] == ["git", "rev-parse"]:
            return next(trees)
        return f"MERGED\n{_MERGED}\n" if cmd[:3] == ["gh", "pr", "view"] else ""

    monkeypatch.setattr(release, "_run", _fake)

    with pytest.raises(SystemExit):
        release._merge("190", _HEAD)

    err = capsys.readouterr().err
    assert "Do not tag that commit" in err
    assert not any(command in err for command in release._TAG_BY_HAND), err


def test_trees_that_cannot_be_compared_stop_before_the_tag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _pr_world(
        monkeypatch,
        {
            ("gh", "pr", "view"): f"MERGED\n{_MERGED}\n",
            ("git", "fetch"): subprocess.CalledProcessError(128, ["git"]),
        },
    )

    with pytest.raises(SystemExit):
        release._merge("190", _HEAD)

    assert "compare them before any tag" in capsys.readouterr().err


def test_a_pull_request_that_cannot_be_opened_stops_with_nothing_merged(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _pr_world(monkeypatch, {("gh", "pr", "create"): "could not create pull request\n"})

    with pytest.raises(SystemExit):
        release._open_pull_request("release/v0.1.1", "v0.1.1")

    err = capsys.readouterr().err
    assert "Nothing reached `main`" in err
    assert "Open a pull request from it into `main`" in err


def test_a_refused_tag_push_stops_with_the_remaining_steps_and_moves_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The release is merged and the signed tag exists here; a traceback would strand both."""
    calls: list[list[str]] = []
    moved: list[str] = []
    monkeypatch.setattr(release, "_return_to_main", moved.append)

    with pytest.raises(SystemExit) as stopped:
        _cut(monkeypatch, _RELEASED, calls, failing=(tuple(_TAG_PUSH),))

    err = capsys.readouterr().err
    assert stopped.value.code == 1
    assert "git push origin refs/tags/vX.Y.Z" in err
    assert "git switch main" in err
    assert moved == []


@pytest.mark.parametrize(
    ("local", "remote"),
    [("  release/v0.1.1\n", ""), ("", "abc123\trefs/heads/release/v0.1.1\n")],
)
def test_a_release_branch_that_already_exists_stops_the_release_before_the_gate(
    monkeypatch: pytest.MonkeyPatch, local: str, remote: str
) -> None:
    """A leftover branch from a stopped release must be finished or removed, never reused blind."""
    _pr_world(
        monkeypatch,
        {
            ("git", "rev-parse", "--abbrev-ref"): "main\n",
            ("git", "rev-parse"): "same\n",
            ("git", "branch", "--list"): local,
            ("git", "ls-remote"): remote,
        },
    )

    with pytest.raises(SystemExit) as refused:
        release._preflight("release/v0.1.1")

    assert "release/v0.1.1 already exists" in str(refused.value.code)


def test_a_free_release_branch_passes_the_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    _pr_world(
        monkeypatch,
        {("git", "rev-parse", "--abbrev-ref"): "main\n", ("git", "rev-parse"): "same\n"},
    )

    release._preflight("release/v0.1.1")


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
    by_hand = [line for line in release._TAG_BY_HAND if " tag -f vX.Y " in line]

    # `tag.gpgSign` would otherwise turn the pointer into a signed tag that needs a message.
    assert calls[0] == ["git", "-c", "tag.gpgSign=false", "tag", "-f", "v0.1", "v0.1.1^{commit}"]
    assert by_hand
    assert all(
        line.startswith("git -c tag.gpgSign=false tag -f") and "^{commit}" in line
        for line in by_hand
    ), by_hand


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
    monkeypatch.setattr(release, "_preflight", lambda branch: order.append("preflight"))
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
    monkeypatch.setattr(release, "_preflight", lambda branch: None)
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
    monkeypatch.setattr(release, "_preflight", lambda branch: None)
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
