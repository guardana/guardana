"""The settings check reports PRESENT only for a setting it read, and never calls a read a drill."""

import base64
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

import check_repo_settings as check

REPO = "acme/widgets"

_WORKFLOW = """\
on:
  push:
    tags: ["v*.*.*"]
jobs:
  ci-passed:
    runs-on: ubuntu-24.04
    steps:
      - run: gh run list --workflow ci.yml
  publish:
    needs: ci-passed
    environment: pypi
    runs-on: ubuntu-24.04
    steps:
      - run: echo publish
"""


def _contents(text: str) -> dict[str, object]:
    return {"encoding": "base64", "content": base64.b64encode(text.encode()).decode()}


def _healthy() -> dict[str, object]:
    """Every response a repository with every setting in place answers."""
    return {
        f"repos/{REPO}": {"owner": {"type": "Organization"}},
        f"repos/{REPO}/private-vulnerability-reporting": {"enabled": True},
        f"repos/{REPO}/rulesets?includes_parents=true&per_page=100": [
            {"id": 7, "target": "branch", "enforcement": "active"},
            {"id": 9, "target": "tag", "enforcement": "active"},
        ],
        f"repos/{REPO}/rulesets/9": {
            "target": "tag",
            "enforcement": "active",
            "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
            "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}],
            "bypass_actors": [
                {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}
            ],
        },
        f"repos/{REPO}/environments/pypi": {
            "protection_rules": [
                {"type": "wait_timer", "wait_timer": 0},
                {"type": "required_reviewers", "reviewers": [{"type": "User"}]},
            ]
        },
        f"repos/{REPO}/actions/workflows/release.yml": {"state": "active"},
        f"repos/{REPO}/contents/.github/workflows/release.yml": _contents(_WORKFLOW),
        "orgs/acme/packages/container/guardana": {"visibility": "public"},
        "orgs/acme/packages/container/guardana-collector": {"visibility": "public"},
    }


class _Fake:
    """An injected runner that answers `gh api <path>` from a table, and records each call."""

    def __init__(self, table: dict[str, object], failures: dict[str, tuple[int, str]]) -> None:
        self.table = table
        self.failures = failures
        self.calls: list[str] = []

    def __call__(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        path = args[-1]
        self.calls.append(path)
        if path in self.failures:
            code, stderr = self.failures[path]
            return subprocess.CompletedProcess(list(args), code, "", stderr)
        if path not in self.table:
            return subprocess.CompletedProcess(list(args), 1, "", "gh: Not Found (HTTP 404)")
        return subprocess.CompletedProcess(list(args), 0, json.dumps(self.table[path]), "")


def _run(
    table: dict[str, object] | None = None, failures: dict[str, tuple[int, str]] | None = None
) -> dict[str, check.Result]:
    fake = _Fake(_healthy() if table is None else table, failures or {})
    return {result.setting: result for result in check.check_all(REPO, check.Api(fake))}


def _outcome(results: dict[str, check.Result], prefix: str) -> check.Outcome:
    (match,) = [result for name, result in results.items() if name.startswith(prefix)]
    return match.outcome


def test_every_setting_in_place_is_present_and_exits_zero() -> None:
    results = _run()

    assert {result.outcome for result in results.values()} == {check.Outcome.PRESENT}
    assert len(results) == 6
    assert check.exit_code(list(results.values())) == 0


def test_vulnerability_reporting_disabled_is_absent() -> None:
    table = _healthy()
    table[f"repos/{REPO}/private-vulnerability-reporting"] = {"enabled": False}

    results = _run(table)

    assert _outcome(results, "private vulnerability") is check.Outcome.ABSENT
    assert check.exit_code(list(results.values())) == 1


@pytest.mark.parametrize(
    "ruleset",
    [
        {"enforcement": "evaluate"},
        {"conditions": {"ref_name": {"include": ["refs/tags/release-*"], "exclude": []}}},
        {"conditions": {"ref_name": {"include": ["~ALL"], "exclude": ["refs/tags/v*"]}}},
        {"conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": ["refs/tags/v*rc*"]}}},
        {"conditions": {"ref_name": {"include": ["refs/tags/v*.*.*"], "exclude": []}}},
        {"rules": [{"type": "update"}, {"type": "deletion"}]},
        {"rules": [{"type": "creation"}, {"type": "deletion"}]},
        {"rules": [{"type": "creation"}, {"type": "update"}]},
        {"bypass_actors": [{"actor_id": 4, "actor_type": "RepositoryRole"}]},
        {"bypass_actors": [{"actor_id": 1, "actor_type": "RepositoryRole"}]},
        {"bypass_actors": [{"actor_id": 31, "actor_type": "RepositoryRole"}]},
        {"bypass_actors": [{"actor_id": 15368, "actor_type": "Integration"}]},
        {"bypass_actors": [{"actor_id": 12, "actor_type": "Team"}]},
        {"bypass_actors": [{"actor_id": None, "actor_type": "DeployKey"}]},
        {
            "bypass_actors": [
                {"actor_id": 5, "actor_type": "RepositoryRole"},
                {"actor_id": 4, "actor_type": "RepositoryRole"},
            ]
        },
    ],
    ids=[
        "not-enforced",
        "other-tags",
        "v-excluded",
        "candidates-excluded",
        "moving-tag-not-included",
        "no-creation-rule",
        "no-update-rule",
        "no-deletion-rule",
        "write-role-bypasses",
        "read-role-bypasses",
        "custom-role-bypasses",
        "app-bypasses",
        "team-bypasses",
        "deploy-key-bypasses",
        "admin-and-write-bypass",
    ],
)
def test_a_tag_ruleset_that_does_not_guard_release_tags_is_absent(
    ruleset: dict[str, object],
) -> None:
    table = _healthy()
    detail = table[f"repos/{REPO}/rulesets/9"]
    assert isinstance(detail, dict)
    table[f"repos/{REPO}/rulesets/9"] = {**detail, **ruleset}

    assert _outcome(_run(table), "tag ruleset") is check.Outcome.ABSENT


@pytest.mark.parametrize(
    "bypass",
    [
        [{"actor_id": 2, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
        [{"actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "always"}],
        [
            {"actor_id": 5, "actor_type": "RepositoryRole"},
            {"actor_id": 2, "actor_type": "RepositoryRole"},
        ],
    ],
    ids=["maintain-role", "organization-admin", "admin-and-maintain"],
)
def test_a_tag_ruleset_only_maintainers_can_bypass_is_present(bypass: list[object]) -> None:
    table = _healthy()
    detail = table[f"repos/{REPO}/rulesets/9"]
    assert isinstance(detail, dict)
    table[f"repos/{REPO}/rulesets/9"] = {**detail, "bypass_actors": bypass}

    assert _outcome(_run(table), "tag ruleset") is check.Outcome.PRESENT


def test_a_tag_ruleset_nobody_can_bypass_is_absent_because_no_release_could_tag() -> None:
    table = _healthy()
    detail = table[f"repos/{REPO}/rulesets/9"]
    assert isinstance(detail, dict)
    table[f"repos/{REPO}/rulesets/9"] = {**detail, "bypass_actors": []}

    results = _run(table)

    assert _outcome(results, "tag ruleset") is check.Outcome.ABSENT
    (ruleset,) = [r for name, r in results.items() if name.startswith("tag ruleset")]
    assert "no one, the release itself included, could create or move a v* tag" in ruleset.detail


def test_a_ruleset_answered_without_its_bypass_list_is_not_checked() -> None:
    """GitHub leaves `bypass_actors` out for a token that may not edit the ruleset."""
    table = _healthy()
    detail = table[f"repos/{REPO}/rulesets/9"]
    assert isinstance(detail, dict)
    table[f"repos/{REPO}/rulesets/9"] = {k: v for k, v in detail.items() if k != "bypass_actors"}

    results = _run(table)

    assert _outcome(results, "tag ruleset") is check.Outcome.NOT_CHECKED
    (ruleset,) = [r for name, r in results.items() if name.startswith("tag ruleset")]
    assert "bypass" in ruleset.detail


def test_a_ruleset_without_an_update_rule_is_absent_whatever_its_bypass_list() -> None:
    """A ruleset that lets anyone move a release tag is a gap the bypass list cannot close."""
    table = _healthy()
    detail = table[f"repos/{REPO}/rulesets/9"]
    assert isinstance(detail, dict)
    table[f"repos/{REPO}/rulesets/9"] = {
        **{k: v for k, v in detail.items() if k != "bypass_actors"},
        "rules": [{"type": "creation"}, {"type": "deletion"}],
    }

    assert _outcome(_run(table), "tag ruleset") is check.Outcome.ABSENT


@pytest.mark.parametrize(
    "ref_name",
    [
        {"include": ["refs/tags/v[0-9]*"], "exclude": []},
        {"include": ["refs/tags/v*"], "exclude": ["refs/tags/v99*"]},
        {"include": ["~ALL"], "exclude": ["refs/*-legacy"]},
    ],
    ids=["narrower-include", "exclude-inside-v", "exclude-reaching-v"],
)
def test_patterns_that_may_leave_a_release_tag_out_are_not_checked(
    ref_name: dict[str, object],
) -> None:
    """Every sample tag is covered, but the patterns do not prove every v* tag is."""
    table = _healthy()
    detail = table[f"repos/{REPO}/rulesets/9"]
    assert isinstance(detail, dict)
    table[f"repos/{REPO}/rulesets/9"] = {**detail, "conditions": {"ref_name": ref_name}}

    assert _outcome(_run(table), "tag ruleset") is check.Outcome.NOT_CHECKED


@pytest.mark.parametrize(
    "ref_name",
    [
        {"include": ["refs/tags/v*"], "exclude": ["refs/tags/nightly-*", "refs/heads/*"]},
        {"include": ["~ALL"], "exclude": ["refs/tags/release-*"]},
        {"include": ["refs/tags/*"], "exclude": []},
    ],
    ids=["unrelated-excludes", "all-but-other-tags", "every-tag"],
)
def test_patterns_that_provably_cover_release_tags_are_present(
    ref_name: dict[str, object],
) -> None:
    table = _healthy()
    detail = table[f"repos/{REPO}/rulesets/9"]
    assert isinstance(detail, dict)
    table[f"repos/{REPO}/rulesets/9"] = {**detail, "conditions": {"ref_name": ref_name}}

    assert _outcome(_run(table), "tag ruleset") is check.Outcome.PRESENT


def test_no_tag_ruleset_at_all_is_absent() -> None:
    table = _healthy()
    table[f"repos/{REPO}/rulesets?includes_parents=true&per_page=100"] = [
        {"id": 7, "target": "branch", "enforcement": "active"}
    ]

    assert _outcome(_run(table), "tag ruleset") is check.Outcome.ABSENT


def test_a_ruleset_detail_that_cannot_be_read_is_not_checked() -> None:
    results = _run(failures={f"repos/{REPO}/rulesets/9": (1, "gh: Forbidden (HTTP 403)")})

    assert _outcome(results, "tag ruleset") is check.Outcome.NOT_CHECKED


@pytest.mark.parametrize(
    "rules",
    [[], [{"type": "required_reviewers", "reviewers": []}], [{"type": "wait_timer"}]],
    ids=["none", "no-reviewers", "timer-only"],
)
def test_a_pypi_environment_without_a_reviewer_is_absent(rules: list[object]) -> None:
    table = _healthy()
    table[f"repos/{REPO}/environments/pypi"] = {"protection_rules": rules}

    assert _outcome(_run(table), "pypi environment") is check.Outcome.ABSENT


def test_a_pypi_environment_answering_404_is_not_checked() -> None:
    table = _healthy()
    del table[f"repos/{REPO}/environments/pypi"]

    assert _outcome(_run(table), "pypi environment") is check.Outcome.NOT_CHECKED


@pytest.mark.parametrize(
    ("needs", "state"),
    [(None, "active"), ("build", "active"), (["build"], "active"), ("ci-passed", "disabled")],
    ids=["no-needs", "other-job", "other-list", "workflow-disabled"],
)
def test_a_publish_that_does_not_wait_for_ci_is_absent(needs: object, state: str) -> None:
    workflow = _WORKFLOW.replace("    needs: ci-passed\n", "")
    if needs is not None:
        workflow = workflow.replace("  publish:\n", f"  publish:\n    needs: {json.dumps(needs)}\n")
    table = _healthy()
    table[f"repos/{REPO}/contents/.github/workflows/release.yml"] = _contents(workflow)
    table[f"repos/{REPO}/actions/workflows/release.yml"] = {"state": state}

    assert _outcome(_run(table), "release workflow") is check.Outcome.ABSENT


def test_a_gate_listed_among_several_needs_is_present() -> None:
    workflow = _WORKFLOW.replace("needs: ci-passed", "needs: [build, ci-passed]")
    table = _healthy()
    table[f"repos/{REPO}/contents/.github/workflows/release.yml"] = _contents(workflow)

    assert _outcome(_run(table), "release workflow") is check.Outcome.PRESENT


@pytest.mark.parametrize(
    "content",
    [_contents("jobs: [unclosed"), _contents("- just\n- a list\n"), {"encoding": "none"}],
    ids=["bad-yaml", "not-a-mapping", "no-content"],
)
def test_a_workflow_that_cannot_be_read_is_not_checked(content: dict[str, object]) -> None:
    table = _healthy()
    table[f"repos/{REPO}/contents/.github/workflows/release.yml"] = content

    assert _outcome(_run(table), "release workflow") is check.Outcome.NOT_CHECKED


def test_a_private_package_is_absent_and_one_without_scope_is_not_checked() -> None:
    table = _healthy()
    table["orgs/acme/packages/container/guardana"] = {"visibility": "private"}
    failures = {
        "orgs/acme/packages/container/guardana-collector": (
            1,
            "gh: You need at least read:packages scope to get a package. (HTTP 403)",
        )
    }

    results = _run(table, failures)

    assert _outcome(results, "ghcr package guardana ") is check.Outcome.ABSENT
    collector = results["ghcr package guardana-collector is public"]
    assert collector.outcome is check.Outcome.NOT_CHECKED
    assert "HTTP 403" in collector.detail
    assert check.exit_code(list(results.values())) == 1


def test_a_user_owned_repository_reads_packages_under_users() -> None:
    table = _healthy()
    table[f"repos/{REPO}"] = {"owner": {"type": "User"}}
    table["users/acme/packages/container/guardana"] = {"visibility": "public"}
    table["users/acme/packages/container/guardana-collector"] = {"visibility": "public"}

    results = _run(table)

    assert _outcome(results, "ghcr package guardana ") is check.Outcome.PRESENT


def test_an_unexpected_response_shape_is_not_checked_never_present() -> None:
    table = _healthy()
    table[f"repos/{REPO}/private-vulnerability-reporting"] = {"enabled": "yes"}
    table["orgs/acme/packages/container/guardana"] = ["not", "an", "object"]

    results = _run(table)

    assert _outcome(results, "private vulnerability") is check.Outcome.NOT_CHECKED
    assert _outcome(results, "ghcr package guardana ") is check.Outcome.NOT_CHECKED


def test_output_that_is_not_json_is_not_checked() -> None:
    fake = _Fake({}, {})

    def runner(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        fake(args)
        return subprocess.CompletedProcess(list(args), 0, "<html>", "")

    results = check.check_all(REPO, check.Api(runner))

    assert {result.outcome for result in results} == {check.Outcome.NOT_CHECKED}


def test_without_authentication_every_setting_is_not_checked_and_exits_two() -> None:
    message = "To get started with GitHub CLI, please run:  gh auth login"
    fake = _Fake({}, {})

    def runner(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        fake(args)
        return subprocess.CompletedProcess(list(args), 4, "", message)

    results = check.check_all(REPO, check.Api(runner))

    assert {result.outcome for result in results} == {check.Outcome.NOT_CHECKED}
    assert all("not authenticated" in result.detail for result in results)
    assert check.exit_code(results) == 2


def test_a_runner_that_times_out_is_not_checked() -> None:
    def runner(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(list(args), 60)

    results = check.check_all(REPO, check.Api(runner))

    assert {result.outcome for result in results} == {check.Outcome.NOT_CHECKED}


def _fake_gh(bin_dir: Path, data_dir: Path) -> None:
    """A `gh` on PATH that serves `gh api <path>` from files, 404 for anything else."""
    script = bin_dir / "gh"
    script.write_text(
        "#!/bin/sh\n"
        "for last; do :; done\n"
        f'f="{data_dir}/$(printf %s "$last" | tr "/?=&." "_____").json"\n'
        'if [ -f "$f" ]; then cat "$f"; exit 0; fi\n'
        'echo "gh: Not Found (HTTP 404)" >&2\n'
        "exit 1\n",
        encoding="utf-8",
    )
    script.chmod(0o755)


def _serve(data_dir: Path, table: dict[str, object]) -> None:
    for path, body in table.items():
        name = path.translate(str.maketrans("/?=&.", "_____"))
        (data_dir / f"{name}.json").write_text(json.dumps(body), encoding="utf-8")


def test_main_with_a_fake_gh_on_path_reads_every_setting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bin_dir, data_dir = tmp_path / "bin", tmp_path / "data"
    bin_dir.mkdir()
    data_dir.mkdir()
    _fake_gh(bin_dir, data_dir)
    _serve(data_dir, _healthy())
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")

    code = check.main(["--repo", REPO])

    out = capsys.readouterr().out
    assert code == 0, out
    assert out.count("PRESENT") >= 6
    assert "EXERCISED" not in out
    assert "not a drill" in out
    assert "docs/" not in out


def test_main_with_a_fake_gh_reports_a_missing_environment_as_not_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bin_dir, data_dir = tmp_path / "bin", tmp_path / "data"
    bin_dir.mkdir()
    data_dir.mkdir()
    _fake_gh(bin_dir, data_dir)
    table = _healthy()
    del table[f"repos/{REPO}/environments/pypi"]
    _serve(data_dir, table)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")

    code = check.main(["--repo", REPO])

    assert code == 2
    assert "NOT CHECKED  pypi environment" in capsys.readouterr().out


def test_without_gh_on_path_every_setting_is_not_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))

    code = check.main(["--repo", REPO])

    out = capsys.readouterr().out
    assert code == 2
    assert "PRESENT " not in out
    assert out.count("NOT CHECKED") == 6
    assert "gh is not installed" in out


def test_help_prints_usage_and_runs_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    fake = _Fake(_healthy(), {})

    with pytest.raises(SystemExit) as exit_info:
        check.main(["--help"], runner=fake)

    assert exit_info.value.code == 0
    assert "--repo" in capsys.readouterr().out
    assert fake.calls == []


@pytest.mark.parametrize("repo", ["acme", "acme/widgets/extra", "../x/y", "acme/w?x=1"])
def test_a_malformed_repository_is_refused_before_any_call(
    repo: str, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = _Fake(_healthy(), {})

    with pytest.raises(SystemExit) as exit_info:
        check.main(["--repo", repo], runner=fake)

    assert exit_info.value.code == 2
    assert "--repo" in capsys.readouterr().err
    assert fake.calls == []


@pytest.mark.parametrize(
    ("outcomes", "expected"),
    [
        ([check.Outcome.PRESENT], 0),
        ([check.Outcome.PRESENT, check.Outcome.ABSENT], 1),
        ([check.Outcome.PRESENT, check.Outcome.NOT_CHECKED], 2),
        ([check.Outcome.NOT_CHECKED, check.Outcome.ABSENT], 1),
        ([], 2),
    ],
)
def test_exit_code(outcomes: list[check.Outcome], expected: int) -> None:
    results = [check.Result(f"s{n}", outcome, "") for n, outcome in enumerate(outcomes)]

    assert check.exit_code(results) == expected
