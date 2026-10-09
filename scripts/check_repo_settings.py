#!/usr/bin/env python3
"""Read the repository settings a safe release relies on, through read-only `gh api` calls.

    uv run python scripts/check_repo_settings.py                 # guardana/guardana
    uv run python scripts/check_repo_settings.py --repo acme/fork

Each setting prints PRESENT, ABSENT or NOT CHECKED. NOT CHECKED means the setting
could not be read: no `gh`, no authentication, a `403` or `404`, or an answer of a
shape this script does not know. GitHub answers `404` both for a missing resource
and for one the token may not see, so a `404` is never read as ABSENT.

Exit codes: 0 every setting present, 1 any absent, 2 any not checked and none absent.
Reading a setting is not a drill: it shows the setting exists, not that it holds.
"""

import argparse
import base64
import binascii
import functools
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase

if sys.version_info < (3, 11):  # noqa: UP036 — explain the system Python failure
    raise SystemExit(
        "check_repo_settings.py needs Python 3.11 or newer; "
        "run `uv run python scripts/check_repo_settings.py`"
    )

from enum import StrEnum

import yaml

DEFAULT_REPO = "guardana/guardana"
PACKAGES = ("guardana", "guardana-collector")
RELEASE_WORKFLOW = ".github/workflows/release.yml"
GATE_JOB = "ci-passed"
PUBLISH_JOB = "publish"
ENVIRONMENT = "pypi"
RELEASE_TAGS = ("refs/tags/v1.2.3", "refs/tags/v1.2")
"""A full release tag and a moving `vX.Y` tag; a tag ruleset has to cover both."""
TAG_RULES = (("creation", "creating"), ("update", "updating"), ("deletion", "deleting"))
"""The ruleset rules a safe release relies on, each with what it restricts."""
_MAINTAINER_ROLES = frozenset({2, 5})
"""GitHub's ids for the built-in Maintain and Admin repository roles."""
_ABOVE_REPOSITORY = frozenset({"OrganizationAdmin", "EnterpriseOwner"})

_TIMEOUT_SECONDS = 60
_GH_NO_CREDENTIALS = 4
"""The exit status `gh` uses when it holds no credentials."""
_HTTP_STATUS = re.compile(r"\(HTTP (\d{3})\)")
_REPO = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]*)/[A-Za-z0-9._-]+")

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


class Outcome(StrEnum):
    """What reading one setting established."""

    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    NOT_CHECKED = "NOT CHECKED"


@dataclass(frozen=True, slots=True)
class Result:
    """One setting, what was established about it, and why."""

    setting: str
    outcome: Outcome
    detail: str


class NotCheckedError(Exception):
    """A setting could not be read, so nothing can be said about it."""


def gh(args: Sequence[str]) -> "subprocess.CompletedProcess[str]":
    """Run `gh` with `args`, raising `NotCheckedError` when it is not installed."""
    executable = shutil.which("gh")
    if executable is None:
        raise NotCheckedError("gh is not installed")
    return subprocess.run(  # noqa: S603 — fixed paths and a validated OWNER/NAME
        [executable, *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=_TIMEOUT_SECONDS,
    )


class Api:
    """Read-only `gh api` GETs, each path asked at most once."""

    def __init__(self, runner: Runner = gh) -> None:
        """Answer each request through `runner`, which takes the arguments after `gh`."""
        self._runner = runner
        self._answers: dict[str, object | NotCheckedError] = {}

    def get(self, path: str) -> object:
        """Return the decoded JSON at `path`, or raise `NotCheckedError` saying why not."""
        if path not in self._answers:
            try:
                self._answers[path] = self._fetch(path)
            except NotCheckedError as error:
                self._answers[path] = error
        answer = self._answers[path]
        if isinstance(answer, NotCheckedError):
            raise answer
        return answer

    def _fetch(self, path: str) -> object:
        args = ["api", "--method", "GET", "-H", "Accept: application/vnd.github+json", path]
        try:
            completed = self._runner(args)
        except subprocess.TimeoutExpired as error:
            raise NotCheckedError(f"gh api {path} timed out") from error
        except OSError as error:
            raise NotCheckedError(f"gh could not run: {error}") from error
        if completed.returncode != 0:
            raise NotCheckedError(_failure(completed))
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise NotCheckedError(f"gh api {path} did not answer JSON") from error


def _failure(completed: "subprocess.CompletedProcess[str]") -> str:
    stderr = completed.stderr.strip()
    if completed.returncode == _GH_NO_CREDENTIALS or "gh auth login" in stderr:
        return "gh is not authenticated (gh auth login)"
    lines = [line for line in stderr.splitlines() if line.strip()]
    if not lines:
        return f"gh exited {completed.returncode}"
    line = next((line for line in lines if _HTTP_STATUS.search(line)), lines[-1])
    return line.removeprefix("gh: ")


def _mapping(value: object, what: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise NotCheckedError(f"{what}: unexpected answer")
    return value


def _sequence(value: object, what: str) -> list[object]:
    if not isinstance(value, list):
        raise NotCheckedError(f"{what}: unexpected answer")
    return value


def _strings(value: object, what: str) -> list[str]:
    items = _sequence([] if value is None else value, what)
    if not all(isinstance(item, str) for item in items):
        raise NotCheckedError(f"{what}: unexpected answer")
    return [str(item) for item in items]


Finding = tuple[Outcome, str]


def vulnerability_reporting(api: Api, repo: str) -> Finding:
    """Check private vulnerability reporting, the channel `SECURITY.md` sends reporters to."""
    answer = _mapping(api.get(f"repos/{repo}/private-vulnerability-reporting"), "reporting")
    enabled = answer.get("enabled")
    if not isinstance(enabled, bool):
        raise NotCheckedError("private vulnerability reporting: unexpected answer")
    return (Outcome.PRESENT, "") if enabled else (Outcome.ABSENT, "disabled")


def _covers_release_tags(ref_name: dict[str, object]) -> bool:
    include = _strings(ref_name.get("include"), "ruleset include")
    exclude = _strings(ref_name.get("exclude"), "ruleset exclude")

    def matched(patterns: list[str], ref: str) -> bool:
        return any(pattern == "~ALL" or fnmatchcase(ref, pattern) for pattern in patterns)

    return all(matched(include, ref) and not matched(exclude, ref) for ref in RELEASE_TAGS)


def _ruleset_gap(detail: dict[str, object]) -> str | None:
    """Say why a tag ruleset does not keep release tags to maintainers, or None if it does.

    Raises `NotCheckedError` when the answer leaves out who may bypass the ruleset.
    """
    name = detail.get("name", detail.get("id"))
    if detail.get("enforcement") != "active":
        return f"ruleset {name} is not enforced"
    conditions = _mapping(detail.get("conditions") or {}, "ruleset conditions")
    ref_name = _mapping(conditions.get("ref_name") or {}, "ruleset ref_name")
    if not _covers_release_tags(ref_name):
        return f"ruleset {name} does not cover refs/tags/v*"
    rules = [_mapping(rule, "ruleset rule") for rule in _sequence(detail.get("rules"), "rules")]
    types = {rule.get("type") for rule in rules}
    for rule_type, verb in TAG_RULES:
        if rule_type not in types:
            return f"ruleset {name} does not restrict {verb} a tag"
    if "bypass_actors" not in detail:
        raise NotCheckedError(
            f"ruleset {name}: the answer lists no bypass_actors, which GitHub shows only to a "
            f"token that may administer the ruleset"
        )
    actors = [_mapping(a, "bypass actor") for a in _sequence(detail["bypass_actors"], "bypass")]
    if not actors:
        return (
            f"ruleset {name} lets nobody bypass it, so no one, the release itself included, "
            f"could create or move a v* tag"
        )
    below = [_actor(actor) for actor in actors if not _maintainer_or_above(actor)]
    if below:
        return f"ruleset {name} lets {', '.join(below)} bypass it"
    return None


def _maintainer_or_above(actor: dict[str, object]) -> bool:
    actor_type = actor.get("actor_type")
    if actor_type in _ABOVE_REPOSITORY:
        return True
    return actor_type == "RepositoryRole" and actor.get("actor_id") in _MAINTAINER_ROLES


def _actor(actor: dict[str, object]) -> str:
    return f"{actor.get('actor_type')} {actor.get('actor_id')}"


def tag_ruleset(api: Api, repo: str) -> Finding:
    """Check for an active tag ruleset that maintainers, and only they, can bypass, on `v*` tags.

    It has to restrict creating, updating and deleting them: a tag moved or recreated after
    a publish no longer names the bytes people installed.
    """
    listing = _sequence(
        api.get(f"repos/{repo}/rulesets?includes_parents=true&per_page=100"), "rulesets"
    )
    gaps: list[str] = []
    unread: list[str] = []
    for entry in (_mapping(item, "ruleset") for item in listing):
        ruleset_id = entry.get("id")
        if entry.get("target") != "tag" or not isinstance(ruleset_id, int):
            continue
        try:
            detail = _mapping(api.get(f"repos/{repo}/rulesets/{ruleset_id}"), "ruleset")
            gap = _ruleset_gap(detail)
        except NotCheckedError as error:
            unread.append(f"ruleset {ruleset_id}: {error}")
            continue
        if gap is None:
            return Outcome.PRESENT, ""
        gaps.append(gap)
    if unread:
        raise NotCheckedError("; ".join(unread))
    return Outcome.ABSENT, "; ".join(gaps) or "no tag ruleset"


def environment_approval(api: Api, repo: str) -> Finding:
    """Check that the `pypi` environment requires a reviewer before a publish proceeds."""
    answer = _mapping(api.get(f"repos/{repo}/environments/{ENVIRONMENT}"), "environment")
    for rule in _sequence(answer.get("protection_rules"), "protection_rules"):
        fields = _mapping(rule, "protection rule")
        if fields.get("type") == "required_reviewers" and fields.get("reviewers"):
            return Outcome.PRESENT, ""
    return Outcome.ABSENT, "no required reviewer"


def _needs(job: dict[str, object]) -> list[str]:
    needs = job.get("needs")
    return [needs] if isinstance(needs, str) else _strings(needs, "needs")


def release_ci_gate(api: Api, repo: str) -> Finding:
    """Check that the release workflow is active and its publish job needs the CI gate job."""
    workflow = _mapping(api.get(f"repos/{repo}/actions/workflows/release.yml"), "workflow")
    state = workflow.get("state")
    if not isinstance(state, str):
        raise NotCheckedError("release workflow: unexpected answer")
    contents = _mapping(api.get(f"repos/{repo}/contents/{RELEASE_WORKFLOW}"), "contents")
    content = contents.get("content")
    if contents.get("encoding") != "base64" or not isinstance(content, str):
        raise NotCheckedError(f"{RELEASE_WORKFLOW}: no file content in the answer")
    try:
        document = yaml.safe_load(base64.b64decode(content).decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, yaml.YAMLError) as error:
        raise NotCheckedError(f"{RELEASE_WORKFLOW} could not be parsed") from error
    jobs = _mapping(_mapping(document, RELEASE_WORKFLOW).get("jobs"), "jobs")
    if state != "active":
        return Outcome.ABSENT, f"the workflow is {state}"
    if GATE_JOB not in jobs:
        return Outcome.ABSENT, f"no {GATE_JOB} job"
    publish = jobs.get(PUBLISH_JOB)
    if publish is None:
        return Outcome.ABSENT, f"no {PUBLISH_JOB} job"
    if GATE_JOB not in _needs(_mapping(publish, PUBLISH_JOB)):
        return Outcome.ABSENT, f"{PUBLISH_JOB} does not need {GATE_JOB}"
    return Outcome.PRESENT, ""


def package_public(api: Api, repo: str, package: str) -> Finding:
    """Check that a container package the release pushes is public, as `docker run` needs."""
    owner = _mapping(_mapping(api.get(f"repos/{repo}"), "repository").get("owner"), "owner")
    scopes = {"Organization": "orgs", "User": "users"}
    owner_type = owner.get("type")
    if not isinstance(owner_type, str) or owner_type not in scopes:
        raise NotCheckedError("repository owner: unexpected answer")
    scope = scopes[owner_type]
    login = repo.split("/", 1)[0]
    answer = _mapping(api.get(f"{scope}/{login}/packages/container/{package}"), "package")
    visibility = answer.get("visibility")
    if not isinstance(visibility, str):
        raise NotCheckedError(f"package {package}: unexpected answer")
    return (Outcome.PRESENT, "") if visibility == "public" else (Outcome.ABSENT, visibility)


CHECKS: tuple[tuple[str, Callable[[Api, str], Finding]], ...] = (
    ("private vulnerability reporting is on", vulnerability_reporting),
    ("tag ruleset guards refs/tags/v*, bypassable by maintainers only", tag_ruleset),
    (f"{ENVIRONMENT} environment requires a reviewer", environment_approval),
    (f"release workflow publishes only after {GATE_JOB}", release_ci_gate),
    *(
        (f"ghcr package {name} is public", functools.partial(package_public, package=name))
        for name in PACKAGES
    ),
)


def check_all(repo: str, api: Api) -> list[Result]:
    """Read every setting in `CHECKS` for `repo`."""
    results: list[Result] = []
    for setting, check in CHECKS:
        try:
            outcome, detail = check(api, repo)
        except NotCheckedError as error:
            outcome, detail = Outcome.NOT_CHECKED, str(error)
        results.append(Result(setting, outcome, detail))
    return results


def exit_code(results: Sequence[Result]) -> int:
    """0 when every setting is present, 1 when any is absent, 2 when any could not be read."""
    outcomes = {result.outcome for result in results}
    if Outcome.ABSENT in outcomes:
        return 1
    if not results or Outcome.NOT_CHECKED in outcomes:
        return 2
    return 0


def _repository(value: str) -> str:
    if not _REPO.fullmatch(value) or value.split("/", 1)[1].strip(".") == "":
        raise argparse.ArgumentTypeError(f"{value!r} is not OWNER/NAME")
    return value


def main(argv: list[str] | None = None, runner: Runner = gh) -> int:
    """Print each setting's outcome and return the exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", type=_repository, default=DEFAULT_REPO, help="OWNER/NAME to read")
    args = parser.parse_args(argv)
    results = check_all(args.repo, Api(runner))
    print(f"Settings a safe release relies on, read from {args.repo}:")
    for result in results:
        line = f"{result.outcome.value:<12} {result.setting}"
        print(f"{line}: {result.detail}" if result.detail else line)
    counts = {outcome: sum(r.outcome is outcome for r in results) for outcome in Outcome}
    print(
        f"{len(results)} settings: {counts[Outcome.PRESENT]} present, "
        f"{counts[Outcome.ABSENT]} absent, {counts[Outcome.NOT_CHECKED]} not checked"
    )
    print("Reading a setting is not a drill: it shows the setting exists, not that it holds.")
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
