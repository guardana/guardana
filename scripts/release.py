#!/usr/bin/env python3
"""Cut a release in one command: gate -> bump -> changelog -> commit -> push -> CI -> tag.

Pushing the tag is what triggers `release.yml` to build and publish all five packages to PyPI (which
still pauses on the `pypi` environment's approval — a deliberate final gate).

The branch and the tag go up as two steps with CI in between, and that ordering is
load-bearing: pushing both at once races CI against the publish, and a red run then
costs a second approval click and leaves a cancelled release in the history.

    uv run python scripts/release.py patch            # 0.1.0 -> 0.1.1
    uv run python scripts/release.py minor            # 0.1.0 -> 0.2.0
    uv run python scripts/release.py 0.1.0            # release the current version (first release)
    uv run python scripts/release.py patch --dry-run  # show the plan, change nothing

Run it from a clean `main`. Only a maintainer (repo admin) can push the resulting
`v*` tag — enforced by a tag protection ruleset — so a release is a deliberate act.
"""

import argparse
import datetime
import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

_ROOT = Path(__file__).resolve().parent.parent
_CORE_PYPROJECT = _ROOT / "packages" / "guardana-core" / "pyproject.toml"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_VERSION_RE = re.compile(r'^version = "(?P<v>[^"]+)"', re.MULTILINE)
# Matches the top unreleased heading in either form the changelog uses: a bare
# `## [Unreleased]` (what a previous roll leaves behind) or `## [X] - Unreleased`.
_UNRELEASED_RE = re.compile(r"^## .*Unreleased.*$", re.MULTILINE | re.IGNORECASE)
# What the release writes besides the files `bump_version.py --dry-run` names: the
# changelog, the lock, and the generators' outputs.
_RELEASE_FILES = frozenset(
    {
        "CHANGELOG.md",
        "uv.lock",
        "packages/guardana-rules/src/guardana/rules/guardana-pack.yaml",
        "site/index.html",
        "site/llms.txt",
        "site/.well-known/security.txt",
        "site/favicon.ico",
        "site/apple-touch-icon.png",
        "site/apple-touch-icon-precomposed.png",
    }
)
_RELEASE_TREES = ("docs/generated/", "site/docs/", "site/schemas/")
_BUMP_WRITES_RE = re.compile(r"^\s*would update (\S+)\s*$", re.MULTILINE)
_SURFACE = "docs/generated/api-surface.json"
_SURFACE_PATH = _ROOT / _SURFACE
_CANDIDATE_RE = re.compile(r"\d+\.\d+\.\d+rc\d+")
_FINAL_RE = re.compile(r"(?P<major>\d+)\.\d+\.\d+")
_VERSIONING = _ROOT / "docs" / "compatibility.md"
# The versioning policy's statement of the project's status, which a final 1.x release makes
# false; a wrapped line may split it, so the gap between the words may hold a newline.
_PRE_1_STATEMENT_RE = re.compile(r"\bis\s+\**(?P<status>pre-1\.0)\b")
# What `main` does after a green CI, spelled for a hand to type when the wait could not be done.
_TAG_BY_HAND = (
    'git tag -a vX.Y.Z -m "Guardana vX.Y.Z"',
    "git push origin refs/tags/vX.Y.Z",
    'git tag -f vX.Y "vX.Y.Z^{commit}" && git push -f origin vX.Y',
)
_SURFACE_SECTION_RE = re.compile(r"^### (Changed|Deprecated|Removed)\b", re.MULTILINE)
_RELEASE_TAG_GLOB = "v[0-9]*.[0-9]*.[0-9]*"
_PACK = "examples/reference_pack"
_PACK_PYPROJECT = _ROOT / _PACK / "pyproject.toml"


def _run(cmd: list[str], *, capture: bool = False) -> str:
    # S603: every command here is a fixed literal (git / uv), never user input.
    result = subprocess.run(  # noqa: S603
        cmd, cwd=_ROOT, check=True, text=True, capture_output=capture
    )
    return result.stdout if capture else ""


def _current_version() -> str:
    match = _VERSION_RE.search(_CORE_PYPROJECT.read_text(encoding="utf-8"))
    if match is None:
        _fail("could not read the current version from guardana-core/pyproject.toml")
    return match.group("v")


def _target_version(arg: str, current: str) -> str:
    if arg not in {"patch", "minor", "major"}:
        return arg  # an explicit version like 0.2.0 or 1.0.0rc1
    if _FINAL_RE.fullmatch(current) is None:
        # From 1.0.0rc1 a patch bump would skip 1.0.0 itself, so the next step is named.
        _fail(
            f"{current} is not a final release; name the next version "
            f"(another candidate, or the final release) instead of {arg!r}"
        )
    major, minor, patch = (int(p) for p in current.split("."))
    if arg == "major":
        return f"{major + 1}.0.0"
    if arg == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def _preflight() -> None:
    branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture=True).strip()
    if branch != "main":
        _fail(f"releases are cut from main, not {branch!r}")
    if _run(["git", "status", "--porcelain"], capture=True).strip():
        _fail("working tree is not clean — commit or stash first")
    _run(["git", "fetch", "--quiet", "origin"])
    local = _run(["git", "rev-parse", "HEAD"], capture=True).strip()
    remote = _run(["git", "rev-parse", "origin/main"], capture=True).strip()
    if local != remote:
        _fail("local main is not in sync with origin/main — pull/push first")


DOGFOOD_PROFILE = "scripts/dogfood.yaml"
"""The profile every dogfood run passes, so none of them gates at a lower bar."""

_DOGFOOD = ["uv", "run", "guardana", "scan", "packages", "--profile", DOGFOOD_PROFILE]


def _gate() -> None:
    print("running the gate (ruff, format, mypy, lint-imports, pytest, dogfood, clean install)…")
    for cmd in (
        ["uv", "run", "ruff", "check", "."],
        ["uv", "run", "ruff", "format", "--check", "."],
        ["uv", "run", "mypy", "--strict", "."],
        ["uv", "run", "lint-imports"],
        ["uv", "run", "pytest", "-q"],
        _DOGFOOD,
        # Last, because only a clean install sees an undeclared dependency the workspace hides.
        ["uv", "run", "--no-project", "python", "scripts/clean_install_check.py"],
    ):
        _run(cmd)


def _roll_changelog(version: str, dry_run: bool) -> None:
    text = _CHANGELOG.read_text(encoding="utf-8")
    match = _UNRELEASED_RE.search(text)
    if match is None:
        _fail("CHANGELOG.md has no '## [...] - Unreleased' section to release")
    today = datetime.datetime.now(tz=datetime.UTC).date().isoformat()
    replacement = f"## [Unreleased]\n\n## [{version}] - {today}"
    updated = text[: match.start()] + replacement + text[match.end() :]
    if dry_run:
        print(f"  would set changelog: {match.group(0)!r} -> '## [{version}] - {today}'")
        return
    _CHANGELOG.write_text(updated, encoding="utf-8")


def _fail(message: str) -> NoReturn:
    sys.exit(f"release: {message}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "part",
        metavar="patch|minor|major|X.Y.Z",
        help="the part to bump, or an explicit version (the current one for a first release)",
    )
    parser.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    return parser


def main(argv: list[str]) -> None:
    """Parse the version argument and cut the release (or preview it with --dry-run)."""
    args = _parser().parse_args(argv)
    dry_run: bool = args.dry_run
    part: str = args.part

    current = _current_version()
    version = _target_version(part, current)
    tag = f"v{version}"
    print(f"releasing {tag} (current {current}){' [dry run]' if dry_run else ''}")

    _preflight()
    _check_surface(version)
    _check_pre_1_statement(version)
    _check_reference_pack()
    _gate()

    bumped: frozenset[str] = frozenset()
    if version != current:
        bump = ["uv", "run", "python", "scripts/bump_version.py", part]
        plan = _run([*bump, "--dry-run"], capture=True)
        print(plan, end="")
        bumped = _bump_writes(plan)
        if not dry_run:
            _run(bump)
    else:
        print("  version already at target — no bump (first release)")

    # The page's *version* is rewritten by bump_version; its rule counts are not,
    # and a release that ships a page claiming last-quarter's numbers is the same
    # staleness one element over. Run after the bump so both land in one commit.
    _run(["uv", "run", "python", "scripts/sync_site.py", *(["--check"] if dry_run else [])])
    _run(["uv", "run", "python", "scripts/generate_docs.py", *(["--check"] if dry_run else [])])
    # `llms.txt` states the version and the rule counts, so it goes stale on exactly
    # the same schedule as the page beside it.
    _run(["uv", "run", "python", "scripts/generate_llms_txt.py", *(["--check"] if dry_run else [])])
    # security.txt carries an expiry date; a release is what keeps it in the future.
    _run(
        ["uv", "run", "python", "scripts/generate_well_known.py", *(["--check"] if dry_run else [])]
    )
    # The documentation site last, because it reads `docs/generated/rules.json` that
    # `generate_docs.py` has just rewritten, and it prints the version in every page
    # footer. Building it before the bump would ship a hundred and ninety pages
    # dated to the previous release.
    _run(["uv", "run", "python", "scripts/build_site.py", *(["--check"] if dry_run else [])])

    _roll_changelog(version, dry_run)

    if dry_run:
        print(
            f"  would: commit 'chore(release): {tag}', push main without tags, "
            f"wait for green CI, then tag {tag} and push the tag"
        )
        return

    _run(["uv", "run", "pytest", "-q"])  # re-gate after the bump touched pyprojects/lock
    _run(_DOGFOOD)
    _stage_release(bumped)
    _run(["git", "commit", "-m", f"chore(release): {tag}"])
    # The tag does not exist until CI is green, and the branch push never carries one:
    # with `push.followTags` set, any reachable annotated tag would leave with `main`.
    _run(["git", "push", "--no-follow-tags", "origin", "main"])
    _await_green_ci()
    _run(["git", "tag", "-a", tag, "-m", f"Guardana {tag}"])
    _run(["git", "push", "origin", f"refs/tags/{tag}"])
    _move_marketplace_tag(version, tag)
    print(f"pushed {tag} — release.yml is building; approve the 'pypi' deployment to publish.")


def _unreleased(changelog: str) -> str:
    """Return the text under the changelog's unreleased heading, up to the next release."""
    match = _UNRELEASED_RE.search(changelog)
    if match is None:
        return ""
    rest = changelog[match.end() :]
    following = re.search(r"^## ", rest, re.MULTILINE)
    return rest if following is None else rest[: following.start()]


def _check_surface(version: str) -> None:
    """Refuse a candidate whose surface moved unannounced, or a final whose surface moved at all.

    A candidate is meant to carry fixes only, so a difference from the previous tag's
    `api-surface.json` must be announced under "Changed", "Deprecated" or "Removed". The
    final release cut from a candidate ships what that candidate was tested as, so any
    difference from it is refused. A previous tag without the file cannot show the surface
    stayed put, so it counts as moved. A final after a final is not compared.
    """
    announced_move_allowed = True
    if _CANDIDATE_RE.fullmatch(version):
        previous = _previous_tag("the supported surface")
    elif _FINAL_RE.fullmatch(version):
        nearest = _nearest_tag()
        candidate = rf"v{re.escape(version)}rc\d+"
        if nearest is None or not re.fullmatch(candidate, nearest):
            candidates = _run(
                ["git", "for-each-ref", "--format=%(refname:short)", f"refs/tags/v{version}rc*"],
                capture=True,
            ).split()
            if any(re.fullmatch(candidate, tag) for tag in candidates):
                _fail(
                    f"v{version} has release candidates ({', '.join(sorted(candidates))}) but "
                    f"the nearest tag behind HEAD is {nearest or 'none'}; a final release is cut "
                    f"from its last candidate, so fetch the tags or cut from that candidate"
                )
            return
        previous = nearest
        announced_move_allowed = False
    else:
        return
    try:
        current = _SURFACE_PATH.read_text(encoding="utf-8")
    except OSError as error:
        _fail(f"cannot read {_SURFACE}: {error}")
    try:
        before: str | None = _run(["git", "show", f"{previous}:{_SURFACE}"], capture=True)
    except subprocess.CalledProcessError:
        before = None
    if before == current:
        return
    if not announced_move_allowed:
        _fail(
            f"the supported surface ({_SURFACE}) differs from {previous}'s; the final release "
            f"ships the surface of its last candidate, so cut another candidate instead"
        )
    if _SURFACE_SECTION_RE.search(_unreleased(_CHANGELOG.read_text(encoding="utf-8"))):
        return
    _fail(
        f"the supported surface ({_SURFACE}) differs from {previous}'s and [Unreleased] in "
        f"CHANGELOG.md has no Changed, Deprecated or Removed section; a release candidate "
        f"changes the surface only when the changelog says so"
    )


def _versioning_name() -> str:
    """Name the versioning policy the way a refusal should: repo-relative when it can be."""
    try:
        return _VERSIONING.relative_to(_ROOT).as_posix()
    except ValueError:
        return str(_VERSIONING)


def _check_pre_1_statement(version: str) -> None:
    """Refuse a final 1.x or later release while the versioning policy still says pre-1.0.

    The policy's rules follow from that statement, so a stable release that leaves it in
    place ships a policy that contradicts the version. A policy that cannot be read cannot
    show the statement is gone, so it refuses too.
    """
    final = _FINAL_RE.fullmatch(version)
    if final is None or int(final.group("major")) < 1:
        return
    try:
        policy = _VERSIONING.read_text(encoding="utf-8")
    except OSError as error:
        _fail(f"cannot read {_versioning_name()} to check it no longer says pre-1.0: {error}")
    statement = _PRE_1_STATEMENT_RE.search(policy)
    if statement is None:
        return
    line = policy.count("\n", 0, statement.start("status")) + 1
    _fail(
        f"{_versioning_name()}:{line} still says the project is pre-1.0; rewrite that line, and "
        f"the versioning rules that follow from it, before releasing {version}"
    )


def _nearest_tag() -> str | None:
    """Return the nearest release tag behind HEAD, or None when there is none."""
    try:
        nearest = _run(
            ["git", "describe", "--tags", "--abbrev=0", "--match", _RELEASE_TAG_GLOB, "HEAD"],
            capture=True,
        ).strip()
    except subprocess.CalledProcessError:
        return None
    return nearest or None


def _previous_tag(what: str) -> str:
    """Return the nearest release tag behind HEAD, or refuse when there is none."""
    previous = _nearest_tag()
    if previous is None:
        _fail(f"no earlier release tag to compare {what} with")
    return previous


def _pack_version(pyproject: str, where: str) -> str:
    match = _VERSION_RE.search(pyproject)
    if match is None:
        _fail(f"could not read the reference pack's version from {where}")
    return match.group("v")


def _check_reference_pack() -> None:
    """Refuse a release whose reference pack changed while keeping the version it shipped as.

    The pack is published beside the five packages under its own version, and the index
    refuses a second upload of a version, so a changed pack must carry a new one. A pack
    absent at the previous tag never shipped, so it has no version to collide with.
    """
    previous = _previous_tag("the reference pack")
    try:
        before = _run(["git", "show", f"{previous}:{_PACK}/pyproject.toml"], capture=True)
    except subprocess.CalledProcessError:
        return
    if not _run(["git", "diff", previous, "--", _PACK], capture=True).strip():
        return
    try:
        current = _PACK_PYPROJECT.read_text(encoding="utf-8")
    except OSError as error:
        _fail(f"cannot read {_PACK}/pyproject.toml: {error}")
    version = _pack_version(current, f"{_PACK}/pyproject.toml")
    if version == _pack_version(before, f"{previous}:{_PACK}/pyproject.toml"):
        _fail(
            f"{_PACK} changed since {previous} but its version is still {version}, the "
            f"version {previous} published; bump it in {_PACK}/pyproject.toml"
        )


def _bump_writes(plan: str) -> frozenset[str]:
    """Name the files a `bump_version.py --dry-run` plan says the bump will rewrite."""
    return frozenset(_BUMP_WRITES_RE.findall(plan))


def _changed_paths() -> list[str]:
    """Every path `git status` reports, both sides of a rename included."""
    status = _run(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], capture=True)
    records = iter(status.split("\0"))
    paths: list[str] = []
    for record in records:
        if not record:
            continue
        paths.append(record[3:])
        if record[0] in "RC":
            paths.append(next(records, ""))
    return paths


def _written_by_release(path: str, bumped: frozenset[str]) -> bool:
    return path in bumped or path in _RELEASE_FILES or path.startswith(_RELEASE_TREES)


def _stage_release(bumped: frozenset[str]) -> None:
    """Stage exactly what the release wrote, and refuse when the tree holds anything else.

    The gate takes minutes; a blanket stage would commit and deploy whatever else
    changed in the tree meanwhile, unchecked.
    """
    changed = _changed_paths()
    stray = sorted({path for path in changed if not _written_by_release(path, bumped)})
    if stray:
        _fail(
            "the tree holds changes the release did not write, so nothing was committed: "
            + ", ".join(stray)
        )
    if not changed:
        _fail("the release wrote nothing to commit")
    _run(["git", "add", "--", *sorted(set(changed))])


def _await_green_ci() -> None:
    """Block until CI concludes on the commit just pushed, and stop if it is not green.

    The tag is what starts the publish, so pushing it beside the branch races CI: a red
    run — for any reason, including one that has nothing to do with the code — then
    leaves a publish already waiting on the `pypi` approval. Cancelling, fixing and
    re-tagging costs a second approval click and leaves a `cancelled` run in the history
    that reads as a failed release.

    Fail-closed when the wait itself cannot be done: without `gh`, this stops before a
    tag exists rather than creating it blind, because an unverified tag is the thing
    being avoided.
    """
    commit = _run(["git", "rev-parse", "HEAD"], capture=True).strip()
    print(f"waiting for CI on {commit[:9]} before creating the tag...")
    try:
        run_id = _run(
            [
                "gh",
                "run",
                "list",
                "--workflow=CI",
                f"--commit={commit}",
                "--limit=1",
                "--json=databaseId",
                "--jq=.[0].databaseId",
            ],
            capture=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        _stop_before_tagging("the GitHub CLI (`gh`) is not available here")
    if not run_id:
        _stop_before_tagging(f"no CI run has started for {commit[:9]} yet")
    # `gh run watch --exit-status` exits non-zero when the run failed, which is the
    # whole check: without the flag it reports the failure and returns 0.
    try:
        _run(["gh", "run", "watch", run_id, "--exit-status"])
    except subprocess.CalledProcessError:
        _stop_before_tagging(f"CI run {run_id} is not green")
    print("CI is green; tagging.")


def _stop_before_tagging(reason: str) -> NoReturn:
    """Leave the release commit pushed and unreleased, which is a state worth being in."""
    print(
        f"error: {reason}, so no tag was created.\n"
        f"The release commit is on `main` and nothing has been published. Once CI is\n"
        f"green on it, create and push the tag by hand (the last line only for a final\n"
        f"release):\n  " + "\n  ".join(_TAG_BY_HAND),
        file=sys.stderr,
    )
    raise SystemExit(1)


def _move_marketplace_tag(version: str, tag: str) -> None:
    """Point the moving `vMAJOR.MINOR` tag (e.g. v0.1) at this release.

    That is the tag users pin for the GitHub Marketplace Action, so it should
    always follow the latest patch — without a manual step per release. Only for a
    final release (a pre-release must not move a stable pin), and best-effort: a
    failure here (e.g. tag protection) must not fail an already-published release.
    The `release.yml` trigger is `v*.*.*`, so moving this two-part tag does not
    re-trigger a publish.
    """
    if not version.replace(".", "").isdigit():
        return
    major, minor = version.split(".")[:2]
    moving = f"v{major}.{minor}"
    try:
        # Peel to the commit (`tag` is annotated) so the moving tag is a clean
        # lightweight pointer straight at the release commit, not at a tag object.
        _run(["git", "tag", "-f", moving, f"{tag}^{{commit}}"])
        _run(["git", "push", "--force", "origin", moving])
        print(f"moved {moving} -> {tag} (pin this for the Marketplace Action)")
    except subprocess.CalledProcessError:
        print(f"note: could not move {moving} (tag protection?) — move it by hand if you pin it")


if __name__ == "__main__":
    main(sys.argv[1:])
