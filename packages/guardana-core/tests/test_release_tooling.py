"""Guards for the repo-level release tooling (`scripts/bump_version.py` and
`.github/release.yml`). These live at the repo root, outside any package, so
this test locates them relative to `guardana-core` — the version-of-record the
bump script reads."""

import importlib.util
import re
import sys
import types
from pathlib import Path

import guardana.core
import pytest
import yaml


def _repo_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "scripts" / "bump_version.py").is_file():
            return parent
    raise AssertionError("could not locate the repo root")


def _load_script(name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, _repo_root() / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_BUMP = _load_script("bump_version")


def test_release_notes_exclude_the_real_dependabot_login() -> None:
    # Dependabot authors PRs as the login `dependabot[bot]`; a bare `dependabot`
    # exclusion never matches, so dependency bumps still leak into the notes.
    config = yaml.safe_load((_repo_root() / ".github" / "release.yml").read_text(encoding="utf-8"))
    authors = config["changelog"]["exclude"]["authors"]
    assert "dependabot[bot]" in authors


def test_core_dunder_version_matches_the_package_version() -> None:
    # `guardana --version` prints `guardana.core.__version__`; the bump script
    # rewrites pyproject versions. If the two drift, the CLI lies about what is
    # installed — this pins them together.

    pyproject = (_repo_root() / "packages" / "guardana-core" / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    match = _BUMP._VERSION_RE.search(pyproject)
    assert match is not None
    assert guardana.core.__version__ == match.group("v")


def test_rewrite_dunder_updates_the_version_line() -> None:
    assert _BUMP._rewrite_dunder('__version__ = "0.1.0"\n', "0.2.0") == '__version__ = "0.2.0"\n'


def test_rewrite_dunder_refuses_a_file_with_no_version_line() -> None:
    # A silent no-op here would quietly reintroduce the pyproject/__version__
    # drift the function exists to prevent.
    with pytest.raises(SystemExit):
        _BUMP._rewrite_dunder("nothing to see\n", "0.2.0")


def test_main_dry_run_lists_the_core_dunder_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["bump_version.py", "patch", "--dry-run"])
    assert _BUMP.main() == 0
    assert "src/guardana/core/__init__.py" in capsys.readouterr().out


def test_rewrite_action_pin_follows_the_released_minor() -> None:
    # The docs tell users to pin the moving `vMAJOR.MINOR` tag for the Marketplace
    # Action. Left behind by a release, that line silently serves an Action from
    # two versions ago — one without the fixes the release shipped.
    assert (
        _BUMP._rewrite_action_pin("- uses: guardana/guardana@v0.1   # moving tag\n", "0.3.0")
        == "- uses: guardana/guardana@v0.3   # moving tag\n"
    )


def test_rewrite_action_pin_leaves_a_prerelease_alone() -> None:
    # `release.py` deliberately does not move the stable moving tag for a
    # pre-release, so rewriting the docs to `v1.0` would point users at a tag that
    # does not exist yet.
    text = "- uses: guardana/guardana@v0.3\n"
    assert _BUMP._rewrite_action_pin(text, "1.0.0rc1") == text


def _workflow(name: str) -> dict[str, object]:
    path = _repo_root() / ".github" / "workflows" / name
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _steps(workflow: dict[str, object], job: str) -> list[dict[str, object]]:
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    assert job in jobs, f"no {job!r} job"
    steps = jobs[job]["steps"]
    assert isinstance(steps, list)
    return steps


def _index_of(steps: list[dict[str, object]], needle: str) -> int:
    for position, step in enumerate(steps):
        if needle in str(step.get("run", "")) or needle in str(step.get("uses", "")):
            return position
    raise AssertionError(f"no step running {needle!r}")


def test_the_release_gate_runs_the_clean_install_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """A promise in a runbook is a promise; a step in the gate is a gate.

    0.9.0 was tagged from a green tree and had to be cancelled: `guardana` crashed
    on every command in a fresh environment. Nothing else in the gate can see that
    class of defect, because everything else runs where the missing module happens
    to be installed.
    """
    release = _load_script("release")
    commands: list[list[str]] = []

    def record(cmd: list[str], *, capture: bool = False) -> str:
        commands.append(cmd)
        return ""

    monkeypatch.setattr(release, "_run", record)

    release._gate()

    assert any("scripts/clean_install_check.py" in cmd for cmd in commands), (
        f"the release gate does not run the clean-install check: {commands}"
    )


def test_ci_runs_the_clean_install_check_on_every_push() -> None:
    steps = _steps(_workflow("ci.yml"), "clean-install")
    _index_of(steps, "scripts/clean_install_check.py")


def test_the_release_workflow_checks_a_clean_install_before_publishing() -> None:
    """Order is the whole point: a gate after the upload is a report, not a gate."""
    steps = _steps(_workflow("release.yml"), "publish")
    check = _index_of(steps, "scripts/clean_install_check.py")
    publish = _index_of(steps, "pypa/gh-action-pypi-publish")

    assert check < publish, "the clean-install check runs after the publish step"


def test_the_release_writes_an_sbom_and_attests_the_distributions() -> None:
    """A published artifact is a supply-chain artifact or it is a mystery binary.

    Order matters here too: the SBOM and the provenance describe what is about to
    be uploaded, so both are produced from the built `dist/` before the upload —
    an attestation taken after the fact attests whatever is lying around.
    """
    steps = _steps(_workflow("release.yml"), "publish")
    build = _index_of(steps, "uv build")
    sbom = _index_of(steps, "scripts/generate_sbom.py")
    attest = _index_of(steps, "actions/attest-build-provenance")
    publish = _index_of(steps, "pypa/gh-action-pypi-publish")

    assert build < sbom < publish, "the SBOM is not written from the built distributions"
    assert build < attest < publish, "the provenance does not cover what is published"


def test_the_sboms_are_attached_to_the_release() -> None:
    """An SBOM nobody can download is a file on a runner that no longer exists."""
    steps = _steps(_workflow("release.yml"), "publish")
    release_step = steps[_index_of(steps, "gh release create")]

    assert "sbom/" in str(release_step["run"]), "the release carries no SBOM assets"


def test_ci_writes_the_sboms_on_every_push() -> None:
    """The tag must not be the first time a release artifact is produced."""
    steps = _steps(_workflow("ci.yml"), "clean-install")
    _index_of(steps, "scripts/generate_sbom.py")


def test_ci_builds_and_runs_both_images_on_every_push() -> None:
    """An image first built at the tag is an image first tested at the worst moment."""
    steps = _steps(_workflow("ci.yml"), "images")
    _index_of(steps, "scripts/image_smoke.py")


def test_the_release_publishes_both_images_with_an_sbom_and_provenance() -> None:
    """A published image is a supply-chain artifact or it is a mystery binary."""
    steps = _steps(_workflow("release.yml"), "images")
    builds = [step for step in steps if "docker/build-push-action" in str(step.get("uses", ""))]

    assert len(builds) == 2, f"expected the CLI and the collector image, got {len(builds)}"
    for build in builds:
        options = build["with"]
        assert isinstance(options, dict)
        assert options["sbom"] is True, f"{build.get('name')} publishes no SBOM"
        assert str(options["provenance"]).startswith("mode="), (
            f"{build.get('name')} publishes no provenance attestation"
        )
        assert options["push"] is True


def test_the_images_are_published_only_after_the_packages() -> None:
    """One approval, one release: an image PyPI never got is a version in one place."""
    jobs = _workflow("release.yml")["jobs"]
    assert isinstance(jobs, dict)

    assert jobs["images"]["needs"] == "publish"
    assert jobs["publish"]["environment"] == "pypi"


def test_every_required_image_tag_file_actually_carries_one() -> None:
    # Which files get rewritten is discovered, not listed — a list is what let four
    # files sit on `:0.9` for twelve releases. But the two a reader starts from must
    # never *stop* carrying a tag: an install page with no version in it is how
    # somebody ends up on `latest`.
    #
    # Whether the tags are current is asserted repo-wide in `test_docs_consistency`,
    # over the same discovery function. One rule, one owner.
    for relative in _BUMP._REQUIRED_IMAGE_PIN:
        text = (_repo_root() / relative).read_text(encoding="utf-8")
        assert _BUMP._IMAGE_PIN_RE.search(text) is not None, f"no image tag in {relative}"


def test_pin_discovery_finds_every_file_carrying_a_tag() -> None:
    # The whole point of discovery: a file nobody added to a list is still covered.
    # `deploy/docker-compose.yml` is the one that proved it — created after the
    # list, invisible to the rewrite, and stale by twelve releases.
    found = _BUMP.pin_bearing_files(_BUMP._IMAGE_PIN_RE)
    assert Path("deploy/docker-compose.yml") in found
    assert Path("packages/guardana-server/README.md") in found
    # Exempt, and each for its own reason: the changelog records the past, and a
    # test fixture feeding an old pin to the rewriter has to stay old.
    assert Path("CHANGELOG.md") not in found
    assert Path("packages/guardana-core/tests/test_release_tooling.py") not in found


def test_a_prerelease_does_not_move_the_documented_image_tag() -> None:
    """`latest` and the moving tag are not pushed for a prerelease, so nor is the doc."""
    text = "docker run ghcr.io/guardana/guardana:0.9 scan ."

    assert _BUMP._rewrite_image_pin(text, "1.0.0rc1") == text
    assert (
        _BUMP._rewrite_image_pin(text, "0.10.0")
        == "docker run ghcr.io/guardana/guardana:0.10 scan ."
    )


def test_every_required_action_pin_file_actually_carries_a_pin() -> None:
    # A file that stopped carrying a pin (a reworded snippet, a renamed tag form)
    # must fail loudly rather than quietly drop out of the rewrite. Whether the
    # pins are current is asserted repo-wide in `test_docs_consistency`.
    for relative in _BUMP._REQUIRED_ACTION_PIN:
        text = (_repo_root() / relative).read_text(encoding="utf-8")
        assert _BUMP._ACTION_PIN_RE.search(text) is not None, f"no action pin in {relative}"


def test_documented_versions_match_the_released_one() -> None:
    # The Action pins are not the only place a version is written down. The
    # landing page, the security policy and the README's roadmap table all name
    # the current release, and all three silently stayed on 0.3 through the 0.4.0
    # release — the same staleness the pin check was added to prevent, one file
    # over. Every one of these is rewritten by `bump_version.py`.
    current = _BUMP._current_version()
    major, minor, _ = _BUMP._core(current)
    for relative, pattern, expected in (
        (Path("site/index.html"), _BUMP._SITE_VERSION_RE, f"v{current}"),
        (Path("SECURITY.md"), _BUMP._SECURITY_VERSION_RE, f"({major}.{minor}.x)"),
        (Path("README.md"), _BUMP._README_CURRENT_RE, f"**{major}.{minor}**"),
        # The sentence beside the moving Action pin. 0.5.0 shipped with the pin
        # rewritten to @v0.5 and the prose next to it still saying "the latest
        # 0.3.x" — the pin automation moved the tag and left its explanation.
        (Path("README.md"), _BUMP._PIN_PROSE_RE, f"latest {major}.{minor}.x"),
        (Path("docs/integrations.md"), _BUMP._PIN_PROSE_RE, f"latest {major}.{minor}.x"),
    ):
        text = (_repo_root() / relative).read_text(encoding="utf-8")
        found = pattern.search(text)
        assert found is not None, f"no version marker in {relative}"
        assert expected in found.group(0), (
            f"{relative} says {found.group(0)!r}, expected {expected}"
        )


def test_a_missing_pin_aborts_before_anything_is_written(monkeypatch: pytest.MonkeyPatch) -> None:
    # The check has to come first. Failing partway through leaves five pyprojects
    # and `__version__` bumped, `uv.lock` stale, and the docs half-rewritten — a
    # broken tree in the middle of a release. LICENSE stands in for a docs file
    # that was reworded and lost its pin.
    before = _BUMP._current_version()
    monkeypatch.setattr(_BUMP, "_REQUIRED_ACTION_PIN", (Path("LICENSE"),))
    monkeypatch.setattr(sys, "argv", ["bump_version.py", "minor"])

    with pytest.raises(SystemExit):
        _BUMP.main()
    assert _BUMP._current_version() == before


def test_main_dry_run_lists_the_action_pin_files(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["bump_version.py", "minor", "--dry-run"])
    assert _BUMP.main() == 0
    assert "README.md" in capsys.readouterr().out


def test_next_version_bumps_the_numeric_core() -> None:
    assert _BUMP._next_version("0.1.0", "patch") == "0.1.1"
    assert _BUMP._next_version("0.1.0", "minor") == "0.2.0"
    assert _BUMP._next_version("0.1.0", "major") == "1.0.0"


def test_next_version_passes_through_a_pep440_prerelease() -> None:
    # RELEASING.md documents `bump_version.py 1.0.0rc1`; the explicit form must
    # accept a PEP 440 pre-release verbatim, not reject it as non-numeric.
    assert _BUMP._next_version("0.1.0", "1.0.0rc1") == "1.0.0rc1"
    assert _BUMP._next_version("0.9.0", "1.0.0b2") == "1.0.0b2"


def test_next_version_rejects_a_non_version_argument() -> None:
    with pytest.raises(SystemExit):
        _BUMP._next_version("0.1.0", "banana")


def test_core_ignores_a_prerelease_suffix() -> None:
    assert _BUMP._core("1.0.0rc1") == (1, 0, 0)
    assert _BUMP._core("0.2.0") == (0, 2, 0)


def test_main_accepts_a_pep440_prerelease_in_dry_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["bump_version.py", "1.0.0rc1", "--dry-run"])
    assert _BUMP.main() == 0
    assert "1.0.0rc1" in capsys.readouterr().out


def test_main_refuses_a_downgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    # A typo'd explicit version must never silently roll the five packages back.
    monkeypatch.setattr(sys, "argv", ["bump_version.py", "0.0.1", "--dry-run"])
    with pytest.raises(SystemExit):
        _BUMP.main()


def test_main_refuses_the_same_version(monkeypatch: pytest.MonkeyPatch) -> None:
    # Re-releasing the current version (0.1.0) is not an increase; reject it too.
    monkeypatch.setattr(sys, "argv", ["bump_version.py", "0.1.0", "--dry-run"])
    with pytest.raises(SystemExit):
        _BUMP.main()


def test_the_action_pins_the_cli_version_it_ships_with() -> None:
    """`guardana/guardana@vX.Y` must install the CLI that tag was released with.

    The `version` input used to default to empty, and empty meant `uvx --from
    guardana-cli` — the newest release on PyPI. So a workflow pinned to `@v0.21`
    would start running the 0.22 CLI the day it published: a pinned pipeline whose
    engine, rules and exit-code contract changed with nobody editing anything.

    A pin that does not pin is worse than no pin, because it is the one a security
    team writes down as evidence that the check is reproducible.
    """
    action = yaml.safe_load((_repo_root() / "action.yml").read_text(encoding="utf-8"))
    assert action["inputs"]["version"]["default"] == guardana.core.__version__


def test_the_action_never_calls_another_action_by_a_moving_tag() -> None:
    """Every action this one calls is pinned to a commit, with the tag in a comment.

    This composite action runs inside other people's pipelines. A moving tag here
    is a moving tag there, under Guardana's name — the supply-chain shape this
    project exists to flag in somebody else's repository.
    """
    text = (_repo_root() / "action.yml").read_text(encoding="utf-8")
    moving = [
        line.strip()
        for line in text.splitlines()
        if "uses:" in line and not re.search(r"@[0-9a-f]{40}\b", line)
    ]
    assert not moving, "actions pinned to a moving ref:\n  " + "\n  ".join(moving)


@pytest.mark.parametrize(
    "workflow", sorted(p.name for p in (Path(__file__).parents[3] / ".github/workflows").iterdir())
)
def test_no_workflow_calls_an_action_by_a_moving_tag(workflow: str) -> None:
    """The same rule one directory over, where the credentials are.

    `release.yml` publishes to PyPI over OIDC and pushes to GHCR. A compromised
    `@v7` on any action it calls publishes a security scanner under this project's
    name — which is exactly the attestation-and-SBOM story the release workflow
    exists to provide, undone at the one point that was not pinned.
    """
    text = (_repo_root() / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
    moving = [
        line.strip()
        for line in text.splitlines()
        if re.search(r"^\s*uses:\s*[^./]", line) and not re.search(r"@[0-9a-f]{40}\b", line)
    ]
    assert not moving, f"{workflow} calls an action by a moving ref:\n  " + "\n  ".join(moving)
