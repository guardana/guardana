"""Guards for the repo-level release tooling (`scripts/bump_version.py` and
`.github/release.yml`). These live at the repo root, outside any package, so
this test locates them relative to `guardana-core` — the version-of-record the
bump script reads."""

import importlib.util
import re
import sys
import tomllib
import types
from fnmatch import fnmatch
from pathlib import Path

import guardana.core
import pytest
import yaml
from _release_series import stable_series
from packaging.version import Version


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


def _next_final_minor() -> str:
    """A final version after the current one, valid whether or not the tree is a candidate."""
    major, minor, _patch = _BUMP._core(_BUMP._current_version())
    return f"{major}.{minor + 1}.0"


def test_release_notes_exclude_the_real_dependabot_login() -> None:
    # Dependabot authors PRs as the login `dependabot[bot]`; a bare `dependabot`
    # exclusion never matches, so dependency bumps still leak into the notes.
    config = yaml.safe_load((_repo_root() / ".github" / "release.yml").read_text(encoding="utf-8"))
    authors = config["changelog"]["exclude"]["authors"]
    assert "dependabot[bot]" in authors


def test_core_dunder_version_matches_the_package_version() -> None:
    # Embedding code reads `guardana.core.__version__`; the bump script
    # rewrites pyproject versions. If the two drift, the attribute lies about what is
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


_SIBLINGS = (
    "guardana-core",
    "guardana-rules",
    "guardana-report",
    "guardana-cli",
    "guardana-server",
)


def test_rewrite_pins_every_sibling_to_the_exact_release() -> None:
    """A range let a fresh install pair this CLI with a later engine nobody tested it with."""
    text = (
        'version = "0.1.0"\n'
        'dependencies = ["guardana-core>=0.1.0,<0.2", "guardana-rules==0.1.0", "pyyaml>=6.0"]\n'
    )

    rewritten = _BUMP._rewrite(text, "0.2.0rc1")

    assert rewritten == (
        'version = "0.2.0rc1"\n'
        'dependencies = ["guardana-core==0.2.0rc1", "guardana-rules==0.2.0rc1", "pyyaml>=6.0"]\n'
    )


def test_every_package_pins_its_siblings_to_its_own_version_exactly() -> None:
    for package in _SIBLINGS:
        project = tomllib.loads(
            (_repo_root() / "packages" / package / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]
        siblings = [dep for dep in project["dependencies"] if dep.startswith("guardana-")]
        assert all(dep.split("==")[0] in _SIBLINGS for dep in siblings), (package, siblings)
        assert siblings == [f"{dep.split('==')[0]}=={project['version']}" for dep in siblings], (
            f"{package} pins its siblings as {siblings}; the release is tested only as one set"
        )


def test_main_dry_run_lists_the_core_dunder_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["bump_version.py", _next_final_minor(), "--dry-run"])
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


def test_the_provenance_names_only_the_distributions() -> None:
    """A subject is a claim that this workflow built that file.

    `uv build` also writes `dist/.gitignore`, so a bare `dist/*` signs a file that
    nobody downloads; every subject must be a wheel or an sdist.
    """
    for job, directory in (("publish", "dist"), ("reference-pack", "dist-reference")):
        steps = _steps(_workflow("release.yml"), job)
        attest = steps[_index_of(steps, "actions/attest-build-provenance")]
        options = attest["with"]
        assert isinstance(options, dict)
        patterns = str(options["subject-path"]).split()

        assert sorted(patterns) == [f"{directory}/*.tar.gz", f"{directory}/*.whl"], patterns


def test_the_sboms_are_attached_to_the_release() -> None:
    """An SBOM nobody can download is a file on a runner that no longer exists."""
    steps = _steps(_workflow("release.yml"), "publish")
    release_step = steps[_index_of(steps, "gh release create")]

    assert "sbom/" in str(release_step["run"]), "the release carries no SBOM assets"


def test_the_five_packages_are_published_without_the_reference_pack() -> None:
    """A pack that fails to build can hold back neither their upload nor the GitHub Release.

    The publish job never touches the pack, and the images wait on that job alone.
    """
    workflow = _workflow("release.yml")
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    publish = yaml.safe_dump(jobs["publish"])

    assert "reference_pack" not in publish
    assert "dist-reference" not in publish
    assert jobs["images"]["needs"] == "publish"


def test_the_reference_pack_is_built_attested_and_attached_after_the_publish() -> None:
    """The pack ships on every GitHub Release, from a job of its own that needs `publish`.

    It publishes nowhere but the Release, so it holds no `pypi` approval and no token
    beyond attaching an asset and signing its provenance.
    """
    jobs = _workflow("release.yml")["jobs"]
    assert isinstance(jobs, dict)
    job = jobs["reference-pack"]
    steps = _steps(_workflow("release.yml"), "reference-pack")
    build = _index_of(steps, "uv build examples/reference_pack --out-dir dist-reference/")
    attest = _index_of(steps, "actions/attest-build-provenance")
    upload = _index_of(steps, "gh release upload")
    command = str(steps[upload]["run"])

    assert job["needs"] == "publish"
    assert "environment" not in job
    assert job["permissions"] == {"contents": "write", "id-token": "write", "attestations": "write"}
    assert build < attest < upload
    assert "dist-reference/*.whl" in command
    assert "dist-reference/*.tar.gz" in command
    assert "--clobber" not in command, "a re-run would replace what PyPI kept from the first"
    assert "gh release view" in command


def test_the_reference_pack_reaches_pypi_only_when_the_owner_turns_it_on() -> None:
    """A separate job, behind the same approval, that the release and the images never wait on."""
    name = "publish-reference-pack"
    jobs = _workflow("release.yml")["jobs"]
    assert isinstance(jobs, dict)
    job = jobs[name]
    steps = _steps(_workflow("release.yml"), name)
    publish = steps[_index_of(steps, "pypa/gh-action-pypi-publish")]

    assert job["needs"] == "reference-pack"
    assert job["environment"] == "pypi"
    assert job["if"] == "vars.REFERENCE_PACK_PYPI == 'true'"
    assert job["permissions"]["id-token"] == "write"
    assert isinstance(publish["with"], dict)
    assert publish["with"]["packages-dir"] == "dist-reference/"
    assert publish["with"]["skip-existing"] is True
    waiting = [other for other, spec in jobs.items() if name in str(spec.get("needs"))]
    assert waiting == []


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


@pytest.mark.parametrize("step", ["cli-meta", "collector-meta"])
def test_image_tags_are_worked_out_from_the_pep440_version(step: str) -> None:
    """A release tag such as v1.0.0rc1 is PEP 440 and not semver; a semver rule tags nothing."""
    steps = _steps(_workflow("release.yml"), "images")
    meta = next(s for s in steps if s.get("id") == step)
    options = meta["with"]
    assert isinstance(options, dict)
    rules = [line.strip() for line in str(options["tags"]).splitlines() if line.strip()]

    assert rules, f"{step} works out no tags"
    assert all(rule.startswith("type=pep440,") for rule in rules), rules


def test_a_tag_publishes_only_the_version_the_packages_carry() -> None:
    """The release is named after the tag, so a tag naming another version stops first."""
    steps = _steps(_workflow("release.yml"), "publish")
    check = _index_of(steps, "packages/guardana-core/pyproject.toml")
    command = str(steps[check]["run"])

    assert check < _index_of(steps, "uv build")
    assert check < _index_of(steps, "pypa/gh-action-pypi-publish")
    assert '"${TAG#v}" != "$packaged"' in command
    assert '[ -z "$packaged" ]' in command
    assert "exit 1" in command


def test_a_prerelease_tag_creates_a_github_prerelease() -> None:
    """The Releases page and the Marketplace must not call a candidate the latest release."""
    steps = _steps(_workflow("release.yml"), "publish")
    command = str(steps[_index_of(steps, "gh release create")]["run"])

    assert "--prerelease" in command
    marked = re.search(r'case "\$version" in (\S+)\)', command)
    assert marked is not None, "no pre-release pattern"
    for version in ("1.0.0a1", "1.0.0b2", "1.0.0rc1", "1.0.0.dev3"):
        assert any(fnmatch(version, p) for p in marked.group(1).split("|")), version
    for version in ("1.0.0", "0.41.0", "1.0.0.post1"):
        assert not any(fnmatch(version, p) for p in marked.group(1).split("|")), version


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
    major, minor = stable_series()
    for relative, pattern, expected in (
        (Path("site/index.html"), _BUMP._SITE_VERSION_RE, f"v{current}"),
        (Path("SECURITY.md"), _BUMP._SECURITY_VERSION_RE, _BUMP._security_line(major, minor)),
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


def _marked(path: str, text: str, new: str) -> str:
    """Apply every version marker `bump_version` keeps for `path` to `text`."""
    for relative, pattern, replacement in _BUMP._documented_versions(new):
        if relative == Path(path):
            text = pattern.sub(replacement, text)
    return text


def test_a_prerelease_keeps_the_series_the_stable_pins_follow() -> None:
    """The moving pin stays on the last final release, so the prose beside it does too."""
    security = "Guardana is pre-1.0 (0.41.x). Security fixes land"
    prose = "uses: guardana/guardana@v0.41   # moving tag → latest 0.41.x"

    assert _marked("SECURITY.md", security, "1.0.0rc1") == security
    assert _marked("README.md", prose, "1.0.0rc1") == prose
    assert _marked("README.md", prose, "1.0.0") == prose.replace("latest 0.41.x", "latest 1.0.x")


_SECURITY_PRE_1 = "Guardana is pre-1.0 (0.41.x). Security fixes land"


def _supported(major: int, series: str) -> str:
    """The security policy's supported line for a final 1.x release, from the script's template."""
    template: str = _BUMP._SECURITY_LINE
    return template.format(major=major, series=series)


def test_the_first_final_1x_bump_writes_the_1x_security_line() -> None:
    marked = _marked("SECURITY.md", _SECURITY_PRE_1, "1.0.0")

    assert marked == f"{_supported(1, '1.0')}. Security fixes land"
    assert "pre-1.0" not in marked


def test_a_later_final_bump_rewrites_the_series_in_the_1x_security_line() -> None:
    first = _marked("SECURITY.md", _SECURITY_PRE_1, "1.0.0")

    assert _marked("SECURITY.md", first, "1.1.0") == f"{_supported(1, '1.1')}. Security fixes land"
    assert _marked("SECURITY.md", first, "1.1.0rc1") == first


def test_a_release_candidate_keeps_the_pre_1_security_line() -> None:
    assert _marked("SECURITY.md", _SECURITY_PRE_1, "1.0.0rc2") == _SECURITY_PRE_1


def test_the_marker_check_accepts_either_security_line() -> None:
    for text in (_SECURITY_PRE_1, _marked("SECURITY.md", _SECURITY_PRE_1, "1.0.0")):
        assert _BUMP._SECURITY_VERSION_RE.search(text) is not None, text
    assert _BUMP._SECURITY_VERSION_RE.search("Guardana is supported.") is None


def _security_line_mismatch(version: str, text: str) -> str | None:
    """Say why `text` is the wrong supported line for a repository at `version`, or None."""
    major, _, _ = _BUMP._core(version)
    if major >= 1 and not Version(version).is_prerelease and "pre-1.0" in text:
        return f"SECURITY.md still says pre-1.0 at the final release {version}"
    supported = re.compile(_BUMP._line_pattern(_BUMP._SECURITY_LINE))
    if major == 0 and supported.search(text) is not None:
        return f"SECURITY.md announces a supported 1.x line at {version}"
    return None


def test_the_security_policy_names_the_line_the_version_belongs_to() -> None:
    text = (_repo_root() / "SECURITY.md").read_text(encoding="utf-8")
    assert _security_line_mismatch(_BUMP._current_version(), text) is None


def test_the_security_line_check_refuses_a_line_from_the_other_side_of_1_0() -> None:
    supported = _marked("SECURITY.md", _SECURITY_PRE_1, "1.0.0")

    assert _security_line_mismatch("1.0.0", _SECURITY_PRE_1) is not None
    assert _security_line_mismatch("0.42.0", supported) is not None
    assert _security_line_mismatch("1.0.0rc2", _SECURITY_PRE_1) is None
    assert _security_line_mismatch("1.0.0", supported) is None
    assert _security_line_mismatch("0.42.0", _SECURITY_PRE_1) is None


def test_a_version_marker_naming_a_prerelease_is_replaced_whole() -> None:
    """The next candidate must not read `v1.0.0rc2rc1`."""
    site = '<span class="ver mono">v1.0.0rc1</span>'
    roadmap = "## What ships today (1.0.0rc1)\n"

    assert _marked("site/index.html", site, "1.0.0rc2") == '<span class="ver mono">v1.0.0rc2</span>'
    assert _marked("ROADMAP.md", roadmap, "1.0.0") == "## What ships today (1.0.0)\n"
    assert _marked("ROADMAP.md", "## What ships today (0.41.0)\n", "1.0.0rc1") == (
        "## What ships today (1.0.0rc1)\n"
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
    monkeypatch.setattr(sys, "argv", ["bump_version.py", _next_final_minor(), "--dry-run"])
    assert _BUMP.main() == 0
    assert "README.md" in capsys.readouterr().out


def test_next_version_bumps_the_numeric_core() -> None:
    assert _BUMP._next_version("0.1.0", "patch") == "0.1.1"
    assert _BUMP._next_version("0.1.0", "minor") == "0.2.0"
    assert _BUMP._next_version("0.1.0", "major") == "1.0.0"


def test_next_version_passes_through_a_pep440_prerelease() -> None:
    # A release candidate is cut as `bump_version.py 1.0.0rc1`; the explicit form must
    # accept a PEP 440 pre-release verbatim, not reject it as non-numeric.
    assert _BUMP._next_version("0.1.0", "1.0.0rc1") == "1.0.0rc1"
    assert _BUMP._next_version("0.9.0", "1.0.0b2") == "1.0.0b2"


@pytest.mark.parametrize("bump", ["patch", "minor", "major"])
def test_a_named_bump_from_a_candidate_is_refused(bump: str) -> None:
    # `patch` from 1.0.0rc2 would otherwise give 1.0.1 and skip the final 1.0.0.
    with pytest.raises(SystemExit, match="not a final release"):
        _BUMP._next_version("1.0.0rc2", bump)
    with pytest.raises(SystemExit, match="not a final release"):
        _load_script("release")._target_version(bump, "1.0.0rc2")


def test_an_explicit_version_after_a_candidate_is_accepted() -> None:
    release = _load_script("release")
    assert _BUMP._next_version("1.0.0rc2", "1.0.0rc3") == "1.0.0rc3"
    assert _BUMP._next_version("1.0.0rc2", "1.0.0") == "1.0.0"
    assert release._target_version("1.0.0", "1.0.0rc2") == "1.0.0"
    assert release._target_version("patch", "1.0.0") == "1.0.1"


def test_next_version_rejects_a_non_version_argument() -> None:
    with pytest.raises(SystemExit):
        _BUMP._next_version("0.1.0", "banana")


def test_core_ignores_a_prerelease_suffix() -> None:
    assert _BUMP._core("1.0.0rc1") == (1, 0, 0)
    assert _BUMP._core("0.2.0") == (0, 2, 0)


def test_main_accepts_a_pep440_prerelease_in_dry_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    major, _, _ = _BUMP._core(_BUMP._current_version())
    candidate = f"{major + 1}.0.0rc1"
    monkeypatch.setattr(sys, "argv", ["bump_version.py", candidate, "--dry-run"])
    assert _BUMP.main() == 0
    assert candidate in capsys.readouterr().out


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


@pytest.mark.parametrize(
    "workflow", sorted(p.name for p in (Path(__file__).parents[3] / ".github/workflows").iterdir())
)
def test_no_workflow_runs_on_a_moving_runner_label(workflow: str) -> None:
    """A `-latest` label changes image under a job without a commit.

    GitHub moves such a label over several weeks, so the CI run on a commit and the
    release run on its tag can land on different systems; a runner change must be a
    reviewed diff.
    """
    config = yaml.safe_load(
        (_repo_root() / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
    )
    moving = {
        name: job["runs-on"]
        for name, job in config.get("jobs", {}).items()
        if "latest" in str(job.get("runs-on", ""))
    }
    assert not moving, f"{workflow}: jobs on a moving runner label: {moving}"


@pytest.mark.parametrize(
    "workflow", sorted(p.name for p in (Path(__file__).parents[3] / ".github/workflows").iterdir())
)
def test_every_workflow_declares_the_token_it_needs(workflow: str) -> None:
    """A workflow with no `permissions:` inherits whatever the repository default is.

    On a repository created before GitHub changed that default, it is read-write —
    so a compromised action would hold a token that can push to `main` of a
    security product. `ci.yml` had no block at all, and nothing noticed, because a
    token that is too wide never fails a build.

    Checked at the file level: a top-level block covers every job in the file, and
    a job may still widen it deliberately (publishing needs `id-token: write`).
    """
    config = yaml.safe_load(
        (_repo_root() / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
    )
    jobs = config.get("jobs", {})
    undeclared = [
        name
        for name, job in jobs.items()
        if "permissions" not in config and "permissions" not in job
    ]
    assert not undeclared, (
        f"{workflow}: jobs with no declared token scope, so they inherit the "
        f"repository default: {undeclared}"
    )


def test_the_no_cache_job_says_so_instead_of_relying_on_a_default() -> None:
    """The example-plugin job runs everything with `--no-cache`, so nothing fills the cache.

    `setup-uv` defaults `enable-cache` to `auto`, which still turns it on — and its
    post step then fails the job trying to save a directory no step created.
    Removing `enable-cache: true` did not fix that; the job simply kept passing
    because another job's cache matched the key, and *restoring* it created the
    directory. The first commit to change `uv.lock` broke a green job for a reason
    unrelated to anything the job tests.

    So the declaration is asserted rather than assumed. A job whose correctness
    depends on a sibling job's cache is a job that is not testing what it says.
    """
    config = yaml.safe_load((_repo_root() / ".github" / "workflows" / "ci.yml").read_text("utf-8"))
    steps = config["jobs"]["example-plugin"]["steps"]
    runs_without_cache = [s for s in steps if "--no-cache" in str(s.get("run", ""))]
    setup = [s for s in steps if "setup-uv" in str(s.get("uses", ""))]

    assert runs_without_cache, "the job no longer runs anything with --no-cache"
    assert setup, "the job no longer installs uv"
    assert setup[0]["with"]["enable-cache"] is False, (
        "example-plugin must declare `enable-cache: false`; `auto` enables it and "
        "its post step fails on a cache directory nothing wrote to"
    )


def test_no_two_ci_jobs_save_one_uv_cache() -> None:
    """Two jobs that compute one cache key race to save it, and the loser warns.

    The key is the runner, the Python version, the lock-file hash and the suffix, so
    every job that caches states a suffix or a Python version no other job uses.
    """
    config = yaml.safe_load((_repo_root() / ".github" / "workflows" / "ci.yml").read_text("utf-8"))
    keys: dict[tuple[str, str], str] = {}
    for name, job in config["jobs"].items():
        for step in job.get("steps", []):
            if "setup-uv" not in str(step.get("uses", "")):
                continue
            options = step.get("with", {})
            if options.get("enable-cache") is False:
                continue
            key = (str(options.get("python-version")), str(options.get("cache-suffix", "")))
            assert key not in keys, f"{name} and {keys[key]} save the same uv cache {key}"
            keys[key] = name


def test_codeql_runs_on_every_push_and_on_a_schedule() -> None:
    """ruff's bandit rules do not do taint tracking; a security product carries both."""
    workflow = (_repo_root() / ".github" / "workflows" / "codeql.yml").read_text(encoding="utf-8")

    assert "github/codeql-action/init@" in workflow
    assert "github/codeql-action/analyze@" in workflow
    assert "schedule:" in workflow
    assert "cron:" in workflow
    assert "security-events: write" in workflow
    assert "languages: python" in workflow
