"""The reproducibility check requires the reference pack exactly when the release published it.

A pack PyPI does not list is NOT PUBLISHED only when the release did not publish it; a
check that starts before PyPI lists a pack the release published must not pass. The
steps' scripts are run here with bash against a fake `gh` and `uv` on PATH, so the test
exercises the shell the runner executes, not a description of it.
"""

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[2]
_JOB = "publish-reference-pack"
_FAKE_GH = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$FAKE_LOG"
case "$1 $2" in
  "run list") printf '%s' "${FAKE_LIST:-}" ;;
  "run view") [ -n "${FAKE_VIEW_FAILS:-}" ] && exit 1; printf '%s' "${FAKE_VIEW:-}" ;;
  *) exit 64 ;;
esac
"""
_FAKE_UV = """#!/usr/bin/env bash
printf 'uv %s\\n' "$*" >> "$FAKE_LOG"
"""


def _workflow(name: str) -> dict[str, object]:
    loaded: dict[str, object] = yaml.safe_load(
        (_ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
    )
    return loaded


def _step(name: str) -> dict[str, object]:
    jobs = _workflow("reproducibility.yml")["jobs"]
    assert isinstance(jobs, dict)
    steps = jobs["reproduce"]["steps"]
    matching = [step for step in steps if step.get("name") == name]
    if len(matching) != 1:
        pytest.fail(f"reproducibility.yml has no single step named {name!r}")
    step: dict[str, object] = matching[0]
    return step


def _run_step(tmp_path: Path, name: str, **env: str) -> tuple[int, str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool, body in (("gh", _FAKE_GH), ("uv", _FAKE_UV)):
        fake = bin_dir / tool
        fake.write_text(body, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    log, output = tmp_path / "calls.log", tmp_path / "output"
    script = tmp_path / "step.sh"
    script.write_text(str(_step(name)["run"]), encoding="utf-8")
    environment = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_LOG": str(log),
        "GITHUB_OUTPUT": str(output),
        "VERSION": "1.0.0",
        **env,
    }
    done = subprocess.run(  # noqa: S603 — bash running the workflow's own step
        ["/bin/bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    calls = log.read_text(encoding="utf-8") if log.exists() else ""
    written = output.read_text(encoding="utf-8") if output.exists() else ""
    return done.returncode, calls, written


def _published(tmp_path: Path, **env: str) -> tuple[str, str]:
    code, calls, written = _run_step(
        tmp_path, "Whether the release published the reference pack", **env
    )
    assert code == 0, calls
    return written.strip(), calls


def test_the_lookup_names_a_job_the_release_workflow_defines() -> None:
    jobs = _workflow("release.yml")["jobs"]
    assert isinstance(jobs, dict)
    assert _JOB in jobs
    assert "name" not in jobs[_JOB], "gh lists the job by its id only while it has no name"
    assert f'select(.name == "{_JOB}")' in str(
        _step("Whether the release published the reference pack")["run"]
    )


def test_a_pack_the_triggering_release_published_is_required(tmp_path: Path) -> None:
    written, calls = _published(tmp_path, RELEASE_RUN="42", FAKE_VIEW="success")

    assert written == "published=true"
    assert calls.splitlines()[0].startswith("run view 42")
    assert "run list" not in calls


@pytest.mark.parametrize("conclusion", ["skipped", "failure", ""])
def test_a_pack_the_release_did_not_publish_stays_optional(tmp_path: Path, conclusion: str) -> None:
    written, _ = _published(tmp_path, RELEASE_RUN="42", FAKE_VIEW=conclusion)

    assert written == "published=false"


def test_a_dispatched_check_finds_the_release_run_of_its_tag(tmp_path: Path) -> None:
    written, calls = _published(tmp_path, RELEASE_RUN="", FAKE_LIST="7", FAKE_VIEW="success")

    listing = calls.splitlines()[0]
    assert listing.startswith("run list")
    assert "release.yml" in listing
    assert "--branch v1.0.0" in listing
    assert "--status success" in listing
    assert written == "published=true"


def test_a_version_without_a_release_run_keeps_the_pack_optional(tmp_path: Path) -> None:
    written, calls = _published(tmp_path, RELEASE_RUN="", FAKE_LIST="")

    assert written == "published=false"
    assert "run view" not in calls


def test_a_release_run_that_cannot_be_read_stops_the_check(tmp_path: Path) -> None:
    code, _, written = _run_step(
        tmp_path,
        "Whether the release published the reference pack",
        RELEASE_RUN="42",
        FAKE_VIEW_FAILS="1",
    )

    assert code != 0
    assert "published=" not in written


@pytest.mark.parametrize(("published", "flagged"), [("true", True), ("false", False)])
def test_the_rebuild_requires_the_pack_only_when_it_was_published(
    tmp_path: Path, published: str, flagged: bool
) -> None:
    code, calls, _ = _run_step(tmp_path, "Rebuild and compare with PyPI", PACK_PUBLISHED=published)

    assert code == 0
    (invocation,) = [line for line in calls.splitlines() if line.startswith("uv ")]
    assert "reproduce_release.py 1.0.0 --source release" in invocation
    assert ("--pack-published" in invocation) is flagged


def _uv_versions(name: str) -> list[object]:
    jobs = _workflow(name)["jobs"]
    assert isinstance(jobs, dict)
    return [
        step.get("with", {}).get("version")
        for job in jobs.values()
        for step in job["steps"]
        if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
    ]


def test_the_rebuild_uses_the_exact_uv_the_release_builds_with() -> None:
    release, rebuild = _uv_versions("release.yml"), _uv_versions("reproducibility.yml")

    assert release
    assert rebuild
    assert len(set(release + rebuild)) == 1
    assert re.fullmatch(r"\d+\.\d+\.\d+", str(release[0]))
