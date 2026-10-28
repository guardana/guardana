"""Dependabot proposes only updates the project can ship."""

from __future__ import annotations

from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]


def _load(path: Path) -> dict[str, object]:
    loaded: dict[str, object] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return loaded


def test_image_updates_stay_on_the_newest_python_ci_tests() -> None:
    """A base image newer than CI's test matrix would ship an untested interpreter."""
    ci = _load(_ROOT / ".github" / "workflows" / "ci.yml")
    jobs = ci["jobs"]
    assert isinstance(jobs, dict)
    tested = jobs["test"]["strategy"]["matrix"]["python-version"]
    major, minor = max(tuple(int(part) for part in version.split(".")) for version in tested)

    config = _load(_ROOT / ".github" / "dependabot.yml")
    updates = config["updates"]
    assert isinstance(updates, list)
    (images,) = [
        entry
        for entry in updates
        if entry["package-ecosystem"] == "docker" and entry["directory"] == "/deploy/docker"
    ]
    assert {"dependency-name": "python", "versions": [f">= {major}.{minor + 1}"]} in images[
        "ignore"
    ]


def test_every_dockerfile_uses_the_newest_python_ci_tests() -> None:
    """The ignore rule above is only right while the images sit on that same version."""
    ci = _load(_ROOT / ".github" / "workflows" / "ci.yml")
    jobs = ci["jobs"]
    assert isinstance(jobs, dict)
    newest = max(
        jobs["test"]["strategy"]["matrix"]["python-version"],
        key=lambda v: tuple(map(int, v.split("."))),
    )
    for dockerfile in sorted((_ROOT / "deploy" / "docker").glob("*.Dockerfile")):
        bases = [
            line.split()[1]
            for line in dockerfile.read_text(encoding="utf-8").splitlines()
            if line.startswith("FROM ")
        ]
        assert bases, dockerfile.name
        for base in bases:
            assert base.startswith(f"python:{newest}-"), f"{dockerfile.name}: {base}"
