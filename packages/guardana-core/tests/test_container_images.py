"""What the two official images must be, checked without a Docker daemon.

`scripts/image_smoke.py` proves the images *behave* — it builds them and runs
them, and CI runs it on every push. This file holds the properties that are
cheaper to assert than to observe, and one that observation cannot see at all:
the collector image must not carry the engine.

That last one is the same contract `lint-imports` enforces for imports, one layer
out. A Dockerfile that copies `guardana-core` into the collector image would make
the collector ship the engine without a single import changing, and the boundary
this project is built on would quietly stop being real.
"""

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
_DOCKER = _REPO / "deploy" / "docker"
_CLI = _DOCKER / "cli.Dockerfile"
_COLLECTOR = _DOCKER / "collector.Dockerfile"
_ROOT_USERS = frozenset({"root", "0"})
_FROM_RE = re.compile(r"^FROM\s+(?P<image>\S+)", re.MULTILINE)
_USER_RE = re.compile(r"^USER\s+(?P<user>\S+)", re.MULTILINE)


def _instructions(dockerfile: Path) -> str:
    """The Dockerfile with its comments removed — what the build actually does.

    Both files explain in prose which packages they deliberately do *not* install,
    so a substring check over the raw text finds the sentence that promises the
    property and calls it a violation.
    """
    lines = dockerfile.read_text(encoding="utf-8").splitlines()
    return "\n".join(line for line in lines if not line.lstrip().startswith("#"))


@pytest.mark.parametrize("dockerfile", [_CLI, _COLLECTOR], ids=["cli", "collector"])
def test_the_image_does_not_run_as_root(dockerfile: Path) -> None:
    """A scanner reads other people's code and never needs to own it."""
    users = _USER_RE.findall(_instructions(dockerfile))

    assert users, f"{dockerfile.name} never switches away from root"
    assert users[-1] not in _ROOT_USERS, f"{dockerfile.name} ends up running as {users[-1]}"


@pytest.mark.parametrize("dockerfile", [_CLI, _COLLECTOR], ids=["cli", "collector"])
def test_the_build_stage_is_not_the_shipped_stage(dockerfile: Path) -> None:
    """Two stages, so a compiler in the builder is not a compiler in production."""
    stages = _FROM_RE.findall(_instructions(dockerfile))

    assert len(stages) >= 2, f"{dockerfile.name} is a single-stage build"


@pytest.mark.parametrize("dockerfile", [_CLI, _COLLECTOR], ids=["cli", "collector"])
def test_every_base_is_pinned_by_digest(dockerfile: Path) -> None:
    """A tag can be moved to other bytes; a digest cannot, and Dependabot moves it."""
    bases = _FROM_RE.findall(_instructions(dockerfile))

    unpinned = [base for base in bases if "@sha256:" not in base]
    assert not unpinned, f"{dockerfile.name} names a base by tag only: {unpinned}"


def test_both_images_share_one_base() -> None:
    """One base to review, one base to patch, one base Dependabot has to notice."""
    bases = {
        dockerfile.name: set(_FROM_RE.findall(_instructions(dockerfile)))
        for dockerfile in (_CLI, _COLLECTOR)
    }

    assert bases[_CLI.name] == bases[_COLLECTOR.name], (
        f"the two images are built on different bases: {bases}"
    )


def test_the_collector_image_does_not_carry_the_engine() -> None:
    """The boundary `lint-imports` enforces for imports, enforced for the image.

    `guardana-server` does not depend on `guardana-core`, and this is the packaging
    equivalent of that rule: copying the engine in would ship it inside the
    collector without one import changing.
    """
    text = _instructions(_COLLECTOR)

    for engine_package in ("guardana-core", "guardana-rules", "guardana-report", "guardana-cli"):
        assert engine_package not in text, (
            f"the collector image copies {engine_package}; the collector does not depend on "
            f"the engine and its image must not either"
        )


def test_the_cli_image_installs_the_rules() -> None:
    """An image without the catalog reports "no findings" and exits 0, forever."""
    text = _instructions(_CLI)

    assert "guardana-rules" in text
    assert "guardana-server" not in text, "the CLI image ships the collector"


@pytest.mark.parametrize(
    ("dockerfile", "exported"),
    [(_CLI, "cli-requirements.txt"), (_COLLECTOR, "collector-requirements.txt")],
    ids=["cli", "collector"],
)
def test_the_image_installs_only_hash_pinned_locked_versions(
    dockerfile: Path, exported: str
) -> None:
    """The versions CI tests from `uv.lock`, by hash, and nothing pip resolves itself."""
    commands = [
        " ".join(command.split())
        for command in re.split(r"&&|\n(?=RUN)", _instructions(dockerfile).replace("\\\n", " "))
        if "pip install" in command or "pip wheel" in command
    ]
    hashed = [command for command in commands if "--require-hashes" in command]

    assert any(f"-r {exported}" in command for command in hashed), commands
    assert any("-r build-requirements.txt" in command for command in hashed), commands
    assert all("--no-deps" in command for command in commands), commands
    assert not [command for command in commands if "--upgrade" in command or " -U " in command]
    assert any("--no-build-isolation" in command for command in commands), commands
    assert "pip check" in _instructions(dockerfile)
