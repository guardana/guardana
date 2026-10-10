"""The arm64 wheel check `image_smoke.py` runs before it builds anything."""

from pathlib import Path

import pytest

import image_smoke

_REPO = Path(__file__).resolve().parents[2]
_PY313 = (3, 13)
_HASH = "    --hash=sha256:" + "0" * 64
_BASE = "python:3.13-slim-bookworm@sha256:" + "a" * 64
_LOCK = """version = 1

[[package]]
name = "pure"
version = "1.0"
wheels = [{ url = "https://files.example/pure-1.0-py3-none-any.whl" }]

[[package]]
name = "compiled"
version = "2.0"
wheels = [
    { url = "https://files.example/compiled-2.0-cp313-cp313-manylinux_2_17_x86_64.whl" },
    { url = "https://files.example/compiled-2.0-cp313-cp313-macosx_11_0_arm64.whl" },
]

[[package]]
name = "fixed"
version = "2.1"
wheels = [{ url = "https://files.example/fixed-2.1-cp39-abi3-manylinux_2_28_aarch64.whl" }]
"""


def _tree(tmp_path: Path, requirements: str) -> Path:
    docker = tmp_path / "deploy" / "docker"
    docker.mkdir(parents=True)
    for name in ("cli.Dockerfile", "collector.Dockerfile"):
        (docker / name).write_text(f"FROM {_BASE} AS builder\nFROM {_BASE}\n", encoding="utf-8")
    (docker / "cli-requirements.txt").write_text(requirements, encoding="utf-8")
    (tmp_path / "uv.lock").write_text(_LOCK, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    "wheel",
    [
        "a-1-py3-none-any.whl",
        "a-1-py2.py3-none-any.whl",
        "a-1-cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64.whl",
        "a-1-cp39-abi3-manylinux_2_28_aarch64.whl",
        "a-1-cp313-cp313-manylinux_2_36_aarch64.whl",
    ],
)
def test_a_wheel_pip_installs_on_the_arm64_image_is_accepted(wheel: str) -> None:
    """Pure wheels, the stable ABI and glibc manylinux up to the base's glibc."""
    assert image_smoke.wheel_installs_on_arm64(wheel, _PY313)


@pytest.mark.parametrize(
    "wheel",
    [
        "a-1-cp313-cp313-manylinux_2_17_x86_64.whl",
        "a-1-cp313-cp313-musllinux_1_2_aarch64.whl",
        "a-1-cp313-cp313-macosx_11_0_arm64.whl",
        "a-1-cp312-cp312-manylinux_2_17_aarch64.whl",
        "a-1-cp313-cp313t-manylinux_2_17_aarch64.whl",
        "a-1-cp313-cp313-manylinux_2_39_aarch64.whl",
        "a-1-cp314-abi3-manylinux_2_17_aarch64.whl",
    ],
)
def test_a_wheel_pip_would_refuse_on_the_arm64_image_is_rejected(wheel: str) -> None:
    """Another CPU, musl, macOS, another CPython, free-threading or a newer glibc."""
    assert not image_smoke.wheel_installs_on_arm64(wheel, _PY313)


def test_requirements_with_arm64_wheels_pass(tmp_path: Path) -> None:
    """A pure wheel and an abi3 aarch64 wheel are each enough."""
    root = _tree(tmp_path, f"# header\npure==1.0 \\\n{_HASH}\nfixed==2.1 \\\n{_HASH}\n")

    assert image_smoke.arm64_gaps(root) == []


def test_a_package_without_an_arm64_wheel_is_named(tmp_path: Path) -> None:
    """Wheels for x86_64 and macOS arm64 are not wheels for the arm64 image."""
    root = _tree(tmp_path, f"pure==1.0 \\\n{_HASH}\ncompiled==2.0 ; sys_platform == 'linux' \\\n")

    assert image_smoke.arm64_gaps(root) == [
        "cli-requirements.txt: compiled==2.0 has no wheel for linux/arm64 in uv.lock"
    ]


def test_a_pin_the_lock_does_not_hold_is_named(tmp_path: Path) -> None:
    """A version the lock does not record has no wheel anyone checked."""
    root = _tree(tmp_path, "pure==1.1 \\\n")

    assert image_smoke.arm64_gaps(root) == ["cli-requirements.txt: pure==1.1 is not in uv.lock"]


def test_nothing_to_check_is_a_failure(tmp_path: Path) -> None:
    """No exported file, or one that pins nothing, is never an empty pass."""
    root = _tree(tmp_path, "# header only\n")

    assert image_smoke.arm64_gaps(root) == ["cli-requirements.txt pins no package"]
    (root / "deploy" / "docker" / "cli-requirements.txt").unlink()
    assert image_smoke.arm64_gaps(root) == [
        "deploy/docker holds no exported requirement files to check"
    ]


@pytest.mark.parametrize(
    ("collector", "named"),
    [
        (
            f"FROM {_BASE.replace('bookworm', 'trixie')}\n",
            "collector.Dockerfile is not built on one digest-pinned python:X.Y-slim-bookworm",
        ),
        (f"FROM {_BASE.partition('@')[0]}\n", "collector.Dockerfile is not built on one"),
        (f"FROM {_BASE} AS builder\nFROM python:3.12-slim\n", "collector.Dockerfile is not"),
        (
            f"FROM {_BASE.replace('3.13', '3.12')}\n",
            "cli.Dockerfile and collector.Dockerfile are built on different base images",
        ),
    ],
    ids=["another-distribution", "no-digest", "two-bases", "disagreeing-images"],
)
def test_a_base_the_wheel_check_cannot_rely_on_is_named(
    tmp_path: Path, collector: str, named: str
) -> None:
    """Another glibc, an unpinned tag or two images that disagree fail before any wheel."""
    root = _tree(tmp_path, f"pure==1.0 \\\n{_HASH}\n")
    (root / "deploy" / "docker" / "collector.Dockerfile").write_text(collector, encoding="utf-8")

    (gap,) = image_smoke.arm64_gaps(root)
    assert gap.startswith(named)


def test_every_package_the_images_install_has_an_arm64_wheel() -> None:
    """The release publishes linux/arm64, which neither CI nor this check builds."""
    assert image_smoke.arm64_gaps(_REPO) == []
