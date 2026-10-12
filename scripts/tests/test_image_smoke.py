"""The wheel check `image_smoke.py` runs before it builds anything."""

from pathlib import Path

import pytest
from packaging import tags
from packaging.utils import parse_wheel_filename

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

[[package]]
name = "native"
version = "3.0"
wheels = [
    { url = "https://files.example/native-3.0-cp313-cp313-manylinux2014_x86_64.whl" },
    { url = "https://files.example/native-3.0-cp39-abi3-manylinux_2_17_aarch64.whl" },
]
"""


_ACCEPTED = [
    ("a-1-py3-none-any.whl", "aarch64"),
    ("a-1-py3-none-any.whl", "x86_64"),
    ("a-1-py2.py3-none-any.whl", "x86_64"),
    ("a-1-cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64.whl", "aarch64"),
    ("a-1-cp39-abi3-manylinux_2_28_aarch64.whl", "aarch64"),
    ("a-1-cp313-cp313-manylinux_2_36_aarch64.whl", "aarch64"),
    ("a-1-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "x86_64"),
    ("a-1-cp313-cp313-manylinux2014_x86_64.whl", "x86_64"),
    ("a-1-cp313-cp313-manylinux2010_x86_64.whl", "x86_64"),
    ("a-1-cp313-cp313-manylinux1_x86_64.whl", "x86_64"),
    ("a-1-cp38-abi3-manylinux_2_36_x86_64.whl", "x86_64"),
]
_REJECTED = [
    ("a-1-cp313-cp313-manylinux_2_17_x86_64.whl", "aarch64"),
    ("a-1-cp313-cp313-manylinux_2_17_aarch64.whl", "x86_64"),
    ("a-1-cp313-cp313-manylinux2014_aarch64.whl", "x86_64"),
    ("a-1-cp313-cp313-musllinux_1_2_aarch64.whl", "aarch64"),
    ("a-1-cp313-cp313-musllinux_1_2_x86_64.whl", "x86_64"),
    ("a-1-cp313-cp313-macosx_11_0_arm64.whl", "aarch64"),
    ("a-1-cp313-cp313-macosx_10_13_x86_64.whl", "x86_64"),
    ("a-1-cp313-cp313-win_amd64.whl", "x86_64"),
    ("a-1-cp312-cp312-manylinux_2_17_aarch64.whl", "aarch64"),
    ("a-1-cp312-cp312-manylinux_2_17_x86_64.whl", "x86_64"),
    ("a-1-cp313-cp313t-manylinux_2_17_aarch64.whl", "aarch64"),
    ("a-1-cp313-cp313-manylinux_2_39_aarch64.whl", "aarch64"),
    ("a-1-cp313-cp313-manylinux_2_39_x86_64.whl", "x86_64"),
    ("a-1-cp314-abi3-manylinux_2_17_aarch64.whl", "aarch64"),
    ("a-1-cp314-abi3-manylinux_2_17_x86_64.whl", "x86_64"),
    ("a-1-cp39-abi3-any.whl", "x86_64"),
    ("a-1-cp313-cp313-any.whl", "aarch64"),
    ("a-1-cp313-cp313-manylinux1_aarch64.whl", "aarch64"),
    ("a-1-cp313-cp313-manylinux2010_aarch64.whl", "aarch64"),
    ("a-1-cp313-cp313-manylinux_2_5_aarch64.whl", "aarch64"),
    ("a-1-cp31-abi3-manylinux_2_17_x86_64.whl", "x86_64"),
    ("a-1-cp31-abi3-manylinux_2_28_aarch64.whl", "aarch64"),
]


def _tree(tmp_path: Path, requirements: str) -> Path:
    docker = tmp_path / "deploy" / "docker"
    docker.mkdir(parents=True)
    for name in ("cli.Dockerfile", "collector.Dockerfile"):
        (docker / name).write_text(f"FROM {_BASE} AS builder\nFROM {_BASE}\n", encoding="utf-8")
    (docker / "cli-requirements.txt").write_text(requirements, encoding="utf-8")
    (tmp_path / "uv.lock").write_text(_LOCK, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    ("wheel", "arch"),
    _ACCEPTED,
)
def test_a_wheel_pip_installs_on_the_image_is_accepted(wheel: str, arch: str) -> None:
    """Pure wheels, the stable ABI and glibc manylinux up to the base's glibc."""
    assert image_smoke.wheel_installs_on(wheel, _PY313, arch)


@pytest.mark.parametrize(
    ("wheel", "arch"),
    _REJECTED,
)
def test_a_wheel_pip_would_refuse_on_the_image_is_rejected(wheel: str, arch: str) -> None:
    """Another CPU or libc, another CPython or ABI, a compiled ABI on `any`, the wrong glibc."""
    assert not image_smoke.wheel_installs_on(wheel, _PY313, arch)


def _pip_tags(python: tuple[int, int], arch: str) -> set[tags.Tag]:
    """What `packaging`, the library pip uses, accepts on the images' glibc for `arch`."""
    oldest = 5 if arch == "x86_64" else 17
    glibc = range(image_smoke._BASE_GLIBC[1], oldest - 1, -1)
    legacy = {17: "manylinux2014", 12: "manylinux2010", 5: "manylinux1"}
    platforms = []
    for minor in glibc:
        platforms.append(f"manylinux_2_{minor}_{arch}")
        if minor in legacy:
            platforms.append(f"{legacy[minor]}_{arch}")
    interpreter = f"cp{python[0]}{python[1]}"
    return set(tags.cpython_tags(python, [interpreter], platforms)) | set(
        tags.compatible_tags(python, interpreter, platforms)
    )


@pytest.mark.parametrize(("wheel", "arch"), _ACCEPTED + _REJECTED)
def test_the_wheel_check_agrees_with_packaging(wheel: str, arch: str) -> None:
    """Every case above is decided the way pip's own tag matching decides it."""
    pip_installs = bool(parse_wheel_filename(wheel)[3] & _pip_tags(_PY313, arch))

    assert image_smoke.wheel_installs_on(wheel, _PY313, arch) == pip_installs


def test_requirements_with_wheels_for_both_platforms_pass(tmp_path: Path) -> None:
    """A pure wheel, or one compiled wheel per CPU, is enough."""
    root = _tree(tmp_path, f"# header\npure==1.0 \\\n{_HASH}\nnative==3.0 \\\n{_HASH}\n")

    assert image_smoke.wheel_gaps(root) == []


def test_a_package_without_an_arm64_wheel_is_named(tmp_path: Path) -> None:
    """Wheels for x86_64 and macOS arm64 are not wheels for the arm64 image."""
    root = _tree(tmp_path, f"pure==1.0 \\\n{_HASH}\ncompiled==2.0 ; sys_platform == 'linux' \\\n")

    assert image_smoke.wheel_gaps(root) == [
        "cli-requirements.txt: compiled==2.0 has no wheel for linux/arm64 in uv.lock"
    ]


def test_a_package_without_an_amd64_wheel_is_named(tmp_path: Path) -> None:
    """An aarch64 wheel alone leaves the amd64 build no wheel it may install."""
    root = _tree(tmp_path, f"fixed==2.1 \\\n{_HASH}\n")

    assert image_smoke.wheel_gaps(root) == [
        "cli-requirements.txt: fixed==2.1 has no wheel for linux/amd64 in uv.lock"
    ]


def test_a_pin_the_lock_does_not_hold_is_named(tmp_path: Path) -> None:
    """A version the lock does not record has no wheel anyone checked."""
    root = _tree(tmp_path, "pure==1.1 \\\n")

    assert image_smoke.wheel_gaps(root) == ["cli-requirements.txt: pure==1.1 is not in uv.lock"]


def test_an_indented_requirement_is_checked_like_any_other(tmp_path: Path) -> None:
    """The export check strips indentation, so the wheel check must not skip such a line."""
    root = _tree(tmp_path, f"pure==1.0 \\\n{_HASH}\n    compiled==2.0 \\\n{_HASH}\n")

    assert image_smoke.wheel_gaps(root) == [
        "cli-requirements.txt: compiled==2.0 has no wheel for linux/arm64 in uv.lock"
    ]


@pytest.mark.parametrize(
    ("requirements", "named"),
    [
        ("pure==1.0\n--index-url https://files.example/simple\n", "not a requirement"),
        ("pure>=1.0\n", "pure>=1.0 is not pinned to one version"),
        ("pure==1.*\n", "pure==1.* is not pinned to one version"),
    ],
    ids=["option-line", "range", "wildcard"],
)
def test_a_line_the_wheel_check_cannot_pin_is_named(
    tmp_path: Path, requirements: str, named: str
) -> None:
    """A line that names no single version leaves no wheel to check, so it is a gap."""
    root = _tree(tmp_path, requirements)

    (gap,) = image_smoke.wheel_gaps(root)
    assert gap.startswith("cli-requirements.txt: ")
    assert named in gap


def test_nothing_to_check_is_a_failure(tmp_path: Path) -> None:
    """No exported file, or one that pins nothing, is never an empty pass."""
    root = _tree(tmp_path, "# header only\n")

    assert image_smoke.wheel_gaps(root) == ["cli-requirements.txt pins no package"]
    (root / "deploy" / "docker" / "cli-requirements.txt").unlink()
    assert image_smoke.wheel_gaps(root) == [
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

    (gap,) = image_smoke.wheel_gaps(root)
    assert gap.startswith(named)


def test_every_package_the_images_install_has_a_wheel_for_both_platforms() -> None:
    """The images install wheels only, for both platforms a release publishes."""
    assert image_smoke.wheel_gaps(_REPO) == []
