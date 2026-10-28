"""The reference pack reaches PyPI only as the bytes the release workflow built and attested."""

import os
import subprocess
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[2]


def _jobs() -> dict[str, dict[str, object]]:
    workflow = yaml.safe_load((_ROOT / ".github" / "workflows" / "release.yml").read_text("utf-8"))
    jobs: dict[str, dict[str, object]] = workflow["jobs"]
    return jobs


def _steps(job: str) -> list[dict[str, object]]:
    steps: list[dict[str, object]] = _jobs()[job]["steps"]  # type: ignore[assignment]
    return steps


def _scripts(job: str) -> str:
    return "\n".join(str(step.get("run", "")) for step in _steps(job))


def test_control_the_built_pack_is_attested_and_kept_for_the_publish_job() -> None:
    steps = _steps("reference-pack")
    (attest,) = [s for s in steps if "attest" in str(s.get("uses", ""))]
    (kept,) = [s for s in steps if "upload-artifact" in str(s.get("uses", ""))]

    assert "dist-reference/*.whl" in str(attest["with"])
    assert "dist-reference/*.whl" in str(kept["with"])


def test_the_published_pack_is_the_attested_build_not_a_release_asset() -> None:
    steps = _steps("publish-reference-pack")
    (publish,) = [i for i, s in enumerate(steps) if "pypi-publish" in str(s.get("uses", ""))]
    before = steps[:publish]
    runs = "\n".join(str(step.get("run", "")) for step in before)

    assert any("download-artifact" in str(step.get("uses", "")) for step in before)
    assert "gh release download" not in runs
    assert "check_pypi_digests.py" in runs


def test_a_release_asset_with_other_bytes_stops_the_attach_step() -> None:
    (attach,) = [s for s in _steps("reference-pack") if "Attach" in str(s.get("name", ""))]

    assert "cmp -s" in str(attach["run"])


def _compare_step(tmp_path: Path, python_exit: int) -> tuple[int, str]:
    (step,) = [s for s in _steps("reference-pack-on-pypi") if s.get("id") == "compare"]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "python3"
    fake.write_text(f"#!/usr/bin/env bash\nexit {python_exit}\n", encoding="utf-8")
    fake.chmod(0o755)
    output = tmp_path / "output"
    output.touch()
    script = tmp_path / "step.sh"
    script.write_text(str(step["run"]), encoding="utf-8")
    environment = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "GITHUB_OUTPUT": str(output)}
    done = subprocess.run(  # noqa: S603 — bash runs the workflow's own step script
        ["/bin/bash", "-eo", "pipefail", str(script)],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    return done.returncode, output.read_text(encoding="utf-8").strip()


@pytest.mark.parametrize(
    ("python_exit", "status", "result"),
    [
        (0, 0, "new"),
        (3, 0, "identical"),
        (1, 1, "differ"),
        (2, 0, "unreadable"),
        (9, 0, "unreadable"),
    ],
)
def test_the_digest_comparison_names_its_result_before_any_approval(
    tmp_path: Path, python_exit: int, status: int, result: str
) -> None:
    assert _compare_step(tmp_path, python_exit) == (status, f"result={result}")


def test_only_new_or_unreadable_files_reach_the_approval_gated_job() -> None:
    jobs = _jobs()
    gate, publish = jobs["reference-pack-on-pypi"], jobs["publish-reference-pack"]
    condition = str(publish["if"])

    assert "environment" not in gate
    assert publish["environment"] == "pypi"
    assert "reference-pack-on-pypi" in publish["needs"]  # type: ignore[operator]
    assert "result == 'new'" in condition
    assert "result == 'unreadable'" in condition
    assert "identical" not in condition
    assert "differ" not in condition
    assert any(
        "download-artifact" in str(step.get("uses", ""))
        for step in _steps("reference-pack-on-pypi")
    )
