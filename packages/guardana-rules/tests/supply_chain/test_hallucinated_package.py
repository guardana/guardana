import os
from pathlib import Path

import pytest
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.hallucinated_package import HallucinatedPackageRule


def test_flags_unknown_import(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("import totally_not_a_real_pkg_xyz\n")
    findings = list(HallucinatedPackageRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any("totally_not_a_real_pkg_xyz" in f.evidence.summary for f in findings)


def test_slopsquat_is_a_low_confidence_lead_not_a_certainty(tmp_path: Path) -> None:
    # A probabilistic signal (the import might be a legit private package) carries a
    # low "lead" confidence, so a policy's min_confidence can treat it as a lead —
    # unlike a deterministic detection, which stays verdict-free and certain.
    (tmp_path / "a.py").write_text("import totally_not_a_real_pkg_xyz\n")
    findings = list(HallucinatedPackageRule().run(ArtifactTarget(tmp_path), RuleContext()))
    lead = next(f for f in findings if "totally_not_a_real_pkg_xyz" in f.evidence.summary)
    assert lead.verdict is not None
    assert lead.verdict.outcome == "fail"
    assert 0.0 < lead.verdict.confidence < 0.5


def test_stdlib_and_local_imports_ok(tmp_path: Path) -> None:
    (tmp_path / "local_mod.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("import os\nimport json\nimport local_mod\n")
    findings = list(HallucinatedPackageRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_src_layout_package_treated_as_local(tmp_path: Path) -> None:
    pkgroot = tmp_path / "pkgroot"
    (pkgroot / "src" / "myns").mkdir(parents=True)
    (pkgroot / "src" / "myns" / "mod.py").write_text("y = 1\n")
    (pkgroot / "app.py").write_text("import myns\nimport os\nimport totally_fake_zzz\n")
    findings = list(HallucinatedPackageRule().run(ArtifactTarget(pkgroot), RuleContext()))
    flagged = {f.evidence.summary for f in findings}
    assert not any("myns" in s for s in flagged)
    assert not any("'os'" in s for s in flagged)
    assert any("totally_fake_zzz" in s for s in flagged)


def test_non_utf8_file_skipped_without_raising(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe\x00invalid utf-8\x80\x81")
    findings = list(HallucinatedPackageRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_curated_real_distribution_not_flagged(tmp_path: Path) -> None:
    # defusedxml is a real distribution and one of Guardana's own dependencies;
    # flagging it broke the dogfood invariant (0 findings on packages/).
    (tmp_path / "x.py").write_text(
        "import defusedxml\nfrom defusedxml.common import DTDForbidden\n", encoding="utf-8"
    )
    findings = list(HallucinatedPackageRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_from_import_of_unknown_package_flagged(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("from totally_fake_zzz import thing\n", encoding="utf-8")
    findings = list(HallucinatedPackageRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any("totally_fake_zzz" in f.evidence.summary for f in findings)


def test_from_import_of_stdlib_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "b.py").write_text("from os.path import join\n", encoding="utf-8")
    findings = list(HallucinatedPackageRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


@pytest.mark.skipif(os.name != "posix", reason="chmod-based access denial is POSIX-only")
def test_unreadable_subdir_skipped_without_raising(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "m.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "a.py").write_text("import os\n", encoding="utf-8")
    locked.chmod(0o000)
    try:
        findings = list(HallucinatedPackageRule().run(ArtifactTarget(tmp_path), RuleContext()))
    finally:
        locked.chmod(0o755)
    assert findings == []


def test_a_padded_file_does_not_evade_the_scan(tmp_path: Path) -> None:
    big = "import totally_fake_zzz\n" + ("# filler\n" * 200_000)
    (tmp_path / "big.py").write_text(big, encoding="utf-8")
    findings = list(HallucinatedPackageRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any("totally_fake_zzz" in f.evidence.summary for f in findings)
