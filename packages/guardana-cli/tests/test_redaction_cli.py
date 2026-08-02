"""Redaction, checked where a user actually meets it: the files a command writes.

The unit tests prove the redactor works and that every renderer goes through it.
This proves the commands are wired to it — which is a separate claim, and the one
that would fail silently.
"""

import json
from pathlib import Path

from guardana.cli.main import app
from guardana.core.report import load_report
from guardana.core.testing import fake_aws_key
from typer.testing import CliRunner

runner = CliRunner()

# Built rather than written: see `guardana.core.testing.secrets`.
_FAKE_KEY = fake_aws_key()
_SOURCE = f'API_KEY = "{_FAKE_KEY}"\n'


def _scan_to(tmp_path: Path, *args: str) -> Path:
    (tmp_path / "config.py").write_text(_SOURCE, encoding="utf-8")
    out = tmp_path / "run.json"
    runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--output", str(out), *args])
    return out


def test_a_saved_run_does_not_contain_the_secret_that_was_found(tmp_path: Path) -> None:
    # The finding is that a credential is hard-coded. Writing the credential into
    # the report to prove it would make the report the second copy of the problem.
    written = _scan_to(tmp_path).read_text(encoding="utf-8")

    assert _FAKE_KEY not in written
    assert "hardcoded_secret" in written, "the finding itself must survive redaction"


def test_the_run_records_which_evidence_policy_was_applied(tmp_path: Path) -> None:
    manifest = load_report(_scan_to(tmp_path)).manifest

    assert str(manifest.privacy.evidence_mode) == "redacted"
    assert manifest.privacy.redaction_policy_digest is not None


def test_a_profile_can_ask_for_metadata_only(tmp_path: Path) -> None:
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: strict\nprivacy:\n  evidence_mode: metadata_only\n", encoding="utf-8")

    document = json.loads(_scan_to(tmp_path, "--profile", str(profile)).read_text(encoding="utf-8"))

    assert document["findings"], "metadata_only withholds the text, never the finding"
    assert all("withheld" in f["evidence"]["summary"] for f in document["findings"])


def test_a_baseline_written_by_the_cli_carries_no_secret(tmp_path: Path) -> None:
    # A baseline is committed to a repository. It is the worst possible resting
    # place for a credential, and the output path an author is least likely to
    # think of as one.
    (tmp_path / "config.py").write_text(_SOURCE, encoding="utf-8")
    baseline = tmp_path / "baseline.yaml"

    runner.invoke(app, ["scan", str(tmp_path), "--write-baseline", str(baseline)])

    assert _FAKE_KEY not in baseline.read_text(encoding="utf-8")


def test_a_baseline_written_by_the_cli_still_waives_what_it_recorded(tmp_path: Path) -> None:
    """The trap: redaction changes a finding's fingerprint, so order matters.

    If a baseline were written from redacted findings and matched against raw
    ones, every waiver would stop matching the moment redaction shipped — and the
    gate would go red for reasons nobody could trace.
    """
    (tmp_path / "config.py").write_text(_SOURCE, encoding="utf-8")
    baseline = tmp_path / "baseline.yaml"
    runner.invoke(app, ["scan", str(tmp_path), "--write-baseline", str(baseline)])
    baseline.write_text(
        baseline.read_text(encoding="utf-8").replace("REPLACE ME", "known, accepted"),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", str(tmp_path), "--baseline", str(baseline)])

    assert "waived" in result.output.lower() or result.exit_code == 0, result.output
