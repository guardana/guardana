"""A waiver has to survive being written down, and every key of it has to be read.

The baseline is the one document in this repository whose whole job is to stop a
gate firing, and it is the one that had no round-trip gate — not because anybody
decided it did not need one, but because the meta-gate that reads the inventory off
the source looked for constants named `*_SCHEMA_VERSION` and this file's is called
`BASELINE_VERSION`. A rule about names is a rule the next document walks past, so
that gate now asks about every `*VERSION` constant and this one answers it.

What the two questions here would catch: an approver or an expiry written by
`baseline create`, or kept by `baseline update`, and dropped on the way back. Both
turn a temporary, owned acceptance into an anonymous permanent one, which is the
single thing this mechanism is not allowed to become.
"""

from datetime import date
from pathlib import Path

import yaml
from _roundtrip import Document, lost_fields, undemonstrative_fields, unread_keys
from guardana.core.report.baseline import (
    Baseline,
    BaselineError,
    Waiver,
    read_baseline,
    serialize_baseline,
)
from guardana.core.report.finding import Evidence, Finding
from guardana.core.report.result import ScanResult
from guardana.core.severity import Severity


def _accepted() -> Waiver:
    """One waiver with every field carrying something a reader could lose."""
    return Waiver(
        fingerprint="705c242957abe403",
        rule="guardana.supply_chain.insecure_transport",
        location="app.py:2",
        reason="internal tool, no traffic leaves the cluster",
        approved_by="security@example.com",
        expires=date(2026, 12, 31),
    )


def _document(waiver: Waiver) -> Document:
    return {
        "version": 2,
        "waivers": [
            {
                "fingerprint": waiver.fingerprint,
                "rule": waiver.rule,
                "location": waiver.location,
                "reason": waiver.reason,
                "approved_by": waiver.approved_by,
                "expires": waiver.expires.isoformat() if waiver.expires else None,
            }
        ],
    }


def _read(document: Document, tmp: Path) -> Baseline:
    path = tmp / "read.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return read_baseline(path)


def test_every_field_of_a_waiver_survives_being_written_and_read_back(tmp_path: Path) -> None:
    accepted = _accepted()
    path = tmp_path / "guardana-baseline.yaml"
    path.write_text(yaml.safe_dump(_document(accepted)), encoding="utf-8")

    restored = read_baseline(path).waivers[0]

    lost = lost_fields(accepted, restored, "waiver")
    assert not lost, "fields a waiver loses on the way back:\n  " + "\n  ".join(lost)


def test_no_key_of_a_baseline_can_be_deleted_without_the_reader_noticing(tmp_path: Path) -> None:
    ignored = unread_keys(
        _document(_accepted()),
        lambda doc: _read(doc, tmp_path),
        root="baseline",
        refusal=BaselineError,
    )

    assert not ignored, (
        "keys a baseline carries that make no difference to what is read back — "
        "either nothing reads them, or the fixture leaves them at the reader's "
        "default:\n  " + "\n  ".join(ignored)
    )


def test_the_fixture_occupies_every_field_a_waiver_has() -> None:
    empty = undemonstrative_fields(_accepted(), "waiver")

    assert not empty, f"fields the waiver fixture leaves empty, so nothing is proved: {empty}"


def test_the_file_the_writer_generates_is_one_this_reader_accepts(tmp_path: Path) -> None:
    """`baseline create` writes it and every later command reads it back.

    Worth its own test now that the reader refuses an unknown key: a writer emitting
    one key the reader has never heard of would make every generated baseline
    unreadable, and the two halves live in different functions with no compiler
    between them.
    """
    finding = Finding(
        rule_id="guardana.supply_chain.hardcoded_secret",
        severity=Severity.HIGH,
        title="Hardcoded secret in repository file",
        taxonomy=(),
        target_ref="app.py:3",
        evidence=Evidence(summary="matched LLM provider API key pattern"),
    )
    path = tmp_path / "guardana-baseline.yaml"
    path.write_text(serialize_baseline(ScanResult((finding,), ("r",), ())), encoding="utf-8")

    restored = read_baseline(path)

    assert [w.fingerprint for w in restored.waivers] == [finding.fingerprint]
    assert restored.unreviewed, "a generated baseline is not usable as-is, and must say so"
