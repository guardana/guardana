"""A saved run is the document this project asks people to keep. It has to read back.

`--format json` writes it, `guardana diff` and `run inspect` read it, and the two
halves live in one package precisely so a field cannot be added on one side and go
unread on the other. That was an argument, not a gate; this is the gate.

The manifest half is pinned by `test_manifest_round_trip.py`. What is pinned here is
the part that is *not* the manifest: the five finding channels, the skips, the stop
reason and the coverage shortfall — the fields that decide whether a re-read run
still fails the way it failed when it was written.
"""

import json
from pathlib import Path

from _documents import run_manifest, scan_result
from _roundtrip import Document, lost_fields, undemonstrative_fields, unread_keys
from guardana.core.report.load import ReportLoadError, load_report
from guardana.core.report.run import RunReport
from guardana.core.report.serialize import run_to_dict

_NOT_DATA = frozenset({"run.$schema"})
"""The published schema's address: a pointer for a validator, not a value anybody reads.

Exempt because deleting it is *supposed* to change nothing about the run that comes
back — the document still means what it meant. Named here so a second key cannot
join it quietly, which is the only thing that keeps this exemption honest.
"""


def _read(document: Document, tmp: Path) -> RunReport:
    path = tmp / "run.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return load_report(path)


def test_every_channel_of_a_saved_run_survives_being_written_and_read_back(
    tmp_path: Path,
) -> None:
    result = scan_result()

    restored = _read(run_to_dict(result, run_manifest()), tmp_path)

    lost = lost_fields(result, restored.result, "result")
    assert not lost, "channels a saved run records and a reader never gets back:\n  " + "\n  ".join(
        lost
    )


def test_no_key_of_a_saved_run_can_be_deleted_without_the_reader_noticing(
    tmp_path: Path,
) -> None:
    """The mutation that stops the assertion above passing on both sides being empty.

    Compared against the whole document read back, never against the `ScanResult`
    that produced it — against the original, a key the reader ignores looks read,
    because the two differ for the deleted key's *neighbours*.
    """
    document = run_to_dict(scan_result(), run_manifest())

    ignored = unread_keys(
        document,
        lambda doc: _read(doc, tmp_path),
        root="run",
        refusal=ReportLoadError,
        exempt=_NOT_DATA,
    )

    assert not ignored, (
        "keys a saved run carries that make no difference to what is read back — "
        "either nothing reads them, or the fixture leaves them at the reader's default:\n  "
        + "\n  ".join(ignored)
    )


def test_the_fixture_occupies_every_channel_a_result_has() -> None:
    """What makes the two assertions above mean anything, and it is not decoration.

    An empty channel reads back as an empty channel whether or not a reader reads
    it. So a field added to `ScanResult` and left out of the fixture would sail
    through both gates above — a green result about something nobody examined,
    which is the failure those gates exist to catch, moved one level up.
    """
    empty = undemonstrative_fields(scan_result(), "result")

    assert not empty, f"channels the saved-run fixture leaves empty, so nothing is proved: {empty}"
