"""No persisted schema ships without a gate that walks it in both directions.

Twelve versioned documents existed when the tenth audit started, and exactly one of
them had a round-trip gate. The other eleven were covered the way the failing one had
been: the writer's tests asserted what it wrote and the reader's asserted what it
read, both correct about their own half, neither able to see a field that fell
between them. Two defects were found that way in two consecutive releases, and a
third in the audit that wrote this file.

So the list is **read off the source**, not written here. A new
`*_SCHEMA_VERSION` constant is a new document somebody will keep, and it arrives
failing this test until its gate exists — which is the only version of this rule
that survives the release after the one that wrote it down.
"""

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_TESTS = "packages/{package}/tests/{module}"

GATED_BY: dict[str, str] = {
    "guardana.core.manifest.model.MANIFEST_SCHEMA_VERSION": _TESTS.format(
        package="guardana-core", module="test_manifest_round_trip.py"
    ),
    "guardana.core.report.run.REPORT_SCHEMA_VERSION": _TESTS.format(
        package="guardana-core", module="test_saved_run_round_trip.py"
    ),
    "guardana.core.reporter.ENVELOPE_SCHEMA_VERSION": _TESTS.format(
        package="guardana-server", module="test_envelope_round_trip.py"
    ),
    "guardana.server.envelope.SCHEMA_VERSION": _TESTS.format(
        package="guardana-server", module="test_envelope_round_trip.py"
    ),
    "guardana.core.trace.model.TRACE_SCHEMA_VERSION": _TESTS.format(
        package="guardana-core", module="trace/test_trace_round_trip.py"
    ),
    "guardana.core.trace.observations.OBSERVATIONS_SCHEMA_VERSION": _TESTS.format(
        package="guardana-core", module="test_hand_written_documents_are_read.py"
    ),
    "guardana.core.contract.model.CONTRACT_SCHEMA_VERSION": _TESTS.format(
        package="guardana-core", module="test_hand_written_documents_are_read.py"
    ),
    "guardana.core.pack.model.PACK_SCHEMA_VERSION": _TESTS.format(
        package="guardana-core", module="test_hand_written_documents_are_read.py"
    ),
    "guardana.core.pack.lock.LOCK_SCHEMA_VERSION": _TESTS.format(
        package="guardana-core", module="test_pack_lock.py"
    ),
    "guardana.core.calibration.store.STORE_SCHEMA_VERSION": _TESTS.format(
        package="guardana-core", module="calibration/test_store_round_trip.py"
    ),
    "guardana.core.diff.model.DIFF_SCHEMA_VERSION": _TESTS.format(
        package="guardana-core", module="test_write_only_documents_are_pinned.py"
    ),
    "guardana.cli.plan.PLAN_SCHEMA_VERSION": _TESTS.format(
        package="guardana-core", module="test_write_only_documents_are_pinned.py"
    ),
    "guardana.rules.agent.mcp_server_manifest.PIN_SCHEMA_VERSION": _TESTS.format(
        package="guardana-rules", module="agent/test_mcp_pin_round_trip.py"
    ),
    "guardana.rules.supply_chain._advisories.SCHEMA_VERSION": _TESTS.format(
        package="guardana-rules", module="supply_chain/test_advisory_document.py"
    ),
}
"""Which gate walks which document. The keys are checked against the source below.

A schema may share a gate with another — the collector envelope is one document
declared on both sides of a package boundary, and the three hand-written formats
answer one question — but no schema may be absent, and no gate may be a file that
does not exist.
"""


def _declared_schemas() -> dict[str, Path]:
    """Every module-level `*SCHEMA_VERSION` constant in the shipped source.

    Parsed rather than imported: an import list is a list, and this has to be an
    inventory. Anything assigned at module level whose name ends in
    `SCHEMA_VERSION` is a document version by this project's own convention.
    """
    found: dict[str, Path] = {}
    for package in sorted((_ROOT / "packages").glob("*/src")):
        for source in sorted(package.glob("guardana/**/*.py")):
            found.update(_constants_in(source, package))
    return found


def _constants_in(source: Path, package: Path) -> dict[str, Path]:
    """The `*SCHEMA_VERSION` names one module assigns at its top level."""
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    module = ".".join(source.relative_to(package).with_suffix("").parts)
    return {
        f"{module}.{target.id}": source
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name) and target.id.endswith("SCHEMA_VERSION")
    }


def test_every_versioned_document_in_the_source_has_a_round_trip_gate() -> None:
    ungated = sorted(set(_declared_schemas()) - set(GATED_BY))

    assert not ungated, (
        "persisted schemas with no gate that writes one, reads it back and deletes "
        "each key in turn — the shape of every document defect found in the last "
        "three audits:\n  " + "\n  ".join(ungated)
    )


def test_no_gate_is_claimed_for_a_schema_that_no_longer_exists() -> None:
    """The other direction: a gate left behind after its document was removed.

    An entry pointing at nothing reads as coverage, and the next person adding a
    schema copies the pattern from an entry that has not run in a year.
    """
    stale = sorted(set(GATED_BY) - set(_declared_schemas()))

    assert not stale, f"gates claimed for schema constants that no longer exist: {stale}"


def test_every_gate_named_here_is_a_file_that_exists() -> None:
    missing = sorted({path for path in GATED_BY.values() if not (_ROOT / path).is_file()})

    assert not missing, f"round-trip gates named in this table that do not exist: {missing}"
