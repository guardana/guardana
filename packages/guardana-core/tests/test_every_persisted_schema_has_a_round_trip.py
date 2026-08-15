"""No persisted schema ships without a gate that walks it in both directions.

Twelve versioned documents existed when the tenth audit started, and exactly one of
them had a round-trip gate. The other eleven were covered the way the failing one had
been: the writer's tests asserted what it wrote and the reader's asserted what it
read, both correct about their own half, neither able to see a field that fell
between them. Two defects were found that way in two consecutive releases, and a
third in the audit that wrote this file.

So the list is **read off the source**, not written here. A new version constant is
a new document somebody will keep, and it arrives failing this test until its gate
exists — which is the only version of this rule that survives the release after the
one that wrote it down.

**And the inventory rule is a name, so the name is where it leaked.** This asked
about constants ending in `SCHEMA_VERSION`, and the baseline — the one document
whose entire job is to stop a gate firing — calls its constant `BASELINE_VERSION`
and was invisible here for four releases, while the 1.0 entry criteria named it as
a published schema in writing. So the question is now every module-level `*VERSION`
constant, and the answer for each is either a round-trip gate or an entry in
`NOT_A_DOCUMENT` with the reason. Classifying it is a person's job; noticing it is
not.
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
    "guardana.core.report.baseline.BASELINE_VERSION": _TESTS.format(
        package="guardana-core", module="report/test_baseline_round_trip.py"
    ),
}
"""Which gate walks which document. The keys are checked against the source below.

A schema may share a gate with another — the collector envelope is one document
declared on both sides of a package boundary, and the three hand-written formats
answer one question — but no schema may be absent, and no gate may be a file that
does not exist.
"""

NOT_A_DOCUMENT: dict[str, str] = {
    "guardana.core.pack.model.EXTENSION_API_VERSION": (
        "the version of the Rule/Evaluator/Target contract this build implements — a "
        "property of the code, not of a file anybody keeps"
    ),
    "guardana.core.target._mcp_wire.LATEST_VERSION": "an MCP protocol revision the other end names",
    "guardana.core.target._mcp_wire.LEGACY_VERSION": "an MCP protocol revision the other end names",
    "guardana.core.target._mcp_wire.META_PROTOCOL_VERSION": "the name of an MCP metadata key",
    "guardana.core.target._mcp_wire.UNSUPPORTED_PROTOCOL_VERSION": "a JSON-RPC error code",
    "guardana.core.formats.gguf._MIN_VERSION": (
        "the oldest GGUF container this reader parses — somebody else's format, which "
        "Guardana reads and never writes"
    ),
    "guardana.cli._evaluators._DEFAULT_PROMPT_VERSION": (
        "which judge prompt a run used, recorded inside the run manifest, which has its own gate"
    ),
    "guardana.rules.supply_chain._advisories._ANY_VERSION": "a glob meaning every package version",
    "guardana.rules.supply_chain.malicious_dependency._ANY_VERSION": (
        "a glob meaning every package version"
    ),
    "guardana.rules.supply_chain.malicious_dependency._LOCK_VERSION": (
        "a regex that reads a version out of somebody else's lock file"
    ),
}
"""`*VERSION` constants that are not a document Guardana persists, and why.

Every one of these was classified by hand, which is the point: a new constant lands
in neither table and fails the test below until somebody decides which it is. The
cost of being wrong is not symmetric — a document misfiled here loses its gate
silently, and a non-document misfiled above costs one line of prose.
"""


def _declared_versions() -> dict[str, Path]:
    """Every module-level `*VERSION` constant in the shipped source.

    Parsed rather than imported: an import list is a list, and this has to be an
    inventory. Deliberately wider than "looks like a schema": the constant that
    escaped this gate was named for its document rather than for the word `schema`,
    so the test asks about all of them and makes a person say which are documents.
    """
    found: dict[str, Path] = {}
    for package in sorted((_ROOT / "packages").glob("*/src")):
        for source in sorted(package.glob("guardana/**/*.py")):
            found.update(_constants_in(source, package))
    return found


def _constants_in(source: Path, package: Path) -> dict[str, Path]:
    """The `*VERSION` names one module assigns at its top level.

    A plural (`SUPPORTED_VERSIONS`) is a set of versions this build accepts and a
    `*_VERSION_KEY` is the name of a field, so neither ends in `VERSION` and neither
    needs classifying.
    """
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    module = ".".join(source.relative_to(package).with_suffix("").parts)
    return {
        f"{module}.{target.id}": source
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name) and target.id.endswith("VERSION")
    }


def test_every_versioned_document_in_the_source_has_a_round_trip_gate() -> None:
    unclassified = sorted(set(_declared_versions()) - set(GATED_BY) - set(NOT_A_DOCUMENT))

    assert not unclassified, (
        "version constants that are neither gated by a test that writes the document, "
        "reads it back and deletes each key in turn, nor recorded in NOT_A_DOCUMENT "
        "with a reason. The first is the shape of every document defect found in the "
        "last four audits; the second costs one line:\n  " + "\n  ".join(unclassified)
    )


def test_no_constant_is_classified_twice() -> None:
    """A document cannot also be "not a document", and the tables must not disagree."""
    both = sorted(set(GATED_BY) & set(NOT_A_DOCUMENT))

    assert not both, f"constants claimed as both gated and not a document: {both}"


def test_no_gate_is_claimed_for_a_schema_that_no_longer_exists() -> None:
    """The other direction: a gate left behind after its document was removed.

    An entry pointing at nothing reads as coverage, and the next person adding a
    schema copies the pattern from an entry that has not run in a year.
    """
    declared = set(_declared_versions())
    stale = sorted((set(GATED_BY) | set(NOT_A_DOCUMENT)) - declared)

    assert not stale, f"entries claimed for version constants that no longer exist: {stale}"


def test_every_gate_named_here_is_a_file_that_exists() -> None:
    missing = sorted({path for path in GATED_BY.values() if not (_ROOT / path).is_file()})

    assert not missing, f"round-trip gates named in this table that do not exist: {missing}"
