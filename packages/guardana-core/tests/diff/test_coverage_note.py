"""A comparison says when the two runs could check different things.

`rules_run` catches a rule that disappeared. It says nothing about a rule whose
corpus was trimmed, an evaluator that stopped being installed, a target that lost a
capability, or a server that answered with an older protocol revision — and every one
of those produces fewer findings, which subtracting two lists reads as a fix.

The fingerprint covers all of it in one value, and the note is deliberately three
outcomes rather than two: same reach, different reach, and **unknown** reach for a
run that recorded none. Reporting the third as the first is the false green.
"""

from datetime import UTC, datetime

from guardana.core.diff import compare_reports
from guardana.core.gate import GateOutcome
from guardana.core.manifest import RunManifest, TargetIdentity, ToolInfo
from guardana.core.manifest.coverage import CoverageRecord, TaxonomyCatalogRecord
from guardana.core.manifest.records import ResultSummary
from guardana.core.manifest.settings import ConfigurationRef, ExecutionSettings
from guardana.core.manifest.usage import RunUsage
from guardana.core.report import RunReport, ScanResult
from guardana.core.target import TargetKind

_RULE = "guardana.prompt.injection.ignore_previous"
_ENDPOINT = "http://x#m"


def _report(
    *,
    coverage: CoverageRecord,
    when: datetime,
    version: str = "0.13.0",
) -> RunReport:
    result = ScanResult(findings=(), rules_run=(_RULE,), rules_skipped=())
    return RunReport(
        manifest=RunManifest(
            run_id="r",
            created_at=when,
            started_at=when,
            completed_at=when,
            guardana=ToolInfo(version=version),
            target=TargetIdentity(kind=TargetKind.ENDPOINT, ref=_ENDPOINT),
            configuration=ConfigurationRef(profile_name="default"),
            execution=ExecutionSettings(concurrency=1, timeout_seconds=30),
            usage=RunUsage(),
            coverage=coverage,
            result_summary=ResultSummary(
                findings=0,
                unverified=0,
                waived=0,
                errors=0,
                observations=0,
                rules_run=(_RULE,),
                rules_skipped=(),
                max_severity=None,
                gate=GateOutcome.PASS,
            ),
        ),
        result=result,
    )


_FIRST = datetime(2026, 8, 1, tzinfo=UTC)
_SECOND = datetime(2026, 8, 2, tzinfo=UTC)
_CATALOGUE = TaxonomyCatalogRecord(framework="OWASP-LLM-2026", digest="sha256:aa", entries=10)


def _notes(before: CoverageRecord, after: CoverageRecord) -> tuple[str, ...]:
    return compare_reports(
        _report(coverage=before, when=_FIRST), _report(coverage=after, when=_SECOND)
    ).notes


def test_an_unchanged_fingerprint_says_nothing() -> None:
    same = CoverageRecord(digest="sha256:one", taxonomies=(_CATALOGUE,))

    assert _notes(same, same) == ()


def test_a_run_with_no_fingerprint_is_unknown_reach_not_equal_reach() -> None:
    # The 0.12-and-older case. "Nothing changed about coverage nobody measured" is
    # the sentence this project refuses to let a report make.
    notes = _notes(CoverageRecord(), CoverageRecord(digest="sha256:one"))

    assert any("unknown rather than settled" in note for note in notes)


def test_a_different_fingerprint_is_reported_as_a_difference_in_reach() -> None:
    notes = _notes(
        CoverageRecord(digest="sha256:one", taxonomies=(_CATALOGUE,)),
        CoverageRecord(digest="sha256:two", taxonomies=(_CATALOGUE,)),
    )

    assert any("did not have the same reach" in note for note in notes)
    # No detail to give: the catalogues and protocols match, so what moved is the
    # rules, their trials, the evaluators or the capabilities — all of which `diff`
    # already reports per rule. Repeating them in aggregate would be one finding twice.
    assert not any("catalogue(s)" in note for note in notes)


def test_a_changed_catalogue_edition_is_named() -> None:
    notes = _notes(
        CoverageRecord(digest="sha256:one", taxonomies=(_CATALOGUE,)),
        CoverageRecord(
            digest="sha256:two",
            taxonomies=(
                TaxonomyCatalogRecord(framework="OWASP-LLM-2026", digest="sha256:bb", entries=10),
            ),
        ),
    )

    assert any("framework catalogue(s) OWASP-LLM-2026 differ" in note for note in notes)


def test_a_catalogue_that_was_not_installed_before_is_named() -> None:
    notes = _notes(
        CoverageRecord(digest="sha256:one"),
        CoverageRecord(digest="sha256:two", taxonomies=(_CATALOGUE,)),
    )

    assert any("OWASP-LLM-2026" in note for note in notes)


def test_an_older_negotiated_protocol_is_named() -> None:
    notes = _notes(
        CoverageRecord(digest="sha256:one", protocols={"mcp": "2025-06-18"}),
        CoverageRecord(digest="sha256:two", protocols={"mcp": "2025-03-26"}),
    )

    assert any("negotiated protocols went from" in note for note in notes)


def test_a_digest_that_moved_across_a_version_boundary_is_not_blamed_on_the_rule() -> None:
    """Across builds, a digest moves when the rule changes *and* when the digest does.

    Removing the framework mapping from `Rule.digest()` was the second kind, and it
    moved every digest at once. A note asserting "19 rules changed definition" there
    is confidently wrong and buries the one rule whose corpus really moved.
    """
    before = _report(coverage=CoverageRecord(digest="d"), when=_FIRST, version="0.12.0")
    after = _report(coverage=CoverageRecord(digest="d"), when=_SECOND, version="0.13.0")
    manifest = before.manifest

    diff = compare_reports(
        RunReport(
            manifest=_with_rules(manifest, {_RULE: "old"}),
            result=before.result,
        ),
        RunReport(
            manifest=_with_rules(after.manifest, {_RULE: "new"}),
            result=after.result,
        ),
    )

    assert any("says nothing about either system" in note for note in diff.notes)
    assert not any("changed definition" in note for note in diff.notes)


def _with_rules(manifest: RunManifest, digests: dict[str, str]) -> RunManifest:
    from dataclasses import replace  # noqa: PLC0415 — local to this helper

    from guardana.core.manifest.records import RuleRecord  # noqa: PLC0415

    return replace(
        manifest, rules=tuple(RuleRecord(id=rid, digest=d) for rid, d in digests.items())
    )
