import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.evaluator import Verdict
from guardana.core.formats import FormatError, read_gguf_metadata
from guardana.core.report import Evidence, Finding
from guardana.core.rule import FixtureOutcome, Rule, RuleContext, RuleError, RuleFixture, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.target.protocols import FileReader
from guardana.core.taxonomy import OWASP_LLM03_2025, OWASP_LLM04_2026
from guardana.core.testing import build_gguf

# Acme's policy: a GGUF model may only be served if its embedded provenance says
# it came from a team we vetted. This is org policy, not a universal threat, which
# is exactly the kind of check that belongs in your own pack rather than upstream.
_APPROVED_ORGANIZATIONS = frozenset({"acme-ml", "acme-research"})
_ORGANIZATION_KEY = "general.organization"
_NAME_KEY = "general.name"


class ApprovedModelRule(Rule):
    """Flags a GGUF model whose embedded provenance is not on Acme's approved list.

    The whole rule is policy: `guardana.core.formats` does the binary parsing,
    bounded and fail-closed, so this file never touches a byte offset. That is
    the division of labour a third-party pack should expect — you bring the
    judgement, the engine brings the plumbing.
    """

    meta = RuleMeta(
        id="acme.supply_chain.approved_model",
        title="GGUF model is not from an approved organization",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM03_2025,
            OWASP_LLM04_2026,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Check the provenance metadata of every GGUF model under the target."""
        if not isinstance(target, FileReader):
            raise RuleError(f"{self.meta.id} needs a file target, got {type(target).__name__}")
        for path in target.iter_files((".gguf",)):
            yield from self._scan(path)

    def _scan(self, path: Path) -> Iterator[Finding]:
        try:
            metadata = read_gguf_metadata(path)
        except FormatError as exc:
            # Unreadable provenance is a decline, not an accusation: we never
            # established which organization this model came from, so reporting
            # it as unapproved would invent evidence — the fail-open this project
            # exists to avoid runs the other way too.
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=str(path),
                evidence=Evidence(
                    summary=f"provenance unreadable: {exc}", detail=f"file={path.name}"
                ),
                verdict=Verdict("inconclusive", 0.0, f"provenance unreadable: {exc}", self.meta.id),
            )
            return
        organization = metadata.text(_ORGANIZATION_KEY)
        if organization is None or organization.lower() not in _APPROVED_ORGANIZATIONS:
            name = metadata.text(_NAME_KEY) or path.name
            yield self._finding(path, f"'{name}' declares organization {organization!r}")

    def _finding(self, path: Path, summary: str) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=f"model is not from an approved organization — {summary}",
                detail=f"file={path.name}; approved={sorted(_APPROVED_ORGANIZATIONS)}",
            ),
        )

    def fixtures(self) -> Iterable[RuleFixture]:
        """Three samples: an unapproved organization, an approved one, and unparseable bytes."""
        root = Path(tempfile.mkdtemp(prefix="acme-fixture-"))
        (root / "finding").mkdir()
        (root / "finding" / "model.gguf").write_bytes(
            build_gguf({"general.organization": "unknown-org"})
        )
        (root / "clean").mkdir()
        (root / "clean" / "model.gguf").write_bytes(build_gguf({"general.organization": "acme-ml"}))
        (root / "inconclusive").mkdir()
        # Five junk bytes fail the GGUF magic-number check before any organization
        # field is even reached, so read_gguf_metadata raises FormatError — verified
        # in this fixture's own run rather than assumed.
        (root / "inconclusive" / "model.gguf").write_bytes(b"\x00\x01\x02\x03\x04")
        return (
            RuleFixture(
                "a model from an unapproved organization",
                ArtifactTarget(root / "finding"),
                FixtureOutcome.FINDING,
            ),
            RuleFixture(
                "a model from an approved organization",
                ArtifactTarget(root / "clean"),
                FixtureOutcome.CLEAN,
            ),
            RuleFixture(
                "a file that is not a well-formed GGUF",
                ArtifactTarget(root / "inconclusive"),
                FixtureOutcome.INCONCLUSIVE,
                note="five junk bytes fail the magic-number check before any field is read",
            ),
        )
