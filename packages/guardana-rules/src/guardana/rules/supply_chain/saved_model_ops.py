from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import ATLAS_T0018, NIST_SUPPLY_CHAIN, OWASP_LLM05, OWASP_ML06
from guardana.rules.supply_chain._leads import lead_verdict

# TensorFlow SavedModel graph operators that touch the filesystem on model load.
# In a serialized GraphDef these op types appear verbatim as ASCII, so a bounded
# bytes-scan surfaces them without deserializing (and without ever running the
# graph). They have legitimate uses in data pipelines, so this is a lead — a
# `WriteFile` that rewrites `~/.ssh/authorized_keys` looks the same at the byte
# level as a benign checkpoint write. Argument evaluation (the follow-on) needs
# a protobuf parser; presence alone is the first-pass signal.
_FILESYSTEM_OPS = (b"ReadFile", b"WriteFile")
_MAX_SCAN_BYTES = 64 * 1024 * 1024


class SavedModelOpsRule(Rule):
    """Flag filesystem operators (`ReadFile`/`WriteFile`) in a TensorFlow SavedModel graph."""

    meta = RuleMeta(
        id="guardana.supply_chain.saved_model_ops",
        title="TensorFlow SavedModel filesystem operator",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM05, OWASP_ML06, ATLAS_T0018, NIST_SUPPLY_CHAIN),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Bytes-scan every `.pb` graph for filesystem operators."""
        if not isinstance(target, ArtifactTarget):
            return
        for path in target.iter_files((".pb",)):
            yield from self._scan(path)

    def _scan(self, path: Path) -> Iterator[Finding]:
        try:
            with path.open("rb") as handle:
                data = handle.read(_MAX_SCAN_BYTES)
        except OSError:
            return
        for op in _FILESYSTEM_OPS:
            if op in data:
                name = op.decode()
                yield Finding(
                    rule_id=self.meta.id,
                    severity=self.meta.severity,
                    title=self.meta.title,
                    taxonomy=self.meta.taxonomy,
                    target_ref=str(path),
                    evidence=Evidence(
                        summary=f"{name} filesystem op in SavedModel graph (load-time file I/O)",
                        detail=f"file={path.name}",
                    ),
                    verdict=lead_verdict(
                        f"{name} op present; legitimate in data pipelines, so a lead, not a verdict"
                    ),
                )
