import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.formats import (
    STANDARD_ONNX_DOMAINS,
    FormatError,
    Limits,
    OnnxSummary,
    read_onnx_summary,
)
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, FileReader, Target, TargetKind
from guardana.core.taxonomy import (
    ATLAS_T0018,
    NIST_SUPPLY_CHAIN,
    OWASP_ASI05_2026,
    OWASP_LLM03_2025,
    OWASP_LLM04_2026,
    OWASP_LLM05_2025,
    OWASP_LLM10_2026,
)
from guardana.rules.prompt._injection_markers import has_smuggled_char
from guardana.rules.supply_chain._leads import lead_verdict

_RULE_ID = "guardana.supply_chain.onnx_graph"
_UNSCANNED_TITLE = "ONNX model not scanned"

# A large transformer export runs to tens of thousands of nodes, each with several
# fields, so the shared default budget would make honest models report as "not
# fully scanned". The walk only seeks and reads field headers, so a budget this
# size still bounds a crafted file to about a second.
_MAX_GRAPH_FIELDS = 1_000_000

# `external_data` names a file the loader opens relative to the model. A path
# that climbs out of that directory, or names an absolute one, is a read
# primitive pointed wherever the model author chose — there is nothing ambiguous
# about it, so it is a verdict rather than a lead.
_TRAVERSAL = re.compile(r"(^|[/\\])\.\.([/\\]|$)|^[/\\]|^~|^[A-Za-z]:[/\\]")
# ONNX metadata is free-form key/value text that tooling reads back and hubs
# render. A published proof of concept hides an obfuscated Python payload there.
_CODE_MARKER = re.compile(
    r"\b__import__\b|\bexec\s*\(|\beval\s*\(|\bos\.system\b|\bsubprocess\b|\bb64decode\b"
)


class OnnxGraphRule(Rule):
    """Flags ONNX models that need native code, read files outside themselves, or hide text.

    ONNX has no pickle in it, which is exactly why scanners skip it — and why
    three of its structural features are worth reading: a non-standard operator
    domain means a native library gets registered before inference, an
    `external_data` path is a file the loader opens, and `metadata_props` is
    free-form text that tooling reads back.
    """

    meta = RuleMeta(
        id=_RULE_ID,
        title="Risky construct in an ONNX model graph",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM03_2025,
            OWASP_LLM04_2026,
            OWASP_LLM05_2025,
            OWASP_LLM10_2026,
            ATLAS_T0018,
            NIST_SUPPLY_CHAIN,
            OWASP_ASI05_2026,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def __init__(self, *, max_entries: int = _MAX_GRAPH_FIELDS) -> None:
        self._limits = Limits(max_entries=max_entries)

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Walk every `.onnx` graph's structure without loading its weights."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files((".onnx",)):
            yield from self._scan(path)

    def _scan(self, path: Path) -> Iterator[Finding]:
        try:
            summary = read_onnx_summary(path, limits=self._limits)
        except FormatError as exc:
            yield self._unscanned(path, str(exc))
            return
        findings = list(self._graded(path, summary))
        yield from findings
        # A partial walk that found nothing has not cleared the model — it ran
        # out of budget before it finished looking.
        if summary.truncated and not findings:
            yield self._unscanned(path, "the graph was too large to walk within the field budget")

    def _graded(self, path: Path, summary: OnnxSummary) -> Iterator[Finding]:
        custom = sorted(
            {
                domain
                for domain in (*summary.node_domains, *summary.opset_domains)
                if domain not in STANDARD_ONNX_DOMAINS
            }
        )
        if custom:
            summary_text = (
                f"model declares operator domain(s) {', '.join(custom)} outside the standard set; "
                "running it requires registering a native operator library"
            )
            yield self._finding(path, Severity.MEDIUM, summary_text, lead=True)
        for location in summary.external_data_paths:
            if _TRAVERSAL.search(location):
                yield self._finding(
                    path,
                    Severity.HIGH,
                    f"external_data points outside the model directory: '{location}'",
                    lead=False,
                )
        yield from self._graded_metadata(path, summary)

    def _graded_metadata(self, path: Path, summary: OnnxSummary) -> Iterator[Finding]:
        for key, value in summary.metadata_props.items():
            if has_smuggled_char(key) or has_smuggled_char(value):
                yield self._finding(
                    path,
                    Severity.HIGH,
                    f"invisible instruction-smuggling character in metadata_props['{key}']",
                    lead=False,
                )
            elif _CODE_MARKER.search(value):
                yield self._finding(
                    path,
                    Severity.MEDIUM,
                    f"metadata_props['{key}'] reads like executable code, not description",
                    lead=True,
                )

    def _finding(self, path: Path, severity: Severity, summary: str, *, lead: bool) -> Finding:
        return Finding(
            rule_id=_RULE_ID,
            severity=severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(summary=summary, detail=f"file={path.name}"),
            verdict=lead_verdict(summary) if lead else None,
        )

    def _unscanned(self, path: Path, reason: str) -> Finding:
        return Finding(
            rule_id=_RULE_ID,
            severity=Severity.LOW,
            title=_UNSCANNED_TITLE,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=f"ONNX graph not scanned: {reason}",
                detail=f"file={path.name}",
            ),
            verdict=lead_verdict("the graph could not be walked, so nothing was cleared"),
        )
