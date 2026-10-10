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
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection
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
from guardana.core.testing import build_onnx
from guardana.rules._base import ArtifactRule
from guardana.rules.prompt._injection_markers import has_smuggled_char
from guardana.rules.supply_chain import _samples
from guardana.rules.supply_chain._leads import lead_verdict, unread_component, unscanned_verdict
from guardana.rules.supply_chain._reading import read_model

_RULE_ID = "guardana.supply_chain.onnx_graph"
_UNSCANNED_TITLE = "ONNX model not scanned"

# The default field budget is one field per two bytes of the file, between a floor and
# a cap. Every protobuf field takes at least two bytes on the wire (a tag, then a value
# or a length) and the walk reads each field once, so below the cap no file runs out.
_MAX_GRAPH_FIELDS = 1_000_000
# Honest graphs spend fields on structure and weights are single large fields, so this
# is far beyond any honest graph while bounding what a crafted file can cost.
_GRAPH_FIELDS_CAP = 8_000_000
_MIN_FIELD_BYTES = 2

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


class OnnxGraphRule(ArtifactRule):
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
        detection=Detection.HEURISTIC,
    )

    def __init__(self, *, max_entries: int | None = None) -> None:
        """Use a fixed field budget of `max_entries`; by default it grows with each file."""
        self._max_entries = max_entries

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample external data outside the model, a standard graph and a model cut short."""
        return materialise(
            (
                _samples.sample(
                    "external_data climbing out of the model directory",
                    FixtureOutcome.FINDING,
                    {
                        "model.onnx": build_onnx(
                            nodes=(("Conv", ""),), external_paths=("../../etc/passwd",)
                        )
                    },
                ),
                _samples.sample(
                    "a graph of standard operators with its data inline",
                    FixtureOutcome.CLEAN,
                    {
                        "model.onnx": build_onnx(
                            nodes=(("Conv", ""), ("Relu", "")), producer="pytorch"
                        )
                    },
                ),
                _samples.sample(
                    "a model cut off inside its graph",
                    FixtureOutcome.INCONCLUSIVE,
                    {"model.onnx": build_onnx(nodes=(("Conv", ""),), producer="pytorch")[:-3]},
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Walk every `.onnx` graph's structure without loading its weights."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files((".onnx",)):
            yield from self._scan(path, ctx)
            ctx.examined(path)

    def _scan(self, path: Path, ctx: RuleContext) -> Iterator[Finding]:
        try:
            summary = read_model(
                read_onnx_summary, path, limits=Limits(max_entries=self._budget(path))
            )
        except FormatError as exc:
            yield self._unscanned(path, str(exc), ctx)
            return
        yield from self._graded(path, summary)
        # A partial walk has not cleared the model, whatever it found: a lead in the
        # fields it reached says nothing about a worse one past the budget.
        if summary.truncated:
            yield self._unscanned(
                path, "the model was too large or nested too deeply to walk in full", ctx
            )

    def _budget(self, path: Path) -> int:
        if self._max_entries is not None:
            return self._max_entries
        try:
            size = path.stat().st_size
        except OSError:
            return _MAX_GRAPH_FIELDS
        return max(_MAX_GRAPH_FIELDS, min(size // _MIN_FIELD_BYTES, _GRAPH_FIELDS_CAP))

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

    def _unscanned(self, path: Path, reason: str, ctx: RuleContext) -> Finding:
        ctx.shortfall(unread_component(_RULE_ID, path, reason))
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
            verdict=unscanned_verdict("the graph could not be walked, so nothing was cleared"),
        )
