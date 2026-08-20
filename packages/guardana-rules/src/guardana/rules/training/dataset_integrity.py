import ast
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.source import PythonSource
from guardana.core.target import Capability, FileReader, Target, TargetKind
from guardana.core.taxonomy import (
    NIST_POISONING,
    OWASP_LLM04_2025,
    OWASP_LLM05_2026,
    OWASP_ML02_2023,
)
from guardana.rules.supply_chain._leads import lead_verdict

# A dataset "loading script" is a Python class the datasets library imports and
# runs to produce examples — arbitrary code that executes while you are "just
# loading data", and a poisoning/RCE surface distinct from the model weights.
# These base classes are specific to Hugging Face `datasets`, so matching them by
# name is precise, not heuristic.
_BUILDER_BASES = frozenset(
    {"GeneratorBasedBuilder", "ArrowBasedBuilder", "BeamBasedBuilder", "DatasetBuilder"}
)


def _base_name(base: ast.expr) -> str:
    if isinstance(base, ast.Attribute):
        return base.attr
    if isinstance(base, ast.Name):
        return base.id
    return ""


def _loader_script_lines(source: PythonSource) -> Iterator[int]:
    for node in source.nodes(ast.ClassDef):
        if any(_base_name(base) in _BUILDER_BASES for base in node.bases):
            yield node.lineno


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _unpinned_load_lines(source: PythonSource) -> Iterator[int]:
    for node in source.nodes(ast.Call):
        if _call_name(node) == "load_dataset" and not any(
            kw.arg == "revision" for kw in node.keywords
        ):
            yield node.lineno


class DatasetIntegrityRule(Rule):
    """Flags training-data hygiene gaps: dataset loading scripts and unpinned dataset pulls.

    Static poisoning *proof* is statistical, not a file scan — this rule instead
    surfaces the two hygiene gaps that make data poisoning possible and that are
    deterministically detectable: a dataset that runs code on load, and a dataset
    pulled from a mutable, unpinned source that can be swapped under you. Both are
    reported as leads, never as a confident poisoning verdict.
    """

    meta = RuleMeta(
        id="guardana.training.dataset_integrity",
        title="Training-data integrity gap (loader script or unpinned dataset)",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM04_2025,
            OWASP_LLM05_2026,
            OWASP_ML02_2023,
            NIST_POISONING,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every `.py` file for dataset loader scripts and unpinned dataset loads."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files((".py",)):
            source = target.python_source(path)
            if source is not None:
                yield from self._scan(source)

    def _scan(self, source: PythonSource) -> Iterator[Finding]:
        path = source.path
        for lineno in _loader_script_lines(source):
            yield self._lead(
                path,
                lineno,
                Severity.MEDIUM,
                "dataset loading script runs code on load (poisoning/RCE surface)",
            )
        for lineno in _unpinned_load_lines(source):
            # LOW on purpose: an unpinned `load_dataset(...)` is in nearly every
            # tutorial and repo, so this is an honest hygiene nudge, never a gate.
            yield self._lead(
                path,
                lineno,
                Severity.LOW,
                "load_dataset() without revision= — training data source can be swapped",
            )

    def _lead(self, path: Path, lineno: int, severity: Severity, summary: str) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=f"{path}:{lineno}",
            evidence=Evidence(summary=summary, detail=f"{path.name}:{lineno}"),
            verdict=lead_verdict(summary),
        )
