import ast
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import NIST_SUPPLY_CHAIN, OWASP_LLM03
from guardana.rules.supply_chain._code_sinks import code_sinks
from guardana.rules.supply_chain._reading import read_text_bounded


class CodeExecutionRule(Rule):
    """Flags dynamic code / shell execution sinks (`eval`, `exec`, `os.system`, `shell=True`)."""

    meta = RuleMeta(
        id="guardana.supply_chain.code_execution",
        title="Dynamic code or shell execution sink",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM03, NIST_SUPPLY_CHAIN),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every `.py` file under the target for code-execution sinks."""
        if not isinstance(target, ArtifactTarget):
            return
        for path in target.iter_files((".py",)):
            yield from self._scan(path)

    def _scan(self, path: Path) -> Iterator[Finding]:
        source = read_text_bounded(path)
        if source is None:
            return
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return
        for lineno, why in code_sinks(tree):
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=f"{path}:{lineno}",
                evidence=Evidence(summary=why, detail=f"{path.name}:{lineno}"),
            )
