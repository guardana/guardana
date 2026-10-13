from collections.abc import Iterable, Iterator

from guardana.core.report import Evidence, Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection
from guardana.core.severity import Severity
from guardana.core.source import PythonSource
from guardana.core.target import Capability, FileReader, Target, TargetKind
from guardana.core.taxonomy import (
    NIST_SUPPLY_CHAIN,
    OWASP_ASI05_2026,
    OWASP_LLM03_2025,
    OWASP_LLM04_2026,
)
from guardana.rules._base import ArtifactRule
from guardana.rules.supply_chain import _samples
from guardana.rules.supply_chain._code_sinks import code_sinks
from guardana.rules.supply_chain._leads import lead_verdict
from guardana.rules.supply_chain._unread_python import unread_python


class CodeExecutionRule(ArtifactRule):
    """Flags dynamic code / shell execution sinks (`eval`, `exec`, `os.system`, `shell=True`)."""

    meta = RuleMeta(
        id="guardana.supply_chain.code_execution",
        title="Dynamic code or shell execution sink",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM03_2025,
            OWASP_LLM04_2026,
            NIST_SUPPLY_CHAIN,
            OWASP_ASI05_2026,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
        detection=Detection.HEURISTIC,
    )

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a shell sink, an argument-list subprocess and a file the scan could not read."""
        return materialise(
            (
                _samples.sample(
                    "os.system running a command string",
                    FixtureOutcome.FINDING,
                    {"run.py": "import os\n\nos.system('id')\n"},
                ),
                _samples.sample(
                    "subprocess.run with an argument list",
                    FixtureOutcome.CLEAN,
                    {"run.py": "import subprocess\n\nsubprocess.run(['ls', '-l'], check=True)\n"},
                ),
                _samples.past_the_source_limit(
                    "a shell sink padded past the read limit, so nobody read it",
                    "run.py",
                    "import os\nos.system('id')\n",
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every `.py` file under the target for code-execution sinks."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files((".py",)):
            source = target.python_source(path)
            if source is None:
                yield from unread_python(self.meta, target, path, ctx)
            else:
                yield from self._scan(source)

    def _scan(self, source: PythonSource) -> Iterator[Finding]:
        path = source.path
        for lineno, why, lead in code_sinks(source):
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=f"{path}:{lineno}",
                evidence=Evidence(summary=why, detail=f"{path.name}:{lineno}"),
                verdict=lead_verdict(why) if lead else None,
            )
