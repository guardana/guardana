import ast
from collections.abc import Iterable, Iterator

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.source import PythonSource
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import NIST_SUPPLY_CHAIN, OWASP_ASI05, OWASP_LLM03

# `trust_remote_code=True` tells transformers / datasets to import and run code
# that ships inside a Hub repo — arbitrary code execution at load time, and the
# single most common RCE vector for a downloaded model. The keyword name is
# specific to that ecosystem, so matching it by name is precise, not heuristic.
_FLAG = "trust_remote_code"


def _trust_remote_code_true(node: ast.Call) -> bool:
    return any(
        kw.arg == _FLAG and isinstance(kw.value, ast.Constant) and kw.value.value is True
        for kw in node.keywords
    )


def _is_hub_load(node: ast.Call) -> bool:
    """Whether the call is `*.hub.load(...)` — `torch.hub.load` runs `hubconf.py`.

    `torch.hub.load("owner/repo", ...)` downloads a GitHub repo and executes its
    `hubconf.py` at load time: arbitrary code, exactly like `trust_remote_code`,
    but a call rather than a flag. The `hub.load` attribute chain is specific
    enough to match by name without false positives.
    """
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "load"
        and isinstance(func.value, ast.Attribute)
        and func.value.attr == "hub"
    )


def _remote_code_calls(source: PythonSource) -> Iterator[tuple[int, str]]:
    for node in source.nodes(ast.Call):
        if _trust_remote_code_true(node):
            yield node.lineno, f"{_FLAG}=True runs code from the repo (arbitrary code on load)"
        elif _is_hub_load(node):
            yield (
                node.lineno,
                "torch.hub.load(...) downloads and runs hubconf.py from a remote repo",
            )


class RemoteCodeRule(Rule):
    """Flags `trust_remote_code=True`, which executes code shipped in a model/dataset repo."""

    meta = RuleMeta(
        id="guardana.supply_chain.remote_code",
        title="Remote code execution enabled on model/dataset load",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM03,
            NIST_SUPPLY_CHAIN,
            OWASP_ASI05,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every `.py` file under the target for `trust_remote_code=True`."""
        if not isinstance(target, ArtifactTarget):
            return
        for path in target.iter_files((".py",)):
            source = target.python_source(path)
            if source is not None:
                yield from self._scan(source)

    def _scan(self, source: PythonSource) -> Iterator[Finding]:
        path = source.path
        for lineno, summary in _remote_code_calls(source):
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=f"{path}:{lineno}",
                evidence=Evidence(summary=summary, detail=f"{path.name}:{lineno}"),
            )
