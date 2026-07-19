import ast
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import NIST_SUPPLY_CHAIN, OWASP_LLM03
from guardana.rules.supply_chain._reading import read_text_bounded

_SAFE_YAML_LOADERS = frozenset({"SafeLoader", "CSafeLoader"})

# `yaml.load(stream, Loader)` — the loader is the second positional parameter,
# and passing it positionally is legal, so a keyword-only check would report a
# false positive on already-safe code.
_YAML_LOADER_ARG_COUNT = 2

# Loaders that deserialize arbitrary Python — pickle and its ecosystem wrappers.
# Any call to one of these on untrusted data is code execution on load, with no
# safe-mode argument to check, so the call itself is the finding. Matched by
# dotted name (`joblib.load`, not an aliased `jl.load`) — see the rule's
# known alias limitation.
_PICKLE_FAMILY_LOADERS = frozenset(
    {"pickle.load", "pickle.loads", "joblib.load", "dill.load", "dill.loads", "pandas.read_pickle"}
)


def _dotted_call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
        return f"{f.value.id}.{f.attr}"
    if isinstance(f, ast.Name):
        return f.id
    return ""


def _has_kw(node: ast.Call, name: str, want: object) -> bool:
    return any(
        kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value == want
        for kw in node.keywords
    )


def _yaml_loader_arg(node: ast.Call) -> ast.expr | None:
    """Return the Loader passed to `yaml.load`, whether by keyword or positionally."""
    for kw in node.keywords:
        if kw.arg == "Loader":
            return kw.value
    if len(node.args) >= _YAML_LOADER_ARG_COUNT:
        return node.args[1]
    return None


def _yaml_loader_is_safe(node: ast.Call) -> bool:
    loader = _yaml_loader_arg(node)
    if isinstance(loader, ast.Attribute):
        return loader.attr in _SAFE_YAML_LOADERS
    if isinstance(loader, ast.Name):
        return loader.id in _SAFE_YAML_LOADERS
    return False


def _sinks(tree: ast.AST) -> Iterator[tuple[int, str]]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted_call_name(node)
        if name in _PICKLE_FAMILY_LOADERS:
            yield node.lineno, f"{name} on possibly-untrusted data"
        elif name == "torch.load" and not _has_kw(node, "weights_only", True):
            yield node.lineno, "torch.load without weights_only=True"
        elif name == "yaml.load" and not _yaml_loader_is_safe(node):
            yield node.lineno, "yaml.load without SafeLoader"
        elif name == "numpy.load" and _has_kw(node, "allow_pickle", True):
            # numpy.load defaults to allow_pickle=False; the True override is the
            # classic ML pickle-RCE vector (a crafted .npy runs code on load).
            yield node.lineno, "numpy.load with allow_pickle=True on possibly-untrusted data"


class DependencyRiskRule(Rule):
    """Flags calls that deserialize untrusted data (pickle family, `torch.load`, `yaml.load`)."""

    meta = RuleMeta(
        id="guardana.supply_chain.dependency_risk",
        title="Unsafe model/deserialization loader call",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM03, NIST_SUPPLY_CHAIN),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every `.py` file under the target for deserialization sinks."""
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
        for lineno, message in _sinks(tree):
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=f"{path}:{lineno}",
                evidence=Evidence(summary=message, detail=f"{path.name}:{lineno}"),
            )
