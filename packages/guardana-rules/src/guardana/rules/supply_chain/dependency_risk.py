import ast
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import NIST_SUPPLY_CHAIN, OWASP_LLM03
from guardana.rules.supply_chain._ast_names import import_aliases, resolved_call_name
from guardana.rules.supply_chain._reading import read_text_bounded

_SAFE_YAML_LOADERS = frozenset({"SafeLoader", "CSafeLoader"})

# `yaml.load(stream, Loader)` — the loader is the second positional parameter,
# and passing it positionally is legal, so a keyword-only check would report a
# false positive on already-safe code.
_YAML_LOADER_ARG_COUNT = 2

# A sentinel distinct from any real keyword value (including None/True/False), so
# "argument absent" and "argument set to False" are told apart — they carry
# different messages for torch.load.
_MISSING = object()

# Loaders that deserialize arbitrary Python — pickle and its ecosystem wrappers.
# Any call to one of these on untrusted data is code execution on load, with no
# safe-mode argument to check, so the call itself is the finding. Resolved through
# import aliases, so `import joblib as jl; jl.load(...)` is caught too.
_PICKLE_FAMILY_LOADERS = frozenset(
    {"pickle.load", "pickle.loads", "joblib.load", "dill.load", "dill.loads", "pandas.read_pickle"}
)


def _kw_constant(node: ast.Call, name: str) -> object:
    for kw in node.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant):
            return kw.value.value
    return _MISSING


def _yaml_loader_arg(node: ast.Call) -> ast.expr | None:
    """Return the Loader passed to `yaml.load`, whether by keyword or positionally."""
    for kw in node.keywords:
        if kw.arg == "Loader":
            return kw.value
    if len(node.args) >= _YAML_LOADER_ARG_COUNT:
        return node.args[1]
    return None


def _yaml_loader_name(node: ast.Call) -> str | None:
    loader = _yaml_loader_arg(node)
    if isinstance(loader, ast.Attribute):
        return loader.attr
    if isinstance(loader, ast.Name):
        return loader.id
    return None


def _torch_load_finding(node: ast.Call) -> tuple[str, Severity] | None:
    weights_only = _kw_constant(node, "weights_only")
    if weights_only is True:
        return None
    if weights_only is False:
        return "torch.load with weights_only=False (executes pickle on load)", Severity.HIGH
    return "torch.load without weights_only=True", Severity.HIGH


def _yaml_load_finding(node: ast.Call) -> tuple[str, Severity] | None:
    name = _yaml_loader_name(node)
    if name in _SAFE_YAML_LOADERS:
        return None
    if name == "FullLoader":
        # FullLoader blocks arbitrary object construction (what yaml.full_load
        # uses) — materially safer than Loader/UnsafeLoader, so a lower-severity
        # note rather than the HIGH the unrestricted loaders earn.
        return (
            "yaml.load with Loader=FullLoader (safer than Loader, still avoid on untrusted input)",
            Severity.MEDIUM,
        )
    shown = f"Loader={name}" if name else "no safe Loader"
    return f"yaml.load with {shown}", Severity.HIGH


def _sinks(tree: ast.AST) -> Iterator[tuple[int, str, Severity]]:
    aliases = import_aliases(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = resolved_call_name(node, aliases)
        if name in _PICKLE_FAMILY_LOADERS:
            yield node.lineno, f"{name} on possibly-untrusted data", Severity.HIGH
        elif name == "torch.load":
            torch_finding = _torch_load_finding(node)
            if torch_finding is not None:
                yield node.lineno, torch_finding[0], torch_finding[1]
        elif name == "yaml.load":
            yaml_finding = _yaml_load_finding(node)
            if yaml_finding is not None:
                yield node.lineno, yaml_finding[0], yaml_finding[1]
        elif name == "numpy.load" and _kw_constant(node, "allow_pickle") is True:
            # numpy.load defaults to allow_pickle=False; the True override is the
            # classic ML pickle-RCE vector (a crafted .npy runs code on load).
            yield (
                node.lineno,
                "numpy.load with allow_pickle=True on possibly-untrusted data",
                Severity.HIGH,
            )


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
        for lineno, message, severity in _sinks(tree):
            yield Finding(
                rule_id=self.meta.id,
                severity=severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=f"{path}:{lineno}",
                evidence=Evidence(summary=message, detail=f"{path.name}:{lineno}"),
            )
