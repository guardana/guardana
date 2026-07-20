import ast
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import OWASP_LLM03
from guardana.rules.supply_chain._known_packages import (
    KNOWN_DISTRIBUTIONS,
    installed_import_names,
)
from guardana.rules.supply_chain._leads import lead_verdict
from guardana.rules.supply_chain._reading import read_text_bounded

_STDLIB = frozenset(sys.stdlib_module_names)


def _imports(tree: ast.AST) -> Iterator[tuple[int, str]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.lineno, node.module.split(".")[0]


def _iterdir(path: Path) -> tuple[Path, ...]:
    """List a directory, treating an unreadable one as empty.

    The scanned repo is untrusted input: an access error must skip the directory,
    never abort the whole scan.
    """
    try:
        return tuple(path.iterdir())
    except OSError:
        return ()


def _walk(root: Path) -> Iterator[Path]:
    pending = [root]
    while pending:
        for child in _iterdir(pending.pop()):
            yield child
            if child.is_dir() and not child.is_symlink():
                pending.append(child)


def _looks_like_package(children: tuple[Path, ...]) -> bool:
    """Report whether a dir holds a .py file, or a child dir does (namespace package)."""
    if any(child.suffix == ".py" for child in children if child.is_file()):
        return True
    return any(
        child.is_dir() and any(grandchild.suffix == ".py" for grandchild in _iterdir(child))
        for child in children
    )


def _local_modules(root: Path) -> frozenset[str]:
    names = set()
    for path in _walk(root):
        if path.suffix == ".py":
            names.add(path.stem)
        elif path.is_dir():
            children = _iterdir(path)
            if any(child.name == "__init__.py" for child in children):
                names.add(path.name)
            if path.name == "src":
                names.update(child.name for child in children if child.is_dir())
            elif _looks_like_package(children):
                names.add(path.name)
    return frozenset(names)


class HallucinatedPackageRule(Rule):
    """Flags an import of a package nobody has heard of — a slopsquat lead, not a verdict."""

    meta = RuleMeta(
        id="guardana.supply_chain.hallucinated_package",
        title="Import of unknown package (possible slopsquat lead)",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM03,),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every `.py` file, treating the target's own modules as known."""
        if not isinstance(target, ArtifactTarget):
            return
        local = _local_modules(Path(target.ref))
        known = _STDLIB | KNOWN_DISTRIBUTIONS | installed_import_names() | local
        for path in target.iter_files((".py",)):
            yield from self._scan(path, known)

    def _scan(self, path: Path, known: frozenset[str]) -> Iterator[Finding]:
        source = read_text_bounded(path)
        if source is None:
            return
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return
        for lineno, name in _imports(tree):
            if name not in known:
                yield Finding(
                    rule_id=self.meta.id,
                    severity=self.meta.severity,
                    title=self.meta.title,
                    taxonomy=self.meta.taxonomy,
                    target_ref=f"{path}:{lineno}",
                    evidence=Evidence(
                        summary=f"unknown import '{name}' (lead — verify it exists on PyPI)",
                        detail=f"{path.name}:{lineno}",
                    ),
                    verdict=lead_verdict(
                        f"unknown import '{name}'; a possible slopsquat, not a certainty"
                    ),
                )
