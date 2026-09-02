import ast
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.source import PythonSource
from guardana.core.target import Capability, FileReader, Target, TargetKind
from guardana.core.taxonomy import OWASP_LLM03_2025, OWASP_LLM04_2026
from guardana.rules._base import ArtifactRule
from guardana.rules.supply_chain._declared_deps import declared_import_names, normalize
from guardana.rules.supply_chain._known_packages import (
    KNOWN_DISTRIBUTIONS,
    installed_import_names,
)
from guardana.rules.supply_chain._leads import lead_verdict

_STDLIB = frozenset(sys.stdlib_module_names)


def _imports(source: PythonSource) -> Iterator[tuple[int, str]]:
    # Sorted by line because this reads two node types: the index orders each type
    # by position, but interleaving `import x` with `from y import z` is this
    # function's own job, and findings that jump around the file read as noise.
    found: list[tuple[int, str]] = [
        (node.lineno, alias.name.split(".")[0])
        for node in source.nodes(ast.Import)
        for alias in node.names
    ]
    found.extend(
        (node.lineno, node.module.split(".")[0])
        for node in source.nodes(ast.ImportFrom)
        if node.level == 0 and node.module
    )
    yield from sorted(found)


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


class HallucinatedPackageRule(ArtifactRule):
    """Flags an import of a package nobody has heard of — a slopsquat lead, not a verdict."""

    meta = RuleMeta(
        id="guardana.supply_chain.hallucinated_package",
        title="Import of unknown package (possible slopsquat lead)",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM03_2025,
            OWASP_LLM04_2026,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every `.py` file, treating the target's own modules as known."""
        if not isinstance(target, FileReader):
            return
        root = Path(target.ref)
        local = _local_modules(root)
        known = _STDLIB | KNOWN_DISTRIBUTIONS | installed_import_names() | local
        # The repo's own declared dependencies (requirements/pyproject), normalized —
        # so a real, in-requirements package is known even under an isolated install
        # where it isn't importable in Guardana's env.
        declared = declared_import_names(root)
        for path in target.iter_files((".py",)):
            source = target.python_source(path)
            if source is not None:
                yield from self._scan(source, known, declared)

    def _scan(
        self, source: PythonSource, known: frozenset[str], declared: frozenset[str]
    ) -> Iterator[Finding]:
        path = source.path
        for lineno, name in _imports(source):
            if name not in known and normalize(name) not in declared:
                yield Finding(
                    rule_id=self.meta.id,
                    severity=self.meta.severity,
                    title=self.meta.title,
                    taxonomy=self.meta.taxonomy,
                    target_ref=f"{path}:{lineno}",
                    evidence=Evidence(
                        summary=(
                            f"import '{name}' isn't a known package or a declared dependency "
                            f"— declare it in requirements/pyproject, or verify it exists on PyPI"
                        ),
                        detail=f"{path.name}:{lineno}",
                    ),
                    verdict=lead_verdict(
                        f"import '{name}' is not in Guardana's known packages nor the repo's "
                        f"declared dependencies; an undeclared-or-slopsquat lead, not a certainty"
                    ),
                )
