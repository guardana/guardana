"""`severity_conditions.yaml` names every non-default severity the rule code can emit, and no other.

The catalog's "Other finding severities" table is rendered from that file, so a
severity a rule starts emitting without an entry would be a finding the documentation
never mentions. The code side is read from source: the `Severity.<NAME>` literals in
each rule's own module, its base classes in `guardana.rules`, and the private helper
modules those import, plus the few severities a rule takes from somewhere other than a
literal, declared below with the reason.
"""

import ast
import importlib.util
import inspect
import re
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from guardana.core.rule import Rule
from guardana.core.severity import Severity
from guardana.rules import provide_rules
from guardana.rules.supply_chain._advisories import load_advisories
from guardana.rules.supply_chain.saved_model_ops import SavedModelOpsRule

import generate_docs

_RULES_PACKAGE = "guardana.rules"


def _advisory_severities() -> set[Severity]:
    return {advisory.severity for advisory in load_advisories()}


def _saved_model_ops_default() -> set[Severity]:
    return {SavedModelOpsRule.meta.severity}


_INDIRECT: dict[str, tuple[str, Callable[[], set[Severity]]]] = {
    # An advisory match carries the advisory's own severity from the bundled dataset.
    "guardana.supply_chain.malicious_dependency": ("advisory.severity", _advisory_severities),
    # A vocabulary read from outside the model is the lead `saved_model_ops` reports.
    "guardana.supply_chain.keras_lambda": (
        "SavedModelOpsRule.meta.severity",
        _saved_model_ops_default,
    ),
}
"""Rule id -> (the expression in its module that names the source, the severities it yields)."""


def _rules() -> list[Rule]:
    return sorted(provide_rules(), key=lambda rule: rule.meta.id)


def _is_private(module: str) -> bool:
    return any(part.startswith("_") for part in module.split(".")[2:])


def _origin(module: str) -> Path | None:
    try:
        spec = importlib.util.find_spec(module)
    except (ModuleNotFoundError, ValueError):
        return None
    if spec is None or spec.origin is None or not spec.origin.endswith(".py"):
        return None
    return Path(spec.origin)


def _imported(tree: ast.Module, module: str) -> Iterator[str]:
    """Yield every module name an import in `tree` could refer to, submodules included."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            package = module if node.level == 0 else module.rsplit(".", node.level)[0]
            base = node.module or ""
            if node.level:
                base = f"{package}.{base}" if base else package
            yield base
            yield from (f"{base}.{alias.name}" for alias in node.names)


def _defining_file(kind: type[Rule]) -> Path:
    source = inspect.getsourcefile(kind)
    if source is None:
        raise AssertionError(f"{kind.__qualname__} has no source file to read")
    return Path(source)


def _sources(rule: Rule) -> dict[str, ast.Module]:
    """Parse the rule's defining module, its `guardana.rules` bases and their private helpers."""
    kind = type(rule)
    pending = {kind.__module__}
    pending |= {
        base.__module__ for base in kind.__mro__ if base.__module__.startswith(f"{_RULES_PACKAGE}.")
    }
    parsed: dict[str, ast.Module] = {}
    while pending:
        module = pending.pop()
        path = _defining_file(kind) if module == kind.__module__ else _origin(module)
        if module in parsed or path is None:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parsed[module] = tree
        pending |= {
            name
            for name in _imported(tree, module)
            if name.startswith(f"{_RULES_PACKAGE}.") and _is_private(name) and name not in parsed
        }
    return parsed


def _literals(tree: ast.Module) -> set[Severity]:
    return {
        Severity[node.attr]
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "Severity"
        and node.attr in Severity.__members__
    }


def _dynamic(tree: ast.Module) -> list[str]:
    """Name each expression that picks a severity at run time rather than spelling it."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript | ast.Call):
            target = node.value if isinstance(node, ast.Subscript) else node.func
            if isinstance(target, ast.Name) and target.id == "Severity":
                found.append(ast.unparse(node))
        elif (
            isinstance(node, ast.Attribute)
            and node.attr == "severity"
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "meta"
            and not (isinstance(node.value.value, ast.Name) and node.value.value.id == "self")
        ):
            found.append(ast.unparse(node))
        elif (
            isinstance(node, ast.keyword)
            and node.arg == "severity"
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "severity"
            and not isinstance(node.value.value, ast.Attribute)
        ):
            found.append(ast.unparse(node.value))
    return found


def _emitted(rule: Rule) -> set[Severity]:
    sources = _sources(rule)
    found = set().union(*(_literals(tree) for tree in sources.values()))
    dynamic = [expr for tree in sources.values() for expr in _dynamic(tree)]
    indirect = _INDIRECT.get(rule.meta.id)
    if indirect is not None:
        marker, severities = indirect
        assert any(marker in expr for expr in dynamic), (
            f"{rule.meta.id}: the declared source {marker!r} no longer appears in its code; "
            f"update _INDIRECT"
        )
        found |= severities()
    else:
        assert not dynamic, (
            f"{rule.meta.id}: severity chosen at run time by {dynamic}; declare where it "
            f"comes from in _INDIRECT"
        )
    return found - {rule.meta.severity}


def _documented() -> dict[str, list[generate_docs.SeverityCondition]]:
    return generate_docs.load_severity_conditions(_rules())


def test_every_rule_module_in_the_package_defines_one_rule_so_a_literal_has_one_owner() -> None:
    owners = Counter(
        type(rule).__module__
        for rule in _rules()
        if type(rule).__module__.startswith(f"{_RULES_PACKAGE}.")
    )
    shared = sorted(module for module, count in owners.items() if count > 1)
    assert not shared, f"modules defining several rules need a per-rule attribution: {shared}"


def test_rules_defined_by_the_engine_have_no_entry_because_they_report_their_default() -> None:
    engine = [
        rule for rule in _rules() if not type(rule).__module__.startswith(f"{_RULES_PACKAGE}.")
    ]
    assert engine, "no YAML, trajectory or scenario rule found; this test reads nothing"
    documented = _documented()
    listed = sorted(rule.meta.id for rule in engine if rule.meta.id in documented)
    assert not listed, f"entries for rules the engine grades at their default severity: {listed}"
    for rule in engine:
        assert _emitted(rule) == set(), f"{rule.meta.id}: the engine emits a non-default severity"


@pytest.mark.parametrize("rule", _rules(), ids=lambda rule: rule.meta.id)
def test_the_listed_severities_are_the_ones_the_rule_code_can_emit(rule: Rule) -> None:
    listed = {condition.severity for condition in _documented().get(rule.meta.id, [])}
    emitted = _emitted(rule)
    assert listed == emitted, (
        f"{rule.meta.id}: severity_conditions.yaml lists {sorted(s.name for s in listed)}, "
        f"the code can emit {sorted(s.name for s in emitted)}"
    )


def test_the_catalog_lists_every_entry_of_the_file_once() -> None:
    page = generate_docs._catalog(_rules())
    _, section = page.split("## Other finding severities", 1)
    rows = [line for line in section.splitlines() if line.startswith("| `")]
    assert len(rows) == sum(len(entries) for entries in _documented().values())


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "severity_conditions.yaml"
    path.write_text(text, encoding="utf-8")
    return path


_HIGH_RULE = "guardana.supply_chain.code_execution"


@pytest.mark.parametrize(
    ("text", "names"),
    [
        ("guardana.no_such.rule:\n  - {severity: LOW, when: x}\n", "guardana.no_such.rule"),
        (f"{_HIGH_RULE}:\n  - {{severity: SEVERE, when: x}}\n", "SEVERE"),
        (f"{_HIGH_RULE}:\n  - {{severity: low, when: x}}\n", "low"),
        (f"{_HIGH_RULE}:\n  - {{severity: HIGH, when: x}}\n", "default"),
        (f"{_HIGH_RULE}:\n  - {{severity: LOW, when: '  '}}\n", "non-blank"),
        (f"{_HIGH_RULE}:\n  - {{severity: LOW}}\n", "exactly"),
        (f"{_HIGH_RULE}:\n  - {{severity: LOW, when: x, why: y}}\n", "exactly"),
        (f"{_HIGH_RULE}:\n  - {{severity: LOW, when: a | b}}\n", "'|'"),
        (
            f"{_HIGH_RULE}:\n  - {{severity: LOW, when: x}}\n  - {{severity: LOW, when: x}}\n",
            "twice",
        ),
        (f"{_HIGH_RULE}: []\n", "non-empty list"),
        (f"{_HIGH_RULE}:\n  severity: LOW\n", "non-empty list"),
        (f"{_HIGH_RULE}:\n  - LOW\n", "exactly"),
        ("- severity: LOW\n", "top level"),
        ("", "top level"),
    ],
)
def test_the_loader_refuses_a_file_the_catalog_cannot_back(
    tmp_path: Path, text: str, names: str
) -> None:
    path = _write(tmp_path, text)
    with pytest.raises(generate_docs.SeverityConditionsError, match=re.escape(names)) as raised:
        generate_docs.load_severity_conditions(_rules(), path)
    assert str(raised.value).startswith(f"{path}: ")


def test_the_loader_reads_a_well_formed_entry(tmp_path: Path) -> None:
    path = _write(
        tmp_path, f"{_HIGH_RULE}:\n  - severity: LOW\n    when: '  the file was unread '\n"
    )
    conditions = generate_docs.load_severity_conditions(_rules(), path)
    assert conditions == {
        _HIGH_RULE: [generate_docs.SeverityCondition(Severity.LOW, "the file was unread")]
    }
