#!/usr/bin/env python3
"""Write the supported surface as one JSON document, so a change to it is a visible diff.

    uv run python scripts/api_surface.py            # write docs/generated/api-surface.json
    uv run python scripts/api_surface.py --check    # exit 1 when the file is stale

Python names are read from source with `ast` and never imported: each exported name is
followed to the module that defines it, and annotations are kept as source text, because
the repr of an evaluated annotation differs between Python versions and the document must
be identical on every Python the project supports. Constant values are read the same way.
The command line is walked through Typer, without help text. `generate_docs.py` writes
this file too, so its `--check` and the suite catch a surface that moved unannounced, and
`release.py` refuses a release candidate whose surface moved without a changelog entry.
"""

import argparse
import ast
import json
import re
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_REPO = Path(__file__).resolve().parent.parent
OUTPUT = _REPO / "docs" / "generated" / "api-surface.json"
SOURCE_ROOTS = tuple(sorted((_REPO / "packages").glob("*/src")))
SURFACE_SCHEMA_VERSION = 1

_FACADE = ("guardana.core.verify", "guardana.core.doubles")
_FACADE_NAMES = {
    "guardana.core.plugins": ("PluginMode", "PluginTrust"),
    "guardana.core.profile": ("load_profile",),
}
"""What building a `Verifier` needs beyond the facade modules themselves."""
_EXTENSION = ("guardana.core", "guardana.core.target.protocols")
_EXTENSION_NAMES = {
    "guardana.core.rule.fixture": (
        "DEMANDED_OUTCOMES",
        "DeclaredFixture",
        "FixtureOutcome",
        "RuleFixture",
        "materialise",
    ),
    "guardana.core.target": ("WireProtocol", "display_url"),
    "guardana.core.source": ("PythonSource", "UnreadSource", "read_source"),
    "guardana.core.report.shortfall": ("CoverageShortfall", "ShortfallKind"),
}
_INTERNAL = frozenset({"guardana.core.Runner"})
"""Exported for the CLI, documented as internal in `docs/python-api.md`, so not frozen."""

_OUTPUTS = ("guardana.core.output",)
_KIT = ("guardana.testing", "guardana.core.testing")
_KIT_NAMES = {
    "guardana.core.pack": (
        "EXTENSION_API_VERSION",
        "PackManifest",
        "Registered",
        "check_pack",
        "installed_manifests",
        "load_manifest",
    ),
    "guardana.core.rule.verify": ("verify_rules",),
    "guardana.core.taxonomy": ("register_all",),
}
"""What the tests `guardana new-pack` writes import, as the pack is pinned below the next major."""

_CONSTANTS = (
    ("guardana.core.entrypoints", "TAXONOMY_GROUP"),
    ("guardana.core.entrypoints", "RULE_GROUP"),
    ("guardana.core.entrypoints", "EVALUATOR_GROUP"),
    ("guardana.core.entrypoints", "TARGET_GROUP"),
    ("guardana.core.entrypoints", "RENDERER_GROUP"),
    ("guardana.core.entrypoints", "REPORTER_GROUP"),
    ("guardana.core.pack.model", "EXTENSION_API_VERSION"),
    ("guardana.core.pack.model", "SUPPORTED_EXTENSION_API_VERSIONS"),
    ("guardana.core.output", "OUTPUT_API_VERSION"),
    ("guardana.core.output", "SUPPORTED_OUTPUT_API_VERSIONS"),
    ("guardana.core.manifest.model", "MANIFEST_SCHEMA_VERSION"),
    ("guardana.core.report.load", "MIGRATABLE_VERSIONS"),
    ("guardana.core.reporter", "ENVELOPE_SCHEMA_VERSION"),
    ("guardana.server.envelope", "SUPPORTED_SCHEMA_VERSIONS"),
    ("guardana.core.pack.model", "PACK_SCHEMA_VERSION"),
    ("guardana.core.pack.lock", "LOCK_SCHEMA_VERSION"),
    ("guardana.core.profile.loader", "PROFILE_SCHEMA_VERSION"),
    ("guardana.core.report.baseline", "BASELINE_VERSION"),
    ("guardana.core.recipe", "RECIPE_SCHEMA_VERSION"),
    ("guardana.core.recipe", "RECIPE_LOCK_SCHEMA_VERSION"),
    ("guardana.core.recording", "RECORDING_FORMAT"),
    ("guardana.core.recording", "READ_FORMATS"),
    ("guardana.core.dataset", "DATASET_FORMAT"),
    ("guardana.core.dataset", "READ_FORMATS"),
    ("guardana.core.fixtures", "FIXTURES_SCHEMA_VERSION"),
    ("guardana.core.contract.model", "CONTRACT_SCHEMA_VERSION"),
    ("guardana.core.contract.load", "MIGRATABLE_VERSIONS"),
    ("guardana.core.trace.observations", "OBSERVATIONS_SCHEMA_VERSION"),
    ("guardana.core.calibration.store", "STORE_SCHEMA_VERSION"),
    ("guardana.core.diff.model", "DIFF_SCHEMA_VERSION"),
    ("guardana.cli.plan", "PLAN_SCHEMA_VERSION"),
    ("guardana.cli._artifact", "ARTIFACT_SCHEMA_VERSION"),
    ("guardana.rules.agent.mcp_server_manifest", "PIN_SCHEMA_VERSION"),
)

_VERSION_NAME = re.compile(
    r"(?:[A-Z][A-Z0-9_]*_)?(?:SCHEMA_VERSIONS?|API_VERSIONS?|MIGRATABLE_VERSIONS"
    r"|BASELINE_VERSION|FORMATS?)"
)
"""The names a version constant the snapshot records goes by."""

_UNRECORDED_VERSIONS = {
    ("guardana.core.trace.model", "TRACE_SCHEMA_VERSION"): (
        "the trace format integrators write is versioned by its JSON schema under schemas/"
    ),
    ("guardana.rules.supply_chain._advisories", "SCHEMA_VERSION"): (
        "the advisory dataset is data packaged with the rules, not a document a user persists"
    ),
    ("guardana.core.report.run", "REPORT_SCHEMA_VERSION"): (
        "an alias of MANIFEST_SCHEMA_VERSION, recorded under that name"
    ),
    ("guardana.server.envelope", "SCHEMA_VERSION"): (
        "the collector's copy of ENVELOPE_SCHEMA_VERSION, recorded under that name"
    ),
    ("guardana.cli._output", "COMPARABLE_FORMAT"): (
        "the name of the output format `diff` reads, not a document version"
    ),
}
"""Version constants the snapshot leaves out on purpose, each with the reason."""

_LOCATOR_SCHEMES = (
    ("guardana.core.registry", "RESERVED_TARGET_SCHEMES"),
    ("guardana.core.registry", "_TARGET_SCHEME"),
    ("guardana.core.output", "RESERVED_RENDERER_NAMES"),
    ("guardana.core.output", "RESERVED_REPORTER_NAMES"),
    ("guardana.core.output", "OUTPUT_NAME_PATTERN"),
    ("guardana.cli._reporting", "_SERVER_SCHEME"),
)

_EXIT_CODES = ("guardana.cli.exit_codes", "ExitCode")
_ACTION = _REPO / "action.yml"
_VARIABLE = re.compile(r"GUARDANA_[A-Z0-9_]*[A-Z0-9]")
_NOT_VARIABLES = frozenset(
    {"GUARDANA_CANARY_PARTICIPATION_CHECK", "GUARDANA_CANARY_PLANNING", "GUARDANA_SYSTEM_PROBE"}
)
"""Markers Guardana plants in what it sends a target; nothing reads them from the environment."""

_UNRECORDED_VALUES = frozenset({"__version__"})
"""Exported names whose value is release metadata, which every release changes."""

_ENUM_BASES = frozenset({"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"})
_PARAMETER_KINDS = (
    "positional_only",
    "positional_or_keyword",
    "var_positional",
    "keyword_only",
    "var_keyword",
)


class SurfaceError(Exception):
    """The surface cannot be described as declared: a name, a module or a value is missing."""


@dataclass
class _Module:
    """One parsed source module and the top-level statements that bind each name."""

    name: str
    path: Path
    is_package: bool
    bindings: dict[str, list[ast.stmt]] = field(default_factory=dict)


class SourceTree:
    """The modules under a set of source roots, parsed once each and never imported."""

    def __init__(self, roots: Sequence[Path] = SOURCE_ROOTS) -> None:
        """Read modules from `roots`, each a directory holding the `guardana` namespace."""
        self._roots = tuple(roots)
        self._modules: dict[str, _Module] = {}

    def module(self, name: str) -> _Module:
        """Return the parsed module `name`, refusing one no root holds."""
        if name in self._modules:
            return self._modules[name]
        parts = name.split(".")
        for root in self._roots:
            base = root.joinpath(*parts)
            candidates = ((base.with_suffix(".py"), False), (base / "__init__.py", True))
            for path, is_package in candidates:
                if path.is_file():
                    parsed = _Module(name, path, is_package)
                    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                    for statement in tree.body:
                        for bound in _bound_names(statement):
                            parsed.bindings.setdefault(bound, []).append(statement)
                    self._modules[name] = parsed
                    return parsed
        raise SurfaceError(f"no source for module {name}")

    def exported(self, module: str) -> tuple[str, ...]:
        """Read a module's `__all__` as a literal list of names."""
        statements = self.module(module).bindings.get("__all__")
        if not statements:
            raise SurfaceError(f"{module} declares no __all__")
        value = _assigned_value(statements[-1])
        try:
            names = ast.literal_eval(value)
        except ValueError as error:
            raise SurfaceError(f"{module}.__all__ is not a literal list of names") from error
        if not isinstance(names, list | tuple) or not all(isinstance(n, str) for n in names):
            raise SurfaceError(f"{module}.__all__ is not a literal list of names")
        return tuple(names)

    def definition(self, module: str, name: str) -> tuple[_Module, list[ast.stmt]]:
        """Follow `name` from `module` through re-exports to the statements that define it."""
        seen: set[tuple[str, str]] = set()
        while (module, name) not in seen:
            seen.add((module, name))
            parsed = self.module(module)
            statements = parsed.bindings.get(name)
            if not statements:
                raise SurfaceError(f"{module} does not bind {name}")
            last = statements[-1]
            if not isinstance(last, ast.ImportFrom):
                return parsed, statements
            if last.level:
                raise SurfaceError(f"{module} imports {name} relatively, which is not read")
            imported = next(a for a in last.names if (a.asname or a.name) == name)
            module, name = last.module or "", imported.name
        raise SurfaceError(f"{module}.{name} is imported in a cycle")


def _bound_names(statement: ast.stmt) -> Iterator[str]:
    """Yield every name a top-level statement binds in its module."""
    if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        yield statement.name
    elif isinstance(statement, ast.Assign):
        for target in statement.targets:
            if isinstance(target, ast.Name):
                yield target.id
    elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
        yield statement.target.id
    elif isinstance(statement, ast.ImportFrom):
        for alias in statement.names:
            yield alias.asname or alias.name


def _assigned_value(statement: ast.stmt) -> ast.expr:
    if isinstance(statement, ast.Assign | ast.AnnAssign) and statement.value is not None:
        return statement.value
    raise SurfaceError(f"line {statement.lineno} assigns no value")


def _text(node: ast.expr | None) -> str | None:
    return None if node is None else ast.unparse(node)


def _parameters(arguments: ast.arguments) -> list[dict[str, Any]]:
    """Describe each parameter by name, kind, annotation text and whether it has a default."""
    positional = [*arguments.posonlyargs, *arguments.args]
    defaults = [False] * (len(positional) - len(arguments.defaults)) + [True] * len(
        arguments.defaults
    )
    described: list[dict[str, Any]] = []
    for index, argument in enumerate(positional):
        kind = _PARAMETER_KINDS[0 if index < len(arguments.posonlyargs) else 1]
        described.append(_parameter(argument, kind, has_default=defaults[index]))
    if arguments.vararg is not None:
        described.append(_parameter(arguments.vararg, _PARAMETER_KINDS[2], has_default=False))
    for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True):
        described.append(_parameter(argument, _PARAMETER_KINDS[3], has_default=default is not None))
    if arguments.kwarg is not None:
        described.append(_parameter(arguments.kwarg, _PARAMETER_KINDS[4], has_default=False))
    return described


def _parameter(argument: ast.arg, kind: str, *, has_default: bool) -> dict[str, Any]:
    return {
        "name": argument.arg,
        "kind": kind,
        "has_default": has_default,
        "annotation": _text(argument.annotation),
    }


def _function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any]:
    return {
        "kind": "function",
        "async": isinstance(node, ast.AsyncFunctionDef),
        "decorators": [ast.unparse(d) for d in node.decorator_list],
        "parameters": _parameters(node.args),
        "returns": _text(node.returns),
    }


def _decorator_name(node: ast.expr) -> str:
    target = node.func if isinstance(node, ast.Call) else node
    return ast.unparse(target).rsplit(".", 1)[-1]


def _base_name(node: ast.expr) -> str:
    target = node.value if isinstance(node, ast.Subscript) else node
    return ast.unparse(target).rsplit(".", 1)[-1]


def _is_public_method(name: str) -> bool:
    return not name.startswith("_") or (name.startswith("__") and name.endswith("__"))


def _fields(node: ast.ClassDef, *, every: bool) -> list[dict[str, Any]]:
    """Annotated class attributes: every one for a dataclass, whose `__init__` takes them all."""
    return [
        {
            "name": statement.target.id,
            "annotation": ast.unparse(statement.annotation),
            "has_default": statement.value is not None and not _is_bare_field(statement.value),
        }
        for statement in node.body
        if isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
        and (every or not statement.target.id.startswith("_"))
    ]


def _methods(node: ast.ClassDef) -> dict[str, Any]:
    methods: dict[str, Any] = {}
    for statement in node.body:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef) and _is_public_method(
            statement.name
        ):
            if statement.name in methods:
                raise SurfaceError(f"{node.name}.{statement.name} is defined twice")
            methods[statement.name] = _function(statement)
    return methods


def _members(node: ast.ClassDef) -> list[dict[str, str]]:
    return [
        {"name": target.id, "value": ast.unparse(statement.value)}
        for statement in node.body
        if isinstance(statement, ast.Assign)
        for target in statement.targets
        if isinstance(target, ast.Name) and not target.id.startswith("_")
    ]


def _class(node: ast.ClassDef) -> dict[str, Any]:
    """Describe a class: its bases, decorators, annotated fields, methods and enum members."""
    bases = [_base_name(base) for base in node.bases]
    is_enum = any(base in _ENUM_BASES for base in bases)
    is_dataclass = "dataclass" in [_decorator_name(d) for d in node.decorator_list]
    kind = "enum" if is_enum else "dataclass" if is_dataclass else "class"
    described: dict[str, Any] = {
        "kind": "protocol" if "Protocol" in bases else kind,
        "bases": [ast.unparse(base) for base in node.bases],
        "decorators": [ast.unparse(d) for d in node.decorator_list],
        "fields": _fields(node, every=is_dataclass),
        "methods": _methods(node),
    }
    if is_enum:
        described["members"] = _members(node)
    return described


def _is_bare_field(value: ast.expr) -> bool:
    """Whether a dataclass default is `field(...)` with neither a default nor a factory."""
    if not (isinstance(value, ast.Call) and _decorator_name(value) == "field"):
        return False
    return not any(k.arg in {"default", "default_factory"} for k in value.keywords)


def describe(tree: SourceTree, module: str, name: str) -> dict[str, Any]:
    """Describe the exported `module.name` as the module that defines it declares it."""
    defined, statements = tree.definition(module, name)
    last = statements[-1]
    described: dict[str, Any]
    if isinstance(last, ast.ClassDef):
        described = _class(last)
    elif isinstance(last, ast.FunctionDef | ast.AsyncFunctionDef):
        if len(statements) > 1:
            raise SurfaceError(f"{defined.name}.{name} is defined more than once")
        described = _function(last)
    elif isinstance(last, ast.Assign | ast.AnnAssign):
        described = {
            "kind": "constant",
            "annotation": _text(last.annotation) if isinstance(last, ast.AnnAssign) else None,
        }
        if name not in _UNRECORDED_VALUES:
            described["value"] = ast.unparse(_assigned_value(last))
    else:
        raise SurfaceError(f"{defined.name}.{name} is bound by a statement that is not read")
    return {"defined_in": defined.name, **described}


def _evaluate(tree: SourceTree, module: str, node: ast.expr) -> object:
    """Evaluate a constant expression from source: literals, names, and set or tuple calls."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return value_of(tree, module, node.id)
    if isinstance(node, ast.Set | ast.Tuple | ast.List):
        items = [_evaluate(tree, module, element) for element in node.elts]
        return frozenset(items) if isinstance(node, ast.Set) else tuple(items)
    if isinstance(node, ast.Dict):
        return frozenset(_evaluate(tree, module, key) for key in node.keys if key is not None)
    if isinstance(node, ast.Call) and len(node.args) == 1 and not node.keywords:
        return _evaluate_call(tree, module, node)
    raise SurfaceError(f"{module}: {ast.unparse(node)} is not a constant this script reads")


def _evaluate_call(tree: SourceTree, module: str, node: ast.Call) -> object:
    """Evaluate `frozenset(x)`, `set(x)`, `tuple(x)` or `re.compile(pattern)` from source."""
    called = ast.unparse(node.func)
    argument = _evaluate(tree, module, node.args[0])
    if called in {"frozenset", "set"} and isinstance(argument, frozenset | tuple):
        return frozenset(argument)
    if called == "tuple" and isinstance(argument, frozenset | tuple):
        return tuple(argument)
    if called == "re.compile" and isinstance(argument, str):
        return argument
    raise SurfaceError(f"{module}: {ast.unparse(node)} is not a constant this script reads")


def value_of(tree: SourceTree, module: str, name: str) -> object:
    """Read the value a module binds to `name`, following imports, without importing."""
    defined, statements = tree.definition(module, name)
    return _evaluate(tree, defined.name, _assigned_value(statements[-1]))


_Plain = int | str | list["_Plain"]


def _plain(value: object, where: str) -> _Plain:
    """Turn a constant into JSON: ints and strings as they are, sets sorted, tuples as lists."""
    if isinstance(value, bool):
        raise SurfaceError(f"{where} is a bool, not an int, str, set or tuple")
    if isinstance(value, int | str):
        return value
    if isinstance(value, tuple):
        return [_plain(item, where) for item in value]
    if isinstance(value, frozenset):
        items = [_plain(item, where) for item in value]
        numbers = sorted(item for item in items if isinstance(item, int))
        words = sorted(item for item in items if isinstance(item, str))
        if len(numbers) + len(words) != len(items):
            raise SurfaceError(f"{where} holds a set inside a set")
        return [*numbers, *words]
    raise SurfaceError(f"{where} is {type(value).__name__}, not an int, str, set or tuple")


def _names(tree: SourceTree, modules: Sequence[str]) -> dict[str, Any]:
    described: dict[str, Any] = {}
    for module in modules:
        for name in tree.exported(module):
            key = f"{module}.{name}"
            if key not in _INTERNAL:
                described[key] = describe(tree, module, name)
    return described


def _constants(tree: SourceTree, names: Sequence[tuple[str, str]]) -> dict[str, Any]:
    return {
        f"{module}.{name}": _plain(value_of(tree, module, name), f"{module}.{name}")
        for module, name in names
    }


def _exit_codes(tree: SourceTree) -> dict[str, int]:
    module, name = _EXIT_CODES
    defined, statements = tree.definition(module, name)
    node = statements[-1]
    if not isinstance(node, ast.ClassDef):
        raise SurfaceError(f"{module}.{name} is not a class")
    codes: dict[str, int] = {}
    for statement in node.body:
        if isinstance(statement, ast.Assign) and isinstance(statement.targets[0], ast.Name):
            value = _evaluate(tree, defined.name, statement.value)
            if not isinstance(value, int) or isinstance(value, bool):
                raise SurfaceError(f"{name}.{statement.targets[0].id} is not an integer")
            codes[statement.targets[0].id] = value
    return codes


def _environment(roots: Sequence[Path]) -> list[str]:
    """Every `GUARDANA_*` name a source module spells as a whole string literal."""
    found: set[str] = set()
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and _VARIABLE.fullmatch(node.value)
                    and node.value not in _NOT_VARIABLES
                ):
                    found.add(node.value)
    return sorted(found)


def _action_inputs(path: Path) -> dict[str, Any]:
    """Each `action.yml` input with whether it is required and whether it has a default."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    inputs = document.get("inputs") if isinstance(document, dict) else None
    if not isinstance(inputs, dict):
        raise SurfaceError(f"{path.name} declares no inputs")
    return {
        name: {
            "required": bool(spec.get("required", False)),
            "has_default": "default" in spec,
        }
        for name, spec in inputs.items()
    }


def _cli() -> dict[str, Any]:
    """Every command path's parameters, read from the Click command Typer builds."""
    import typer.main  # noqa: PLC0415
    from guardana.cli.main import app  # noqa: PLC0415
    from typer.core import TyperGroup  # noqa: PLC0415

    commands: dict[str, Any] = {}

    def walk(path: str, command: Any) -> None:  # noqa: ANN401 — Typer types it in a private module
        commands[path] = [
            {
                "name": parameter.name,
                "kind": parameter.param_type_name,
                "opts": list(parameter.opts),
                "secondary_opts": list(parameter.secondary_opts),
                "required": parameter.required,
                "flag": bool(getattr(parameter, "is_flag", False)),
                "multiple": parameter.multiple,
                "hidden": bool(getattr(parameter, "hidden", False)),
                "has_default": parameter.default is not None,
            }
            for parameter in command.params
        ]
        if isinstance(command, TyperGroup):
            for name in sorted(command.commands):
                walk(f"{path} {name}", command.commands[name])

    walk("guardana", typer.main.get_command(app))
    return commands


def build(roots: Sequence[Path] = SOURCE_ROOTS) -> dict[str, Any]:
    """Describe the whole supported surface as one JSON-ready mapping."""
    tree = SourceTree(roots)
    facade = _names(tree, _FACADE)
    for module, names in _FACADE_NAMES.items():
        facade.update({f"{module}.{name}": describe(tree, module, name) for name in names})
    extension = _names(tree, _EXTENSION)
    for module, names in _EXTENSION_NAMES.items():
        extension.update({f"{module}.{name}": describe(tree, module, name) for name in names})
    kit = _names(tree, _KIT)
    for module, names in _KIT_NAMES.items():
        kit.update({f"{module}.{name}": describe(tree, module, name) for name in names})
    return {
        "schema_version": SURFACE_SCHEMA_VERSION,
        "generated_by": "scripts/api_surface.py from source — do not edit by hand",
        "facade": facade,
        "extension": extension,
        "outputs": _names(tree, _OUTPUTS),
        "kit": kit,
        "constants": _constants(tree, _CONSTANTS),
        "cli": _cli(),
        "exit_codes": _exit_codes(tree),
        "locator_schemes": _constants(tree, _LOCATOR_SCHEMES),
        "action_inputs": _action_inputs(_ACTION),
        "environment_variables": _environment(roots),
    }


def unrecorded_versions(roots: Sequence[Path] = SOURCE_ROOTS) -> list[str]:
    """Name every module-level version constant the snapshot neither records nor excludes.

    Only a value assigned in the module counts; an import of one is recorded where it is
    defined. `_UNRECORDED_VERSIONS` holds the deliberate exclusions with their reasons.
    """
    covered = set(_CONSTANTS) | set(_UNRECORDED_VERSIONS)
    found: list[str] = []
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            module = ".".join(path.relative_to(root).with_suffix("").parts)
            module = module.removesuffix(".__init__")
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            found.extend(
                f"{module}.{name}"
                for statement in tree.body
                if isinstance(statement, ast.Assign | ast.AnnAssign)
                for name in _bound_names(statement)
                if _VERSION_NAME.fullmatch(name) and (module, name) not in covered
            )
    return found


def render(roots: Sequence[Path] = SOURCE_ROOTS) -> str:
    """Render the surface as the text `docs/generated/api-surface.json` holds."""
    return json.dumps(build(roots), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """Write the surface document, or with `--check` report whether it is stale."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if stale; write nothing")
    args = parser.parse_args(argv)
    try:
        wanted = render()
    except SurfaceError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.is_file() else None
    if current == wanted:
        print(f"{OUTPUT.name} is current")
        return 0
    if args.check:
        print(f"{OUTPUT.name} is out of date: run `uv run python scripts/api_surface.py`")
        return 1
    OUTPUT.write_text(wanted, encoding="utf-8")
    print(f"regenerated: {OUTPUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
