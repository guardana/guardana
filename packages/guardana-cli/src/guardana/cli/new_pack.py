"""Scaffold an installable pack that passes its own verification before it is edited."""

import importlib.metadata
import importlib.resources
import keyword
import re
from pathlib import Path
from typing import Annotated

import typer
import yaml
from guardana.cli.exit_codes import ExitCode
from guardana.core import __version__ as core_version
from guardana.core.pack import EXTENSION_API_VERSION, MANIFEST_NAME
from guardana.core.registry import RESERVED_NAMESPACE, RESERVED_TARGET_SCHEMES

_SCAFFOLD_SCHEMA = 2
"""The manifest schema a scaffold writes: it declares no output, which is all schema 3
adds, and a schema 2 manifest also loads on builds that predate outputs."""

_SHAPES = {
    "prompt": ("prompt_secret_disclosure.yaml", "prompt_rule.yaml.tmpl"),
    "scenario": ("scenario_retrieved_document.yaml", "scenario_rule.yaml.tmpl"),
    "agent": ("agent_tool_exfiltration.yaml", "agent_rule.yaml.tmpl"),
}


def _template(name: str) -> str:
    """Read one template out of the package, so a missing one fails where it is used."""
    return (
        importlib.resources.files("guardana.cli.pack_templates").joinpath(name).read_text("utf-8")
    )


_DISTRIBUTION_NAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

# A directory holding only these is still empty for our purposes: refusing
# `git init && guardana new-pack mypack --dir .` would refuse the likeliest real
# invocation there is.
# How many occupants to name before the message stops being readable.
_NAMED_IN_A_REFUSAL = 3

_IGNORED_WHEN_EMPTY = frozenset({".git", ".gitignore", ".DS_Store", ".idea", ".vscode"})


class _Names:
    """Every name derived from the one the author typed."""

    def __init__(self, distribution: str) -> None:
        self.distribution = distribution
        self.module = distribution.replace("-", "_")
        self.prefix = distribution.split("-", maxsplit=1)[0]
        self.scheme = distribution
        self.klass = "".join(part.capitalize() for part in distribution.split("-"))
        self.marker = f"{self.prefix.upper()}_CANARY"

    def render(self, template: str) -> str:
        """Substitute the template tokens, longest first so prefixes do not collide."""
        api_range = f">={EXTENSION_API_VERSION},<{EXTENSION_API_VERSION + 1}"
        floor, ceiling = _core_range(core_version)
        for token, value in (
            ("__MARKER__", self.marker),
            ("__MODULE__", self.module),
            ("__PREFIX__", self.prefix),
            ("__SCHEME__", self.scheme),
            ("__CLASS__", self.klass),
            ("__DIST__", self.distribution),
            ("__API_RANGE__", api_range),
            ("__SCHEMA__", str(_SCAFFOLD_SCHEMA)),
            ("__CORE_FLOOR__", floor),
            ("__CORE_CEILING__", ceiling),
        ):
            template = template.replace(token, value)
        return template


def _core_range(version: str) -> tuple[str, str]:
    """Return the `guardana-core` this pack is made with and the next major it stops before.

    The local label is dropped: a requirement may not name one.
    """
    public = version.partition("+")[0]
    release = re.match(r"(\d+)\.(\d+)", public)
    if release is None:
        raise ValueError(f"guardana-core reports a version that is not PEP 440: {version!r}")
    return public, str(int(release[1]) + 1)


def _refuse(message: str) -> typer.Exit:
    typer.echo(f"error: {message}", err=True)
    return typer.Exit(code=ExitCode.INVALID_USAGE)


def _check_name(name: str) -> _Names:
    """Refuse every name that would produce a pack this build cannot load.

    Each of these is caught here rather than by a later command, because a scaffold
    that emits an invalid pack and leaves the validator to notice is a false green
    wearing documentation's clothes.
    """
    if not _DISTRIBUTION_NAME.match(name):
        raise _refuse(
            f"{name!r} is not a distribution name; use lowercase letters, digits "
            f"and hyphens, starting and ending with a letter or digit"
        )
    names = _Names(name)
    if not names.module.isidentifier() or keyword.iskeyword(names.module):
        raise _refuse(f"{name!r} becomes the module {names.module!r}, which is not importable")
    if f"{names.prefix}." == RESERVED_NAMESPACE:
        raise _refuse(
            f"rule ids would start with {RESERVED_NAMESPACE}, which is reserved for "
            f"Guardana's own rules; the registry refuses them at load time"
        )
    if names.scheme in RESERVED_TARGET_SCHEMES:
        raise _refuse(
            f"the target scheme would be {names.scheme!r}, which is reserved "
            f"({', '.join(sorted(RESERVED_TARGET_SCHEMES))}); the target would be "
            f"refused at discovery and the pack would not load"
        )
    try:
        importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return names
    raise _refuse(
        f"{name!r} is already installed in this environment; two origins claiming "
        f"one id is a registry error, so pick another name"
    )


def _check_directory(target: Path) -> None:
    if not target.is_dir():
        raise _refuse(f"{target} is not a directory; --dir names where the pack goes")
    occupied = sorted(p.name for p in target.iterdir() if p.name not in _IGNORED_WHEN_EMPTY)
    if occupied:
        raise _refuse(
            f"{target} is not empty ({', '.join(occupied[:_NAMED_IN_A_REFUSAL])}"
            f"{', …' if len(occupied) > _NAMED_IN_A_REFUSAL else ''}); refusing to write over it"
        )


def _manifest(names: _Names, catalog: Path) -> str:
    """Render the manifest from the catalogue files on disk, not from an id list.

    Rendered from one in-memory list, the manifest and the catalogue would agree by
    construction and every test comparing them would pass whatever this command did.
    Read back from the files, a rule that failed to write is a rule the manifest
    does not claim.
    """
    ids = [yaml.safe_load(path.read_text())["id"] for path in sorted(catalog.glob("*.yaml"))]
    lines = [names.render(_template("manifest_header.yaml.tmpl")), "  rules:\n"]
    lines.extend(f"    - {rule_id}\n" for rule_id in ids)
    lines.append(f"  targets:\n    - {names.klass}Target\n")
    return "".join(lines)


def new_pack(
    name: Annotated[str, typer.Argument(help="Distribution name, e.g. acme-rules")],
    dir: Annotated[
        Path | None, typer.Option(help="Where to write it. Defaults to ./<name>")
    ] = None,
    shape: Annotated[
        list[str],
        typer.Option("--shape", help="Rule shapes to write: prompt|scenario|agent; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Scaffold an installable pack: manifest, entry points, sampled rules, target, tests."""
    names = _check_name(name)
    shapes = list(dict.fromkeys(shape)) if shape else list(_SHAPES)
    unknown = [s for s in shapes if s not in _SHAPES]
    if unknown:
        raise _refuse(f"unknown shape(s) {', '.join(unknown)}; use {', '.join(_SHAPES)}")

    target = dir if dir is not None else Path(name)
    if target.exists():
        _check_directory(target)

    package = target / "src" / names.module
    catalog = package / "catalog"
    catalog.mkdir(parents=True, exist_ok=True)
    (target / "tests").mkdir(exist_ok=True)

    written = []
    for key in shapes:
        filename, template = _SHAPES[key]
        written.append(_write(catalog / filename, names.render(_template(template))))
    written.append(_write(catalog / "__init__.py", '"""The rule catalogue, shipped as data."""\n'))
    written.append(_write(package / "__init__.py", names.render(_template("package_init.py.tmpl"))))
    written.append(_write(package / "target.py", names.render(_template("target.py.tmpl"))))
    written.append(_write(package / "py.typed", ""))
    written.append(
        _write(target / "pyproject.toml", names.render(_template("pyproject.toml.tmpl")))
    )
    written.append(_write(target / "README.md", names.render(_template("readme.md.tmpl"))))
    written.append(
        _write(
            target / "tests" / "test_manifest.py", names.render(_template("test_manifest.py.tmpl"))
        )
    )
    written.append(
        _write(
            target / "tests" / "test_rules_are_sampled.py",
            names.render(_template("test_rules_are_sampled.py.tmpl")),
        )
    )
    written.append(
        _write(target / "tests" / "test_target.py", names.render(_template("test_target.py.tmpl")))
    )
    # Last, and read back from what was just written rather than from `shapes`.
    written.append(_write(package / MANIFEST_NAME, _manifest(names, catalog)))

    typer.echo(f"Wrote {len(written)} files to {target}{'/' if str(target) != '.' else ''}")
    typer.echo("Install and verify it:")
    typer.echo(f"  pip install -e {target}")
    # Guardana loads only its built-ins unless trust is stated, so each command
    # admits this pack by its distribution name.
    admit = f"--plugins allowlist --allow-plugin {names.distribution}"
    typer.echo(f"  guardana pack validate {package / MANIFEST_NAME} {admit}")
    typer.echo(f"  guardana rule test '{names.prefix}.*' {admit}")
    typer.echo(f"  pytest {target / 'tests'}")


def _write(path: Path, content: str) -> Path:
    path.write_text(content)
    return path
