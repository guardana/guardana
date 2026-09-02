import ast
import re
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, FileReader, Target, TargetKind
from guardana.core.taxonomy import (
    ATLAS_T0018,
    NIST_SUPPLY_CHAIN,
    OWASP_LLM03_2025,
    OWASP_LLM04_2026,
    OWASP_ML06_2023,
)
from guardana.rules._base import ArtifactRule
from guardana.rules.supply_chain._advisories import Advisory, load_advisories
from guardana.rules.supply_chain._leads import lead_verdict
from guardana.rules.supply_chain._reading import read_text_bounded

_MANIFEST_SUFFIXES = (".txt", ".toml", ".lock", ".cfg", ".in")
_MANIFEST_NAMES = frozenset({"Pipfile"})
_ANY_VERSION = "*"

# A network fetch inside setup.py runs at install time (`pip install`), the exact
# stage a malicious package uses to pull a second-stage payload. setup.py almost
# never legitimately reaches the network, so a fetch here is a lead worth raising.
_NETWORK_CALLS = frozenset({"urlopen", "urlretrieve", "get", "post", "Request"})

# Only *exact* pins are matched. `torch>=2.0` does not say which version will be
# installed, and inventing one would manufacture findings; a lockfile — which is
# what CI actually installs from — always pins exactly.
_EXACT_PIN = re.compile(
    r"""(?:^|[\s"'\[,])(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*["']?"""
    r"""(?P<version>[0-9][\w.+!-]*)"""
)
# The `package = "1.2.3"` form of `[tool.poetry.dependencies]`. The quoted value
# must be a bare version: `"^2.2.0"` and `"~1.4"` are ranges, and treating a range
# as a pin would invent a version nobody chose.
_TOML_PIN = re.compile(
    r"""^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*["'](?P<version>[0-9][\w.+!-]*)["']\s*$"""
)
# The `[[package]]` block form used by poetry.lock / uv.lock / pdm.lock, where the
# name and the version sit on separate lines — the form that authoritatively pins
# a resolved dependency, and that a same-line-only scan misses entirely.
_LOCK_NAME = re.compile(r"""^\s*name\s*=\s*["']([^"']+)["']""")
_LOCK_VERSION = re.compile(r"""^\s*version\s*=\s*["']([^"']+)["']""")


def _is_manifest(path: Path) -> bool:
    return path.suffix in _MANIFEST_SUFFIXES or path.name in _MANIFEST_NAMES


def _exact_pins(text: str) -> set[tuple[str, str]]:
    """Collect every `(package, version)` a manifest pins exactly."""
    pins: set[tuple[str, str]] = set()
    pending_name: str | None = None
    for line in text.splitlines():
        lock_name = _LOCK_NAME.match(line)
        if lock_name:
            pending_name = lock_name.group(1).lower()
            continue
        lock_version = _LOCK_VERSION.match(line)
        if lock_version:
            name, pending_name = pending_name, None
            if name is not None:
                pins.add((name, lock_version.group(1)))
            continue
        toml_pin = _TOML_PIN.match(line)
        if toml_pin:
            pins.add((toml_pin.group("name").lower(), toml_pin.group("version")))
        for pin in _EXACT_PIN.finditer(line):
            pins.add((pin.group("name").lower(), pin.group("version")))
    return pins


def _mentions(text: str, package: str) -> bool:
    """Whether a manifest declares the package at all, at any version."""
    pattern = rf"""^\s*(?:name\s*=\s*)?["']?{re.escape(package)}\b"""
    return re.search(pattern, text, re.IGNORECASE | re.MULTILINE) is not None


def _setup_network_calls(source: str) -> Iterator[int]:
    """Yield the line of each network-fetch call in a setup.py AST."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name in _NETWORK_CALLS:
                yield node.lineno


class MaliciousDependencyRule(ArtifactRule):
    """Flag advisory-listed package releases, and install-time network fetches in setup.py.

    The advisory dataset is AI/ML-only by construction (see `_advisories`): a
    compromised release, or a loader whose vulnerability is what turns an artifact
    this scan already found into code that runs. Pass `advisories=` to run the
    same rule against your own dataset.
    """

    meta = RuleMeta(
        id="guardana.supply_chain.malicious_dependency",
        title="Known-malicious dependency or install-time payload",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM03_2025,
            OWASP_LLM04_2026,
            OWASP_ML06_2023,
            ATLAS_T0018,
            NIST_SUPPLY_CHAIN,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def __init__(self, *, advisories: Sequence[Advisory] | None = None) -> None:
        self._advisories = tuple(advisories) if advisories is not None else load_advisories()

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Match dependency manifests against the advisory dataset; scan setup.py for fetches."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files():
            if _is_manifest(path):
                yield from self._scan_manifest(path)
        for path in target.iter_files((".py",)):
            if path.name == "setup.py":
                yield from self._scan_setup(path)

    def _scan_manifest(self, path: Path) -> Iterator[Finding]:
        text = read_text_bounded(path, errors="ignore")
        if text is None:
            return
        pins = _exact_pins(text)
        for advisory in self._advisories:
            version = self._affected_version(advisory, text, pins)
            if version is not None:
                yield self._finding(path, advisory, version)

    @staticmethod
    def _affected_version(advisory: Advisory, text: str, pins: set[tuple[str, str]]) -> str | None:
        """Return the pinned version this advisory covers, or None.

        A wildcard advisory is about the package *name* — a dependency-confusion
        squat is malicious at every version — so a mention is enough there.
        """
        if _ANY_VERSION in advisory.versions:
            return _ANY_VERSION if _mentions(text, advisory.package) else None
        for name, version in sorted(pins):
            if name == advisory.package and advisory.matches(version):
                return version
        return None

    def _finding(self, path: Path, advisory: Advisory, version: str) -> Finding:
        pinned = advisory.package if version == _ANY_VERSION else f"{advisory.package}=={version}"
        vulnerable_loader = advisory.kind == "vulnerable_loader"
        summary = (
            f"{pinned}: {advisory.summary}"
            if not vulnerable_loader
            else f"{pinned} is a loader that would execute what a poisoned artifact carries — "
            f"{advisory.summary}"
        )
        return Finding(
            rule_id=self.meta.id,
            severity=advisory.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=summary,
                detail=f"file={path.name}; advisory={advisory.id}; see {advisory.reference}",
            ),
            # A compromised release is a fact about that exact version. A
            # vulnerable loader only matters if something poisoned reaches it, so
            # it is reported as a lead.
            verdict=lead_verdict(summary) if vulnerable_loader else None,
        )

    def _scan_setup(self, path: Path) -> Iterator[Finding]:
        source = read_text_bounded(path)
        if source is None:
            return
        for lineno in _setup_network_calls(source):
            yield Finding(
                rule_id=self.meta.id,
                severity=Severity.MEDIUM,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=f"{path}:{lineno}",
                evidence=Evidence(
                    summary="install-time network fetch in setup.py (second-stage payload vector)",
                    detail=f"{path.name}:{lineno}",
                ),
                verdict=lead_verdict("network fetch in setup.py; a lead, not a certainty"),
            )
