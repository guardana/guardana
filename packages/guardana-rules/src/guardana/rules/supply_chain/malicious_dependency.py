import ast
import json
import re
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import NamedTuple

from guardana.core.report import Evidence, Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection
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
from guardana.rules.supply_chain import _samples
from guardana.rules.supply_chain._advisories import Advisory, load_advisories
from guardana.rules.supply_chain._leads import lead_verdict, unread_component, unscanned_verdict
from guardana.rules.supply_chain._reading import MAX_SCAN_BYTES, read_text_prefix
from guardana.rules.supply_chain._versions import canonical_name

_MANIFEST_SUFFIXES = (".txt", ".toml", ".lock", ".cfg", ".in")
_MANIFEST_NAMES = frozenset(
    {"pipfile", "environment.yml", "environment.yaml", "conda.yml", "conda.yaml"}
)
_ANY_VERSION = "*"

# A network fetch inside setup.py runs at install time (`pip install`), the exact
# stage a malicious package uses to pull a second-stage payload. setup.py almost
# never legitimately reaches the network, so a fetch here is a lead worth raising.
_NETWORK_CALLS = frozenset({"urlopen", "urlretrieve", "get", "post", "Request"})

# Only *exact* pins are matched. `torch>=2.0` does not say which version will be
# installed, and inventing one would manufacture findings; a lockfile — which is
# what CI actually installs from — always pins exactly. `===` is arbitrary equality.
# The whitespace runs are possessive and the extras group excludes `[`, so a line of
# spaces or of unclosed `[` costs time linear in its length, not quadratic. `\s` keeps
# the Unicode spaces a line may hold around the operator, which `splitlines` does not cut.
_EXACT_PIN = re.compile(
    r"""(?:^|[\s"'\[,])(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*+(?:\[[^\]\[]*+\])?\s*+"""
    r"""(?P<operator>===?)\s*+["']?(?P<version>[vV]?[0-9][\w.+!-]*)"""
)
# The `package = "1.2.3"` form of `[tool.poetry.dependencies]`. The quoted value
# must be a bare version: `"^2.2.0"` and `"~1.4"` are ranges, and treating a range
# as a pin would invent a version nobody chose.
_TOML_PIN = re.compile(
    r"""^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*["'](?:(?P<operator>===?)\s*)?"""
    r"""(?P<version>[vV]?[0-9][\w.+!-]*)["']\s*$"""
)
# The `[[package]]` block form used by poetry.lock / uv.lock / pdm.lock, where the
# name and the version sit on separate lines — the form that authoritatively pins
# a resolved dependency, and that a same-line-only scan misses entirely.
_LOCK_NAME = re.compile(r"""^\s*name\s*=\s*["']([^"']+)["']""")
_LOCK_VERSION = re.compile(r"""^\s*version\s*=\s*["']([^"']+)["']""")
_PAST_THE_BOUND = f"only the first {MAX_SCAN_BYTES} bytes were read (the read bound)"
_SETUP_UNSCANNED = "setup.py not scanned"


def _is_manifest(path: Path) -> bool:
    return path.suffix.lower() in _MANIFEST_SUFFIXES or path.name.lower() in _MANIFEST_NAMES


class _Pin(NamedTuple):
    """One exact pin: the PEP 503 name, the version as written, and whether it used `===`."""

    name: str
    version: str
    arbitrary: bool


def _pin(name: str, version: str, operator: str | None) -> _Pin:
    return _Pin(canonical_name(name), version, operator == "===")


def _exact_pins(text: str) -> set[_Pin]:
    """Collect every pin a manifest makes exactly, by `==`, `===` or a lockfile version."""
    pins: set[_Pin] = set()
    pending_name: str | None = None
    for line in text.splitlines():
        lock_name = _LOCK_NAME.match(line)
        if lock_name:
            pending_name = lock_name.group(1)
            continue
        lock_version = _LOCK_VERSION.match(line)
        if lock_version:
            name, pending_name = pending_name, None
            if name is not None:
                pins.add(_pin(name, lock_version.group(1), None))
            continue
        toml_pin = _TOML_PIN.match(line)
        if toml_pin:
            pins.add(_pin(toml_pin["name"], toml_pin["version"], toml_pin["operator"]))
        for pin in _EXACT_PIN.finditer(line):
            pins.add(_pin(pin["name"], pin["version"], pin["operator"]))
    return pins | _json_lock_pins(text)


def _json_lock_pins(text: str) -> set[_Pin]:
    """Collect the pins a JSON lockfile (`Pipfile.lock`) records under its package sections.

    Its versions sit in `"version": "==X"` beside a name on another line, which no line
    pattern pairs; anything that is not such a document holds no pins here.
    """
    if not text.lstrip().startswith("{"):
        return set()
    try:
        document = json.loads(text)
    except ValueError:
        return set()
    if not isinstance(document, dict):
        return set()
    pins: set[_Pin] = set()
    for section in ("default", "develop"):
        packages = document.get(section)
        if not isinstance(packages, dict):
            continue
        for name, entry in packages.items():
            version = entry.get("version") if isinstance(entry, dict) else None
            if isinstance(name, str) and isinstance(version, str):
                operator = "===" if version.startswith("===") else "=="
                if version.startswith(operator):
                    pins.add(_pin(name, version[len(operator) :].strip(), operator))
    return pins


def _mentions(text: str, package: str) -> bool:
    """Whether a manifest declares the package at all, at any version, in any PEP 503 spelling.

    A line may open with a YAML list bullet, as the pip section of a conda environment does.
    """
    name = r"[-_.]+".join(re.escape(part) for part in canonical_name(package).split("-"))
    pattern = rf"""^[ \t]*(?:-[ \t]+)?(?:name[ \t]*=[ \t]*)?["']?{name}(?![\w.-])"""
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


_LATIN_1_SETUP = (
    b"# -*- coding: latin-1 -*-\n# Autor: Jos\xe9\nfrom setuptools import setup\n\n"
    b"setup(name='sample')\n"
)


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
        detection=Detection.HEURISTIC,
    )

    def __init__(self, *, advisories: Sequence[Advisory] | None = None) -> None:
        self._advisories = tuple(advisories) if advisories is not None else load_advisories()

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a compromised pin, the clean release and a setup.py this rule cannot decode."""
        return materialise(
            (
                _samples.sample(
                    "requirements pinning a compromised ultralytics release",
                    FixtureOutcome.FINDING,
                    {"requirements.txt": "ultralytics==8.3.41\n"},
                ),
                _samples.sample(
                    "requirements pinning the clean ultralytics release",
                    FixtureOutcome.CLEAN,
                    {"requirements.txt": "ultralytics==8.3.43\n"},
                ),
                _samples.sample(
                    "a Latin-1 setup.py, which pip runs and this rule cannot read as UTF-8",
                    FixtureOutcome.INCONCLUSIVE,
                    {"setup.py": _LATIN_1_SETUP},
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Match dependency manifests against the advisory dataset; scan setup.py for fetches."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files():
            if _is_manifest(path):
                yield from self._scan_manifest(path, ctx)
        for path in target.iter_files((".py",)):
            if path.name.lower() == "setup.py":
                yield from self._scan_setup(path, ctx)

    def _scan_manifest(self, path: Path, ctx: RuleContext) -> Iterator[Finding]:
        prefix = read_text_prefix(path, errors="ignore")
        if prefix is None:
            yield self._unscanned(
                path, "Dependency manifest not scanned", "it could not be read", ctx
            )
            return
        text, truncated = prefix
        pins = _exact_pins(text)
        for advisory in self._advisories:
            pinned = self._affected_pin(advisory, text, pins)
            if pinned is not None:
                yield self._finding(path, advisory, pinned)
        if truncated:
            yield self._unscanned(path, "Dependency manifest not scanned", _PAST_THE_BOUND, ctx)

    @staticmethod
    def _affected_pin(advisory: Advisory, text: str, pins: set[_Pin]) -> str | None:
        """Return the pin this advisory covers, spelled with the manifest's version, or None.

        A wildcard advisory is about the package *name* — a dependency-confusion
        squat is malicious at every version — so a mention is enough there.
        """
        if _ANY_VERSION in advisory.versions:
            return advisory.package if _mentions(text, advisory.package) else None
        package = canonical_name(advisory.package)
        for pin in sorted(pins):
            if pin.name == package and advisory.matches(pin.version, arbitrary=pin.arbitrary):
                operator = "===" if pin.arbitrary else "=="
                return f"{advisory.package}{operator}{pin.version}"
        return None

    def _finding(self, path: Path, advisory: Advisory, pinned: str) -> Finding:
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

    def _scan_setup(self, path: Path, ctx: RuleContext) -> Iterator[Finding]:
        prefix = read_text_prefix(path)
        if prefix is None:
            yield self._unscanned(path, _SETUP_UNSCANNED, "it could not be read as UTF-8", ctx)
            return
        source, truncated = prefix
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
        if truncated:
            yield self._unscanned(path, _SETUP_UNSCANNED, _PAST_THE_BOUND, ctx)

    def _unscanned(self, path: Path, title: str, reason: str, ctx: RuleContext) -> Finding:
        ctx.shortfall(unread_component(self.meta.id, path, reason))
        return Finding(
            rule_id=self.meta.id,
            severity=Severity.LOW,
            title=title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(summary=f"{title}: {reason}", detail=f"file={path.name}"),
            verdict=unscanned_verdict("the file was not read whole, so nothing in it was cleared"),
        )
