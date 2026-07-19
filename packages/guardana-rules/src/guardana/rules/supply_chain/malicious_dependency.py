import ast
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import ATLAS_T0018, NIST_SUPPLY_CHAIN, OWASP_LLM03, OWASP_ML06
from guardana.rules.supply_chain._leads import lead_verdict
from guardana.rules.supply_chain._reading import read_text_bounded

# Curated known-malicious package releases from confirmed supply-chain incidents.
# The exact (name, version) pair is the signal — a firm finding, not a lead —
# because a compromised *legitimate* package passes every "unknown import" and
# "unpinned download" check. Keep this list short and sourced; grow it as
# incidents are confirmed. Source: PyPI security blog, 2024-12-11 (ultralytics).
_KNOWN_BAD: dict[str, frozenset[str]] = {
    "ultralytics": frozenset({"8.3.41", "8.3.42", "8.3.45", "8.3.46"}),
}
_MANIFEST_SUFFIXES = (".txt", ".toml", ".lock", ".cfg", ".in")
_MANIFEST_NAMES = frozenset({"Pipfile"})

# A network fetch inside setup.py runs at install time (`pip install`), the exact
# stage a malicious package uses to pull a second-stage payload. setup.py almost
# never legitimately reaches the network, so a fetch here is a lead worth raising.
_NETWORK_CALLS = frozenset({"urlopen", "urlretrieve", "get", "post", "Request"})


def _is_manifest(path: Path) -> bool:
    return path.suffix in _MANIFEST_SUFFIXES or path.name in _MANIFEST_NAMES


_NAME_LINE = re.compile(r"""^\s*name\s*=\s*["']([^"']+)["']""")
_VERSION_LINE = re.compile(r"""^\s*version\s*=\s*["']([^"']+)["']""")


def _version_present(version: str, line: str) -> bool:
    """Whether `version` appears in `line` as a whole version, not a prefix.

    A plain substring test flags `8.3.41` inside `8.3.410` (a different, innocent
    release). Anchoring on non-`[.digit]` boundaries keeps the match exact.
    """
    return re.search(rf"(?<![\d.]){re.escape(version)}(?![\d.])", line) is not None


def _known_bad_hits(text: str) -> Iterator[tuple[str, str]]:
    """Yield (package, version) for each known-bad release pinned in a manifest.

    Handles both shapes: the single-line form of `requirements.txt`/`Pipfile`
    (`ultralytics==8.3.41`) and the multi-line `[[package]]` block used by
    `poetry.lock`/`uv.lock`/`pdm.lock`, where the name and version sit on
    separate lines — the form that authoritatively pins a resolved dependency,
    and that a same-line-only scan missed entirely.
    """
    pending_name: str | None = None
    for line in text.splitlines():
        name_match = _NAME_LINE.match(line)
        if name_match:
            pending_name = name_match.group(1).lower()
            continue
        version_match = _VERSION_LINE.match(line)
        if version_match:
            name, pending_name = pending_name, None
            if name is not None and version_match.group(1) in _KNOWN_BAD.get(name, frozenset()):
                yield name, version_match.group(1)
            continue
        lowered = line.lower()
        for package, bad_versions in _KNOWN_BAD.items():
            if package in lowered:
                for version in bad_versions:
                    if _version_present(version, line):
                        yield package, version


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


class MaliciousDependencyRule(Rule):
    """Flag known-malicious package releases, and install-time network fetches in setup.py."""

    meta = RuleMeta(
        id="guardana.supply_chain.malicious_dependency",
        title="Known-malicious dependency or install-time payload",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM03, OWASP_ML06, ATLAS_T0018, NIST_SUPPLY_CHAIN),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan dependency manifests for known-bad releases, and setup.py for fetches."""
        if not isinstance(target, ArtifactTarget):
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
        for package, version in _known_bad_hits(text):
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=str(path),
                evidence=Evidence(
                    summary=f"known-malicious release pinned: {package}=={version}",
                    detail=f"file={path.name}",
                ),
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
