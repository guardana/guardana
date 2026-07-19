import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.evaluator.base import Verdict
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import OWASP_LLM02
from guardana.rules._secrets import ALLOWLIST, FILE_SECRET_PATTERNS, redact
from guardana.rules.supply_chain._reading import MAX_SCAN_BYTES

_RULE_ID = "guardana.supply_chain.hardcoded_secret"

# Text-like config/source suffixes worth scanning. Deliberately excludes
# markdown/docs and binaries/model formats to keep noise and runtime down.
_SCAN_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".env",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".txt",
        ".sh",
        ".properties",
    }
)

# `Path.suffix` never matches a file literally named ".env" or ".env.local"
# (it treats the whole name as the stem for dotfiles), so those must be
# recognized by name instead of by suffix.
_ENV_DOTFILE = re.compile(r"^\.env(\..+)?$")


def _should_scan(path: Path) -> bool:
    if path.suffix in _SCAN_SUFFIXES:
        return True
    return bool(_ENV_DOTFILE.match(path.name))


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _scan_text(text: str) -> Iterator[tuple[int, str, str]]:
    for label, pattern in FILE_SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if value in ALLOWLIST:
                continue
            yield _line_number(text, match.start()), label, value


class HardcodedSecretRule(Rule):
    """Scans repository files for high-precision, prefix-anchored secret shapes."""

    meta = RuleMeta(
        id=_RULE_ID,
        title="Hardcoded secret in repository file",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM02,),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every text-like file under the target for secret shapes."""
        if not isinstance(target, ArtifactTarget):
            return
        for path in target.iter_files():
            if _should_scan(path):
                yield from self._scan(path)

    def _scan(self, path: Path) -> Iterator[Finding]:
        try:
            # Bounded read, mirroring model_format.py: a crafted huge file
            # can't stall the scan.
            with path.open("rb") as fh:
                data = fh.read(MAX_SCAN_BYTES)
            text = data.decode("utf-8", errors="ignore")
        except OSError:
            return
        for lineno, label, secret in _scan_text(text):
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=f"{path}:{lineno}",
                evidence=Evidence(
                    summary=f"matched {label} pattern: {redact(secret)}",
                    detail=f"{path.name}:{lineno}",
                ),
                verdict=Verdict(
                    outcome="fail",
                    confidence=0.95,
                    rationale=f"matched {label} shape in repository file",
                    evaluator_id=self.meta.id,
                ),
            )
