import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import OWASP_LLM02

_SUFFIXES = (".env", ".yaml", ".yml", ".ini", ".cfg")

# Acme's own convention: internal service keys always start with this
# prefix. A real hardcoded_secret check would cover more shapes; this one
# is deliberately narrow to keep the example precise and dependency-free.
_ACME_KEY = re.compile(r"ACME_LIVE_KEY_[A-Za-z0-9]{16,}")


def _scan_text(text: str) -> Iterator[re.Match[str]]:
    yield from _ACME_KEY.finditer(text)


class HardcodedAcmeKeyRule(Rule):
    """Flags an Acme live API key checked into a config file."""

    meta = RuleMeta(
        id="acme.supply_chain.hardcoded_key",
        title="Acme live API key hardcoded in a config file",
        severity=Severity.CRITICAL,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM02,),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan Acme config files for a live key."""
        if not isinstance(target, ArtifactTarget):
            return
        for path in target.iter_files(_SUFFIXES):
            yield from self._scan(path)

    def _scan(self, path: Path) -> Iterator[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return
        for match in _scan_text(text):
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=str(path),
                evidence=Evidence(
                    summary=f"hardcoded Acme live key: {match.group(0)[:16]}…",
                    detail=f"file={path.name}",
                ),
            )
