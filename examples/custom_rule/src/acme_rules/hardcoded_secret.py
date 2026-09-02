import re
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.evaluator import Verdict
from guardana.core.report import Evidence, Finding
from guardana.core.rule import FixtureOutcome, Rule, RuleContext, RuleError, RuleFixture, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.target.protocols import FileReader
from guardana.core.taxonomy import OWASP_LLM02_2025, OWASP_LLM02_2026

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
        taxonomy=(
            OWASP_LLM02_2025,
            OWASP_LLM02_2026,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan Acme config files for a live key."""
        if not isinstance(target, FileReader):
            raise RuleError(f"{self.meta.id} needs a file target, got {type(target).__name__}")
        for path in target.iter_files(_SUFFIXES):
            yield from self._scan(path)

    def _scan(self, path: Path) -> Iterator[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError as exc:
            # A config file we could not read is not a config file we cleared —
            # silence here would be the fail-open this project exists to avoid.
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=str(path),
                evidence=Evidence(summary=f"could not read {path.name}: {exc}"),
                verdict=Verdict("inconclusive", 0.0, "file unreadable", self.meta.id),
            )
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

    def fixtures(self) -> Iterable[RuleFixture]:
        """Three samples: a live key, a vault reference, and a file nobody can read."""
        root = Path(tempfile.mkdtemp(prefix="acme-fixture-"))
        (root / "finding").mkdir()
        (root / "finding" / "settings.env").write_text("ACME_KEY=ACME_LIVE_KEY_9f8a7b6c5d4e3f21\n")
        (root / "clean").mkdir()
        (root / "clean" / "settings.env").write_text("ACME_KEY=${ACME_KEY_FROM_VAULT}\n")
        (root / "unreadable").mkdir()
        # A directory named settings.env would never reach `iter_files`: `os.walk`
        # sorts directories into `dirnames`, not `filenames`, so that shape would
        # silently be a CLEAN fixture rather than an INCONCLUSIVE one — exactly the
        # failure this fixture exists to catch. A dangling symlink is a file by
        # `os.walk`'s own reckoning, and `Path.read_text` raises `OSError` on it.
        (root / "unreadable" / "settings.env").symlink_to(root / "unreadable" / "gone")
        return (
            RuleFixture(
                "a live key checked in", ArtifactTarget(root / "finding"), FixtureOutcome.FINDING
            ),
            RuleFixture("a vault reference", ArtifactTarget(root / "clean"), FixtureOutcome.CLEAN),
            RuleFixture(
                "a config path that cannot be read",
                ArtifactTarget(root / "unreadable"),
                FixtureOutcome.INCONCLUSIVE,
                note="a dangling symlink: os.walk lists it as a file, read_text raises OSError",
            ),
        )
