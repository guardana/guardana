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

# Explicit bound for example file reads: a config file nobody can fully
# read is reported, never silently skipped or truncated.
_READ_LIMIT_BYTES = 256 * 1024


def _read_guarded(path: Path) -> tuple[str | None, str | None]:
    """Read a config file with a regular-file guard, a size bound, and strict decoding.

    Returns (text, None) on success, or (None, reason) when the file must be
    reported instead of scanned. Only stdlib Path operations are used, so the
    rule stays on the supported extension surface.
    """
    try:
        if not path.is_file():
            return None, "not a regular file"
        with path.open("rb") as handle:
            raw = handle.read(_READ_LIMIT_BYTES + 1)
    except OSError as exc:
        return None, f"could not read: {exc}"
    if len(raw) > _READ_LIMIT_BYTES:
        return None, f"larger than {_READ_LIMIT_BYTES} bytes"
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError as exc:
        return None, f"not valid UTF-8: {exc}"


def _scan_text(text: str) -> Iterator[re.Match[str]]:
    yield from _ACME_KEY.finditer(text)


class _ListedThenGone(ArtifactTarget):
    """A directory whose config file is removed after the scan listed it and before it is read.

    The engine reports a path it cannot list as an unread source of its own, so a rule only
    meets an unreadable file it was already handed, which is this case.
    """

    def iter_files(self, suffixes: tuple[str, ...] | None = None) -> Iterator[Path]:
        """List as the base target does, removing each file before it is handed on."""
        for path in super().iter_files(suffixes):
            path.unlink(missing_ok=True)
            yield path


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
        text, reason = _read_guarded(path)
        if text is None:
            # A config file we could not read is not a config file we cleared —
            # silence here would be the fail-open this project exists to avoid.
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=str(path),
                evidence=Evidence(summary=f"could not read {path.name}: {reason}"),
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
        (root / "unreadable" / "settings.env").write_text("ACME_KEY=${ACME_KEY_FROM_VAULT}\n")
        return (
            RuleFixture(
                "a live key checked in", ArtifactTarget(root / "finding"), FixtureOutcome.FINDING
            ),
            RuleFixture("a vault reference", ArtifactTarget(root / "clean"), FixtureOutcome.CLEAN),
            RuleFixture(
                "a config path that cannot be read",
                _ListedThenGone(root / "unreadable"),
                FixtureOutcome.INCONCLUSIVE,
                note="a file removed after the scan listed it: read_text raises OSError",
            ),
        )
