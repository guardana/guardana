import math
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.evaluator.base import Verdict
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import OWASP_LLM02
from guardana.rules._secrets import ALLOWLIST, FILE_SECRET_PATTERNS, is_scannable_text, redact
from guardana.rules.supply_chain._reading import MAX_SCAN_BYTES

_RULE_ID = "guardana.supply_chain.hardcoded_secret"

# --- Opt-in entropy mode -------------------------------------------------------
# Off by default: generic entropy matching is false-positive-prone, so the
# prefix-anchored patterns above are what run for everyone. A user turns this on
# with `rule_config.<id>.entropy: true` to also catch provider-less secrets — a
# database password, a shared JWT signing key — that carry no recognizable prefix.
_ENTROPY_MIN = 3.0
_MIN_CHAR_CLASSES = 2
_SENSITIVE = (
    r"secret|passwd|password|pwd|token|api[_-]?key|access[_-]?key|"
    r"auth[_-]?key|private[_-]?key|client[_-]?secret|credential"
)
_ASSIGNMENT = re.compile(
    rf"(?i)([A-Za-z0-9_.\-]*(?:{_SENSITIVE})[A-Za-z0-9_.\-]*)\s*[:=]\s*"
    r"[\"']([^\"'\n]{12,120})[\"']"
)
# Values that are plainly not real secrets: placeholders, env indirection, examples.
_PLACEHOLDER = re.compile(
    r"(?i)(change[_-]?me|placeholder|example|redacted|dummy|sample|"
    r"your[_-]|xxx|\.\.\.|todo|fixme|<[^>]+>|\$\{[^}]+\}|%\([^)]+\)|"
    r"^env[:.]|^none$|^null$|^true$|^false$)"
)
# NAME suffixes that read as config, not a secret value — reduce opt-in noise.
_NON_SECRET_NAME = re.compile(
    r"(?i)(_id|_name|_length|_len|_type|_url|_uri|_path|_file|_field|"
    r"_header|_regex|_pattern|_prompt|_hint|_format|_expiry|_ttl|_rotation)$"
)


def _shannon(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _looks_like_secret(value: str) -> bool:
    """Report whether a value has real entropy and mixed classes and isn't a placeholder."""
    if _PLACEHOLDER.search(value):
        return False
    classes = (
        int(any(c.islower() for c in value))
        + int(any(c.isupper() for c in value))
        + int(any(c.isdigit() for c in value))
        + int(any(not c.isalnum() for c in value))
    )
    return classes >= _MIN_CHAR_CLASSES and _shannon(value) >= _ENTROPY_MIN


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _scan_prefixed(text: str) -> Iterator[tuple[int, str, str]]:
    for label, pattern in FILE_SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if value in ALLOWLIST:
                continue
            yield _line_number(text, match.start()), label, value


def _scan_entropy(text: str) -> Iterator[tuple[int, str, str]]:
    for match in _ASSIGNMENT.finditer(text):
        name, value = match.group(1), match.group(2)
        if _NON_SECRET_NAME.search(name) or not _looks_like_secret(value):
            continue
        yield _line_number(text, match.start()), name, value


class HardcodedSecretRule(Rule):
    """Scans repository files for hardcoded secrets.

    Runs high-precision, prefix-anchored shapes for everyone; an opt-in entropy
    mode (`rule_config.<id>.entropy: true`) additionally flags a high-entropy
    value assigned to a secret-named variable, catching provider-less secrets at
    the cost of more false positives — which is why it is off by default.
    """

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
        entropy = bool(ctx.config.get("entropy"))
        for path in target.iter_files():
            if is_scannable_text(path):
                yield from self._scan(path, entropy=entropy)

    def _scan(self, path: Path, *, entropy: bool) -> Iterator[Finding]:
        try:
            # Bounded read, mirroring model_format.py: a crafted huge file
            # can't stall the scan.
            with path.open("rb") as fh:
                data = fh.read(MAX_SCAN_BYTES)
            text = data.decode("utf-8", errors="ignore")
        except OSError:
            return
        for lineno, label, secret in _scan_prefixed(text):
            yield self._finding(
                path,
                lineno,
                summary=f"matched {label} pattern: {redact(secret)}",
                rationale=f"matched {label} shape in repository file",
                confidence=0.95,
            )
        if entropy:
            for lineno, name, value in _scan_entropy(text):
                yield self._finding(
                    path,
                    lineno,
                    summary=f"high-entropy value assigned to '{name}': {redact(value)}",
                    rationale="high-entropy value assigned to a secret-named variable",
                    confidence=0.75,
                )

    def _finding(
        self, path: Path, lineno: int, *, summary: str, rationale: str, confidence: float
    ) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=f"{path}:{lineno}",
            evidence=Evidence(summary=summary, detail=f"{path.name}:{lineno}"),
            verdict=Verdict(
                outcome="fail",
                confidence=confidence,
                rationale=rationale,
                evaluator_id=self.meta.id,
            ),
        )
