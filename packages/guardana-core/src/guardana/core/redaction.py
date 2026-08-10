"""One redactor, at one seam, between findings and every way they leave the process.

Guardana's evidence is by construction the most sensitive text in a deployment:
the prompt that worked, the reply that leaked, the tool argument that carried a
key. Until now it was redacted by *convention* — rules were careful. Convention
held while every rule was ours; it does not survive an extension API, where a
third-party rule can put anything in `Evidence.detail` and it flows unchanged into
the JSON report, the SARIF file and the collector envelope.

So the policy lives in one place and every output path goes through it. A policy
applied in thirty places has thirty exceptions, and the one that matters is the
one somebody forgot.
"""

import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING

from guardana.core.fingerprint import digest_of

if TYPE_CHECKING:  # everything downstream builds on this module; the arrow runs one way
    from guardana.core.report.check_error import CheckError
    from guardana.core.report.finding import Finding
    from guardana.core.report.result import ScanResult
    from guardana.core.report.shortfall import CoverageShortfall


class EvidenceMode(StrEnum):
    """How much of what the target said is kept in the evidence.

    Lives with the policy rather than with the manifest that records it: the
    profile has to parse this before anything has built a document, and a
    dependency from configuration into the report format would tie the two
    together for no reason.
    """

    METADATA_ONLY = "metadata_only"
    REDACTED = "redacted"
    FULL = "full"


DEFAULT_MAX_EVIDENCE_BYTES = 16 * 1024
"""Unbounded evidence is a denial-of-service against a collector and a memory risk
locally, and a 64 MiB model reply in a report helps nobody."""

_REDACTED = "[redacted:{label}]"
_TRUNCATED = "… [truncated: evidence exceeded {limit} bytes]"
_WITHHELD_EVIDENCE = "[evidence withheld: metadata_only]"
_WITHHELD_REASON = "[reason withheld: metadata_only]"

# Ordered most specific first: a key that also matches a generic high-entropy
# pattern should be labelled as the key it is.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
    ("google-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{16,}")),
    (
        "credential-assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*"
            r"[\"']?([A-Za-z0-9/_+.-]{12,})[\"']?"
        ),
    ),
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_ALREADY_REDACTED = re.compile(r"\[redacted:[a-z0-9-]+(?::[0-9a-f]{12})?\]")
"""A placeholder this redactor itself wrote, so a second pass leaves it alone.

Redaction runs twice by design — once in the command, so a baseline is written
from the same text a finding is fingerprinted on, and once at the renderer seam
so no output path can skip it. Without this, the second pass reads the first
pass's label as content: `[redacted:github-token:…]` contains `token:` followed
by twelve hex characters, which is exactly what the generic credential pattern
looks for.

**Deliberately narrow, because evidence is attacker-influenced text.** It is the
model's reply. A permissive `\\[redacted:[^\\]]*\\]` would let anything that can
make a model emit `[redacted:` around a credential carry that credential through
the redactor untouched — the redactor's own output format turned into a smuggling
envelope. This matches only what `_placeholder` can produce: a lower-case label
and an optional twelve-hex digest. Nothing that fits inside it is a secret, an
address or an IP, because none of those are twelve lower-case hex characters.
"""


@dataclass(frozen=True, slots=True)
class RedactionPolicy:
    """What evidence a run is allowed to keep.

    `FULL` is the default only because it is what this build did before the
    redactor existed, and changing behaviour silently would be worse than the
    delay. The CLI defaults to `REDACTED`; a library caller opts in.

    There is deliberately no switch for secrets. One existed, it only took effect
    at `FULL`, and it turned the most permissive mode into the only one that would
    write a live credential to disk — a setting whose sole reachable effect was the
    outcome the whole module exists to prevent. A field that cannot be set to the
    unsafe value is better than a field documented as never being set to it.
    """

    mode: EvidenceMode = EvidenceMode.FULL
    redact_emails: bool = True
    redact_ip_addresses: bool = False
    """Off by default: an IP address is frequently the finding itself."""

    hash_identifiers: bool = True
    """Replace a redacted value with a short digest of it rather than a bare label.

    Two occurrences of the same secret then stay comparable across runs — which is
    what makes a finding fingerprint stable — without the value being stored.
    """

    custom_patterns: tuple[str, ...] = ()
    max_evidence_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES

    @property
    def digest(self) -> str:
        """A digest of this policy, recorded in the manifest alongside the evidence."""
        return digest_of(
            str(self.mode),
            str(self.redact_emails),
            str(self.redact_ip_addresses),
            str(self.hash_identifiers),
            "|".join(self.custom_patterns),
            str(self.max_evidence_bytes),
        )


class EvidenceRedactor:
    """Removes what must not be stored, and says when it removed something.

    Silent redaction produces a second kind of dishonest report: one that looks
    complete and is not. So a finding whose evidence was changed says so in the
    text a reader sees, for the same reason `unverified` exists.
    """

    def __init__(self, policy: RedactionPolicy | None = None) -> None:
        self._policy = policy if policy is not None else RedactionPolicy()
        self._custom = tuple(
            (f"custom-{index}", re.compile(pattern))
            for index, pattern in enumerate(self._policy.custom_patterns)
        )

    @property
    def policy(self) -> RedactionPolicy:
        """The policy in force, for recording in the manifest."""
        return self._policy

    def redact_text(self, text: str) -> str:
        """Apply the policy to one piece of text."""
        if not text:
            return text
        mode = self._policy.mode
        if mode is EvidenceMode.METADATA_ONLY:
            return ""
        return self._bound(self._apply(text, self._patterns_for(mode)))

    def _patterns_for(self, mode: EvidenceMode) -> tuple[tuple[str, re.Pattern[str]], ...]:
        """Every pattern this mode removes, most specific first.

        Secrets lead and are never conditional. `full` means "keep the model's
        words", never "store a live credential": the finding is that the secret
        appeared, not what it was, so there is nothing a reader loses.
        """
        patterns: list[tuple[str, re.Pattern[str]]] = [*_SECRET_PATTERNS, *self._custom]
        if mode is not EvidenceMode.FULL:
            if self._policy.redact_emails:
                patterns.append(("email", _EMAIL))
            if self._policy.redact_ip_addresses:
                patterns.append(("ip", _IP))
        return tuple(patterns)

    def redact(self, finding: "Finding") -> "Finding":
        """Return this finding with its evidence brought within the policy."""
        from guardana.core.report.finding import Evidence  # noqa: PLC0415 — one-way dependency

        evidence = finding.evidence
        summary = self.redact_text(evidence.summary)
        detail = self.redact_text(evidence.detail)
        if summary == evidence.summary and detail == evidence.detail:
            return finding
        return replace(
            finding, evidence=Evidence(summary=summary or _WITHHELD_EVIDENCE, detail=detail)
        )

    def redact_error(self, error: "CheckError") -> "CheckError":
        """Return this recorded failure with its reason brought within the policy.

        The reason is an exception message, and an exception message is written by
        whoever raised it — a third-party rule, a provider, a parser handed the
        model's own reply. `post_json` puts 120 bytes of an unparseable response in
        it; a rule may put anything at all. That is the same untrusted, target-shaped
        text `Evidence` carries, so it goes through the same policy: bounding its
        *length* (which this already did) is not the half that keeps a credential
        out of a report.

        Never emptied. Under `metadata_only` the reason is replaced by a note, because
        an error with a blank reason reads as a check that failed for no reason rather
        than one whose reason this run declined to keep.
        """
        reason = self.redact_text(error.reason)
        if reason == error.reason:
            return error
        return replace(error, reason=reason or _WITHHELD_REASON)

    def redact_shortfall(self, gap: "CoverageShortfall") -> "CoverageShortfall":
        """Return this unmet coverage demand with its sentence brought within the policy.

        The detail is Guardana's own prose, which is why it is tempting to leave
        alone — and it is prose *about the user's material*: it quotes a target ref
        (a file path an operator chose), the AI system they named, and the contract
        names they wrote. That is the same shape of borrowed text `errors[].reason`
        carries, and leaving one channel out is precisely how the redactor covered
        three of four before.

        Never emptied: a shortfall with no detail reads as a demand that failed for
        no reason rather than one whose reason this run declined to keep.
        """
        detail = self.redact_text(gap.detail)
        if detail == gap.detail:
            return gap
        return replace(gap, detail=detail or _WITHHELD_REASON)

    def redact_result(self, result: "ScanResult") -> "ScanResult":
        """Apply the policy to every channel of a result — errors and shortfalls included.

        All of them, because "nothing to report" has more than one meaning and the
        redactor's promise is about the seam, not about the channel: a run that kept
        a secret out of its findings and posted it to a collector inside
        `errors[].reason` has leaked it exactly as far.
        """
        return replace(
            result,
            findings=tuple(self.redact(f) for f in result.findings),
            unverified=tuple(self.redact(f) for f in result.unverified),
            waived=tuple(self.redact(f) for f in result.waived),
            errors=tuple(self.redact_error(e) for e in result.errors),
            coverage_shortfall=tuple(self.redact_shortfall(g) for g in result.coverage_shortfall),
        )

    def _apply(self, text: str, patterns: tuple[tuple[str, re.Pattern[str]], ...]) -> str:
        """Replace every match in one pass, so no pattern ever rewrites another's placeholder.

        Substituting pattern by pattern read the *output* of the previous pattern,
        and the ordering that puts specific patterns first was defeated by it: a
        GitHub token became `[redacted:github-[redacted:credential-assignment:…]]`,
        because the generic "token = value" pattern matched the label of the
        placeholder that had just replaced it. The label is the part a reader acts
        on, so losing it costs the redaction most of its usefulness.

        Matches are therefore collected against the original text and spliced in
        once. An earlier pattern owns the span it claimed, which is what "ordered
        most specific first" was always supposed to mean — and the placeholders
        of a previous pass claim their spans first, which is what makes redacting
        twice produce the same text as redacting once.
        """
        claimed: list[tuple[int, int, str]] = [
            (m.start(), m.end(), m.group(0)) for m in _ALREADY_REDACTED.finditer(text)
        ]
        for label, pattern in patterns:
            for match in pattern.finditer(text):
                start, end = match.span()
                if any(
                    start < taken_end and taken_start < end for taken_start, taken_end, _ in claimed
                ):
                    continue
                claimed.append((start, end, self._placeholder(label, match.group(0))))
        if not claimed:
            return text
        claimed.sort()
        pieces: list[str] = []
        cursor = 0
        for start, end, replacement in claimed:
            pieces.append(text[cursor:start])
            pieces.append(replacement)
            cursor = end
        pieces.append(text[cursor:])
        return "".join(pieces)

    def _placeholder(self, label: str, value: str) -> str:
        if not self._policy.hash_identifiers:
            return _REDACTED.format(label=label)
        return _REDACTED.format(label=f"{label}:{digest_of(value)[7:19]}")

    def _bound(self, text: str) -> str:
        limit = self._policy.max_evidence_bytes
        encoded = text.encode("utf-8")
        if len(encoded) <= limit:
            return text
        # Truncation is announced, never silent: a report that quietly drops the
        # half of the evidence that mattered looks complete and is not.
        kept = encoded[:limit].decode("utf-8", errors="ignore")
        return kept + _TRUNCATED.format(limit=limit)
