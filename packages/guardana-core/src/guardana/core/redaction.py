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

import atexit
import re
import threading
from bisect import bisect_right
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field, fields, is_dataclass, replace
from datetime import date
from enum import Enum, StrEnum
from functools import cache
from types import NoneType
from typing import TYPE_CHECKING, Any, ClassVar, Protocol, TypeVar, cast

from guardana.core.fingerprint import digest_of
from guardana.core.gate import StopReason

if TYPE_CHECKING:  # everything downstream builds on this module; the arrow runs one way
    from guardana.core.evaluator.regex import _SearchWorker
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

CUSTOM_PATTERN_TIMEOUT_SECONDS = 2.0
"""How long one profile pattern may search one text before the redaction fails.

A profile's `custom_patterns` are the operator's own regexes, applied to text the target
chose, so they run in a worker process that is killed at this bound rather than on the
thread that holds the run.
"""

MAX_CUSTOM_PATTERN_CHARS = 16 * 1024 * 1024
"""The longest text a profile pattern is searched in; a longer one fails the redaction."""


class RedactionBoundError(Exception):
    """A profile pattern could not be searched within its bounds, so the text is not released.

    Raised rather than returned: the text it was meant to clean may hold exactly what the
    pattern exists to remove, and no caller may treat it as redacted. `pattern` names the
    entry by its position in `custom_patterns`, never by its source, which may itself be a
    value the operator wants withheld; `failure` says which bound it missed; `stopped_by`
    is why the run had already stopped, when it had, so the stop keeps its exit code.
    """

    def __init__(self, pattern: str, failure: str, *, stopped_by: StopReason | None = None) -> None:
        super().__init__(f"{pattern} {failure}")
        self.pattern = pattern
        self.failure = failure
        self.stopped_by = stopped_by


OMITTED_WHEN_DEFAULT = "guardana.omitted_when_default"
"""Field metadata: a setting left out of a profile's digest while it holds its default.

A switch added later marks itself so, and every profile that does not use it keeps the
digest its saved runs already record.
"""

_REDACTED = "[redacted:{label}]"
_TRUNCATED = "… [truncated: evidence exceeded {limit} bytes]"
_WITHHELD_EVIDENCE = "[evidence withheld: metadata_only]"
_WITHHELD_SUMMARY = re.compile(r"\[evidence withheld: metadata_only(?::[0-9a-f]{12})?\]")
_WITHHELD_REASON = "[reason withheld: metadata_only]"

_WORD_START = r"(?<![A-Za-z0-9_])"
"""Where a secret may start: after anything but an ASCII letter, digit or underscore.

Not `\b`, which treats every Unicode letter as a word character, so a token written
straight after Chinese or accented text would have no boundary before it and stay.
"""

# Ordered most specific first: a key that also matches a generic high-entropy
# pattern should be labelled as the key it is, as a span keeps the label of the
# earliest pattern that claimed it (`_claim`). A private key leads because its span
# holds the whole block. A block with no END runs to the end of the text, since any
# line that stopped it sooner would leave the key material after that line in the
# clear; the END branch gives up at the next BEGIN, so the scan stays one pass.
_PRIVATE_KEY_LABEL = r"[A-Z ]*PRIVATE KEY(?: BLOCK)?"
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private-key",
        re.compile(
            rf"-----BEGIN {_PRIVATE_KEY_LABEL}-----"
            rf"(?:(?:(?!-----BEGIN )[\s\S])*?-----END {_PRIVATE_KEY_LABEL}-----|[\s\S]*)"
        ),
    ),
    ("aws-key", re.compile(rf"{_WORD_START}(?:AKIA|ASIA)[0-9A-Z]{{16}}")),
    ("github-pat", re.compile(rf"{_WORD_START}github_pat_[A-Za-z0-9_]{{22,}}")),
    ("github-token", re.compile(rf"{_WORD_START}gh[pousr]_[A-Za-z0-9]{{16,}}")),
    ("slack-token", re.compile(rf"{_WORD_START}xox[abprs]-[A-Za-z0-9-]{{10,}}")),
    ("anthropic-key", re.compile(rf"{_WORD_START}sk-ant-[A-Za-z0-9_-]{{16,}}")),
    ("openai-key", re.compile(rf"{_WORD_START}sk-[A-Za-z0-9_-]{{16,}}")),
    ("google-key", re.compile(rf"{_WORD_START}AIza[0-9A-Za-z_-]{{35}}")),
    (
        "jwt",
        re.compile(
            rf"{_WORD_START}eyJ[A-Za-z0-9_-]{{8,}}\.[A-Za-z0-9_-]{{8,}}\.[A-Za-z0-9_-]{{8,}}"
        ),
    ),
    ("bearer-token", re.compile(rf"(?i){_WORD_START}bearer\s+(?P<value>[A-Za-z0-9._-]{{16,}})")),
    (
        "credential-assignment",
        re.compile(
            rf"(?i){_WORD_START}(?:api[_-]?key|secret|password|passwd|token)(?![A-Za-z0-9_])\s*[:=]\s*"
            r"[\"']?(?P<value>[A-Za-z0-9/_+.-]{12,})[\"']?"
        ),
    ),
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class _Dataclass(Protocol):
    """Any dataclass instance, as `dataclasses.fields` and `replace` accept one."""

    __dataclass_fields__: ClassVar[dict[str, Any]]


_Record = TypeVar("_Record", bound=_Dataclass)
_Walked = TypeVar("_Walked")

_SCALARS = (int, float, NoneType, date)
"""Values the span walk returns as they are: none of them holds text a pattern could match.

`bool` is an `int` and `datetime` a `date`; an `Enum` is checked before `str`, as a
`StrEnum` member is both.
"""

_COLLECTIONS = (tuple, list, set, frozenset)
"""What the span walk rebuilds item by item; only a tuple is walked by `redact`."""

_WRITTEN_LABELS = (*(label for label, _ in _SECRET_PATTERNS), "email", "ip", "query", "url")
"""Every label the engine writes with an optional digest; `custom-<n>` and `credential` aside."""

_ALREADY_REDACTED = re.compile(
    r"\[redacted:(?:(?:"
    + "|".join(re.escape(label) for label in _WRITTEN_LABELS)
    + r"|custom-(?:0|[1-9][0-9]*))(?::[0-9a-f]{12})?|credential)\]"
)
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
envelope. This matches only what the engine writes: one of its own labels with an
optional twelve-hex digest, or `[redacted:credential]`. Any other bracketed text is
ordinary text the patterns read. A secret that is itself twelve lower-case hex
characters still fits the digest slot of a real label.
"""

_PLACEHOLDER_SHAPE = re.compile(r"\[redacted:[a-z0-9-]+(?::[0-9a-f]{12})?\]")
"""Anything shaped like a placeholder, whatever wrote it; detection errs toward finding one."""

_SENT_VALUE_PLACEHOLDER = "[redacted:credential]"
_SHORTEST_SECRET = 4
"""A shorter sent value is not withheld, as it would blank ordinary text wherever it occurs."""

_TRUNCATED_MARKER = re.compile(re.escape(_TRUNCATED).replace(re.escape("{limit}"), r"\d+"))
_WITHHELD_REASON_MARKER = re.compile(re.escape(_WITHHELD_REASON))


def holds_redaction_marker(text: str) -> bool:
    """Tell whether `text` carries a placeholder this redactor writes in place of what it removed.

    Text holding one is no longer what the target said, so whoever grades it is grading
    the redactor's output. A placeholder counts whatever label it has.
    """
    return any(
        pattern.search(text) is not None
        for pattern in (
            _PLACEHOLDER_SHAPE,
            _WITHHELD_SUMMARY,
            _WITHHELD_REASON_MARKER,
            _TRUNCATED_MARKER,
        )
    )


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
    keep_exchanges: bool = field(default=False, metadata={OMITTED_WHEN_DEFAULT: True})
    """Keep a probe's chat exchanges, redacted span by span, beside the saved run."""

    def __post_init__(self) -> None:
        """Refuse keeping exchanges under `metadata_only`, which forbids what they hold."""
        if self.keep_exchanges and self.mode is EvidenceMode.METADATA_ONLY:
            raise ValueError(
                "keep_exchanges stores what the target said, which evidence mode "
                "metadata_only forbids; set one of the two differently"
            )

    @property
    def digest(self) -> str:
        """A digest of this policy, recorded in the manifest alongside the evidence.

        `keep_exchanges` joins only when set, so a policy that does not keep exchanges
        digests as it did before the switch existed.
        """
        parts = [
            str(self.mode),
            str(self.redact_emails),
            str(self.redact_ip_addresses),
            str(self.hash_identifiers),
            "|".join(self.custom_patterns),
            str(self.max_evidence_bytes),
        ]
        if self.keep_exchanges:
            parts.append("keep_exchanges")
        return digest_of(*parts)


class EvidenceRedactor:
    """Removes what must not be stored, and says when it removed something.

    Silent redaction produces a second kind of dishonest report: one that looks
    complete and is not. So a finding whose evidence was changed says so in the
    text a reader sees, for the same reason `unverified` exists.

    `secrets` are values the run sends to authenticate. No pattern may recognise
    them, so each is replaced as written, in every mode and before any pattern runs;
    one shorter than four characters is left alone, as it would blank ordinary text.
    """

    def __init__(
        self, policy: RedactionPolicy | None = None, *, secrets: Iterable[str] = ()
    ) -> None:
        self._policy = policy if policy is not None else RedactionPolicy()
        kept = {value for value in secrets if len(value) >= _SHORTEST_SECRET}
        # Longest first, so a value holding a shorter one is replaced whole.
        self._secrets = tuple(sorted(kept, key=len, reverse=True))
        self._custom = tuple(
            (f"custom-{index}", re.compile(pattern))
            for index, pattern in enumerate(self._policy.custom_patterns)
        )
        self._isolated = frozenset(pattern for _, pattern in self._custom)

    @property
    def policy(self) -> RedactionPolicy:
        """The policy in force, for recording in the manifest."""
        return self._policy

    @property
    def secrets(self) -> tuple[str, ...]:
        """The sent values this redactor withholds as written, the longest first."""
        return self._secrets

    def redact_text(self, text: str) -> str:
        """Apply the policy to one piece of text."""
        if not text:
            return text
        mode = self._policy.mode
        if mode is EvidenceMode.METADATA_ONLY:
            return ""
        return self._bound(self._apply(text, self._patterns_for(mode)))

    def redact_spans(self, text: str) -> str:
        """Replace each matched secret or identifier span in `text`, keeping every other character.

        For text that may be graded again: nothing is withheld under `metadata_only` and
        nothing is cut to a size bound, because an emptied or truncated reply would be
        graded as something the target never said. Lone surrogates become U+FFFD.
        """
        return self._label(text)

    def redact_spans_in(self, value: _Walked) -> _Walked:
        """Return `value` with every str inside it redacted as `redact_spans` redacts it.

        Walks dataclasses (rebuilt over their `init` fields), tuples, lists, sets,
        frozensets and mapping values; a changed mapping comes back as a `dict` and its
        keys are kept. Identifier fields and records are left alone, as `redact` leaves them, and
        nothing is emptied or truncated. Any other value that is not an `Enum`, a number,
        `None` or a date raises `TypeError`, a path and bytes included, so a value whose
        text this walk does not read can never pass through unredacted.
        """
        return cast("_Walked", self._value(value, spans_only=True))

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
        """Return this finding with every text it carries brought within the policy.

        Evidence, title, location and the verdict's rationale alike: a judge's reply
        lands in the rationale and an imported claim supplies the title and the ref,
        so each is the same untrusted text the evidence is.
        """
        return self._record(finding)

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
        return self._record(error)

    def redact_shortfall(self, gap: "CoverageShortfall") -> "CoverageShortfall":
        """Return this coverage shortfall with its sentence brought within the policy.

        The detail is Guardana's own prose, which is why it is tempting to leave
        alone — and it is prose *about the user's material*: it quotes a target ref
        (a file path an operator chose), the AI system they named, and the contract
        names they wrote. That is the same shape of borrowed text `errors[].reason`
        carries, and leaving one channel out is precisely how the redactor covered
        three of four before.

        Never emptied: a shortfall with no detail reads as a demand that failed for
        no reason rather than one whose reason this run declined to keep.
        """
        return self._record(gap)

    def redact_result(self, result: "ScanResult") -> "ScanResult":
        """Apply the policy to every text of every channel of a result.

        All of them, because "nothing to report" has more than one meaning and the
        redactor's promise is about the seam, not about the channel: a run that kept
        a secret out of its findings and posted it to a collector inside
        `errors[].reason` has leaked it exactly as far. The result is walked field by
        field rather than channel by channel, so a channel added later is covered
        without anyone remembering to add it here.
        """
        return self._record(result)

    def _record(self, record: _Record, *, spans_only: bool = False) -> _Record:
        """Return `record` with every string inside it redacted, or `record` itself.

        Narrative text from the target or a third party (evidence, reasons,
        rationales) gets the full policy: emptied under `metadata_only` and bounded
        in size. Every other string is a name or a location a reader navigates by,
        so only the matched spans are replaced and it is never emptied or truncated.
        With `spans_only`, narrative text is redacted by span as well.
        """
        if isinstance(record, _identifier_types()):
            return record
        narrative = {} if spans_only else _narrative_fields()
        identifiers = _identifier_record_fields()
        changes: dict[str, object] = {}
        for spec in fields(record):
            if not spec.init or spec.name in _IDENTIFIER_FIELDS:
                continue
            if (type(record), spec.name) in identifiers:
                continue
            current = getattr(record, spec.name)
            withheld = narrative.get((type(record), spec.name))
            if withheld is not None and isinstance(current, str):
                cleaned: object = self.redact_text(current)
                if cleaned != current:
                    cleaned = cleaned or self._withheld(withheld, current)
            else:
                cleaned = self._value(current, spans_only=spans_only)
            if cleaned is not current:
                changes[spec.name] = cleaned
        return replace(record, **changes) if changes else record

    def _withheld(self, note: str, text: str) -> str:
        """Return what stands in for withheld text; an evidence summary keeps a digest.

        A baseline waiver matches on the evidence summary, so two findings of one rule in
        one file need different notes, or waiving one waives both. The digest is taken
        of the text as `redacted` would show it, so it says nothing that mode does not.
        """
        if note != _WITHHELD_EVIDENCE:
            return note
        if _WITHHELD_SUMMARY.fullmatch(text):
            return text
        shown = self._apply(text, self._patterns_for(EvidenceMode.REDACTED))
        return f"{note[:-1]}:{digest_of(shown)[7:19]}]"

    def _value(self, value: object, *, spans_only: bool = False) -> object:
        """Redact one field's value, returning the same object when nothing changed.

        With `spans_only`, lists and sets are walked too and a value of any type the
        walk does not know raises `TypeError` instead of being returned unexamined.
        """
        if isinstance(value, Enum):
            return value
        if isinstance(value, str):
            return self._label(value)
        if isinstance(value, _COLLECTIONS) and type(value) in (
            _COLLECTIONS if spans_only else (tuple,)
        ):
            walked = [self._value(item, spans_only=spans_only) for item in value]
            unchanged = all(a is b for a, b in zip(walked, value, strict=True))
            return value if unchanged else type(value)(walked)
        if isinstance(value, Mapping):
            entries = {key: self._value(item, spans_only=spans_only) for key, item in value.items()}
            return value if all(entries[key] is item for key, item in value.items()) else entries
        if is_dataclass(value) and not isinstance(value, type):
            return self._record(value, spans_only=spans_only)
        if spans_only and not isinstance(value, _SCALARS):
            raise TypeError(f"the span walk does not know a {type(value).__qualname__}")
        return value

    def _label(self, text: str) -> str:
        """Redact a name or a location: matched spans only, never emptied or truncated."""
        if not text:
            return text
        return self._apply(text, self._patterns_for(self._policy.mode))

    def _apply(self, text: str, patterns: tuple[tuple[str, re.Pattern[str]], ...]) -> str:
        """Replace every match in one pass, so no pattern ever rewrites another's placeholder.

        Substituting pattern by pattern read the *output* of the previous pattern,
        and the ordering that puts specific patterns first was defeated by it: a
        GitHub token became `[redacted:github-[redacted:credential-assignment:…]]`,
        because the generic "token = value" pattern matched the label of the
        placeholder that had just replaced it. The label is the part a reader acts
        on, so losing it costs the redaction most of its usefulness.

        Matches are therefore collected against the original text and spliced in
        once, most specific pattern first; see `_claim` for how a later match that
        collides with an earlier one is taken. A previous pass's placeholders are kept
        as written and a match inside one is ignored, which is what makes redacting
        twice produce the same text as redacting once.
        """
        text = without_lone_surrogates(text)
        for value in self._secrets:
            text = text.replace(value, _SENT_VALUE_PLACEHOLDER)
        kept = [m.span() for m in _ALREADY_REDACTED.finditer(text)]
        claimed = [(start, end, len(patterns)) for start, end in kept]
        for rank, (label, pattern) in enumerate(patterns):
            found = (
                _isolated_spans(label, pattern, text)
                if pattern in self._isolated
                else _spans(pattern.finditer(text))
            )
            claimed = _claim(claimed, rank, found)
        spans = _outside(kept, claimed)
        if not spans:
            return text
        pieces: list[str] = []
        cursor = 0
        for start, end, rank in spans:
            pieces.append(text[cursor:start])
            pieces.append(self._placeholder(patterns[rank][0], text[start:end]))
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


_IDENTIFIER_FIELDS = frozenset({"rule_id", "rules_run", "evaluator_id", "assessor", "stage"})
"""Fields that name an engine object rather than carry text from a target.

A custom pattern broad enough to match `LLM03` or `supply_chain` would otherwise rewrite
the framework mapping and the rule a finding belongs to, and with them its identity in
every comparison.
"""


def at_redacted_mode(policy: RedactionPolicy) -> EvidenceRedactor:
    """Return a redactor applying `policy` at `redacted` mode, for text that must never blank.

    A run's source or target ref identifies what was verified, so `metadata_only` must not
    empty it where it leaves the machine; it is redacted as strictly as anything kept.
    """
    return EvidenceRedactor(replace(policy, mode=EvidenceMode.REDACTED))


@dataclass(frozen=True, slots=True)
class MessageQuoting:
    """How a message quotes what an endpoint said: under the run's policy, without its secrets."""

    redactor: EvidenceRedactor

    @classmethod
    def of(cls, privacy: RedactionPolicy, secrets: Iterable[str] = ()) -> "MessageQuoting":
        """Quote under `privacy`, withholding `secrets` as `EvidenceRedactor` does."""
        return cls(EvidenceRedactor(privacy, secrets=secrets))

    @property
    def secrets(self) -> tuple[str, ...]:
        """The values a quote never holds, the longest first."""
        return self.redactor.secrets

    @property
    def withholds_text(self) -> bool:
        """Whether the policy forbids quoting what the endpoint said."""
        return self.redactor.policy.mode is EvidenceMode.METADATA_ONLY

    def spans(self, text: str) -> str:
        """Replace each secret the run sends, then each span the policy removes."""
        return self.redactor.redact_spans(text)

    def detail(self, text: str) -> str:
        """Quote `text` as `spans` does, or under `metadata_only` give only its size."""
        if self.withholds_text:
            return (
                f"its detail ({len(text.encode('utf-8'))} bytes) is not shown under "
                f"evidence mode metadata_only"
            )
        return self.spans(text)


@cache
def _identifier_record_fields() -> frozenset[tuple[type, str]]:
    """Name the fields that hold a rule's or an evaluator's id under a name others also use."""
    from guardana.core.manifest.records import (  # noqa: PLC0415 — one-way dependency
        EvaluatorRecord,
        RuleRecord,
    )

    return frozenset({(RuleRecord, "id"), (EvaluatorRecord, "id")})


@cache
def _identifier_types() -> tuple[type, ...]:
    """Return the records that only identify and never carry target text."""
    from guardana.core.taxonomy import TaxonomyRef  # noqa: PLC0415 — one-way dependency

    return (TaxonomyRef,)


_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def without_lone_surrogates(text: str) -> str:
    """Replace each unpaired surrogate with U+FFFD, which every encoder downstream accepts.

    JSON read from a target can carry one, and a string holding it cannot be encoded as
    UTF-8, so the first renderer or digest to try would raise.
    """
    if _LONE_SURROGATE.search(text) is None:
        return text
    return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")


_Claimed = list[tuple[int, int, int]]
_Span = tuple[int, int, int, int]
"""One match as `(start, end, value_start, value_end)`; without a matched `value`, the match."""


def _spans(matches: Iterator[re.Match[str]]) -> Iterator[_Span]:
    """Read in-process matches as spans, the shape the worker answers in.

    A `value` group that took no part in the match stands for the whole match, so a
    collision never claims less than the match.
    """
    for match in matches:
        start, end = match.span()
        value = match.span("value") if "value" in match.re.groupindex else (-1, -1)
        yield start, end, *((start, end) if value == (-1, -1) else value)


_workers: dict[float, "_SearchWorker"] = {}
_workers_lock = threading.Lock()


def _isolated_spans(label: str, pattern: re.Pattern[str], text: str) -> tuple[_Span, ...]:
    """Match a profile pattern in the worker process, raising `RedactionBoundError` past a bound."""
    from guardana.core.evaluator.regex import (  # noqa: PLC0415
        _NotSearchedError,
        _SearchTimeoutError,
    )

    named = f"custom_patterns[{label.removeprefix('custom-')}]"
    if len(text) > MAX_CUSTOM_PATTERN_CHARS:
        raise RedactionBoundError(
            named,
            f"was not searched in a {len(text)}-character text, over the "
            f"{MAX_CUSTOM_PATTERN_CHARS}-character bound",
        )
    try:
        return _custom_worker().spans(pattern.pattern, text)
    except _SearchTimeoutError as exc:
        raise RedactionBoundError(
            named, f"did not finish within {CUSTOM_PATTERN_TIMEOUT_SECONDS:g} s on one text"
        ) from exc
    except _NotSearchedError as exc:
        raise RedactionBoundError(named, f"could not be searched ({exc})") from exc


def _custom_worker() -> "_SearchWorker":
    """Return the worker for the current bound, started on first use and stopped at exit."""
    from guardana.core.evaluator.regex import _SearchWorker  # noqa: PLC0415 — one-way dependency

    timeout = CUSTOM_PATTERN_TIMEOUT_SECONDS
    with _workers_lock:
        worker = _workers.get(timeout)
        if worker is None:
            worker = _workers[timeout] = _SearchWorker(timeout)
            atexit.register(worker.stop)
    return worker


def _claim(claimed: _Claimed, rank: int, matches: Iterable[_Span]) -> _Claimed:
    """Add one pattern's matches to `claimed`, sorted and disjoint `(start, end, rank)` spans.

    A match clear of every claimed span is claimed whole. One that collides is claimed
    by its `value` group, or whole when it has none, unless claimed spans already cover
    that value, so a generic pattern around a specific key changes nothing. A value
    reaching past them merges with the spans it overlaps under the lowest rank, so no
    character of a longer credential survives.
    """
    starts = [start for start, _, _ in claimed]
    fresh: _Claimed = []
    for start, end, value_start, value_end in matches:
        if start == end:
            continue
        if not _collides(claimed, starts, start, end):
            fresh.append((start, end, rank))
            continue
        if not _covered(claimed, starts, value_start, value_end):
            fresh.append((value_start, value_end, rank))
    if not fresh:
        return claimed
    merged: _Claimed = []
    for start, end, span_rank in sorted([*claimed, *fresh]):
        if merged and start < merged[-1][1]:
            last_start, last_end, last_rank = merged[-1]
            merged[-1] = (last_start, max(last_end, end), min(last_rank, span_rank))
        else:
            merged.append((start, end, span_rank))
    return merged


def _collides(claimed: _Claimed, starts: list[int], start: int, end: int) -> bool:
    """Whether `start`..`end` overlaps a claimed span, given spans sorted and disjoint."""
    index = bisect_right(starts, start)
    before = claimed[index - 1] if index else None
    after = claimed[index] if index < len(claimed) else None
    return any(
        _overlaps(start, end, span[0], span[1]) for span in (before, after) if span is not None
    )


def _covered(claimed: _Claimed, starts: list[int], start: int, end: int) -> bool:
    """Whether claimed spans, touching end to end, cover every character of `start`..`end`."""
    index = bisect_right(starts, start) - 1
    if index < 0 or claimed[index][1] <= start:
        return False
    reach = claimed[index][1]
    while reach < end:
        index += 1
        if index == len(claimed) or claimed[index][0] != reach:
            return False
        reach = claimed[index][1]
    return True


def _outside(kept: list[tuple[int, int]], claimed: _Claimed) -> _Claimed:
    """Return the parts of `claimed` that lie outside `kept`, both sorted and disjoint."""
    spans: _Claimed = []
    first = 0
    for start, end, rank in claimed:
        while first < len(kept) and kept[first][1] <= start:
            first += 1
        cursor = start
        index = first
        while index < len(kept) and kept[index][0] < end:
            kept_start, kept_end = kept[index]
            if cursor < kept_start:
                spans.append((cursor, kept_start, rank))
            cursor = max(cursor, kept_end)
            index += 1
        if cursor < end:
            spans.append((cursor, end, rank))
    return spans


def _overlaps(start: int, end: int, taken_start: int, taken_end: int) -> bool:
    return start < taken_end and taken_start < end


@cache
def _narrative_fields() -> dict[tuple[type, str], str]:
    """Name the fields that carry narrative text, each with what stands in when withheld.

    Imported on first use: these types are built on this module, not the other way.
    """
    from guardana.core.assessment import Assessment  # noqa: PLC0415 — one-way dependency
    from guardana.core.evaluator.base import Verdict  # noqa: PLC0415
    from guardana.core.report.check_error import CheckError  # noqa: PLC0415
    from guardana.core.report.finding import Evidence  # noqa: PLC0415
    from guardana.core.report.shortfall import CoverageShortfall  # noqa: PLC0415

    return {
        (Evidence, "summary"): _WITHHELD_EVIDENCE,
        (Evidence, "detail"): "",
        (CheckError, "reason"): _WITHHELD_REASON,
        (CoverageShortfall, "detail"): _WITHHELD_REASON,
        (Verdict, "rationale"): _WITHHELD_REASON,
        (Assessment, "rationale"): _WITHHELD_REASON,
    }
