"""A recording: what an application answered, as one JSONL file graded without calling it.

The first non-blank line is a header naming the recording and stating whether its replies
are exactly what the application said; every other non-blank line is one exchange — the
messages a rule sent and the reply it got. A team writes one by hand, or `probe` keeps one
beside a run. The dataset is the grading side; a recording is only the answers.

Format 2 adds the header's optional `subject_kind`; a format-1 file is still read, as a
recording that declares no kind. Format 3 lets a line hold `declined` in place of `reply`,
for a request the application declined, and an optional `meta`, what the reply carried
beside its text; formats 1 and 2 are still read.

This module reads, bounds, renders and digests the file and nothing more. Matching an
exchange to the rule that asks for it belongs to the target that replays it.
"""

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from guardana.core.fingerprint import DigestKind, DocumentDigest, digest_of
from guardana.core.formats._stream import read_regular
from guardana.core.redaction import holds_redaction_marker
from guardana.core.subject import SubjectKind
from guardana.core.target import ChatMessage
from guardana.core.target.decline import (
    NEVER_A_DECLINE,
    Decline,
    DeclineReading,
    is_valid_decline_name,
)
from guardana.core.target.endpoint import MAX_METADATA_CHARS, MAX_METADATA_NAMES, METADATA_NAME
from guardana.core.trace.limits import MAX_RECORD_BYTES, MAX_TRACE_BYTES

RECORDING_FORMAT = 3
"""The header's `guardana_recording` value this build writes."""

READ_FORMATS = (1, 2, 3)
"""Every `guardana_recording` value this build reads."""

MAX_EXCHANGES = 1_000_000
"""Exchanges read from one recording; a file with more is refused, never cut short."""

_FORMAT_KEY = "guardana_recording"
_V1_HEADER_KEYS = frozenset(
    {_FORMAT_KEY, "name", "version", "verbatim", "subject", "rule", "origin"}
)
_HEADER_KEYS = {
    1: _V1_HEADER_KEYS,
    2: _V1_HEADER_KEYS | {"subject_kind"},
    3: _V1_HEADER_KEYS | {"subject_kind"},
}
_ORIGIN_KEYS = frozenset(
    {"run_id", "target", "started_at", "stopped_by", "gate", "trials", "rules"}
)
_V1_LINE_KEYS = frozenset({"rule", "input", "reply", "key", "altered"})
_LINE_KEYS = {1: _V1_LINE_KEYS, 2: _V1_LINE_KEYS, 3: _V1_LINE_KEYS | {"declined", "meta"}}
_DECLINED_KEYS = frozenset({"name", "reading", "status"})
_MESSAGE_KEYS = frozenset({"role", "content"})
_ROLES: tuple[Literal["system", "user", "assistant"], ...] = ("system", "user", "assistant")
_KEY = re.compile(r"sha256:[0-9a-f]{64}")
_RENDERED = "<rendered recording>"


class RecordingError(ValueError):
    """A recording that cannot be read or written, named down to the line at fault."""


@dataclass(frozen=True, slots=True)
class RecordingOrigin:
    """The probe run a recording was kept from, as that run declared it.

    `trials` is the trials per case each rule ran with and `rules` every rule the run's
    plain pass planned, reached or not. Declared by the producer and not verified.
    """

    run_id: str
    target: str
    started_at: str | None
    stopped_by: str | None
    gate: str | None
    trials: Mapping[str, int]
    rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RecordedExchange:
    """One exchange: the messages a rule sent, and the application's reply or its decline.

    `key` is `messages_key` of the messages as the rule sent them, taken before anything
    redacted them, so it can match when `input` no longer does. `line` is the source line
    when read and is not written. Exactly one of `reply` and `declined` is set; a declined
    exchange has no reply to alter, so it is never `altered`. `meta` is what the reply
    carried beside its text, by the names an adapter's `metadata_paths:` give.
    """

    rule: str
    input: tuple[ChatMessage, ...]
    reply: str | None
    key: str | None = None
    altered: bool = False
    line: int = 0
    declined: Decline | None = None
    meta: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Refuse both a reply and a decline, neither of them, and an altered decline."""
        if (self.reply is None) == (self.declined is None):
            raise ValueError("a recorded exchange holds exactly one of a reply and a decline")
        if self.declined is not None and self.altered:
            raise ValueError("a declined exchange has no reply to alter")


@dataclass(frozen=True, slots=True)
class Recording:
    """A loaded recording: its identity, what it claims about itself, and its exchanges.

    `digest` covers every byte read and is None for a recording built in memory.
    `subject_kind` is what answered, as the producer declared it; None when it declared
    nothing, as every format-1 file does.
    """

    name: str
    version: str
    verbatim: bool
    subject: str | None
    origin: RecordingOrigin | None
    exchanges: tuple[RecordedExchange, ...]
    digest: DocumentDigest | None
    subject_kind: SubjectKind | None = None

    @property
    def identity(self) -> str:
        """The recording as a run names it, `name@version`."""
        return f"{self.name}@{self.version}"

    @property
    def rules(self) -> frozenset[str]:
        """Every rule the recording answers for: named on a line or planned by its origin."""
        planned = self.origin.rules if self.origin is not None else ()
        return frozenset(exchange.rule for exchange in self.exchanges) | frozenset(planned)

    def reply_altered(self, exchange: RecordedExchange) -> bool:
        """Tell whether `exchange`'s reply may differ from what the application said.

        Never for a declined exchange: the decline is what the application did, and it
        carries no text a redactor could have changed.
        """
        if exchange.reply is None:
            return False
        return not self.verbatim or exchange.altered or holds_redaction_marker(exchange.reply)


def messages_key(messages: Sequence[ChatMessage]) -> str:
    """Digest the messages a rule sent, by role and content, stably across runs and builds.

    The JSON encoding keeps message boundaries, so moving text from one message to the
    next changes the key. Tool calls are not covered; a recording carries none.
    """
    canonical = json.dumps(
        [[message.role, message.content] for message in messages],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return digest_of(canonical)


def read_recording(path: Path) -> Recording:
    """Read and validate the recording at `path`, refusing the whole file on any bad line.

    Formats 1 to 3 are read; a format-1 file reads with `subject_kind` None. Only a
    regular file is read, opened without waiting on a writer.
    """
    try:
        data = read_regular(path, MAX_TRACE_BYTES)
    except OSError as exc:
        raise RecordingError(f"{path} could not be read: {exc}") from exc
    if len(data) > MAX_TRACE_BYTES:
        raise RecordingError(
            f"{path} is over the {MAX_TRACE_BYTES}-byte ceiling; it is refused rather than "
            f"read in part"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RecordingError(
            f"{path} is not UTF-8 text, so it is not a JSONL recording: {exc}"
        ) from exc
    return replace(_parse_text(text, str(path)), digest=DocumentDigest.of(data, DigestKind.CONTENT))


def render_recording(recording: Recording) -> str:
    """Render `recording` as JSONL text that `read_recording` reads back field for field.

    The output is deterministic and always format 3: header first, then one compact object
    per exchange in order, keys in a fixed order, absent optional keys left out. A recording
    the reader would refuse is refused here instead of written.
    """
    lines = [_dump(_header_record(recording))]
    lines.extend(_dump(_exchange_record(exchange)) for exchange in recording.exchanges)
    text = "".join(f"{line}\n" for line in lines)
    size = len(text.encode("utf-8"))
    if size > MAX_TRACE_BYTES:
        raise RecordingError(
            f"{_RENDERED}: the recording would be {size} bytes, over the {MAX_TRACE_BYTES}-byte "
            f"ceiling every reader applies"
        )
    _parse_text(text, _RENDERED)
    return text


def _header_record(recording: Recording) -> dict[str, object]:
    """Build the header line's object, keys in their written order."""
    record: dict[str, object] = {
        _FORMAT_KEY: RECORDING_FORMAT,
        "name": recording.name,
        "version": recording.version,
        "verbatim": recording.verbatim,
    }
    if recording.subject is not None:
        record["subject"] = recording.subject
    if recording.subject_kind is not None:
        record["subject_kind"] = recording.subject_kind.value
    origin = recording.origin
    if origin is not None:
        record["origin"] = {
            "run_id": origin.run_id,
            "target": origin.target,
            "started_at": origin.started_at,
            "stopped_by": origin.stopped_by,
            "gate": origin.gate,
            "trials": {rule: origin.trials[rule] for rule in sorted(origin.trials)},
            "rules": list(origin.rules),
        }
    return record


def _exchange_record(exchange: RecordedExchange) -> dict[str, object]:
    """Build one exchange line's object, `input` always as a message list."""
    messages: list[dict[str, str]] = []
    for message in exchange.input:
        if message.tool_calls or message.tool_call_id is not None:
            raise RecordingError(
                f"{_RENDERED}: an exchange of rule {exchange.rule!r} carries a tool call; a "
                f"recording holds plain chat messages only"
            )
        messages.append({"role": message.role, "content": message.content})
    record: dict[str, object] = {"rule": exchange.rule, "input": messages}
    if exchange.declined is not None:
        record["declined"] = {
            "name": exchange.declined.name,
            "reading": exchange.declined.reading.value,
            "status": exchange.declined.status,
        }
    else:
        record["reply"] = exchange.reply
    if exchange.meta:
        record["meta"] = {name: exchange.meta[name] for name in sorted(exchange.meta)}
    if exchange.key is not None:
        record["key"] = exchange.key
    if exchange.altered:
        record["altered"] = True
    return record


def exchange_size(exchange: RecordedExchange) -> int:
    """How many bytes `exchange` takes in a rendered recording, its line ending included."""
    return len(_dump(_exchange_record(exchange)).encode("utf-8")) + 1


def exchange_fits(exchange: RecordedExchange) -> bool:
    """Whether `exchange` renders as one line under the line ceiling every reader applies."""
    return exchange_size(exchange) - 1 <= MAX_RECORD_BYTES


def _dump(record: dict[str, object]) -> str:
    """Encode one compact JSON line, non-ASCII text kept as written."""
    return json.dumps(record, ensure_ascii=False, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class _Header:
    """The header line, validated."""

    format: int
    name: str
    version: str
    verbatim: bool
    subject: str | None
    subject_kind: SubjectKind | None
    rule: str | None
    origin: RecordingOrigin | None


def _parse_text(text: str, where: str) -> Recording:
    """Validate a whole recording's text, digest left unset; `where` names it in every refusal."""
    header: _Header | None = None
    exchanges: list[RecordedExchange] = []
    for number, raw in enumerate(text.split("\n"), start=1):
        try:
            size = len(raw.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise RecordingError(f"{where}:{number}: the line is not encodable as UTF-8") from exc
        if size > MAX_RECORD_BYTES:
            raise RecordingError(
                f"{where}:{number}: the line is over the {MAX_RECORD_BYTES}-byte ceiling; it "
                f"is refused rather than truncated"
            )
        stripped = raw.strip()
        if not stripped:
            continue
        record = _parse(stripped, where, number)
        if header is None:
            header = _header(record, where, number)
            continue
        if len(exchanges) >= MAX_EXCHANGES:
            raise RecordingError(
                f"{where}:{number}: the recording has more than {MAX_EXCHANGES} exchanges; split it"
            )
        exchanges.append(_exchange(record, header, where, number))
    if header is None:
        raise RecordingError(
            f"{where} has no header; its first line must be "
            f'{{"{_FORMAT_KEY}": {RECORDING_FORMAT}, "name": …, "version": …, "verbatim": …}}'
        )
    if not exchanges:
        raise RecordingError(
            f"{where} has a header and no exchanges; an empty recording answers nothing"
        )
    return Recording(
        name=header.name,
        version=header.version,
        verbatim=header.verbatim,
        subject=header.subject,
        origin=header.origin,
        exchanges=tuple(exchanges),
        digest=None,
        subject_kind=header.subject_kind,
    )


class _RepeatedKeyError(ValueError):
    """A JSON object named one key twice."""


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build an object, refusing a repeated key that `json` would silently resolve to the last."""
    parsed: dict[str, object] = {}
    for key, value in pairs:
        if key in parsed:
            raise _RepeatedKeyError(key)
        parsed[key] = value
    return parsed


def _parse(raw: str, where: str, number: int) -> dict[str, object]:
    """Parse one line into a JSON object, refusing anything else by its line number."""
    try:
        parsed: object = json.loads(raw, object_pairs_hook=_unique_keys)
    except _RepeatedKeyError as exc:
        raise RecordingError(f"{where}:{number}: the key {exc} appears twice on the line") from exc
    except json.JSONDecodeError as exc:
        raise RecordingError(f"{where}:{number}: the line is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise RecordingError(f"{where}:{number}: the line is not a JSON object")
    return parsed


def _header(record: dict[str, object], where: str, number: int) -> _Header:
    """Validate the header line."""
    if _FORMAT_KEY not in record:
        raise RecordingError(
            f"{where}:{number}: the recording does not open with a header; its first line "
            f'must be {{"{_FORMAT_KEY}": {RECORDING_FORMAT}, "name": …, "version": …, '
            f'"verbatim": …}}'
        )
    # The format is checked before the keys: a later format may add header keys, and
    # its file should be refused as another version, not as a typo.
    fmt = record[_FORMAT_KEY]
    if not isinstance(fmt, int) or isinstance(fmt, bool):
        raise RecordingError(
            f"{where}:{number}: `{_FORMAT_KEY}` must be the integer {_listed('or')}, not {fmt!r}"
        )
    allowed = _HEADER_KEYS.get(fmt)
    if allowed is None:
        raise RecordingError(
            f"{where}:{number}: recording format {fmt} was written by another Guardana "
            f"version; this build reads formats {_listed('and')}"
        )
    _refuse_unknown(record, allowed, "header", where, number)
    verbatim = record.get("verbatim")
    if not isinstance(verbatim, bool):
        raise RecordingError(
            f"{where}:{number}: the header's `verbatim` must be true or false, stating "
            f"whether every reply is exactly what the application said; it has no default"
        )
    return _Header(
        format=fmt,
        name=_non_blank(record.get("name"), "the header's `name`", where, number),
        version=_non_blank(record.get("version"), "the header's `version`", where, number),
        verbatim=verbatim,
        subject=_optional(record, "subject", "the header's `subject`", where, number),
        subject_kind=_subject_kind(record, where, number),
        rule=_optional(record, "rule", "the header's `rule`", where, number),
        origin=_origin(record["origin"], where, number) if "origin" in record else None,
    )


def _listed(joiner: str) -> str:
    """Name every format this build reads: `1, 2 and 3`."""
    *first, last = map(str, READ_FORMATS)
    return f"{', '.join(first)} {joiner} {last}" if first else last


def _subject_kind(record: Mapping[str, object], where: str, number: int) -> SubjectKind | None:
    """Read the header's optional `subject_kind`, refusing a value that names no kind."""
    if "subject_kind" not in record:
        return None
    value = record["subject_kind"]
    for kind in SubjectKind:
        if value == kind.value:
            return kind
    choices = ", ".join(kind.value for kind in SubjectKind)
    raise RecordingError(
        f"{where}:{number}: the header's `subject_kind` must be one of {choices}, not {value!r}"
    )


def _origin(value: object, where: str, number: int) -> RecordingOrigin:
    """Validate the header's `origin`, the probe run the recording was kept from."""
    if not isinstance(value, dict):
        raise RecordingError(f"{where}:{number}: the header's `origin` must be an object")
    _refuse_unknown(value, _ORIGIN_KEYS, "`origin`", where, number)
    for required in ("run_id", "target", "trials", "rules"):
        if required not in value:
            raise RecordingError(f"{where}:{number}: `origin` has no `{required}`")
    return RecordingOrigin(
        run_id=_non_blank(value["run_id"], "`origin.run_id`", where, number),
        target=_non_blank(value["target"], "`origin.target`", where, number),
        started_at=_nullable(value.get("started_at"), "`origin.started_at`", where, number),
        stopped_by=_nullable(value.get("stopped_by"), "`origin.stopped_by`", where, number),
        gate=_nullable(value.get("gate"), "`origin.gate`", where, number),
        trials=_trials(value["trials"], where, number),
        rules=_planned_rules(value["rules"], where, number),
    )


def _trials(value: object, where: str, number: int) -> Mapping[str, int]:
    """Read `origin.trials`: rule id to trials per case, each at least one."""
    if not isinstance(value, dict):
        raise RecordingError(
            f"{where}:{number}: `origin.trials` must be an object of rule id to trials per case"
        )
    trials: dict[str, int] = {}
    for rule, count in value.items():
        _non_blank(rule, "a rule id in `origin.trials`", where, number)
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise RecordingError(
                f"{where}:{number}: `origin.trials` gives rule {rule!r} {count!r} trials; it "
                f"must be an integer of at least 1"
            )
        trials[rule] = count
    return MappingProxyType(trials)


def _planned_rules(value: object, where: str, number: int) -> tuple[str, ...]:
    """Read `origin.rules`: the distinct rule ids the original run planned."""
    if not isinstance(value, list):
        raise RecordingError(f"{where}:{number}: `origin.rules` must be a list of rule ids")
    rules = tuple(_non_blank(rule, "a rule id in `origin.rules`", where, number) for rule in value)
    repeated = sorted({rule for rule in rules if rules.count(rule) > 1})
    if repeated:
        raise RecordingError(
            f"{where}:{number}: `origin.rules` names {', '.join(repeated)} more than once"
        )
    return rules


def _exchange(
    record: dict[str, object], header: _Header, where: str, number: int
) -> RecordedExchange:
    """Validate one exchange line."""
    _refuse_unknown(record, _LINE_KEYS[header.format], "line", where, number)
    rule = _optional(record, "rule", "`rule`", where, number) or header.rule
    if rule is None:
        raise RecordingError(
            f"{where}:{number}: the line names no `rule` and the header names no default `rule`"
        )
    if "input" not in record:
        raise RecordingError(f"{where}:{number}: the line has no `input`")
    declined = _declined(record["declined"], where, number) if "declined" in record else None
    reply = record.get("reply")
    if declined is not None and "reply" in record:
        raise RecordingError(
            f"{where}:{number}: the line holds both `reply` and `declined`; a request was "
            f"either answered or declined"
        )
    if declined is None and not isinstance(reply, str):
        raise RecordingError(f"{where}:{number}: the line's `reply` must be a string")
    key = record.get("key")
    if "key" in record and not (isinstance(key, str) and _KEY.fullmatch(key)):
        raise RecordingError(
            f"{where}:{number}: `key` must be 'sha256:' and 64 lowercase hex digits, not {key!r}"
        )
    altered = record.get("altered", False)
    if not isinstance(altered, bool):
        raise RecordingError(f"{where}:{number}: `altered` must be true or false")
    if declined is not None and altered:
        raise RecordingError(
            f"{where}:{number}: a declined line is never `altered`; it holds no reply"
        )
    return RecordedExchange(
        rule=rule,
        input=_input(record["input"], where, number),
        reply=reply if isinstance(reply, str) else None,
        key=key if isinstance(key, str) else None,
        altered=altered,
        line=number,
        declined=declined,
        meta=_meta(record["meta"], where, number) if "meta" in record else {},
    )


def _declined(value: object, where: str, number: int) -> Decline:
    """Read a line's `declined`: the decline entry's name, its reading and the status."""
    if not isinstance(value, dict):
        raise RecordingError(
            f"{where}:{number}: `declined` must be an object of `name`, `reading` and `status`"
        )
    _refuse_unknown(value, _DECLINED_KEYS, "`declined`", where, number)
    name = value.get("name")
    if not isinstance(name, str) or not is_valid_decline_name(name):
        raise RecordingError(
            f"{where}:{number}: `declined.name` must match [a-z0-9][a-z0-9_.-]*, not {name!r}"
        )
    reading = next((r for r in DeclineReading if value.get("reading") == r.value), None)
    if reading is None:
        choices = ", ".join(r.value for r in DeclineReading)
        raise RecordingError(
            f"{where}:{number}: `declined.reading` must be one of {choices}, not "
            f"{value.get('reading')!r}"
        )
    status = value.get("status")
    if (
        not isinstance(status, int)
        or isinstance(status, bool)
        or not (200 <= status <= 299 or 400 <= status <= 499)  # noqa: PLR2004 — HTTP classes
        or status in NEVER_A_DECLINE
    ):
        refused = ", ".join(map(str, sorted(NEVER_A_DECLINE)))
        raise RecordingError(
            f"{where}:{number}: `declined.status` must be 200-299 or 400-499 and none of "
            f"{refused}, not {status!r}"
        )
    return Decline(name=name, reading=reading, status=status)


def _meta(value: object, where: str, number: int) -> Mapping[str, str]:
    """Read a line's `meta`: named strings, as an adapter's `metadata_paths:` keeps them."""
    if not isinstance(value, dict):
        raise RecordingError(f"{where}:{number}: `meta` must be an object of names to strings")
    if len(value) > MAX_METADATA_NAMES:
        raise RecordingError(f"{where}:{number}: `meta` holds more than {MAX_METADATA_NAMES} names")
    meta: dict[str, str] = {}
    for name, text in value.items():
        if not METADATA_NAME.fullmatch(name):
            raise RecordingError(
                f"{where}:{number}: `meta` name {name!r} must match [a-z][a-z0-9_]*"
            )
        if not isinstance(text, str) or len(text) > MAX_METADATA_CHARS:
            raise RecordingError(
                f"{where}:{number}: `meta.{name}` must be a string of at most "
                f"{MAX_METADATA_CHARS} characters"
            )
        meta[name] = text
    return meta


def _input(value: object, where: str, number: int) -> tuple[ChatMessage, ...]:
    """Read a line's input: a non-empty prompt, or a message list that ends on the user."""
    if isinstance(value, str):
        return (ChatMessage(role="user", content=_non_blank(value, "`input`", where, number)),)
    if not isinstance(value, list) or not value:
        raise RecordingError(
            f"{where}:{number}: `input` must be a non-empty string or a non-empty list of "
            f'{{"role", "content"}} messages'
        )
    messages = tuple(_message(item, where, number) for item in value)
    if messages[-1].role != "user":
        raise RecordingError(
            f"{where}:{number}: `input` ends on a {messages[-1].role} message; the last "
            f"message must be from the user, because it is what the reply answers"
        )
    return messages


def _message(item: object, where: str, number: int) -> ChatMessage:
    """One `{"role", "content"}` message; the content is kept exactly, empty included."""
    if not isinstance(item, dict):
        raise RecordingError(f"{where}:{number}: every item of `input` must be an object")
    _refuse_unknown(item, _MESSAGE_KEYS, "message", where, number)
    content = item.get("content")
    if not isinstance(content, str):
        raise RecordingError(f"{where}:{number}: a message's `content` must be a string")
    role = item.get("role")
    for allowed in _ROLES:
        if role == allowed:
            return ChatMessage(role=allowed, content=content)
    raise RecordingError(
        f"{where}:{number}: message role {role!r} is not one of {', '.join(_ROLES)}"
    )


def _optional(
    record: Mapping[str, object], key: str, what: str, where: str, number: int
) -> str | None:
    """Return a key's non-blank string value, or None when the key is absent."""
    if key not in record:
        return None
    return _non_blank(record[key], what, where, number)


def _nullable(value: object, what: str, where: str, number: int) -> str | None:
    """Return `value` as a non-blank string, or None when it is null or absent."""
    if value is None:
        return None
    return _non_blank(value, what, where, number)


def _non_blank(value: object, what: str, where: str, number: int) -> str:
    """Return `value` if it is a string with content, refusing it otherwise."""
    if not isinstance(value, str) or not value.strip():
        raise RecordingError(f"{where}:{number}: {what} must be a non-empty string")
    return value


def _refuse_unknown(
    record: Mapping[str, object], allowed: frozenset[str], what: str, where: str, number: int
) -> None:
    """Refuse any key outside `allowed`, naming them all at once."""
    unknown = sorted(set(record) - allowed)
    if unknown:
        raise RecordingError(
            f"{where}:{number}: unknown {what} key(s) {', '.join(unknown)}; expected only "
            f"{', '.join(sorted(allowed))}"
        )
