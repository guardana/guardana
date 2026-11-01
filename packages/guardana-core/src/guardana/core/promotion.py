"""Promote one kept exchange into a regression case of a YAML suite's dataset.

This module selects the exchange, refuses what would make the case ask another question
or record another failure, and builds the dataset text the case would be written into,
held to every rule the suite loads under. Proving the case and writing the file are the
caller's; nothing here sends or writes.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

import yaml
from guardana.core._yaml import load_yaml
from guardana.core.dataset import (
    REGRESSION_TAG,
    Dataset,
    DatasetCase,
    DatasetError,
    RegressionPair,
    parse_dataset,
    read_dataset_text,
    render_case,
    render_header,
    resolve_dataset_path,
)
from guardana.core.recording import RecordedExchange, Recording, messages_key
from guardana.core.redaction import holds_redaction_marker
from guardana.core.rule._suite_schema import is_suite, parse_suite, suite_over
from guardana.core.rule.errors import RuleLoadError
from guardana.core.rule.suite_rule import SuiteCase, SuiteRule
from guardana.core.target import ChatMessage
from guardana.core.trace.limits import MAX_RECORD_BYTES

INPUT_REWRITTEN_TAG = "input:rewritten"
"""A case whose input a reviewer wrote in place of the one the application was sent."""

OBSERVED_SYNTHETIC_TAG = "observed:synthetic"
"""A case whose failing reply a reviewer reconstructed in place of the application's."""


class PromotionRefusedError(ValueError):
    """A case that cannot be promoted as asked, refused before anything is proven."""


@dataclass(frozen=True, slots=True)
class SuiteFile:
    """A YAML suite file as it loads now, with its own text and its dataset's path and text.

    Both texts are what the proof was built from, so a writer can tell either file changed.
    """

    path: Path
    text: str
    raw: Mapping[str, object]
    rule: SuiteRule
    dataset_path: Path
    dataset_text: str
    dataset: Dataset


@dataclass(frozen=True, slots=True)
class Promotion:
    """The dataset text with the new case appended, and the suite as it would load from it."""

    text: str
    dataset: Dataset
    rule: SuiteRule
    case: SuiteCase


@dataclass(frozen=True, slots=True)
class Reviewed:
    """What a reviewer supplies beside the kept exchange.

    `input` and `observed` replace the recorded ones when given; `accepted` is the
    correct reply and `expect` the case's own expectation.
    """

    expect: Mapping[str, object]
    accepted: str
    label: str | None = None
    input: str | None = None
    observed: str | None = None


def open_suite(path: Path) -> SuiteFile:
    """Load the YAML suite at `path` as the registry would, with its dataset's text.

    A file holding several rules, a rule that is not a suite, and a suite that does not
    load are refused.
    """
    try:
        source = path.read_text(encoding="utf-8")
        raw = load_yaml(source)
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
        raise PromotionRefusedError(f"{path} could not be read as YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise PromotionRefusedError(
            f"{path} does not hold one rule mapping; a case is added to a file holding one suite"
        )
    if not is_suite(raw):
        raise PromotionRefusedError(f"{path} is not a suite: it names no `dataset:`")
    try:
        rule = parse_suite(raw, path)
        dataset_path = resolve_dataset_path(str(raw["dataset"]), path)
        text = read_dataset_text(dataset_path)
        dataset = parse_dataset(text, str(dataset_path))
    except (RuleLoadError, DatasetError) as exc:
        raise PromotionRefusedError(f"the suite does not load as it is: {exc}") from exc
    return SuiteFile(path, source, MappingProxyType(raw), rule, dataset_path, text, dataset)


def select_exchange(recording: Recording, *, key: str | None, line: int | None) -> RecordedExchange:
    """Pick the one kept exchange `key` or `line` names, refusing an ambiguous choice.

    A line with no key can be picked only by `line`, and a key on several lines only
    by `line` too. A line the application declined is refused: it holds no reply to pair.
    """
    if (key is None) == (line is None):
        raise PromotionRefusedError("name the exchange with exactly one of --key and --line")
    if line is not None:
        for exchange in recording.exchanges:
            if exchange.line == line:
                _reply_of(recording, exchange)
                return exchange
        lines = ", ".join(str(e.line) for e in recording.exchanges)
        raise PromotionRefusedError(
            f"no kept exchange is on line {line} of {recording.identity}; its exchanges are "
            f"on lines {lines}"
        )
    matches = [e for e in recording.exchanges if e.key == key]
    if not matches:
        raise PromotionRefusedError(f"no kept exchange of {recording.identity} has key {key}")
    if len(matches) > 1:
        lines = ", ".join(str(e.line) for e in matches)
        raise PromotionRefusedError(
            f"key {key} is on lines {lines} of {recording.identity}; pick one with --line"
        )
    _reply_of(recording, matches[0])
    return matches[0]


def _reply_of(recording: Recording, exchange: RecordedExchange) -> str:
    """Return the reply `exchange` holds, refusing one the application declined."""
    if exchange.reply is None:
        declined = "declined" if exchange.declined is None else exchange.declined.described
        raise PromotionRefusedError(
            f"line {exchange.line} of {recording.identity} was {declined}; it holds no reply "
            f"to pair with a correct one"
        )
    return exchange.reply


def input_altered(recording: Recording, exchange: RecordedExchange) -> str | None:
    """Return why the exchange's input may not be what the application was asked, or None."""
    if any(holds_redaction_marker(message.content) for message in exchange.input):
        return "the input holds a redaction placeholder"
    if exchange.key is not None and messages_key(exchange.input) != exchange.key:
        return "the input no longer matches the key taken before it was redacted"
    if exchange.key is None and not recording.verbatim:
        return "the line has no key and the recording is not verbatim"
    return None


def promoted_case(
    recording: Recording, exchange: RecordedExchange, reviewed: Reviewed
) -> DatasetCase:
    """Build the case a kept exchange and a reviewer's additions make, or refuse it.

    An altered input is refused unless the reviewer rewrote it; an altered reply is
    refused unless the reviewer reconstructed it. Each replacement is tagged, and no text
    the reviewer wrote may hold a redaction placeholder. A declined exchange is refused
    whatever the reviewer supplies: the application gave no failing reply to pair.
    """
    recorded_reply = _reply_of(recording, exchange)
    tags = [REGRESSION_TAG]
    if reviewed.label is not None:
        if not reviewed.label.strip():
            raise PromotionRefusedError("--label must not be blank")
        tags.append(f"label:{reviewed.label}")
    if recording.origin is not None:
        tags.append(f"origin:{recording.origin.run_id}")
    for flag, written in (
        ("--input-file", reviewed.input),
        ("--observed-file", reviewed.observed),
        ("--accepted-file", reviewed.accepted),
    ):
        if written is not None and holds_redaction_marker(written):
            raise PromotionRefusedError(
                f"{flag} holds a redaction placeholder; write the text the case is to hold, "
                f"never what a redactor left of it"
            )
    if reviewed.input is not None:
        case_input: str | tuple[ChatMessage, ...] = reviewed.input
        tags.append(INPUT_REWRITTEN_TAG)
    else:
        altered = input_altered(recording, exchange)
        if altered is not None:
            raise PromotionRefusedError(
                f"line {exchange.line}: {altered}, so the case would ask another question; "
                f"give the question with --input-file"
            )
        case_input = _recorded_input(exchange.input)
    if reviewed.observed is not None:
        observed = reviewed.observed
        tags.append(OBSERVED_SYNTHETIC_TAG)
    elif recording.reply_altered(exchange):
        raise PromotionRefusedError(
            f"line {exchange.line}: the reply was redacted or not kept verbatim, so it is not "
            f"the failure the application gave; write a stand-in that reproduces it without "
            f"the removed data and pass it with --observed-file"
        )
    else:
        observed = recorded_reply
    return DatasetCase(
        line=0,
        input=case_input,
        expect=MappingProxyType(dict(reviewed.expect)),
        tags=tuple(tags),
        pair=RegressionPair(observed=observed, accepted=reviewed.accepted),
    )


def _recorded_input(messages: tuple[ChatMessage, ...]) -> str | tuple[ChatMessage, ...]:
    """Return a single user message as a string input, as a suite sends a string."""
    if len(messages) == 1 and messages[0].role == "user":
        return messages[0].content
    return messages


def promote(suite: SuiteFile, case: DatasetCase, version: str) -> Promotion:
    """Append `case` to the suite's dataset under `version`, held to every load-time rule.

    The header is rewritten in the format this build writes; every other line is kept
    byte for byte.
    """
    if version == suite.dataset.version:
        raise PromotionRefusedError(
            f"--version {version} is the dataset's current version; a new case is a new version"
        )
    line = render_case(case)
    size = len(line.encode("utf-8"))
    if size > MAX_RECORD_BYTES:
        raise PromotionRefusedError(
            f"the case would be a {size}-byte line, over the dataset's {MAX_RECORD_BYTES}-byte "
            f"line limit"
        )
    text = _with_case(suite.dataset_text, render_header(suite.dataset.name, version), line)
    try:
        dataset = parse_dataset(text, str(suite.dataset_path))
        rule = suite_over(dict(suite.raw), suite.path, dataset)
    except (RuleLoadError, DatasetError) as exc:
        raise PromotionRefusedError(f"the suite would not load with the case: {exc}") from exc
    added = max(rule.cases, key=lambda c: c.line)
    return Promotion(text=text, dataset=dataset, rule=rule, case=added)


def _with_case(text: str, header: str, line: str) -> str:
    lines = text.split("\n")
    for index, raw in enumerate(lines):
        if raw.strip():
            lines[index] = header + ("\r" if raw.endswith("\r") else "")
            break
    body = "\n".join(lines)
    if body and not body.endswith("\n"):
        body += "\n"
    return f"{body}{line}\n"


__all__ = [
    "INPUT_REWRITTEN_TAG",
    "OBSERVED_SYNTHETIC_TAG",
    "Promotion",
    "PromotionRefusedError",
    "Reviewed",
    "SuiteFile",
    "open_suite",
    "promote",
    "promoted_case",
    "select_exchange",
]
