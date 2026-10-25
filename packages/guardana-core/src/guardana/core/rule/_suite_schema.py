"""Validation of a declarative suite — a rule with `dataset:` — into a `SuiteRule`.

Everything is checked at load, the dataset included: a case whose expectation its
evaluator cannot read, a gate that could never conclude over the cases that will run, or
a fixture too small for the gate, each fails where a typo fails rather than as a suite
that declines on every run.
"""

import json
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from guardana.core.assessment import case_id_for
from guardana.core.dataset import (
    Dataset,
    DatasetCase,
    DatasetError,
    read_dataset,
    resolve_dataset_path,
)
from guardana.core.evaluator.base import Expectation
from guardana.core.rule._digest import declaration_digest, digest_parts
from guardana.core.rule._fixture_schema import _endpoint, _note, _outcome, _reply, _text
from guardana.core.rule._yaml_schema import (
    check_evaluator_expectations,
    parse_expectation,
    parse_meta,
    reject_unknown_keys,
)
from guardana.core.rule.base import RuleMeta
from guardana.core.rule.errors import RuleLoadError
from guardana.core.rule.fixture import DeclaredFixture
from guardana.core.rule.suite_rule import SuiteCase, SuiteRule, select_sample
from guardana.core.suite import SuiteGate
from guardana.core.target import ChatMessage
from guardana.core.testing import ScriptedTransport

_ALLOWED_SUITE_KEYS = frozenset(
    {
        "id",
        "title",
        "severity",
        "target_kind",
        "taxonomy",
        "evaluator",
        "requires",
        "dataset",
        "expect",
        "sample",
        "gate",
        "fixtures",
        "detection",
    }
)
_ALLOWED_GATE_KEYS = frozenset({"min_pass_rate", "min_sample"})
_ALLOWED_SAMPLE_KEYS = frozenset({"size", "seed"})
_ALLOWED_SUITE_FIXTURE_KEYS = frozenset({"name", "reply", "dataset", "outcome", "note"})
_SAMPLE_TAG = "sample:"


def is_suite(raw: dict[str, Any]) -> bool:
    """Whether a rule mapping declares a suite: it names a dataset of cases."""
    return "dataset" in raw


def parse_suite(raw: dict[str, Any], path: Path) -> SuiteRule:
    """Validate a suite declaration and its dataset into a `SuiteRule`."""
    return suite_over(raw, path, _dataset(raw.get("dataset"), path, fixture=False))


def suite_over(raw: dict[str, Any], path: Path, dataset: Dataset) -> SuiteRule:
    """Validate a suite declaration over `dataset`, already read, into a `SuiteRule`.

    Every load-time refusal applies, so a dataset not yet written can be held to the
    rules the suite will be loaded under.
    """
    meta = parse_meta(raw, path, allowed=_ALLOWED_SUITE_KEYS)
    default = parse_expectation(raw.get("expect"), path)
    cases = _cases(meta, default, dataset, path)
    gate = _gate(raw.get("gate"), path)
    sample = _sample(raw.get("sample"), path)
    _refuse_an_outvotable_regression(dataset, gate, sample, path)
    if sample is not None and sample[0] < len(cases):
        size, seed = sample
        chosen = tuple(
            replace(case, tags=(*case.tags, f"{_SAMPLE_TAG}{seed}"))
            for case in select_sample(cases, size, seed)
        )
    else:
        sample, chosen = None, cases
    if gate.min_sample > len(chosen):
        raise RuleLoadError(
            f"invalid rule in {path}: gate.min_sample is {gate.min_sample} and "
            f"{len(chosen)} case(s) will run, so the suite could never conclude"
        )
    rule = SuiteRule(
        meta=meta,
        cases=chosen,
        gate=gate,
        dataset=dataset.identity,
        dataset_digest=dataset.digest,
        sample=sample,
        source_digest=digest_parts((declaration_digest(raw), dataset.digest)),
    )
    return replace(rule, declared_fixtures=_fixtures(raw.get("fixtures"), path, rule, default))


def _refuse_an_outvotable_regression(
    dataset: Dataset, gate: SuiteGate, sample: tuple[int, int] | None, path: Path
) -> None:
    """Refuse a regression dataset under a suite that samples or tolerates a failure.

    A regression case that may not run, or that other cases can outvote, prevents
    nothing, so a dataset holding one is a gate every case of which must pass.
    """
    if not dataset.holds_regressions:
        return
    held = f"dataset {dataset.identity} holds a regression case"
    if sample is not None:
        raise RuleLoadError(
            f"invalid rule in {path}: {held}, and 'sample' would leave cases unsent; a "
            f"regression suite runs every case"
        )
    if gate.min_pass_rate < 1:
        raise RuleLoadError(
            f"invalid rule in {path}: {held}, and gate.min_pass_rate {gate.min_pass_rate} "
            f"lets other cases outvote it; a regression suite sets it to 1"
        )


def _dataset(value: object, path: Path, *, fixture: bool) -> Dataset:
    if not isinstance(value, str):
        raise RuleLoadError(
            f"invalid rule in {path}: 'dataset' must be a path to a JSONL file beside the rule"
        )
    try:
        return read_dataset(resolve_dataset_path(value, path), fixture=fixture)
    except DatasetError as exc:
        raise RuleLoadError(f"invalid rule in {path}: {exc}") from exc


def _cases(
    meta: RuleMeta, default: Expectation, dataset: Dataset, path: Path
) -> tuple[SuiteCase, ...]:
    """Build every case with its effective expectation, refusing a repeated one by its lines."""
    if default.canary is not None:
        raise RuleLoadError(
            f"invalid rule in {path}: a suite plants no canary, so 'expect.canary' would be "
            f"looked for and never found"
        )
    seen: dict[str, int] = {}
    cases = []
    for entry in dataset.cases:
        case = _case(meta, default, entry, path)
        if case.case_id in seen:
            raise RuleLoadError(
                f"invalid rule in {path}: dataset lines {seen[case.case_id]} and {entry.line} "
                f"are the same case — the same input graded against the same expectation"
            )
        seen[case.case_id] = entry.line
        cases.append(case)
    return tuple(cases)


def _case(meta: RuleMeta, default: Expectation, entry: DatasetCase, path: Path) -> SuiteCase:
    where = f"{path} (dataset line {entry.line})"
    own = parse_expectation(dict(entry.expect), Path(where))
    if own.canary is not None:
        raise RuleLoadError(f"invalid rule in {where}: a suite plants no canary")
    expectation = Expectation(
        goal=own.goal if own.goal is not None else default.goal,
        fields={**default.fields, **own.fields},
    )
    check_evaluator_expectations(meta, expectation, Path(where))
    messages = (
        (ChatMessage(role="user", content=entry.input),)
        if isinstance(entry.input, str)
        else tuple(entry.input)
    )
    identity = json.dumps(
        {
            "input": entry.input
            if isinstance(entry.input, str)
            else [[m.role, m.content] for m in entry.input],
            "goal": expectation.goal,
            "expect": dict(expectation.fields),
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    return SuiteCase(
        case_id=case_id_for(meta.id, identity),
        messages=messages,
        expectation=expectation,
        tags=entry.tags,
        line=entry.line,
        pair=entry.pair,
    )


def _gate(value: object, path: Path) -> SuiteGate:
    if not isinstance(value, dict) or "min_pass_rate" not in value:
        raise RuleLoadError(
            f"invalid rule in {path}: a suite needs 'gate' with 'min_pass_rate', the share "
            f"of cases that must pass"
        )
    reject_unknown_keys(value, _ALLOWED_GATE_KEYS, "gate", path)
    try:
        return SuiteGate(**value)
    except ValueError as exc:
        raise RuleLoadError(f"invalid rule in {path}: gate.{exc}") from exc


def _sample(value: object, path: Path) -> tuple[int, int] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RuleLoadError(f"invalid rule in {path}: 'sample' must be a mapping of size and seed")
    reject_unknown_keys(value, _ALLOWED_SAMPLE_KEYS, "sample", path)
    size, seed = value.get("size"), value.get("seed")
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise RuleLoadError(
            f"invalid rule in {path}: sample.size must be a whole number of at least 1"
        )
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise RuleLoadError(
            f"invalid rule in {path}: sample.seed must be a whole number — the subset is a "
            f"choice, and the same seed chooses the same cases on every run"
        )
    return size, seed


def _fixtures(
    raw: object, path: Path, rule: SuiteRule, default: Expectation
) -> tuple[DeclaredFixture, ...]:
    """Validate a suite's samples: one reply for every case, or a small dataset of their own."""
    if raw is None:
        return ()
    if not isinstance(raw, list) or not raw:
        raise RuleLoadError(
            f"invalid rule in {path}: 'fixtures' must be a non-empty list — an empty "
            f"one declares samples and provides none, which reads as checked"
        )
    return tuple(
        _fixture(entry, path, number, rule, default) for number, entry in enumerate(raw, start=1)
    )


def _fixture(
    raw: object, path: Path, number: int, rule: SuiteRule, default: Expectation
) -> DeclaredFixture:
    if not isinstance(raw, dict):
        raise RuleLoadError(f"invalid rule in {path}: fixture {number} must be a mapping")
    unknown = sorted(str(key) for key in raw if key not in _ALLOWED_SUITE_FIXTURE_KEYS)
    if unknown:
        raise RuleLoadError(
            f"invalid rule in {path}: fixture {number} has unknown key(s) "
            f"{', '.join(unknown)}; expected {sorted(_ALLOWED_SUITE_FIXTURE_KEYS)}"
        )
    name, outcome, note = _text(raw, "name", path, number), _outcome(raw, path, number), _note(raw)
    if "dataset" not in raw:
        reply = _reply(raw, path, number)
        return DeclaredFixture(name, outcome, lambda: _endpoint(ScriptedTransport(reply)), note)
    dataset = _dataset(raw["dataset"], path, fixture=True)
    fallback = _reply(raw, path, number) if "reply" in raw else None
    cases = _cases(rule.meta, default, dataset, path)
    if rule.gate.min_sample > len(cases):
        raise RuleLoadError(
            f"invalid rule in {path}: fixture {number}'s dataset has {len(cases)} case(s) "
            f"and gate.min_sample is {rule.gate.min_sample}, so the sample could only decline"
        )
    replies = _replies(dataset.cases, cases, fallback, path, number)
    variant = replace(
        rule,
        cases=cases,
        dataset=dataset.identity,
        dataset_digest=dataset.digest,
        sample=None,
        declared_fixtures=(),
    )
    return DeclaredFixture(name, outcome, lambda: _endpoint(_ByMessages(replies)), note, variant)


def _replies(
    entries: Sequence[DatasetCase],
    cases: Sequence[SuiteCase],
    fallback: str | None,
    path: Path,
    number: int,
) -> dict[tuple[tuple[str, str], ...], str]:
    """Map each fixture case's messages to its scripted reply, refusing two replies for one."""
    replies: dict[tuple[tuple[str, str], ...], str] = {}
    for entry, case in zip(entries, cases, strict=True):
        reply = entry.reply if entry.reply is not None else fallback
        if reply is None:
            raise RuleLoadError(
                f"invalid rule in {path}: fixture {number}'s dataset line {entry.line} has no "
                f"'reply' and the fixture gives none"
            )
        key = tuple((m.role, m.content) for m in case.messages)
        if replies.get(key, reply) != reply:
            raise RuleLoadError(
                f"invalid rule in {path}: fixture {number}'s dataset gives two replies to the "
                f"same messages (line {entry.line}); the double could not tell them apart"
            )
        replies[key] = reply
    return replies


class _ByMessages:
    """A double that answers each fixture case with the reply its dataset line scripts."""

    def __init__(self, replies: dict[tuple[tuple[str, str], ...], str]) -> None:
        self._replies = replies

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """Reply with the scripted answer for exactly these messages."""
        key = tuple((m.role, m.content) for m in messages)
        if key not in self._replies:
            raise LookupError("the fixture scripts no reply for these messages")
        return self._replies[key]
