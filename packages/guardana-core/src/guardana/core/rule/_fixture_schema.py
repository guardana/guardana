"""Parse a YAML rule's `fixtures:` block into declared samples, one shape at a time.

Every declarative rule kind grades something different — a reply, a conversation,
an agent run — so each one's fixture scripts a different thing, and each is
validated against what that rule actually declares: the number of steps, the
tools it offers, the step budget it may spend. That is why these parsers take the
rule's own declaration rather than only the mapping: a `call:` naming a tool
nobody offers, or a script longer than `max_steps`, has to fail where a typo
fails, not halfway through a verification.

An artifact rule needs bytes, and bytes in YAML is either a path to a checked-in
malicious file or base64 nobody can review — so a plugin rule overrides
`Rule.fixtures()` in Python instead, using the builders `guardana.core.testing`
already ships.
"""

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from guardana.core.rule.errors import RuleLoadError
from guardana.core.rule.fixture import DeclaredFixture, FixtureOutcome
from guardana.core.target import EndpointTarget, Target
from guardana.core.target.endpoint import ChatTransport, ToolCall, ToolCallReply
from guardana.core.testing import ScriptedAgentTransport, ScriptedTransport

_ALLOWED_FIXTURE_KEYS = frozenset({"name", "reply", "outcome", "note"})
_ALLOWED_SCENARIO_FIXTURE_KEYS = frozenset({"name", "replies", "outcome", "note"})
_ALLOWED_TRAJECTORY_FIXTURE_KEYS = frozenset({"name", "turns", "then_turns", "outcome", "note"})
_ALLOWED_TURN_KEYS = frozenset({"say", "call", "arguments"})

_Builder = Callable[[dict[str, Any], Path, int], Callable[[], Target]]


def parse_fixtures(raw: object, path: Path) -> tuple[DeclaredFixture, ...]:
    """Validate a single-turn rule's `fixtures:` list, or return nothing when it has none.

    Absent is allowed and is **not** the same as fine: `verify_rule` reports an
    unsampled rule as a gap, and `guardana rule test` turns that into
    `indeterminate`. Refusing at load time instead would make every existing rule
    file unreadable by this build, which is a migration that breaks a user's own
    rules to enforce a bar on ours.
    """
    return _fixtures(raw, path, _ALLOWED_FIXTURE_KEYS, _single_reply)


def parse_scenario_fixtures(raw: object, path: Path, *, steps: int) -> tuple[DeclaredFixture, ...]:
    """Validate a scenario's `fixtures:` list against the number of turns it drives."""

    def builder(entry: dict[str, Any], where: Path, number: int) -> Callable[[], Target]:
        return _scenario_script(entry, where, number, steps=steps)

    return _fixtures(raw, path, _ALLOWED_SCENARIO_FIXTURE_KEYS, builder)


def parse_trajectory_fixtures(  # noqa: PLR0913 — every bound the script is checked against
    raw: object,
    path: Path,
    *,
    tools: Sequence[str],
    max_steps: int,
    forbidden: frozenset[str],
    has_then: bool,
) -> tuple[DeclaredFixture, ...]:
    """Validate an agent rule's `fixtures:` list against the run it can actually drive."""

    def builder(entry: dict[str, Any], where: Path, number: int) -> Callable[[], Target]:
        return _trajectory_script(
            entry,
            where,
            number,
            tools=tools,
            max_steps=max_steps,
            forbidden=forbidden,
            has_then=has_then,
        )

    return _fixtures(raw, path, _ALLOWED_TRAJECTORY_FIXTURE_KEYS, builder)


def _fixtures(
    raw: object, path: Path, allowed: frozenset[str], builder: _Builder
) -> tuple[DeclaredFixture, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or not raw:
        raise RuleLoadError(
            f"invalid rule in {path}: 'fixtures' must be a non-empty list — an empty "
            f"one declares samples and provides none, which reads as checked"
        )
    return tuple(
        _fixture(entry, path, number, allowed, builder) for number, entry in enumerate(raw, start=1)
    )


def _fixture(
    raw: object, path: Path, number: int, allowed: frozenset[str], builder: _Builder
) -> DeclaredFixture:
    if not isinstance(raw, dict):
        raise RuleLoadError(f"invalid rule in {path}: fixture {number} must be a mapping")
    unknown = sorted(str(key) for key in raw if key not in allowed)
    if unknown:
        raise RuleLoadError(
            f"invalid rule in {path}: fixture {number} has unknown key(s) "
            f"{', '.join(unknown)}; expected {sorted(allowed)}"
        )
    return DeclaredFixture(
        name=_text(raw, "name", path, number),
        outcome=_outcome(raw, path, number),
        build=builder(raw, path, number),
        note=_note(raw),
    )


def _note(raw: dict[str, Any]) -> str:
    """Read the optional note; an empty key is no note rather than the word "None"."""
    value = raw.get("note")
    return "" if value is None else str(value)


def _single_reply(raw: dict[str, Any], path: Path, number: int) -> Callable[[], Target]:
    """Script the one reply a single-turn rule's double answers with."""
    reply = _reply(raw, path, number)
    return lambda: _endpoint(ScriptedTransport(reply))


def _scenario_script(
    raw: dict[str, Any], path: Path, number: int, *, steps: int
) -> Callable[[], Target]:
    """Script one reply per step, refusing any other count.

    The double repeats its last reply once exhausted, so a shorter list still
    runs — and a step added to the scenario without a reply added here would
    silently grade the previous turn's answer on the new turn.
    """
    value = raw.get("replies")
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuleLoadError(
            f"invalid rule in {path}: fixture {number} needs a 'replies' list of strings, "
            f'one per step ("" is allowed, and is how a decline is sampled)'
        )
    if len(value) != steps:
        raise RuleLoadError(
            f"invalid rule in {path}: fixture {number} scripts {len(value)} reply/replies "
            f"for a scenario of {steps} step(s) — every step needs its own reply, or a "
            f"turn is graded against the answer to the turn before it"
        )
    replies = tuple(value)
    return lambda: _endpoint(ScriptedTransport(*replies))


def _trajectory_script(  # noqa: PLR0913 — every bound the script is checked against
    raw: dict[str, Any],
    path: Path,
    number: int,
    *,
    tools: Sequence[str],
    max_steps: int,
    forbidden: frozenset[str],
    has_then: bool,
) -> Callable[[], Target]:
    """Script one turn per round trip, per session, refusing a script that cannot play."""
    if has_then and "then_turns" not in raw:
        raise RuleLoadError(
            f"invalid rule in {path}: fixture {number} needs 'then_turns' — this rule opens "
            f"a second session, and a sample silent about it says nothing about the session "
            f"the verdict is read from"
        )
    if not has_then and "then_turns" in raw:
        raise RuleLoadError(
            f"invalid rule in {path}: fixture {number} scripts 'then_turns' for a rule that "
            f"declares no 'then' — that session is never opened"
        )
    keys = ["turns", "then_turns"] if has_then else ["turns"]
    scripts = tuple(
        _turns(
            raw.get(key),
            path,
            number,
            key,
            tools=tools,
            max_steps=max_steps,
            forbidden=forbidden,
        )
        for key in keys
    )
    return lambda: _endpoint(ScriptedAgentTransport(*scripts))


def _turns(  # noqa: PLR0913 — every bound the script is checked against
    value: object,
    path: Path,
    number: int,
    key: str,
    *,
    tools: Sequence[str],
    max_steps: int,
    forbidden: frozenset[str],
) -> tuple[ToolCallReply, ...]:
    if not isinstance(value, list) or not value:
        raise RuleLoadError(
            f"invalid rule in {path}: fixture {number} needs a non-empty '{key}' list — "
            f"a run nobody scripted cannot be played"
        )
    if len(value) > max_steps:
        raise RuleLoadError(
            f"invalid rule in {path}: fixture {number} scripts {len(value)} turn(s) in "
            f"'{key}' and the rule allows {max_steps} — the run truncates before the last "
            f"turn is read, so the sample would come out inconclusive through a bound "
            f"rather than through what it says it demonstrates"
        )
    turns = tuple(
        _turn(entry, path, f"fixture {number}, {key} turn {position}", tools=tools, at=position)
        for position, entry in enumerate(value, start=1)
    )
    _refuse_an_unreachable_turn(turns, path, number, key, max_steps=max_steps, forbidden=forbidden)
    return turns


def _turn(raw: object, path: Path, where: str, *, tools: Sequence[str], at: int) -> ToolCallReply:
    if not isinstance(raw, dict):
        raise RuleLoadError(f"invalid rule in {path}: {where} must be a mapping")
    unknown = sorted(str(key) for key in raw if key not in _ALLOWED_TURN_KEYS)
    if unknown:
        raise RuleLoadError(
            f"invalid rule in {path}: {where} has unknown key(s) {', '.join(unknown)}; "
            f"expected {sorted(_ALLOWED_TURN_KEYS)}"
        )
    if "say" not in raw and "call" not in raw:
        raise RuleLoadError(
            f"invalid rule in {path}: {where} neither says anything nor calls a tool, "
            f"which is not a turn a model can take"
        )
    text = _say(raw, path, where)
    if "call" not in raw:
        if "arguments" in raw:
            raise RuleLoadError(
                f"invalid rule in {path}: {where} carries 'arguments' without a 'call' — "
                f"they would be passed to nothing"
            )
        return ToolCallReply(text=text, tool_calls=())
    name = raw.get("call")
    if not isinstance(name, str) or not name:
        raise RuleLoadError(f"invalid rule in {path}: {where} needs a non-empty 'call' name")
    if name not in tools:
        raise RuleLoadError(
            f"invalid rule in {path}: {where} calls {name!r}, which this rule does not "
            f"offer; it offers {sorted(tools)}"
        )
    call = ToolCall(name=name, arguments=_arguments(raw, path, where), id=f"call_{at}")
    return ToolCallReply(text=text, tool_calls=(call,))


def _say(raw: dict[str, Any], path: Path, where: str) -> str | None:
    """Read a turn's prose, keeping the empty string and refusing an empty key.

    `say: ""` is the model that answered with nothing — the case a grader most
    often reads as "no attack found". `say:` with no value at all is neither that
    nor an absent key, and guessing which one the author meant is how a sample
    ends up demonstrating something nobody wrote.
    """
    if "say" not in raw:
        return None
    value = raw.get("say")
    if not isinstance(value, str):
        raise RuleLoadError(
            f"invalid rule in {path}: {where} has a 'say' that is not a string "
            f'(use `say: ""` for a model that answered with nothing)'
        )
    return value


def _arguments(raw: dict[str, Any], path: Path, where: str) -> str:
    r"""Render a turn's arguments the way a tool-calling API carries them.

    Compact JSON, and **not ASCII-escaped**: a planted canary is matched as a
    substring of this string, so escaping `ü` would make a marker containing it
    unfindable by that match and let a `clean` sample pass for a reason nobody wrote.
    """
    if "arguments" not in raw:
        return "{}"
    value = raw.get("arguments")
    if not isinstance(value, dict):
        raise RuleLoadError(f"invalid rule in {path}: {where} needs 'arguments' to be a mapping")
    try:
        return json.dumps(
            value, separators=(",", ":"), ensure_ascii=False, sort_keys=True, allow_nan=False
        )
    except (TypeError, ValueError) as exc:
        raise RuleLoadError(
            f"invalid rule in {path}: {where} has arguments YAML parsed into something "
            f"JSON cannot carry ({exc}) — quote the value"
        ) from exc


def _refuse_an_unreachable_turn(  # noqa: PLR0913 — the bounds are the check
    turns: tuple[ToolCallReply, ...],
    path: Path,
    number: int,
    key: str,
    *,
    max_steps: int,
    forbidden: frozenset[str],
) -> None:
    """Refuse a script whose turns the run would never ask for, or would ask past.

    A session ends when the model answers without calling a tool, when it calls a
    tool the rule forbids, or when the step budget runs out — so a script ends in
    one of those three ways and in no other. A script that continues past an
    ending carries turns no verification reads; one that stops before any ending
    leaves the run asking for a turn nobody wrote. Both let a sample come out
    `inconclusive` through a bound rather than through what its name claims.
    """
    for position, turn in enumerate(turns[:-1], start=1):
        remaining = len(turns) - position
        if not turn.tool_calls:
            raise RuleLoadError(
                f"invalid rule in {path}: fixture {number}, {key} turn {position} calls no "
                f"tool, which ends the session — the {remaining} turn(s) after it would "
                f"never be read"
            )
        if turn.tool_calls[0].name in forbidden:
            raise RuleLoadError(
                f"invalid rule in {path}: fixture {number}, {key} turn {position} calls "
                f"{turn.tool_calls[0].name!r}, which the rule forbids and which ends the "
                f"run — the {remaining} turn(s) after it would never be read"
            )
    last = turns[-1]
    if not last.tool_calls or last.tool_calls[0].name in forbidden or len(turns) == max_steps:
        return
    raise RuleLoadError(
        f"invalid rule in {path}: fixture {number}, {key} ends on a call to "
        f"{last.tool_calls[0].name!r} and the run would ask for another turn. End the script "
        f"with a turn that only says something, with a forbidden call, or with {max_steps} "
        f"turns — the step budget, which truncates the run"
    )


def _endpoint(transport: ChatTransport) -> Target:
    return EndpointTarget("http://fixture.invalid", "fixture", transport=transport)


def _text(raw: dict[str, Any], key: str, path: Path, number: int) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuleLoadError(f"invalid rule in {path}: fixture {number} needs a non-empty '{key}'")
    return value


def _reply(raw: dict[str, Any], path: Path, number: int) -> str:
    """Read the scripted reply, allowing the empty string a decline fixture needs.

    `""` is the most valuable reply a fixture can script — a model that answered
    with nothing is the case a grader most often reads as "no attack found" — so it
    is a legal value here where every other string field requires content.
    """
    value = raw.get("reply")
    if not isinstance(value, str):
        raise RuleLoadError(
            f"invalid rule in {path}: fixture {number} needs a 'reply' string (\"\" is "
            f"allowed, and is how a decline is sampled)"
        )
    return value


def _outcome(raw: dict[str, Any], path: Path, number: int) -> FixtureOutcome:
    value = raw.get("outcome")
    try:
        return FixtureOutcome(str(value))
    except ValueError as exc:
        raise RuleLoadError(
            f"invalid rule in {path}: fixture {number} has outcome {value!r}; expected "
            f"one of {[str(o) for o in FixtureOutcome]}"
        ) from exc
