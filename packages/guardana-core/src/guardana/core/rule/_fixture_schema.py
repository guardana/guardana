"""Parse a YAML rule's `fixtures:` block into declared samples.

A YAML rule's `target_kind` is `endpoint` by construction, so its double is always a
scripted model and a fixture only has to say what that model replies. That is the
whole reason this can be data: there is exactly one shape of target to build.

An artifact rule needs bytes, and bytes in YAML is either a path to a checked-in
malicious file or base64 nobody can review — so a plugin rule overrides
`Rule.fixtures()` in Python instead, using the builders `guardana.core.testing`
already ships.
"""

from pathlib import Path
from typing import Any

from guardana.core.rule.errors import RuleLoadError
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture
from guardana.core.target import EndpointTarget
from guardana.core.testing import ScriptedTransport

_ALLOWED_FIXTURE_KEYS = frozenset({"name", "reply", "outcome", "note"})


def parse_fixtures(raw: object, path: Path) -> tuple[RuleFixture, ...]:
    """Validate a `fixtures:` list, or return nothing when a rule declares none.

    Absent is allowed and is **not** the same as fine: `verify_rule` reports an
    unsampled rule as a gap, and `guardana rule test` turns that into
    `indeterminate`. Refusing at load time instead would make every existing rule
    file unreadable by this build, which is a migration that breaks a user's own
    rules to enforce a bar on ours.
    """
    if raw is None:
        return ()
    if not isinstance(raw, list) or not raw:
        raise RuleLoadError(
            f"invalid rule in {path}: 'fixtures' must be a non-empty list — an empty "
            f"one declares samples and provides none, which reads as checked"
        )
    return tuple(_fixture(entry, path, number) for number, entry in enumerate(raw, start=1))


def _fixture(raw: object, path: Path, number: int) -> RuleFixture:
    if not isinstance(raw, dict):
        raise RuleLoadError(f"invalid rule in {path}: fixture {number} must be a mapping")
    unknown = sorted(set(raw) - _ALLOWED_FIXTURE_KEYS)
    if unknown:
        raise RuleLoadError(
            f"invalid rule in {path}: fixture {number} has unknown key(s) "
            f"{', '.join(unknown)}; expected {sorted(_ALLOWED_FIXTURE_KEYS)}"
        )
    return RuleFixture(
        name=_text(raw, "name", path, number),
        target=EndpointTarget(
            "http://fixture.invalid",
            "fixture",
            transport=ScriptedTransport(_reply(raw, path, number)),
        ),
        outcome=_outcome(raw, path, number),
        note=str(raw.get("note", "")),
    )


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
