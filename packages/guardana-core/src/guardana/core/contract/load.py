"""Read a security contract, refusing everything it cannot honour exactly.

Every refusal here exists for one reason: an invariant a team believes they wrote
down and that nothing checks is worse than an invariant they never wrote. A
misspelled `assertoins:` that loaded as an empty contract would produce a run
that grades nothing and exits `0`, which is the same fail-open a mistyped
`rules.include` was hardened against in 0.7.
"""

import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import yaml
from guardana.core.contract.assertion import (
    AllowedScopes,
    ApprovalRequired,
    Assertion,
    AssertionKind,
    CredentialBoundary,
    ForbiddenSink,
    TenantBoundary,
)
from guardana.core.contract.errors import ContractError
from guardana.core.contract.model import CONTRACT_SCHEMA_VERSION, AppliesTo, SecurityContract
from guardana.core.severity import Severity
from guardana.core.trace.effect import EffectStatus, SinkKind

_MIGRATIONS: dict[int, Callable[[Mapping[str, Any]], dict[str, Any]]] = {}
"""One step forward per version, keyed by the version the document *is*.

Empty at version 1 because nothing precedes it. The table and its refusal path
exist now rather than when they are first needed, so the first migration is an
entry here instead of an argument about where migrations should live — the same
shape `guardana.core.report.load` uses, deliberately.

There is no `contract migrate` command to match `run migrate`, and that is a
decision rather than an omission: a run document is generated and Guardana may
rewrite it, while a contract is hand-written and belongs to the team. Migration
happens in memory at load; the upgrade note tells them what to change on disk.
"""

MIGRATABLE_VERSIONS = frozenset(_MIGRATIONS)
"""Which declared versions this build can carry forward."""

_ALLOWED_CONTRACT_KEYS = frozenset({"schema_version", "name", "applies_to", "assertions"})
_ALLOWED_APPLIES_TO_KEYS = frozenset({"ai_system"})
_COMMON_ASSERTION_KEYS = frozenset({"id", "type", "title", "severity"})
_ALLOWED_ASSERTION_KEYS: dict[AssertionKind, frozenset[str]] = {
    AssertionKind.TENANT_BOUNDARY: _COMMON_ASSERTION_KEYS | {"sources"},
    AssertionKind.APPROVAL_REQUIRED: _COMMON_ASSERTION_KEYS | {"actions", "sinks", "approvers"},
    AssertionKind.ALLOWED_SCOPES: _COMMON_ASSERTION_KEYS | {"boundaries", "allow"},
    AssertionKind.CREDENTIAL_BOUNDARY: _COMMON_ASSERTION_KEYS | {"boundaries"},
    AssertionKind.FORBIDDEN_SINK: _COMMON_ASSERTION_KEYS | {"sinks", "actions", "statuses"},
}

_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
"""What a contract name and an assertion id may look like.

Constrained because both become part of a rule id (`contract.<name>.<id>`), and a
rule id is what a profile globs on and a baseline waives by. A dot would let one
assertion's id swallow a whole contract's namespace in an `exclude:` pattern
somebody wrote for a different purpose.
"""


def load_contract(path: Path) -> SecurityContract:
    """Read one security contract, or raise `ContractError` naming what is wrong with it."""
    try:
        raw_document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ContractError(f"cannot read contract {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ContractError(f"invalid contract {path}: {exc}") from exc
    return contract_from_dict(raw_document, source=str(path))


def contract_from_dict(raw_document: object, *, source: str) -> SecurityContract:
    """Build a contract from an already-parsed document, refusing anything unreadable."""
    if not isinstance(raw_document, dict):
        raise ContractError(f"invalid contract {source}: the top level must be a mapping")
    raw = _migrated(raw_document, source)
    _reject_unknown(raw, _ALLOWED_CONTRACT_KEYS, "contract", source)
    name = _name(raw.get("name"), "name", source)
    assertions = _assertions(raw.get("assertions"), source)
    return SecurityContract(
        name=name,
        assertions=assertions,
        source=source,
        applies_to=_applies_to(raw.get("applies_to"), source),
    )


def _migrated(raw: dict[str, Any], source: str) -> dict[str, Any]:
    """Carry an older document forward, and refuse one this build has never heard of.

    A version this build does not know is refused rather than read optimistically:
    a newer writer may have changed the meaning of a key this reader still
    recognises, and grading an application against a contract that was
    misunderstood is worse than grading it against none.
    """
    version = raw.get("schema_version")
    if version is None:
        raise ContractError(
            f"invalid contract {source}: no schema_version — a contract is a document you "
            f"keep, so it has to say which version it is (this build writes "
            f"{CONTRACT_SCHEMA_VERSION})"
        )
    if isinstance(version, bool) or not isinstance(version, int):
        raise ContractError(f"invalid contract {source}: schema_version must be a whole number")
    if version == CONTRACT_SCHEMA_VERSION:
        return raw
    if version not in _MIGRATIONS:
        raise ContractError(
            f"invalid contract {source}: schema_version {version} — this build reads "
            f"{CONTRACT_SCHEMA_VERSION} and can migrate {sorted(_MIGRATIONS)} "
            f"— upgrade whichever side is older"
        )
    document: dict[str, Any] = dict(raw)
    while version < CONTRACT_SCHEMA_VERSION:
        document = _MIGRATIONS[version](document)
        version += 1
    return document


def _reject_unknown(
    raw: Mapping[str, Any], allowed: frozenset[str], what: str, source: str
) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ContractError(
            f"invalid contract {source}: unknown {what} key(s): {', '.join(unknown)}"
        )


def _name(value: object, what: str, source: str) -> str:
    if not isinstance(value, str) or not _NAME.match(value):
        raise ContractError(
            f"invalid contract {source}: '{what}' must be lower-case letters, digits, "
            f"'-' or '_' (it becomes part of a rule id), got {value!r}"
        )
    return value


def _applies_to(raw: object, source: str) -> AppliesTo:
    if raw is None:
        return AppliesTo()
    if not isinstance(raw, dict):
        raise ContractError(f"invalid contract {source}: 'applies_to' must be a mapping")
    _reject_unknown(raw, _ALLOWED_APPLIES_TO_KEYS, "applies_to", source)
    ai_system = raw.get("ai_system")
    if ai_system is not None and not isinstance(ai_system, str):
        raise ContractError(f"invalid contract {source}: 'applies_to.ai_system' must be a string")
    if isinstance(ai_system, str) and not ai_system.strip():
        raise ContractError(
            f"invalid contract {source}: 'applies_to.ai_system' is empty — omit the key to "
            f"apply this contract to whatever it is pointed at"
        )
    return AppliesTo(ai_system=ai_system)


def _assertions(raw: object, source: str) -> tuple[Assertion, ...]:
    if not isinstance(raw, list) or not raw:
        raise ContractError(
            f"invalid contract {source}: 'assertions' must be a non-empty list — a contract "
            f"that asserts nothing would report clean on every execution"
        )
    out: list[Assertion] = []
    seen: set[str] = set()
    for entry in raw:
        assertion = _assertion(entry, source)
        if assertion.id in seen:
            raise ContractError(
                f"invalid contract {source}: two assertions share the id {assertion.id!r}, "
                f"so one would silently replace the other in the registry"
            )
        seen.add(assertion.id)
        out.append(assertion)
    return tuple(out)


def _assertion(raw: object, source: str) -> Assertion:
    if not isinstance(raw, dict):
        raise ContractError(f"invalid contract {source}: every assertion must be a mapping")
    kind = _kind(raw.get("type"), source)
    _reject_unknown(raw, _ALLOWED_ASSERTION_KEYS[kind], f"{kind} assertion", source)
    identifier = _name(raw.get("id"), "assertions[].id", source)
    common = {
        "id": identifier,
        "title": _title(raw.get("title"), identifier, source),
        "severity": _severity(raw.get("severity"), source),
    }
    return _BUILDERS[kind](raw, common, source)


def _kind(raw: object, source: str) -> AssertionKind:
    try:
        return AssertionKind(str(raw))
    except ValueError as exc:
        raise ContractError(
            f"invalid contract {source}: unknown assertion type {raw!r}; expected one of "
            f"{[str(k) for k in AssertionKind]}"
        ) from exc


def _title(raw: object, identifier: str, source: str) -> str:
    """Read the sentence a report prints, falling back to the id rather than to nothing.

    Not defaulted from the kind: two assertions of one kind in one contract would
    then be indistinguishable in a report, which is exactly when a title matters.
    """
    if raw is None:
        return identifier
    if not isinstance(raw, str) or not raw.strip():
        raise ContractError(
            f"invalid contract {source}: assertion {identifier!r} has a non-text title"
        )
    return raw


def _severity(raw: object, source: str) -> Severity:
    if raw is None:
        return Severity.HIGH
    name = str(raw).upper()
    if name not in Severity.__members__:
        raise ContractError(
            f"invalid contract {source}: unknown severity {raw!r}; expected one of "
            f"{[s.name.lower() for s in Severity]}"
        )
    return Severity[name]


def _globs(raw: object, what: str, source: str, *, required: bool = False) -> tuple[str, ...]:
    """Parse a list of patterns, refusing the one mistake that would silence the check.

    YAML accepts `sinks: shell` — a string, not a list — and `tuple()` of a string
    explodes it into single characters that match nothing. An assertion matching
    nothing is an assertion that passes on every execution, so this is a hard error
    rather than a coercion.
    """
    if raw is None:
        if required:
            raise ContractError(f"invalid contract {source}: '{what}' is required and missing")
        return ()
    if not isinstance(raw, list):
        raise ContractError(
            f"invalid contract {source}: '{what}' must be a list of strings, "
            f"got {type(raw).__name__}"
        )
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise ContractError(
                f"invalid contract {source}: every entry in '{what}' must be a non-empty string"
            )
    if required and not raw:
        raise ContractError(
            f"invalid contract {source}: '{what}' is empty, which matches nothing — an "
            f"assertion that matches nothing reports clean on every execution"
        )
    return tuple(raw)


def _sinks(raw: object, what: str, source: str, *, required: bool = False) -> tuple[str, ...]:
    """Parse sink names against the closed list, so a typo cannot become a sink nobody has.

    `SinkKind` is closed for this exact reason, and a contract naming `sql_server`
    where the model says `sql` would otherwise be a forbidden-sink rule that never
    matches — a control that silently stopped running.
    """
    names = _globs(raw, what, source, required=required)
    known = {str(s) for s in SinkKind}
    unknown = sorted(set(names) - known)
    if unknown:
        raise ContractError(
            f"invalid contract {source}: unknown sink(s) in '{what}': {', '.join(unknown)}; "
            f"expected one of {sorted(known)}"
        )
    return names


def _statuses(raw: object, source: str) -> tuple[EffectStatus, ...]:
    if raw is None:
        return (EffectStatus.EXECUTED, EffectStatus.ATTEMPTED)
    names = _globs(raw, "statuses", source, required=True)
    out: list[EffectStatus] = []
    for name in names:
        try:
            out.append(EffectStatus(name))
        except ValueError as exc:
            raise ContractError(
                f"invalid contract {source}: unknown effect status {name!r}; expected one of "
                f"{[str(s) for s in EffectStatus]}"
            ) from exc
    return tuple(out)


def _tenant_boundary(raw: dict[str, Any], common: dict[str, Any], source: str) -> Assertion:
    return TenantBoundary(**common, sources=_globs(raw.get("sources"), "sources", source))


def _approval_required(raw: dict[str, Any], common: dict[str, Any], source: str) -> Assertion:
    return ApprovalRequired(
        **common,
        actions=_globs(raw.get("actions"), "actions", source),
        sinks=_sinks(raw.get("sinks"), "sinks", source),
        approvers=_globs(raw.get("approvers"), "approvers", source),
    )


def _allowed_scopes(raw: dict[str, Any], common: dict[str, Any], source: str) -> Assertion:
    return AllowedScopes(
        **common,
        boundaries=_globs(raw.get("boundaries"), "boundaries", source),
        # Required, and an empty list is refused rather than read as "allow nothing":
        # both readings are defensible, which is precisely why the document has to
        # say which one it meant.
        allow=_globs(raw.get("allow"), "allow", source, required=True),
    )


def _credential_boundary(raw: dict[str, Any], common: dict[str, Any], source: str) -> Assertion:
    return CredentialBoundary(
        **common,
        boundaries=_globs(raw.get("boundaries"), "boundaries", source, required=True),
    )


def _forbidden_sink(raw: dict[str, Any], common: dict[str, Any], source: str) -> Assertion:
    return ForbiddenSink(
        **common,
        sinks=_sinks(raw.get("sinks"), "sinks", source, required=True),
        actions=_globs(raw.get("actions"), "actions", source),
        statuses=_statuses(raw.get("statuses"), source),
    )


_BUILDERS: dict[AssertionKind, Callable[[dict[str, Any], dict[str, Any], str], Assertion]] = {
    AssertionKind.TENANT_BOUNDARY: _tenant_boundary,
    AssertionKind.APPROVAL_REQUIRED: _approval_required,
    AssertionKind.ALLOWED_SCOPES: _allowed_scopes,
    AssertionKind.CREDENTIAL_BOUNDARY: _credential_boundary,
    AssertionKind.FORBIDDEN_SINK: _forbidden_sink,
}
