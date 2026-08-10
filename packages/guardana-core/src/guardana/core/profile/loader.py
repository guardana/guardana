import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from guardana.core.budget import Budgets, parse_duration
from guardana.core.profile.errors import ProfileError
from guardana.core.profile.model import FailOn, Policy, Profile
from guardana.core.redaction import DEFAULT_MAX_EVIDENCE_BYTES, EvidenceMode, RedactionPolicy
from guardana.core.severity import Severity
from guardana.core.trace.model import Dimension

# Typos must fail loudly: a misspelled `fail_on:` would otherwise silently
# fall back to defaults and weaken the gate the user thinks they configured.
_ALLOWED_PROFILE_KEYS = frozenset(
    {
        "name",
        "rules",
        "fail_on",
        "rule_config",
        "evaluators",
        "budgets",
        "privacy",
        "trace",
        "contracts",
    }
)
_ALLOWED_RULES_KEYS = frozenset({"include", "exclude", "paths", "paths_exclude"})
_ALLOWED_TRACE_KEYS = frozenset({"require"})
_ALLOWED_FAIL_ON_KEYS = frozenset(
    {"severity", "min_confidence", "fail_on_inconclusive", "fail_on_error", "fail_on_skipped"}
)
_ALLOWED_BUDGET_KEYS = frozenset(
    {"max_requests", "max_input_tokens", "max_output_tokens", "max_duration"}
)
_ALLOWED_PRIVACY_KEYS = frozenset(
    {
        "evidence_mode",
        "redact_secrets",
        "redact_emails",
        "redact_ip_addresses",
        "hash_identifiers",
        "custom_patterns",
        "max_evidence_bytes",
    }
)


def default_profile() -> Profile:
    """Every rule, failing on HIGH, evidence redacted — what you get without a `guardana.yaml`.

    Redaction is on by default here because this is what a command uses. A tool
    that quietly wrote model output to disk would be a liability the first time
    somebody pointed it at a production support agent.
    """
    return Profile(
        name="default",
        policy=Policy(),
        privacy=RedactionPolicy(mode=EvidenceMode.REDACTED),
    )


def _as_mapping(value: object, what: str, path: Path) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ProfileError(f"invalid profile {path}: '{what}' must be a mapping")
    return value


def _reject_unknown_keys(
    raw: Mapping[str, Any], allowed: frozenset[str], what: str, path: Path
) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ProfileError(f"invalid profile {path}: unknown {what} key(s): {', '.join(unknown)}")


def _as_glob_list(value: object, what: str, path: Path) -> tuple[str, ...]:
    """Parse a list of globs, refusing the one mistake that would silence the scan.

    YAML accepts `include: "guardana.*"` (a string, not a list), and `tuple()` of
    a string explodes it into single-character globs that match no rule id — a
    scan that runs zero rules and exits 0 on a malicious repo. A gate you think
    you configured but didn't is worse than no gate, so this is a hard error.
    """
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ProfileError(
            f"invalid profile {path}: '{what}' must be a list of strings, "
            f"got {type(value).__name__}"
        )
    for item in value:
        if not isinstance(item, str):
            raise ProfileError(f"invalid profile {path}: every entry in '{what}' must be a string")
    return tuple(value)


def _fail_on(raw: dict[str, Any], path: Path) -> FailOn:
    _reject_unknown_keys(raw, _ALLOWED_FAIL_ON_KEYS, "fail_on", path)
    severity_name = raw.get("severity", "high")
    if not isinstance(severity_name, str) or severity_name.upper() not in Severity.__members__:
        raise ProfileError(f"invalid profile {path}: unknown severity {severity_name!r}")
    try:
        min_confidence = float(raw.get("min_confidence", 0.0))
    except (TypeError, ValueError) as exc:
        raise ProfileError(f"invalid profile {path}: min_confidence must be a number") from exc
    # NaN and out-of-range values silently disable the confidence gate — the
    # comparison `confidence >= min_confidence` is always False for them.
    if not 0.0 <= min_confidence <= 1.0:
        raise ProfileError(
            f"invalid profile {path}: min_confidence must be in [0.0, 1.0], got {min_confidence}"
        )
    fail_on_inconclusive = raw.get("fail_on_inconclusive", False)
    if not isinstance(fail_on_inconclusive, bool):
        raise ProfileError(f"invalid profile {path}: fail_on_inconclusive must be true or false")
    fail_on_error = raw.get("fail_on_error", True)
    if not isinstance(fail_on_error, bool):
        raise ProfileError(f"invalid profile {path}: fail_on_error must be true or false")
    fail_on_skipped = raw.get("fail_on_skipped", False)
    if not isinstance(fail_on_skipped, bool):
        raise ProfileError(f"invalid profile {path}: fail_on_skipped must be true or false")
    return FailOn(
        severity=Severity[severity_name.upper()],
        min_confidence=min_confidence,
        fail_on_inconclusive=fail_on_inconclusive,
        fail_on_error=fail_on_error,
        fail_on_skipped=fail_on_skipped,
    )


def _positive_int(raw: dict[str, Any], key: str, path: Path) -> int | None:
    """Read one ceiling, refusing anything that would not actually bound a run."""
    value = raw.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProfileError(f"invalid profile {path}: budgets.{key} must be a whole number")
    if value < 1:
        raise ProfileError(
            f"invalid profile {path}: budgets.{key} must be at least 1 — a ceiling of "
            f"{value} would stop the run before it checked anything, which is not a budget"
        )
    return value


def _budgets(raw: dict[str, Any], path: Path) -> Budgets:
    """Parse the `budgets:` block, refusing every value that cannot bound a run.

    Loud on a bad value, like every other part of a profile: a ceiling somebody
    believes they set and did not is worse than no ceiling, because they stop
    watching the bill.
    """
    _reject_unknown_keys(raw, _ALLOWED_BUDGET_KEYS, "budgets", path)
    duration = raw.get("max_duration")
    seconds: float | None = None
    if duration is not None:
        try:
            seconds = parse_duration(str(duration))
        except ValueError as exc:
            raise ProfileError(f"invalid profile {path}: {exc}") from exc
    return Budgets(
        max_requests=_positive_int(raw, "max_requests", path),
        max_input_tokens=_positive_int(raw, "max_input_tokens", path),
        max_output_tokens=_positive_int(raw, "max_output_tokens", path),
        max_duration_seconds=seconds,
    )


def _flag(raw: dict[str, Any], key: str, default: bool, path: Path) -> bool:
    value = raw.get(key, default)
    if not isinstance(value, bool):
        raise ProfileError(f"invalid profile {path}: privacy.{key} must be true or false")
    return value


def _privacy(raw: dict[str, Any], path: Path) -> RedactionPolicy:
    """Parse the `privacy:` block, refusing a mode or a pattern nobody can honour.

    An unreadable custom pattern raises rather than being dropped: a redaction
    rule somebody believes is applied and is not is worse than none, because they
    stop checking the output.
    """
    _reject_unknown_keys(raw, _ALLOWED_PRIVACY_KEYS, "privacy", path)
    if raw.get("redact_secrets") is False:
        # Accepted as a key and refused as a value, rather than dropped from the
        # schema: somebody who wrote it deserves to be told that secrets are
        # always removed, not to be told the key does not exist.
        raise ProfileError(
            f"invalid profile {path}: privacy.redact_secrets cannot be false — a secret is "
            f"removed at every evidence mode, because the finding is that it appeared and "
            f"never what it was"
        )
    mode_name = str(raw.get("evidence_mode", EvidenceMode.REDACTED))
    try:
        mode = EvidenceMode(mode_name)
    except ValueError as exc:
        raise ProfileError(
            f"invalid profile {path}: unknown privacy.evidence_mode {mode_name!r}; "
            f"expected one of {[str(m) for m in EvidenceMode]}"
        ) from exc
    patterns = _as_glob_list(raw.get("custom_patterns"), "privacy.custom_patterns", path)
    for pattern in patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ProfileError(
                f"invalid profile {path}: privacy.custom_patterns entry {pattern!r} "
                f"is not a valid regular expression: {exc}"
            ) from exc
    limit = raw.get("max_evidence_bytes", DEFAULT_MAX_EVIDENCE_BYTES)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ProfileError(
            f"invalid profile {path}: privacy.max_evidence_bytes must be a positive whole number"
        )
    return RedactionPolicy(
        mode=mode,
        redact_emails=_flag(raw, "redact_emails", True, path),
        redact_ip_addresses=_flag(raw, "redact_ip_addresses", False, path),
        hash_identifiers=_flag(raw, "hash_identifiers", True, path),
        custom_patterns=patterns,
        max_evidence_bytes=limit,
    )


def _required_dimensions(raw: dict[str, Any], path: Path) -> tuple[Dimension, ...]:
    """Parse `trace.require:`, refusing a dimension nobody can satisfy.

    Loud on an unknown name, for the reason every other list here is: `require:
    [aproval]` would be a coverage demand that can never be met, so every run
    against every trace would be indeterminate — a gate that fails closed on
    everything is as useless as one that fails open on everything, and neither is
    what the operator wrote.
    """
    _reject_unknown_keys(raw, _ALLOWED_TRACE_KEYS, "trace", path)
    names = _as_glob_list(raw.get("require"), "trace.require", path)
    known = {str(d) for d in Dimension}
    unknown = sorted(set(names) - known)
    if unknown:
        raise ProfileError(
            f"invalid profile {path}: unknown trace.require dimension(s): "
            f"{', '.join(unknown)}; expected one of {sorted(known)}"
        )
    return tuple(dict.fromkeys(Dimension(name) for name in names))


def load_profile(path: Path) -> Profile:
    """Parse a `guardana.yaml`, rejecting anything it can't honour.

    A typo'd key raises rather than silently falling back to a weaker default:
    a gate you think you configured but didn't is worse than no gate.
    """
    try:
        raw_document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ProfileError(f"cannot read profile {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ProfileError(f"invalid profile {path}: {exc}") from exc

    raw = _as_mapping(raw_document, "profile", path)
    _reject_unknown_keys(raw, _ALLOWED_PROFILE_KEYS, "profile", path)
    rules = _as_mapping(raw.get("rules"), "rules", path)
    _reject_unknown_keys(rules, _ALLOWED_RULES_KEYS, "rules", path)

    include = _as_glob_list(rules.get("include", ["*"]), "rules.include", path)
    if not include:
        raise ProfileError(
            f"invalid profile {path}: 'rules.include' is empty, which matches no rule "
            f"(omit it to include everything)"
        )
    policy = Policy(
        include=include,
        exclude=_as_glob_list(rules.get("exclude"), "rules.exclude", path),
        fail_on=_fail_on(_as_mapping(raw.get("fail_on"), "fail_on", path), path),
    )
    return Profile(
        name=str(raw.get("name", "custom")),
        policy=policy,
        rule_config=_as_mapping(raw.get("rule_config"), "rule_config", path),
        evaluator_config=_as_mapping(raw.get("evaluators"), "evaluators", path),
        rule_paths=_as_glob_list(rules.get("paths"), "rules.paths", path),
        path_excludes=_as_glob_list(rules.get("paths_exclude"), "rules.paths_exclude", path),
        budgets=_budgets(_as_mapping(raw.get("budgets"), "budgets", path), path),
        privacy=_privacy(_as_mapping(raw.get("privacy"), "privacy", path), path),
        required_dimensions=_required_dimensions(
            _as_mapping(raw.get("trace"), "trace", path), path
        ),
        contract_paths=_as_glob_list(raw.get("contracts"), "contracts", path),
    )
