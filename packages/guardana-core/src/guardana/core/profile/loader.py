from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from guardana.core.profile.errors import ProfileError
from guardana.core.profile.model import FailOn, Policy, Profile
from guardana.core.severity import Severity

# Typos must fail loudly: a misspelled `fail_on:` would otherwise silently
# fall back to defaults and weaken the gate the user thinks they configured.
_ALLOWED_PROFILE_KEYS = frozenset({"name", "rules", "fail_on", "rule_config", "evaluators"})
_ALLOWED_RULES_KEYS = frozenset({"include", "exclude", "paths", "paths_exclude"})
_ALLOWED_FAIL_ON_KEYS = frozenset({"severity", "min_confidence", "fail_on_inconclusive"})


def default_profile() -> Profile:
    """Every rule, failing on HIGH — what you get without a `guardana.yaml`."""
    return Profile(name="default", policy=Policy())


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
    return FailOn(
        severity=Severity[severity_name.upper()],
        min_confidence=min_confidence,
        fail_on_inconclusive=fail_on_inconclusive,
    )


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
    )
