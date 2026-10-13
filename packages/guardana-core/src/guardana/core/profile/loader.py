import math
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from guardana.core.budget import Budgets, parse_duration
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile.errors import ProfileError
from guardana.core.profile.model import FailOn, Policy, Profile
from guardana.core.redaction import DEFAULT_MAX_EVIDENCE_BYTES, EvidenceMode, RedactionPolicy
from guardana.core.severity import Severity
from guardana.core.trace.model import Dimension
from guardana.core.trials import check_trials

PROFILE_SCHEMA_VERSION = 1
"""The profile schema this build reads; a profile without `schema_version` is version 1.

No writer states it while it is 1, so a profile this build writes still loads in a build
that predates the key. A key added later raises it, and an older build then refuses the
file naming the upgrade instead of reading the new key as a typo.
"""

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
        "calibrations",
        "trials",
        "plugins",
        "delivery",
    }
)
_ALLOWED_RULES_KEYS = frozenset({"include", "exclude", "paths", "paths_exclude"})
_ALLOWED_TRACE_KEYS = frozenset({"require"})
_ALLOWED_PLUGINS_KEYS = frozenset({"mode", "allow"})
_ALLOWED_DELIVERY_KEYS = frozenset({"required"})
_ALLOWED_FAIL_ON_KEYS = frozenset(
    {
        "severity",
        "min_confidence",
        "fail_on_inconclusive",
        "fail_on_error",
        "fail_on_skipped",
        "min_graded_share",
    }
)
_ALLOWED_BUDGET_KEYS = frozenset(
    {
        "max_requests",
        "max_input_tokens",
        "max_output_tokens",
        "max_duration",
        "max_requests_per_minute",
    }
)
EVALUATOR_BLOCK_KEYS: Mapping[str, frozenset[str]] = {
    "llm_judge": frozenset(
        {
            "endpoint",
            "model",
            "api_key_env",
            "provider",
            "adapter",
            "prompt_version",
            "min_agreement",
            "calibration",
        }
    ),
    "guard": frozenset({"endpoint", "model", "api_key_env", "provider", "adapter"}),
}
"""The blocks `evaluators:` may hold and the keys each accepts; anything else is a typo."""

_ALLOWED_PRIVACY_KEYS = frozenset(
    {
        "evidence_mode",
        "redact_secrets",
        "redact_emails",
        "redact_ip_addresses",
        "hash_identifiers",
        "custom_patterns",
        "max_evidence_bytes",
        "keep_exchanges",
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


def check_evaluator_blocks(blocks: Mapping[str, object], *, where: str = "") -> None:
    """Refuse a block under `evaluators:` this build does not know, or a key it does not read.

    A misspelled judge block was never wired, so the rules naming its evaluator were
    skipped while the profile read as configured. `where` prefixes each message.
    """
    unknown = sorted(str(name) for name in set(blocks) - set(EVALUATOR_BLOCK_KEYS))
    if unknown:
        raise ProfileError(
            f"{where}unknown evaluators block(s): {', '.join(unknown)}; "
            f"known: {', '.join(sorted(EVALUATOR_BLOCK_KEYS))}"
        )
    for name, block in blocks.items():
        if not isinstance(block, Mapping):
            raise ProfileError(f"{where}evaluators.{name} must be a mapping")
        keys = sorted(str(key) for key in set(block) - EVALUATOR_BLOCK_KEYS[name])
        if keys:
            raise ProfileError(f"{where}unknown evaluators.{name} key(s): {', '.join(keys)}")


def _evaluators(raw: object, path: Path) -> dict[str, Any]:
    blocks = _as_mapping(raw, "evaluators", path)
    check_evaluator_blocks(blocks, where=f"invalid profile {path}: ")
    return blocks


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


def _beside_the_profile(patterns: tuple[str, ...], path: Path) -> tuple[str, ...]:
    """Anchor relative entries to the profile's own directory, leaving absolute ones alone.

    A profile is a committed file naming its neighbours, so a relative entry means
    "beside this file" and not "beside whatever directory the caller happened to be
    in" — otherwise the same profile works from a repository root and fails from a
    hook or a CI step. Joined rather than resolved, so a glob keeps its meaning.
    """
    return tuple(p if Path(p).is_absolute() else str(path.parent / p) for p in patterns)


def _fail_on(raw: dict[str, Any], path: Path) -> FailOn:
    _reject_unknown_keys(raw, _ALLOWED_FAIL_ON_KEYS, "fail_on", path)
    severity_name = raw.get("severity", "high")
    if not isinstance(severity_name, str) or severity_name.upper() not in Severity.__members__:
        raise ProfileError(f"invalid profile {path}: unknown severity {severity_name!r}")
    raw_confidence = raw.get("min_confidence", 0.0)
    min_confidence = _confidence_number(raw_confidence)
    if min_confidence is None:
        raise ProfileError(
            f"invalid profile {path}: min_confidence must be a number, got {raw_confidence!r}"
        )
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
        min_graded_share=_graded_share(raw.get("min_graded_share"), path),
    )


def _confidence_number(value: object) -> float | None:
    """Read `min_confidence` as a number: an int, a float or a quoted finite number; never a bool.

    YAML `true` is an int to Python, and reading it as 1.0 would hide every finding below
    full confidence from the gate.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            number = float(value)
        except ValueError:
            return None
        return number if math.isfinite(number) else None
    return None


def _graded_share(value: object, path: Path) -> float | None:
    """Read the floor on a rule's graded share, refusing anything outside `(0, 1]`.

    Zero is refused with the rest: a floor nothing can fall below is not a floor, and a
    team that wrote one believes the run is held to it.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ProfileError(f"invalid profile {path}: fail_on.min_graded_share must be a number")
    share = float(value)
    if not 0.0 < share <= 1.0:
        raise ProfileError(
            f"invalid profile {path}: fail_on.min_graded_share must be in (0, 1], got {value}"
        )
    return share


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
        max_requests_per_minute=_positive_int(raw, "max_requests_per_minute", path),
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
    keep_exchanges = _flag(raw, "keep_exchanges", False, path)
    if keep_exchanges and mode is EvidenceMode.METADATA_ONLY:
        raise ProfileError(
            f"invalid profile {path}: privacy.keep_exchanges is true and "
            f"privacy.evidence_mode is metadata_only; keeping exchanges stores what the "
            f"target said, which metadata_only forbids, so set one of the two differently"
        )
    return RedactionPolicy(
        mode=mode,
        redact_emails=_flag(raw, "redact_emails", True, path),
        redact_ip_addresses=_flag(raw, "redact_ip_addresses", False, path),
        hash_identifiers=_flag(raw, "hash_identifiers", True, path),
        custom_patterns=patterns,
        max_evidence_bytes=limit,
        keep_exchanges=keep_exchanges,
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


def _trials(raw: object, path: Path) -> int:
    """Parse `trials:`, refusing anything that is not a whole number of attempts."""
    try:
        return check_trials(raw)
    except ValueError as exc:
        raise ProfileError(f"invalid profile {path}: {exc}") from exc


def _plugins(raw: object, path: Path) -> PluginTrust | None:
    """Parse `plugins:`, refusing any shape whose trust is not exactly what was written.

    An allowlist with nobody on it, or names beside a mode that ignores them, would
    load something other than what the author believes they stated.
    """
    if raw is None:
        return None
    block = _as_mapping(raw, "plugins", path)
    _reject_unknown_keys(block, _ALLOWED_PLUGINS_KEYS, "plugins", path)
    modes = [str(mode) for mode in PluginMode]
    mode_name = block.get("mode")
    if not isinstance(mode_name, str) or mode_name not in modes:
        raise ProfileError(
            f"invalid profile {path}: plugins.mode must be one of {', '.join(modes)}, "
            f"got {mode_name!r}"
        )
    mode = PluginMode(mode_name)
    if "allow" in block and mode is not PluginMode.ALLOWLIST:
        raise ProfileError(
            f"invalid profile {path}: plugins.allow names distributions, which only "
            f"plugins.mode: allowlist admits; mode is {mode_name!r}"
        )
    allow = _as_glob_list(block.get("allow"), "plugins.allow", path)
    if any(not name.strip() for name in allow):
        raise ProfileError(f"invalid profile {path}: plugins.allow holds an empty name")
    if mode is PluginMode.ALLOWLIST and not allow:
        raise ProfileError(
            f"invalid profile {path}: plugins.mode: allowlist needs plugins.allow to name "
            f"at least one distribution; for the built-ins alone use mode: builtins"
        )
    return PluginTrust(mode=mode, allowed=frozenset(allow))


def _delivery_required(raw: object, path: Path) -> bool:
    """Parse `delivery:`, whose one key says whether every delivery must be acknowledged."""
    block = _as_mapping(raw, "delivery", path)
    _reject_unknown_keys(block, _ALLOWED_DELIVERY_KEYS, "delivery", path)
    required = block.get("required", False)
    if not isinstance(required, bool):
        raise ProfileError(f"invalid profile {path}: delivery.required must be true or false")
    return required


def _check_schema_version(raw: Mapping[str, Any], path: Path) -> None:
    """Refuse a profile written for a schema this build does not read.

    Checked before unknown keys, so a profile from a newer build names the upgrade rather
    than the key that build added.
    """
    if "schema_version" not in raw:
        return
    version = raw["schema_version"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise ProfileError(f"invalid profile {path}: schema_version must be an integer")
    if version > PROFILE_SCHEMA_VERSION:
        raise ProfileError(
            f"invalid profile {path}: profile schema {version} was written by a newer "
            f"Guardana; this build reads schema {PROFILE_SCHEMA_VERSION} — upgrade Guardana"
        )
    if version < 1:
        raise ProfileError(f"invalid profile {path}: schema_version {version} does not exist")


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
    _check_schema_version(raw, path)
    _reject_unknown_keys(raw, _ALLOWED_PROFILE_KEYS | {"schema_version"}, "profile", path)
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
        evaluator_config=_evaluators(raw.get("evaluators"), path),
        rule_paths=_beside_the_profile(
            _as_glob_list(rules.get("paths"), "rules.paths", path), path
        ),
        path_excludes=_as_glob_list(rules.get("paths_exclude"), "rules.paths_exclude", path),
        budgets=_budgets(_as_mapping(raw.get("budgets"), "budgets", path), path),
        privacy=_privacy(_as_mapping(raw.get("privacy"), "privacy", path), path),
        required_dimensions=_required_dimensions(
            _as_mapping(raw.get("trace"), "trace", path), path
        ),
        contract_paths=_beside_the_profile(
            _as_glob_list(raw.get("contracts"), "contracts", path), path
        ),
        calibration_paths=_beside_the_profile(
            _as_glob_list(raw.get("calibrations"), "calibrations", path), path
        ),
        trials=_trials(raw.get("trials", 1), path),
        plugins=_plugins(raw.get("plugins"), path),
        delivery_required=_delivery_required(raw.get("delivery"), path),
        source=path,
    )
