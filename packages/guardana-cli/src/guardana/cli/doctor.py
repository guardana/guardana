"""`guardana doctor` — what this installation is, and what is wrong with it.

The command somebody runs when a scan behaved unexpectedly, and the one a support
conversation should start with. It answers questions that are otherwise guessed
at: which distributions are installed and at what versions, which plugins were
discovered and which failed to import, whether the profile parses, and whether any
setting weakens the gate in a way the user may not have intended.

It never contacts a target. Diagnosing an installation must not cost money or
appear in somebody's production logs.
"""

from dataclasses import dataclass
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._plugins import resolve_trust
from guardana.cli._profile import resolve_profile
from guardana.cli.exit_codes import ExitCode
from guardana.core.profile import Profile
from guardana.core.redaction import EvidenceMode
from guardana.core.registry import Registry

_DISTRIBUTIONS = ("guardana-core", "guardana-rules", "guardana-cli", "guardana-report")


class Level(StrEnum):
    """How much a diagnostic matters."""

    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


_MARK = {Level.OK: "✓", Level.WARN: "!", Level.FAIL: "✖"}


@dataclass(frozen=True, slots=True)
class Check:
    """One thing doctor looked at."""

    name: str
    level: Level
    detail: str


def _versions() -> list[Check]:
    """Report each distribution's version, and flag a mismatch.

    A mismatch is a real failure mode rather than a tidiness concern: a stale
    `guardana-rules` beside a current CLI is a different tool than the version
    string suggests, and it is invisible until a rule behaves unexpectedly.
    """
    found: dict[str, str] = {}
    checks: list[Check] = []
    for name in _DISTRIBUTIONS:
        try:
            found[name] = version(name)
        except PackageNotFoundError:
            checks.append(Check(name, Level.WARN, "not installed"))
    checks.extend(Check(name, Level.OK, found_version) for name, found_version in found.items())
    distinct = set(found.values())
    if len(distinct) > 1:
        checks.append(
            Check(
                "version consistency",
                Level.WARN,
                f"distributions are at different versions ({', '.join(sorted(distinct))}) — "
                f"a rule may behave differently from what the CLI version suggests",
            )
        )
    return checks


def _plugins(registry: Registry) -> list[Check]:
    checks: list[Check] = []
    rules = registry.rules()
    checks.append(Check("rules discovered", Level.OK if rules else Level.FAIL, str(len(rules))))
    checks.append(Check("evaluators discovered", Level.OK, str(len(registry.evaluators()))))
    checks.extend(
        Check(f"plugin {error.source}", Level.FAIL, f"did not load ({error.stage}): {error.reason}")
        for error in registry.load_errors
    )
    third_party = sorted({rule.meta.id.split(".", 1)[0] for rule in rules} - {"guardana"})
    if third_party:
        checks.append(
            Check(
                "third-party rules",
                Level.WARN,
                f"rules from {', '.join(third_party)} are installed and will run — "
                f"a plugin is code this process imports (see SECURITY.md)",
            )
        )
    return checks


def _policy(profile: Profile) -> list[Check]:
    """Flag settings that weaken the gate, whether or not that was intended.

    Reported as warnings, never as failures: each of these is a legitimate choice
    somebody may have made deliberately. What must not happen is making it
    silently — a gate you think you configured and did not is worse than no gate.
    """
    checks: list[Check] = [Check("profile", Level.OK, f"{profile.name} parsed")]
    fail_on = profile.policy.fail_on
    if not fail_on.fail_on_error:
        checks.append(
            Check(
                "fail_on_error",
                Level.WARN,
                "off — a check that could not run will not fail the build",
            )
        )
    if profile.policy.exclude:
        checks.append(
            Check(
                "rules.exclude",
                Level.WARN,
                f"{len(profile.policy.exclude)} pattern(s) exclude rules: "
                f"{', '.join(profile.policy.exclude)}",
            )
        )
    if profile.privacy.mode is EvidenceMode.FULL:
        checks.append(
            Check(
                "evidence_mode",
                Level.WARN,
                "full — model output is stored in reports (secrets are still removed)",
            )
        )
    if profile.allow_destructive:
        checks.append(Check("allow_destructive", Level.WARN, "on — destructive rules may run"))
    if profile.budgets.is_unbounded:
        checks.append(
            Check(
                "budgets",
                Level.WARN,
                "no ceiling set — a probe against a paid endpoint has no upper bound",
            )
        )
    return checks


def doctor(
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[str | None, typer.Option(help="Named policy preset")] = None,
    plugins: Annotated[
        str, typer.Option(help="Which installed plugins to load: all|builtins|allowlist|disabled")
    ] = "all",
) -> None:
    """Report what this installation is and what is wrong with it. Contacts nothing."""
    prof = resolve_profile(profile, preset)
    registry = Registry.discover(resolve_trust(plugins, [], no_plugins=False))
    checks = [*_versions(), *_plugins(registry), *_policy(prof)]
    for check in checks:
        typer.echo(f"{_MARK[check.level]} {check.name}: {check.detail}")
    failures = [c for c in checks if c.level is Level.FAIL]
    warnings = [c for c in checks if c.level is Level.WARN]
    typer.echo("")
    typer.echo(f"{len(failures)} problem(s), {len(warnings)} thing(s) worth knowing.")
    if failures:
        # Something here is broken rather than merely unusual, so the command that
        # exists to find that says so in its exit status too.
        raise typer.Exit(code=ExitCode.INVALID_USAGE)
