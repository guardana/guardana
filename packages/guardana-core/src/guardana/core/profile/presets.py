"""Named policy presets for the moments a scan runs in.

A preset tunes only the *failure bar* (and, later, rule selection). Which security
layer actually runs is already decided by the command — `scan` runs the
build-time (static) rules, `probe`/`monitor` the runtime (dynamic) ones — so a
preset does not need to filter by surface, only to say how strict the gate is for
that moment.
"""

from guardana.core.profile.errors import ProfileError
from guardana.core.profile.model import FailOn, Policy, Profile
from guardana.core.severity import Severity

_PRESETS: dict[str, Profile] = {
    # CI / local dev gate: fail on HIGH, the standard bar.
    "ci": Profile(name="ci", policy=Policy(fail_on=FailOn(severity=Severity.HIGH))),
    # The training server, before a run consumes data/weights: stricter, so
    # MEDIUM leads (unpinned datasets, provenance gaps) block too.
    "pre-training": Profile(
        name="pre-training", policy=Policy(fail_on=FailOn(severity=Severity.MEDIUM))
    ),
    # A live monitor must not tolerate its own checks going dark: an inconclusive
    # verdict fails the gate alongside a HIGH finding.
    "monitor": Profile(
        name="monitor",
        policy=Policy(fail_on=FailOn(severity=Severity.HIGH, fail_on_inconclusive=True)),
    ),
}

PRESET_NAMES = tuple(_PRESETS)


def preset(name: str) -> Profile:
    """Return the built-in profile for a preset name, raising `ProfileError` if unknown."""
    try:
        return _PRESETS[name]
    except KeyError:
        raise ProfileError(
            f"unknown preset {name!r}; choose one of {', '.join(PRESET_NAMES)}"
        ) from None
