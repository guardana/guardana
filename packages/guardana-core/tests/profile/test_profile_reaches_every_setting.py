"""Every setting the code can hold must be reachable from a `guardana.yaml`.

`FailOn.fail_on_skipped` shipped, was documented in `docs/usage-target.md` with a
worked example, was printed by `guardana config explain` — and the loader's
allowed-key set had never heard of it, so the documented example failed to load
and the gate it describes could not be turned on by anybody.

The specific fix is one word in a frozenset. The durable fix is the first test
below, which derives the expected keys from the dataclass rather than restating
them: a field added to `FailOn` without a way to set it now fails here.
"""

from dataclasses import fields
from pathlib import Path

import pytest
from guardana.core.profile import ProfileError, load_profile
from guardana.core.profile.model import FailOn


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "guardana.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_every_fail_on_field_can_be_set_from_a_profile(tmp_path: Path) -> None:
    # Derived from the dataclass, so this cannot go stale the way the frozenset did.
    booleans = [f.name for f in fields(FailOn) if isinstance(f.default, bool)]
    body = "name: t\nfail_on:\n  severity: HIGH\n" + "".join(
        f"  {name}: true\n" for name in booleans
    )

    profile = load_profile(_write(tmp_path, body))

    for name in booleans:
        assert getattr(profile.policy.fail_on, name) is True, (
            f"fail_on.{name} exists on FailOn but a profile cannot set it"
        )


def test_fail_on_skipped_turns_a_coverage_gap_into_a_configurable_gate(tmp_path: Path) -> None:
    # The setting `docs/usage-target.md` shows verbatim.
    profile = load_profile(_write(tmp_path, "name: t\nfail_on:\n  fail_on_skipped: true\n"))

    assert profile.policy.fail_on.fail_on_skipped is True


def test_fail_on_skipped_defaults_to_off(tmp_path: Path) -> None:
    profile = load_profile(_write(tmp_path, "name: t\n"))

    assert profile.policy.fail_on.fail_on_skipped is False


def test_a_non_boolean_fail_on_skipped_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ProfileError, match="fail_on_skipped"):
        load_profile(_write(tmp_path, "name: t\nfail_on:\n  fail_on_skipped: sometimes\n"))


def test_turning_off_secret_redaction_is_refused(tmp_path: Path) -> None:
    """`full` used to mean "store the live credential" the moment this was set.

    The switch only ever took effect at `full`, so its single reachable outcome
    was writing a working key into a report — while the module documented the
    opposite. Refused with a reason rather than dropped from the schema, because
    somebody who wrote it is owed an explanation.
    """
    body = "name: t\nprivacy:\n  evidence_mode: full\n  redact_secrets: false\n"

    with pytest.raises(ProfileError, match="removed at every evidence mode"):
        load_profile(_write(tmp_path, body))


def test_leaving_secret_redaction_on_is_still_accepted(tmp_path: Path) -> None:
    # Refusing `true` as well would break every profile that states the default.
    profile = load_profile(_write(tmp_path, "name: t\nprivacy:\n  redact_secrets: true\n"))

    assert profile.privacy.mode is not None
