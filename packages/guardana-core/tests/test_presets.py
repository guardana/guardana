import pytest
from guardana.core.profile import PRESET_NAMES, ProfileError, preset
from guardana.core.severity import Severity


def test_ci_preset_fails_on_high() -> None:
    fail_on = preset("ci").policy.fail_on
    assert fail_on.severity is Severity.HIGH
    assert fail_on.fail_on_inconclusive is False


def test_pre_training_preset_is_stricter_and_fails_on_medium() -> None:
    # The training server catches leads (unpinned data, provenance) before a run.
    assert preset("pre-training").policy.fail_on.severity is Severity.MEDIUM


def test_monitor_preset_fails_on_inconclusive() -> None:
    # A monitor must not tolerate its own checks going dark.
    assert preset("monitor").policy.fail_on.fail_on_inconclusive is True


def test_unknown_preset_raises_loudly() -> None:
    with pytest.raises(ProfileError, match="unknown preset"):
        preset("nope")


def test_every_preset_name_resolves() -> None:
    assert PRESET_NAMES
    for name in PRESET_NAMES:
        assert preset(name).name == name
