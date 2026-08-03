"""Three smaller findings from the review of the finished 0.7 code.

Each is a promise the code made in prose and did not keep: a plugin mode that
refused everything without saying so, a request ceiling that only held when
nothing ran in parallel, and a plan that priced rules the run would refuse.
"""

import threading

import pytest
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.plan import build_plan
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import default_profile
from guardana.core.registry import Registry
from guardana.core.safety import Impact
from guardana.core.usage import UsageMeter


def test_disabling_plugins_records_what_it_refused() -> None:
    """Every other mode says what it did not load; `disabled` returned before the loop.

    A run with no rules whose report says nothing about why is a run whose silence
    means nothing — and `disabled` is the only mode where that silence covers
    every check the tool has.
    """
    refused = Registry.discover(PluginTrust(mode=PluginMode.DISABLED))

    assert refused.rules() == ()
    assert refused.load_errors, "the run loaded nothing and did not say so"
    assert any("disabled" in error.reason for error in refused.load_errors)


def test_a_refusal_names_the_distribution_it_came_from() -> None:
    trust = PluginTrust(mode=PluginMode.ALLOWLIST, allowed=frozenset({"nothing-installed"}))

    reasons = " ".join(error.reason for error in Registry.discover(trust).load_errors)

    assert "guardana-rules" not in reasons, "a built-in is trusted in every mode but disabled"


def test_concurrent_reservations_cannot_exceed_the_request_ceiling() -> None:
    """`reserve` promises "200 means 200, never 201". It read a counter that moved late.

    Every thread of a `--concurrency 4` probe passed the same check at once, so
    four more requests went out over the ceiling — a promise that held only in the
    sequential case the docstring was written for.
    """
    ceiling, racers = 4, 8
    meter = UsageMeter(Budgets(max_requests=ceiling))
    granted = 0
    lock = threading.Lock()
    # Two barriers, so the interleaving is decided by the test and not by the
    # scheduler: every racer claims before any racer records, which is the state a
    # probe running four rules at once is in for the whole length of a request.
    # With one barrier the window is microseconds wide and the broken code passes,
    # and a test that cannot be broken checks nothing.
    claiming = threading.Barrier(racers)
    recording = threading.Barrier(racers)

    def claim() -> None:
        nonlocal granted
        claiming.wait()
        try:
            meter.reserve()
        except BudgetExhausted:
            recording.wait()
            return
        with lock:
            granted += 1
        recording.wait()
        meter.record(None)

    threads = [threading.Thread(target=claim) for _ in range(racers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert granted == ceiling, f"{granted} racers passed a ceiling of {ceiling}"


def test_a_request_in_flight_already_counts_against_the_ceiling() -> None:
    """The same defect stated without a race, which is where it actually lives.

    The ceiling counted requests that had come *back*. Between sending a request
    and recording its reply, the counter says the slot is free — so the guarantee
    held only while exactly one request was ever in flight.
    """
    meter = UsageMeter(Budgets(max_requests=2))

    meter.reserve()
    meter.reserve()

    with pytest.raises(BudgetExhausted):
        meter.reserve()


def test_an_unbounded_meter_still_grants_everything() -> None:
    meter = UsageMeter()

    for _ in range(50):
        meter.reserve()
        meter.record(None)

    assert meter.snapshot().requests == 50


def test_a_plan_does_not_price_a_rule_the_safety_ceiling_would_refuse() -> None:
    """`plan` documents itself as selecting exactly the way `Runner` does.

    It applied the kind, the policy globs and the capability check, and skipped
    the impact ceiling the runner applies — so pricing a `--safety passive` probe
    listed every active rule that run would refuse to make.
    """
    from dataclasses import replace  # noqa: PLC0415

    from guardana.core.target import EndpointTarget  # noqa: PLC0415
    from guardana.core.testing import RefusingTransport  # noqa: PLC0415

    registry = Registry.discover()
    target = EndpointTarget("http://x", "m", transport=RefusingTransport())
    active = build_plan(registry, default_profile(), target)

    passive = build_plan(registry, replace(default_profile(), max_impact=Impact.PASSIVE), target)

    assert active.rules, "the fixture selected no rules at all"
    assert not passive.rules, "a passive run would refuse these, so a plan must not price them"
    assert set(active.rules) <= set(passive.skipped)


@pytest.mark.parametrize("impact", list(Impact))
def test_a_plan_and_a_run_agree_about_every_impact_level(impact: Impact) -> None:
    from dataclasses import replace  # noqa: PLC0415

    from guardana.core.runner import Runner  # noqa: PLC0415
    from guardana.core.target import EndpointTarget  # noqa: PLC0415
    from guardana.core.testing import RefusingTransport  # noqa: PLC0415

    registry = Registry.discover()
    profile = replace(default_profile(), max_impact=impact)
    target = EndpointTarget("http://x", "m", transport=RefusingTransport())

    planned = set(build_plan(registry, profile, target).rules)
    executed = set(Runner(registry=registry, profile=profile).run(target).rules_run)

    assert executed <= planned, f"the run at {impact} ran a rule the plan never listed"
