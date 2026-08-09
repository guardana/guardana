"""The landing page states rule counts as fact; pin them to the registry.

`FEATURES.md` has had this gate since 0.2 and the page did not, so while the
release tooling rewrote its version marker on every release, the sentence beside
it went on claiming 25 rules through three releases that took the number to 32.
An automated version next to a hand-maintained count is the same staleness the
Action pin had — one element over.

Only the counts are pinned, not the illustrative rule list: a landing page is
allowed to show six checks out of thirty-two. What it is not allowed to do is
state a total that is not the total.
"""

import re
from pathlib import Path

from guardana.core.surface import Surface
from guardana.rules import provide_rules

_TOTAL_RE = re.compile(r">(\d+) rules · two surfaces<")
_BUILD_RE = re.compile(r">(\d+) rules · your laptop")
_RUNTIME_RE = re.compile(r">(\d+) rules · a served model, or a run it already performed<")


def _page() -> str:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "site" / "index.html"
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise AssertionError("could not locate site/index.html at the repo root")


def _stated(pattern: re.Pattern[str], page: str, what: str) -> int:
    match = pattern.search(page)
    assert match is not None, (
        f"site/index.html no longer states a {what} count in the form this test pins "
        f"({pattern.pattern!r}) — the page was reworded, so update this test with it "
        f"rather than deleting the check"
    )
    return int(match.group(1))


def test_the_page_states_the_real_rule_total() -> None:
    rules = list(provide_rules())

    assert _stated(_TOTAL_RE, _page(), "total rule") == len(rules)


def test_the_page_states_the_real_split_between_the_two_surfaces() -> None:
    rules = list(provide_rules())
    page = _page()
    build = sum(1 for r in rules if r.meta.surface is Surface.BUILD)
    runtime = sum(1 for r in rules if r.meta.surface is Surface.RUNTIME)

    assert _stated(_BUILD_RE, page, "build-time rule") == build
    assert _stated(_RUNTIME_RE, page, "runtime rule") == runtime


def test_the_page_only_shows_rules_that_exist() -> None:
    """An illustrative list may be short; it may not name a check nobody ships."""
    page = _page()
    shipped = {rule.meta.id.removeprefix("guardana.") for rule in provide_rules()}
    shown = set(re.findall(r"<li><b>([a-z0-9_.]+)</b> —", page))
    # A page may shorten an id to the part that reads well (`system_prompt_leak`
    # for `prompt.system_prompt_leak.canary`); it may not invent one.
    unknown = {name for name in shown if not any(name in rule for rule in shipped)}

    assert not unknown, f"site/index.html advertises rule(s) that do not ship: {sorted(unknown)}"


def test_the_page_labels_the_collector_beta_rather_than_implying_it_is_finished() -> None:
    """The page's one maturity claim, pinned because it is the one that ages.

    The collector gained tenancy, environments and run history across three
    releases; it still has no finding lifecycle, audit log or retention. A landing
    page that dropped the label would be claiming the second half too — and this
    project's own history is a page advertising 25 rules through three releases
    that took the number to 32.
    """
    page = _page()

    assert "beta" in page
    assert "optional in every direction" in page


def test_the_page_does_not_promise_a_hosted_collector() -> None:
    # There isn't one. A "managed cloud" line on the page would be a capability
    # claim with nothing behind it.
    page = _page().lower()

    assert "managed cloud" not in page
    assert "hosted for you" not in page


_PLAN_RULES_RE = re.compile(r"(\d+) rule\(s\) would run, (\d+) skipped\.")
_PLAN_COST_RE = re.compile(r"requests: at least (\d+), at most (\d+)")


def test_the_terminal_demo_quotes_what_plan_probe_actually_prints() -> None:
    """The other half of the staleness this file exists to stop.

    The rule counts were pinned; the `plan probe` transcript beside them was not,
    and it drifted to numbers no build has produced for several releases — the same
    shape as the "25 rules" sentence, one element over. Nothing here contacts a
    model: pricing a run is the one command that must not.
    """
    from guardana.cli.main import app  # noqa: PLC0415 — the page quotes the CLI, not the rules
    from typer.testing import CliRunner  # noqa: PLC0415

    printed = CliRunner().invoke(
        app, ["plan", "probe", "--url", "http://model.invalid", "--model", "m"]
    )
    assert printed.exit_code == 0, printed.output
    live = _PLAN_RULES_RE.search(printed.output)
    cost = _PLAN_COST_RE.search(printed.output)
    assert live is not None, printed.output
    assert cost is not None, printed.output

    page = _page()
    reworded = (
        "site/index.html no longer shows a `plan probe` transcript in the form this "
        "test pins — reword the test with the page rather than deleting the check"
    )
    stated_rules = _PLAN_RULES_RE.search(page)
    stated_cost = _PLAN_COST_RE.search(page)
    assert stated_rules is not None, reworded
    assert stated_cost is not None, reworded

    assert stated_rules.groups() == live.groups()
    assert stated_cost.groups() == cost.groups()
