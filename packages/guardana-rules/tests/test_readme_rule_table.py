"""The README's rule table is a public claim, so it is pinned to the registry.

`FEATURES.md` has had this gate since 0.2, the landing page since 0.9 and `docs/`
since 0.12. The README — the page most people read first — was still hand-typed,
and by the time this test was written it advertised thirty-two rules, "the static
seventeen" and "the dynamic eight" when nineteen and fifteen shipped, with bare
short ids that no longer identify a control now two OWASP editions are installed.

Only the parts a machine can check are pinned: the count, the split, and the rule
ids. The prose around them stays a human's to write.
"""

import re
from pathlib import Path

from guardana.core.rule import Rule
from guardana.core.surface import Surface
from guardana.rules import provide_rules

_ROW = re.compile(
    r"^\| `(guardana\.[a-z0-9_.]+)` \| ([A-Z/]+) \| (build|runtime) \| (.+) \|$", re.MULTILINE
)
_TOTAL = re.compile(r"^(\d+) built-in rules,", re.MULTILINE)
_SPLIT = re.compile(r"The static (\d+) \(`artifact` surface\).+?The dynamic (\d+) ", re.DOTALL)


def _readme() -> str:
    """Find the *repository* README, not the one in this package.

    Every package has a README, and the nearest one going up is `guardana-rules`'.
    Anchoring on it would have made all four checks below pass against a file that
    has no rule table at all — a test that cannot fail, which is the one kind this
    project treats as worse than no test. `ROADMAP.md` marks the root.
    """
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "README.md"
        if candidate.is_file() and (parent / "ROADMAP.md").is_file():
            return candidate.read_text(encoding="utf-8")
    raise AssertionError("could not locate the repository README.md")


def _rules() -> list[Rule]:
    return list(provide_rules())


def test_every_built_in_rule_has_a_row_and_every_row_is_a_rule() -> None:
    listed = {match.group(1) for match in _ROW.finditer(_readme())}
    installed = {rule.meta.id for rule in _rules()}

    assert listed == installed, (
        f"README.md is out of step with the registry — missing {sorted(installed - listed)}, "
        f"stale {sorted(listed - installed)}"
    )


def test_each_row_states_the_surface_the_rule_actually_runs_on() -> None:
    surfaces = {rule.meta.id: rule.meta.surface.value for rule in _rules()}

    wrong = [
        f"{m.group(1)}: says {m.group(3)}, runs on {surfaces[m.group(1)]}"
        for m in _ROW.finditer(_readme())
        if surfaces[m.group(1)] != m.group(3)
    ]

    assert not wrong, "\n  ".join(wrong)


def test_each_row_names_the_edition_of_every_reference_that_has_one() -> None:
    # A bare `LLM07` in a public table is the defect this release repaired: it names
    # System Prompt Leakage to this build and Misinformation to a reader.
    mapped = {rule.meta.id: {ref.reference for ref in rule.meta.taxonomy} for rule in _rules()}

    wrong = [
        f"{m.group(1)}: README says {sorted(stated)}, registry says {sorted(mapped[m.group(1)])}"
        for m in _ROW.finditer(_readme())
        if (stated := set(m.group(4).split(" · "))) != mapped[m.group(1)]
    ]

    assert not wrong, "\n  ".join(wrong)


def test_the_headline_count_and_the_split_are_the_real_ones() -> None:
    rules = _rules()
    readme = _readme()
    build = sum(1 for r in rules if r.meta.surface is Surface.BUILD)

    reworded = (
        "README.md no longer states its counts in the form this test pins — it was "
        "reworded, so update the test with it rather than deleting the check"
    )
    total = _TOTAL.search(readme)
    assert total is not None, reworded
    split = _SPLIT.search(readme)
    assert split is not None, reworded
    assert int(total.group(1)) == len(rules)
    assert (int(split.group(1)), int(split.group(2))) == (build, len(rules) - build)
