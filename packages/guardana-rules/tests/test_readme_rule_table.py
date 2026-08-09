"""The README's rule counts are a public claim, so they are pinned to the registry.

`FEATURES.md` has had this gate since 0.2, the landing page since 0.9 and `docs/`
since 0.12. The README — the page most people read first — was still hand-typed, and
by the time this test was written it advertised thirty-two rules, "the static
seventeen" and "the dynamic eight" when nineteen and fifteen shipped.

**What is pinned changed in 0.14, and this note is why.** The README used to carry a
row per rule, with the id, severity, surface and full framework mapping of all forty
of them — pinned exactly. It was the single largest block on the page, it duplicated
[`docs/generated/rule-catalog.md`](../../../docs/generated/rule-catalog.md) line for
line, and it grew with every release. The catalog is generated; the README is read
first. So the README now carries one row per rule **family** and the check moved with
it: the total, the build/runtime split, and — the part that keeps a rule from being
added or removed in silence — every installed family has a row and every row is a
real family. The per-rule detail is checked where it is generated.

Only what a machine can check is pinned. The prose around it stays a human's to write.
"""

import re
from collections import Counter
from pathlib import Path

from guardana.core.rule import Rule
from guardana.core.surface import Surface
from guardana.rules import provide_rules

_FAMILY_ROW = re.compile(r"^\| `guardana\.([a-z_]+)\.\*` \| (\d+) \| ([a-z +]+) \| ", re.MULTILINE)
_TOTAL = re.compile(r"^(\d+) built-in rules,", re.MULTILINE)
_SPLIT = re.compile(r"The static (\d+) \(`artifact` surface\).+?The dynamic (\d+) ", re.DOTALL)

_REWORDED = (
    "README.md no longer states its counts in the form this test pins — it was "
    "reworded, so update the test with it rather than deleting the check"
)


def _readme() -> str:
    """Find the *repository* README, not the one in this package.

    Every package has a README, and the nearest one going up is `guardana-rules`'.
    Anchoring on it would have made every check below pass against a file that has no
    rule table at all — a test that cannot fail, which is the one kind this project
    treats as worse than no test. `ROADMAP.md` marks the root.
    """
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "README.md"
        if candidate.is_file() and (parent / "ROADMAP.md").is_file():
            return candidate.read_text(encoding="utf-8")
    raise AssertionError("could not locate the repository README.md")


def _rules() -> list[Rule]:
    return list(provide_rules())


def _families(rules: list[Rule]) -> Counter[str]:
    return Counter(rule.meta.id.split(".")[1] for rule in rules)


def test_every_rule_family_has_a_row_and_every_row_is_a_family() -> None:
    """A family added or removed cannot pass unnoticed, which is what the per-rule table did."""
    listed = {match.group(1) for match in _FAMILY_ROW.finditer(_readme())}
    assert listed, _REWORDED
    installed = set(_families(_rules()))

    assert listed == installed, (
        f"README.md is out of step with the registry — missing {sorted(installed - listed)}, "
        f"stale {sorted(listed - installed)}"
    )


def test_each_family_row_states_how_many_rules_are_really_in_it() -> None:
    counts = _families(_rules())
    wrong = [
        f"guardana.{m.group(1)}.*: says {m.group(2)}, registry has {counts[m.group(1)]}"
        for m in _FAMILY_ROW.finditer(_readme())
        if int(m.group(2)) != counts[m.group(1)]
    ]

    assert not wrong, "\n  ".join(wrong)


def test_each_family_row_states_the_surfaces_that_family_actually_runs_on() -> None:
    """A family spanning both surfaces has to say so; one that does not must not claim it."""
    rules = _rules()
    surfaces = {
        family: {r.meta.surface.value for r in rules if r.meta.id.split(".")[1] == family}
        for family in _families(rules)
    }
    wrong = [
        f"guardana.{m.group(1)}.*: says {m.group(3).strip()!r}, runs on "
        f"{' + '.join(sorted(surfaces[m.group(1)]))}"
        for m in _FAMILY_ROW.finditer(_readme())
        if set(m.group(3).split(" + ")) != {s.strip() for s in surfaces[m.group(1)]}
    ]

    assert not wrong, "\n  ".join(wrong)


def test_the_headline_count_and_the_split_are_the_real_ones() -> None:
    rules = _rules()
    readme = _readme()
    build = sum(1 for r in rules if r.meta.surface is Surface.BUILD)

    total = _TOTAL.search(readme)
    assert total is not None, _REWORDED
    split = _SPLIT.search(readme)
    assert split is not None, _REWORDED
    assert int(total.group(1)) == len(rules)
    assert (int(split.group(1)), int(split.group(2))) == (build, len(rules) - build)


def test_the_family_rows_account_for_every_installed_rule() -> None:
    """The rows and the headline have to agree, or one of them is decoration."""
    stated = sum(int(m.group(2)) for m in _FAMILY_ROW.finditer(_readme()))

    assert stated == len(_rules())
