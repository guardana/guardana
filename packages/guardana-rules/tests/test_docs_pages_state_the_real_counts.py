"""The `docs/` pages state counts as fact; pin them to the registry like the page.

`FEATURES.md` has had this gate since 0.2 and `site/index.html` since 0.9, and
`docs/` never did — so while both of those tracked the registry, `how-it-works.md`
went on describing eight runtime rules through the five agentic checks that took
the number to thirteen, and `usage-scan.md` showed a dogfood transcript claiming
seventeen rules ran when nineteen do.

This is the same staleness the landing page had, one directory over: a number a
human has to remember, next to prose nobody re-reads. Only counts are pinned — a
page is free to describe a subset in words.
"""

import re
from pathlib import Path

from guardana.core.surface import Surface
from guardana.rules import provide_rules

_BUILD_RE = re.compile(r"\*\*Build-time \(static, artifact\)\*\* — (\d+) rules")
_RUNTIME_RE = re.compile(r"\*\*Runtime \(dynamic, endpoint and trace\)\*\* — (\d+) rules")
_TRANSCRIPT_RE = re.compile(r"^\d+ finding\(s\); (\d+) rule\(s\) run", re.MULTILINE)
_PLUGIN_SPLIT_RE = re.compile(r"Of the (\d+) built-in rules, (\d+) are build-time")
_RUN_SCHEMA_RE = re.compile(r"\| `schema_version` \| `(\d+)`\.")
_ENVELOPE_RE = re.compile(r"ENVELOPE_SCHEMA_VERSION`, currently\n`(\d+)`\)")


def _docs() -> Path:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "docs"
        if (candidate / "how-it-works.md").is_file():
            return candidate
    raise AssertionError("could not locate docs/ at the repo root")


def _read(name: str) -> str:
    return (_docs() / name).read_text(encoding="utf-8")


def _counts(pattern: re.Pattern[str], text: str, where: str) -> list[int]:
    found = pattern.findall(text)
    assert found, (
        f"{where} no longer states a count in the form this test pins "
        f"({pattern.pattern!r}) — the page was reworded, so update this test with it "
        f"rather than deleting the check"
    )
    return [int(value) for value in found]


def test_how_it_works_states_the_real_split_between_the_two_surfaces() -> None:
    rules = list(provide_rules())
    page = _read("how-it-works.md")

    assert _counts(_BUILD_RE, page, "docs/how-it-works.md") == [
        sum(1 for r in rules if r.meta.surface is Surface.BUILD)
    ]
    assert _counts(_RUNTIME_RE, page, "docs/how-it-works.md") == [
        sum(1 for r in rules if r.meta.surface is Surface.RUNTIME)
    ]


def test_the_rule_authoring_page_states_the_real_total_and_split() -> None:
    """It said "of the 32 built-in rules, 19 are build-time" while 51 shipped.

    The 32 was the *runtime* count, promoted to a total by a release that grew the
    other half — two true numbers rearranged into a false sentence, which is what a
    hand-maintained count does when only one of its parts is remembered.
    """
    rules = list(provide_rules())
    page = _read("writing-rules.md")

    match = _PLUGIN_SPLIT_RE.search(page)
    assert match is not None, (
        "docs/writing-rules.md no longer states the total/build split in the form this "
        "test pins — update the test with the rewording rather than deleting the check"
    )
    assert (int(match.group(1)), int(match.group(2))) == (
        len(rules),
        sum(1 for r in rules if r.meta.surface is Surface.BUILD),
    )


def test_the_scan_page_transcripts_run_the_rules_a_scan_really_runs() -> None:
    """A transcript is a promise about what the reader will see when they type it.

    `scan` selects every build-surface rule and skips none against a directory, so
    the number in the example is not illustrative — it is checkable, and a reader
    who sees a different one concludes their install is broken.
    """
    build = sum(1 for r in provide_rules() if r.meta.surface is Surface.BUILD)

    stated = _counts(_TRANSCRIPT_RE, _read("usage-scan.md"), "docs/usage-scan.md")

    assert set(stated) == {build}, f"docs/usage-scan.md shows {stated} rule(s) run; {build} do"


def test_the_saved_run_page_states_the_schema_version_this_build_writes() -> None:
    """A document version is the first thing a consumer branches on.

    A page naming the wrong one sends somebody to the wrong contract, and the field
    table underneath it describes a document they will not receive.
    """
    from guardana.core.report.run import REPORT_SCHEMA_VERSION  # noqa: PLC0415

    stated = _counts(_RUN_SCHEMA_RE, _read("usage-run.md"), "docs/usage-run.md")

    assert stated == [REPORT_SCHEMA_VERSION]


def test_the_architecture_page_states_the_envelope_version_agents_send() -> None:
    from guardana.core.reporter import ENVELOPE_SCHEMA_VERSION  # noqa: PLC0415

    page = _read("architecture.md")

    assert _counts(_ENVELOPE_RE, page, "docs/architecture.md") == [ENVELOPE_SCHEMA_VERSION]
    assert f'"schema_version": {ENVELOPE_SCHEMA_VERSION},' in page, (
        "the example envelope on docs/architecture.md carries a version no agent sends"
    )


def _repo_file(name: str) -> str:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / name
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise AssertionError(f"could not locate {name} at the repo root")


_ROADMAP_OURS_RE = re.compile(r"against our (\d+) rules")
_SAMPLED_RE = re.compile(r"(\d+) rules ship and \*\*(\d+) are fully sampled\*\*")


def test_the_roadmap_compares_competitors_against_the_real_rule_total() -> None:
    """A count in a sentence about somebody else is still a count about us.

    `ROADMAP.md` compared DeepTeam's coverage "against our 32 rules" while 51
    shipped, for four releases. It is the `47 security checks` failure exactly: a
    number three screens away from a table that was correct, in a file nothing
    checked, because the check was written for the *pages* and this one is at the
    repository root. Grep the whole file for every other number of the same thing —
    a number is not covered because it sits near one that is.
    """
    total = len(list(provide_rules()))

    stated = _counts(_ROADMAP_OURS_RE, _repo_file("ROADMAP.md"), "ROADMAP.md")

    assert stated == [total], (
        f"ROADMAP.md compares competitors against {stated} rule(s); the registry has {total}"
    )


def test_the_rule_test_page_states_how_many_rules_are_really_sampled() -> None:
    """Two numbers, and the second is the honest one this project keeps pointing at.

    "51 ship and 5 are fully sampled" is a coverage claim, and a coverage claim that
    drifts upward on its own is the shape of a false green. The ratchet in
    `test_builtin_fixture_coverage.py` pins the sampled count; nothing pinned the
    sentence that quotes it.
    """
    from test_builtin_fixture_coverage import _FULLY_SAMPLED  # noqa: PLC0415

    total = len(list(provide_rules()))

    (stated,) = _SAMPLED_RE.findall(_read("usage-rule-test.md"))

    assert (int(stated[0]), int(stated[1])) == (total, _FULLY_SAMPLED), (
        f"docs/usage-rule-test.md says {stated[0]} ship and {stated[1]} are sampled; "
        f"the registry has {total} and the ratchet pins {_FULLY_SAMPLED}"
    )
