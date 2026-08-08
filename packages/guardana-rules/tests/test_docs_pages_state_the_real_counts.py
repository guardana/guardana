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
_RUNTIME_RE = re.compile(r"\*\*Runtime \(dynamic, endpoint\)\*\* — (\d+) rules")
_TRANSCRIPT_RE = re.compile(r"^\d+ finding\(s\); (\d+) rule\(s\) run", re.MULTILINE)
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
