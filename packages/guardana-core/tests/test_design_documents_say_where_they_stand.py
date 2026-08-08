"""Every design document opens with a status, and no status outlives its release.

`docs/design/README.md` states the convention and lists the four statuses in use.
Nothing checked it, and two documents drifted: the collector domain model still
read `proposed · Target: v0.7 · Current maturity: experimental` four releases after
persistence, authentication and tenancy shipped, and the enterprise-readiness plan
carried no status line at all.

Neither was caught by `test_no_page_still_denies_a_capability_the_collector_now_has`,
and correctly so — that test exempts `docs/design/`, because a design document is
allowed to state the problem it solved. The exemption is right for the body. The
status line is the part that has to move, and this is what moves it.
"""

import re
from pathlib import Path

from guardana.core import __version__

_STATUS = re.compile(r"^\*\*Status:\*\* (.+)$", re.MULTILINE)
_TARGET = re.compile(r"\*\*Target:\*\* v(\d+)\.(\d+)")
_KNOWN_PREFIXES = ("proposed", "accepted", "implemented in", "superseded by")


def _design() -> Path:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "docs" / "design"
        if (candidate / "README.md").is_file():
            return candidate
    raise AssertionError("could not locate docs/design/")


def _documents() -> list[Path]:
    return sorted(p for p in _design().glob("*.md") if p.name != "README.md")


def _status_of(path: Path) -> str:
    match = _STATUS.search(path.read_text(encoding="utf-8"))
    assert match is not None, (
        f"{path.name} has no `**Status:**` line — docs/design/README.md requires one, "
        f"because a document whose standing a reader has to infer is one they will "
        f"infer wrongly"
    )
    return match.group(1).strip().lower()


def test_every_design_document_opens_with_a_status() -> None:
    unknown = [
        f"{path.name}: {_status_of(path)!r}"
        for path in _documents()
        if not _status_of(path).startswith(_KNOWN_PREFIXES)
    ]

    assert not unknown, (
        "design documents whose status is not one of the four in docs/design/README.md:\n  "
        + "\n  ".join(unknown)
    )


def test_no_document_is_still_proposed_for_a_release_that_has_shipped() -> None:
    """A proposal for last quarter is a decision somebody made and forgot to record.

    Either it was built — in which case the status is `implemented in X` or a
    `superseded by` pointing at the documents that replaced it — or it was dropped,
    which is worth saying out loud.
    """
    current = tuple(int(part) for part in __version__.split(".")[:2])
    stale = []
    for path in _documents():
        status = _status_of(path)
        target = _TARGET.search(path.read_text(encoding="utf-8"))
        if status.startswith("proposed") and target is not None:
            named = (int(target.group(1)), int(target.group(2)))
            if named <= current:
                stale.append(
                    f"{path.name}: proposed for v{named[0]}.{named[1]}, now at {__version__}"
                )

    assert not stale, (
        "design documents still proposing work for a shipped release:\n  " + "\n  ".join(stale)
    )
