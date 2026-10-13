"""The decline a rule reading Python reports for a file its target could not read."""

from collections.abc import Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import FileReader
from guardana.rules.supply_chain._leads import unread_component, unscanned_verdict


def unread_python(
    meta: RuleMeta, target: FileReader, path: Path, ctx: RuleContext
) -> Iterator[Finding]:
    """Decline `path` by name when the target was prevented from reading it as Python.

    The run also records the file as an error, but `fail_on_error: false` switches that
    off; the shortfall has no switch, so the run stays `indeterminate` either way. A file
    the target read and parsed is not in `unread_sources` and yields nothing.
    """
    unread = next((u for u in target.unread_sources() if u.path == path), None)
    if unread is None:
        return
    ctx.shortfall(unread_component(meta.id, path, unread.reason))
    yield Finding(
        rule_id=meta.id,
        severity=Severity.LOW,
        title="Python file not scanned",
        taxonomy=meta.taxonomy,
        target_ref=str(path),
        evidence=Evidence(
            summary=f"Python file not scanned: {unread.reason}", detail=f"file={path.name}"
        ),
        verdict=unscanned_verdict("the file could not be read, so nothing in it was cleared"),
    )
