"""Relativize a `Finding.target_ref` path for portable rendering and baselining.

A static finding's `target_ref` is `"path:line"`; a dynamic one is `"url#model"`.
Rewriting file paths relative to the checkout root gives the SARIF renderer a
repo-relative `uri` (what GitHub code scanning needs to attach an alert) and gives
the baseline fingerprint a path that is stable between a dev machine and CI.
"""

import contextlib
import os
import re
from dataclasses import replace
from pathlib import Path, PurePath

from guardana.core.report._ref import split_ref
from guardana.core.report.finding import Finding
from guardana.core.report.result import ScanResult
from guardana.core.report.shortfall import CoverageShortfall, ShortfallKind
from guardana.core.target.scope import FileScope

_NAMED_BY_PATH = frozenset({ShortfallKind.UNEXAMINED_COMPONENT, ShortfallKind.EMPTY_TARGET})
"""Shortfall kinds whose name may be a file or a target path rather than a label."""


def relativize(ref: str, base: Path) -> str:
    """Rewrite a file ref's path relative to `base`; leave endpoint refs and outside paths."""
    if "#" in ref:  # an endpoint "url#model", not a file
        return ref
    path_str, line = split_ref(ref)
    try:
        rel = Path(path_str).resolve().relative_to(base.resolve())
    except (ValueError, OSError):
        return ref
    return f"{rel}:{line}" if line is not None else str(rel)


def _relativize_shortfall(gap: CoverageShortfall, base: Path) -> CoverageShortfall:
    """Rewrite a path-named shortfall relative to `base`, and drop `base` from its detail.

    A bare name — a model format such as `pickle` — is a label, not a location, and
    passes unchanged; so does every kind that is never named by a path.
    """
    if gap.kind not in _NAMED_BY_PATH:
        return gap
    name = gap.name
    if PurePath(name).is_absolute() or len(PurePath(name).parts) > 1:
        name = relativize(name, base)
    return replace(gap, name=name, detail=_without_root(gap.detail, base))


_PATH_START = r"(?<![^\s,(\'\"])"
"""Where a path may start: the text's start, or after a space, comma, bracket or quote.

Anywhere else the root is an inner segment of another path, which is not under it.
"""


def _without_root(text: str, base: Path) -> str:
    """Remove `base` as a leading directory from every path `text` spells out."""
    roots = {str(base), str(base.absolute())}
    with contextlib.suppress(OSError):
        roots.add(str(base.resolve()))
    # Longest first: `/var/x/` sits inside `/private/var/x/`, and removing the shorter
    # spelling first would leave `/private` in front of every path.
    for root in sorted(roots, key=len, reverse=True):
        spelled = PurePath(root)
        # The filesystem root would strip every separator in the text, not one prefix.
        if spelled.is_absolute() and spelled.parent != spelled:
            prefix = re.escape(root.rstrip(os.sep) + os.sep)
            text = re.sub(_PATH_START + prefix, "", text)
    return text


def _relativize_scope(scope: FileScope, base: Path) -> FileScope:
    """Rewrite every path a file scope names relative to `base`, as its listing is."""
    skipped = scope.skipped_models
    return replace(
        scope,
        files=tuple(relativize(path, base) for path in scope.files),
        excludes=None
        if scope.excludes is None
        else tuple(
            e if e.file is None else replace(e, file=relativize(e.file, base))
            for e in scope.excludes
        ),
        kept_models=tuple(
            replace(kept, path=relativize(kept.path, base)) for kept in scope.kept_models
        ),
        skipped_models=None
        if skipped is None
        else replace(
            skipped,
            directories=tuple(
                replace(d, path=relativize(d.path, base)) for d in skipped.directories
            ),
        ),
    )


def relativize_findings(result: ScanResult, base: Path) -> ScanResult:
    """Return a copy of `result` with every file location made relative to `base`.

    Applied once before rendering and baselining, so both the SARIF `uri` and the
    baseline fingerprint use a portable, repo-relative path instead of the absolute
    checkout path (which differs between a dev machine and CI).
    """

    def rel(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
        return tuple(replace(f, target_ref=relativize(f.target_ref, base)) for f in findings)

    return replace(
        result,
        findings=rel(result.findings),
        unverified=rel(result.unverified),
        waived=rel(result.waived),
        # Observations too, or one report mixes relative finding paths with
        # absolute component paths: the run-to-run diff the channel exists for
        # would call every component changed the moment the checkout moved, and
        # an uploaded report would carry the checkout path the findings beside it
        # were deliberately scrubbed of.
        observations=tuple(replace(o, ref=relativize(o.ref, base)) for o in result.observations),
        # The listing too, or a finding's location and the file it was found in
        # would be spelled two ways and every comparison would read the file as gone.
        scope=None if result.scope is None else _relativize_scope(result.scope, base),
        # A file the run could not read is named the way its finding is, or a saved run
        # would name one file two ways and carry the checkout path the findings dropped.
        coverage_shortfall=tuple(
            _relativize_shortfall(gap, base) for gap in result.coverage_shortfall
        ),
    )
