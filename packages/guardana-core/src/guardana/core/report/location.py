"""Relativize a `Finding.target_ref` path for portable rendering and baselining.

A static finding's `target_ref` is `"path:line"`; a dynamic one is `"url#model"`.
Rewriting file paths relative to the checkout root gives the SARIF renderer a
repo-relative `uri` (what GitHub code scanning needs to attach an alert) and gives
the baseline fingerprint a path that is stable between a dev machine and CI.
"""

from dataclasses import replace
from pathlib import Path

from guardana.core.report._ref import split_ref
from guardana.core.report.finding import Finding
from guardana.core.report.result import ScanResult


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


def relativize_findings(result: ScanResult, base: Path) -> ScanResult:
    """Return a copy of `result` with every file target_ref made relative to `base`.

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
    )
