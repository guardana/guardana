"""Compare two runs and name every way the second one is worse.

Works on `ScanResult`s rather than on files, so the same logic serves the `diff`
command (two saved runs) and the monitor (two cycles held in memory). Two
definitions of "worse" in one project would drift apart, and the one that drifted
would be the one nobody was reading.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from guardana.core.diff.errors import IncomparableRunsError
from guardana.core.diff.model import Change, ChangeKind, CheckState, Outcome, RunDiff
from guardana.core.report import Finding, ScanResult, split_ref

_NO_VERDICT_CONFIDENCE = 1.0

Identity = tuple[str, str]


def finding_identity(finding: Finding, root: str) -> Identity:
    """Return the key a finding keeps between runs: its rule, and where it was found.

    The location is relative to what the run examined. Against a live model or an
    MCP server the finding's location *is* the thing under test, so it collapses
    to empty — which is what lets a model swap (`…#llama3` to `…#llama4`) compare
    at all instead of reading as every check vanishing and every check appearing.
    Against files it is the path, with the line dropped, so an edit above a
    finding is not a new finding.

    Deliberately not `Finding.fingerprint`: that one includes the evidence summary,
    which for a dynamic finding is the evaluator's rationale — and three built-in
    evaluators quote the model verbatim in it. Comparing on that would report
    movement on every re-run of an unchanged system.
    """
    if finding.target_ref == root:
        return (finding.rule_id, "")
    path, _line = split_ref(finding.target_ref)
    return (finding.rule_id, _within(path, root))


def _within(path: str, root: str) -> str:
    """Strip the run's root from a file path, so the key does not carry a checkout path.

    `relativize_findings` already makes paths repo-relative when the target is
    inside the checkout. It cannot when it is not — scanning `/models`, or a
    directory mounted at a different place in CI than on a laptop — and the
    absolute prefix would then differ between two runs of the same thing, making
    every check read as vanished and every check as new.
    """
    if not root:
        return path
    root_path, _line = split_ref(root)
    try:
        return str(PurePosixPath(path).relative_to(PurePosixPath(root_path)))
    except ValueError:
        return path


@dataclass(frozen=True, slots=True)
class RunContext:
    """What one run examined, and with which rules.

    One per side, and never shared between them. Normalising both runs against a
    single root is precisely what breaks the comparison this module exists for: a
    model swap changes the root (`…#llama3` to `…#llama4`), and so does scanning
    the same tree from a different checkout. Making the context per-side means
    that mistake cannot be written.
    """

    root: str = ""
    """What the run was pointed at: a directory, an endpoint, an MCP server."""

    rules: Mapping[str, str] = field(default_factory=dict)
    """Each rule that ran, mapped to its digest. Empty is fine — the monitor
    compares two cycles of one process, where the rules are the same objects by
    construction and there is nothing to tell apart."""


_NO_CONTEXT = RunContext()
"""What the monitor gets: two cycles of one process, one target, one rule set."""


def compare(
    before: ScanResult,
    after: ScanResult,
    *,
    before_context: RunContext = _NO_CONTEXT,
    after_context: RunContext = _NO_CONTEXT,
) -> RunDiff:
    """Compare two runs of the same kind of target.

    Raises `IncomparableRunsError` when a comparison would be a fiction: a run that
    executed no rules (nothing was verified, so there is no baseline), or two runs
    with no rule in common (they tested different things).
    """
    _refuse_if_not_comparable(before, after)
    before_states = _states(before, before_context.root)
    after_states = _states(after, after_context.root)
    ran_before, ran_after = _executed(before), _executed(after)
    digests_before = before_context.rules
    digests_after = after_context.rules

    changes: list[Change] = []
    unchanged = 0
    for identity in sorted(before_states.keys() | after_states.keys()):
        rule_id, location = identity
        # A check only compares where both runs actually ran its rule. Where one
        # did not, the coverage change below is the honest report — pairing a
        # state against a rule that never ran would invent a verdict.
        if rule_id not in ran_before or rule_id not in ran_after:
            continue
        was, now = before_states.get(identity), after_states.get(identity)
        kind, detail = _classify(was, now)
        if kind is None:
            unchanged += 1
            continue
        changes.append(
            Change(
                kind=kind,
                rule_id=rule_id,
                location=location,
                detail=detail,
                before=was,
                after=now,
                rule_changed=_rule_changed(rule_id, digests_before, digests_after),
            )
        )
    changes.extend(_coverage_changes(ran_before, ran_after))
    return RunDiff(
        changes=tuple(changes),
        unchanged=unchanged,
        notes=_notes(ran_before & ran_after, digests_before, digests_after),
    )


def _executed(result: ScanResult) -> frozenset[str]:
    """Which rules this run actually ran, trusting a finding over the plan.

    A finding is proof its rule ran, and a stronger one than a list: the list is
    assembled by the runner, while a report read off disk may be hand-edited,
    truncated, or produced by a third-party tool. Where the two disagree, taking
    the finding keeps the comparison closed — the alternative is dropping a real
    check on the grounds that a list did not mention it.
    """
    reported = {
        finding.rule_id
        for channel in (result.findings, result.unverified, result.waived)
        for finding in channel
    }
    return frozenset(result.rules_run) | reported


def _refuse_if_not_comparable(before: ScanResult, after: ScanResult) -> None:
    """Refuse the two cases where a diff would be a fiction rather than a comparison."""
    for label, result in (("first", before), ("second", after)):
        if not result.rules_run:
            raise IncomparableRunsError(
                f"the {label} run executed no rules, so it is not a baseline for anything "
                f"— nothing in it was verified"
            )
    if not frozenset(before.rules_run) & frozenset(after.rules_run):
        raise IncomparableRunsError(
            "the two runs have no rule in common, so they did not test the same thing "
            "— comparing them would report every check as both lost and new"
        )


def _states(result: ScanResult, root: str) -> dict[Identity, CheckState]:
    """Fold a run's channels into one state per check.

    A waived finding still counts as a problem, carrying a flag: a waiver takes a
    finding out from under the gate, it does not make it stop existing. Were
    `waived` a state of its own, adding a waiver would read as a fix.
    """
    grouped: dict[Identity, list[tuple[Finding, bool, Outcome]]] = {}
    for finding in result.findings:
        grouped.setdefault(finding_identity(finding, root), []).append((finding, False, "fail"))
    for finding in result.waived:
        grouped.setdefault(finding_identity(finding, root), []).append((finding, True, "fail"))
    for finding in result.unverified:
        grouped.setdefault(finding_identity(finding, root), []).append(
            (finding, False, "unverified")
        )
    return {identity: _state(entries) for identity, entries in grouped.items()}


def _state(entries: list[tuple[Finding, bool, Outcome]]) -> CheckState:
    # "fail" wins over "unverified": a check that proved a problem on one prompt
    # and could not grade another has proved a problem.
    outcome: Outcome = "fail" if any(o == "fail" for _f, _w, o in entries) else "unverified"
    relevant = [(f, w) for f, w, o in entries if o == outcome]
    return CheckState(
        outcome=outcome,
        severity=max(f.severity for f, _w in relevant),
        confidence=max(_confidence(f) for f, _w in relevant),
        count=len(relevant),
        waived=all(w for _f, w in relevant),
    )


def _confidence(finding: Finding) -> float:
    return _NO_VERDICT_CONFIDENCE if finding.verdict is None else finding.verdict.confidence


def _classify(was: CheckState | None, now: CheckState | None) -> tuple[ChangeKind | None, str]:
    if was is None and now is not None:
        return _appeared(now)
    if was is not None and now is None:
        return _cleared(was)
    if was is not None and now is not None:
        return _moved(was, now)
    # Unreachable: an identity is only in the map because one run or the other put
    # it there. Returned rather than asserted — an assert disappears under -O.
    return None, ""


def _appeared(now: CheckState) -> tuple[ChangeKind, str]:
    if now.outcome == "fail":
        return ChangeKind.APPEARED, f"a {now.severity.name} problem that was not reported before"
    return ChangeKind.BLINDED, "this check used to come back clean and can no longer grade"


def _cleared(was: CheckState) -> tuple[ChangeKind, str]:
    if was.outcome == "fail":
        return ChangeKind.RESOLVED, f"the {was.severity.name} problem is no longer reported"
    return ChangeKind.CLARIFIED, "a check that could not grade now comes back clean"


def _moved(was: CheckState, now: CheckState) -> tuple[ChangeKind | None, str]:
    """Classify a check that is present in both runs."""
    if was.outcome == "unverified" and now.outcome == "fail":
        return ChangeKind.PROVEN, "a check that could not grade now proves the problem"
    if was.outcome == "fail" and now.outcome == "unverified":
        return ChangeKind.BLINDED, "a proven problem can no longer be graded, not fixed"
    return _same_outcome(was, now)


def _same_outcome(was: CheckState, now: CheckState) -> tuple[ChangeKind | None, str]:
    """Classify a check whose verdict held, by whatever else moved around it."""
    if now.severity > was.severity:
        return (
            ChangeKind.ESCALATED,
            f"severity rose from {was.severity.name} to {now.severity.name}",
        )
    if now.severity < was.severity:
        return (
            ChangeKind.DE_ESCALATED,
            f"severity fell from {was.severity.name} to {now.severity.name}",
        )
    if now.waived != was.waived:
        moved = "waived by a baseline" if now.waived else "no longer waived"
        return ChangeKind.WAIVER_CHANGED, f"unchanged in itself, {moved}"
    if now.count != was.count:
        return ChangeKind.COUNT_CHANGED, f"{was.count} finding(s) became {now.count}"
    return None, ""


def _coverage_changes(before: frozenset[str], after: frozenset[str]) -> list[Change]:
    lost = [
        Change(
            kind=ChangeKind.COVERAGE_LOST,
            rule_id=rule_id,
            location="",
            detail="this rule ran in the first run and not in the second, so whatever it "
            "would have found is unknown rather than absent",
        )
        for rule_id in sorted(before - after)
    ]
    gained = [
        Change(
            kind=ChangeKind.COVERAGE_GAINED,
            rule_id=rule_id,
            location="",
            detail="this rule ran only in the second run, so anything it reports is new "
            "coverage rather than a system that got worse",
        )
        for rule_id in sorted(after - before)
    ]
    return lost + gained


def _rule_changed(rule_id: str, before: Mapping[str, str], after: Mapping[str, str]) -> bool:
    both = before.get(rule_id), after.get(rule_id)
    return all(digest is not None for digest in both) and both[0] != both[1]


def _notes(
    shared: frozenset[str], before: Mapping[str, str], after: Mapping[str, str]
) -> tuple[str, ...]:
    changed = sorted(r for r in shared if _rule_changed(r, before, after))
    if not changed:
        return ()
    return (
        f"{len(changed)} rule(s) changed definition between these runs "
        f"({', '.join(changed[:3])}{'…' if len(changed) > 3 else ''}) — a different "  # noqa: PLR2004
        f"result there may be the sharper test rather than a worse system",
    )
