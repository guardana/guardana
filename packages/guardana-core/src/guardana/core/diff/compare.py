"""Compare two runs and name every way the second one is worse.

Works on `ScanResult`s rather than on files, so the same logic serves the `diff`
command (two saved runs) and the monitor (two cycles held in memory). Two
definitions of "worse" in one project would drift apart, and the one that drifted
would be the one nobody was reading.
"""

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from guardana.core.diff.errors import IncomparableRunsError
from guardana.core.diff.measurement import measure
from guardana.core.diff.model import Change, ChangeKind, CheckState, Outcome, RunDiff
from guardana.core.redaction import is_redaction_of
from guardana.core.report import (
    Finding,
    ScanResult,
    SkippedRule,
    SkipReason,
    StopReason,
    split_ref,
)

_NO_VERDICT_CONFIDENCE = 1.0

Identity = tuple[str, str]


def finding_identity(finding: Finding, root: str) -> Identity:
    """Return the key a finding keeps between runs: its rule, and where it was found.

    The location is relative to what the run examined. Against a live model or an
    MCP server the finding's location *is* the thing under test, so it collapses
    to empty — which is what lets a model swap (`…#llama3` to `…#llama4`) compare
    at all instead of reading as every check vanishing and every check appearing.
    Against files it is the path, with the line dropped, so an edit above a
    finding is not a new finding. A location the run's privacy policy redacted still
    names the target it was redacted from: the run records the target unredacted.

    Deliberately not `Finding.fingerprint`: that one includes the evidence summary,
    which for a dynamic finding is the evaluator's rationale — and three built-in
    evaluators quote the model verbatim in it. Comparing on that would report
    movement on every re-run of an unchanged system.
    """
    if finding.target_ref == root or is_redaction_of(finding.target_ref, root):
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
class Grader:
    """One evaluator a rule graded with, as its run recorded it; None where nothing was.

    Each field is compared only when both runs recorded it: a migrated run, or an
    evaluator that states no judge, is unknown rather than different.
    """

    version: str | None = None
    digest: str | None = None
    judge: str | None = None
    """The judge identity the evaluator stated: model, endpoint, samples per verdict."""


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

    tool_version: str = ""
    """Which build produced this run, or empty when the caller does not know.

    Read only to qualify what a changed digest means. Across a version boundary a
    digest can move because the rule changed *or* because what a digest covers
    changed, and a note that asserted the first would be confidently wrong every
    time the second happened."""

    grading: Mapping[str, Mapping[str, Grader]] = field(default_factory=dict)
    """Each rule that graded something, mapped to the assessors its verdicts name.

    A rule absent here graded nothing on record, which is unknown rather than
    unchanged; the monitor leaves it empty because one process grades both cycles."""

    fixtures: str | None = None
    """The digest of the fixtures file the run was given; None when it was given none.

    The monitor leaves it None on both sides, since one process runs both cycles."""

    markers: int | None = None
    """The algorithm the run's seeded markers were derived with; None without fixtures.

    The same file under another algorithm seeds other markers, so it asks other questions."""


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

    shared = ran_before & ran_after
    retried = _trials_changed(before, after, shared)
    regraded = _grading_changed(shared, before_context.grading, after_context.grading)
    excluded = retried.keys() | regraded
    listed_after = _listed(after, after_context.root)
    # Two file scans read the same bytes the same way every time, so a count that rose
    # there is a new problem, not sampling.
    static = before.scope is not None and after.scope is not None

    changes: list[Change] = []
    unchanged = 0
    for identity in sorted(before_states.keys() | after_states.keys()):
        rule_id, location = identity
        # A check only compares where both runs actually ran its rule. Where one
        # did not, the coverage change below is the honest report — pairing a
        # state against a rule that never ran would invent a verdict.
        if rule_id not in ran_before or rule_id not in ran_after:
            continue
        # Nor where the two runs made a different number of attempts at each case:
        # a failure found in five tries and missed in one is more sampling, not a
        # regression. Nor where another evaluator or judge graded it: a verdict that
        # moved with the grader says nothing about the system. The refusals below
        # name both.
        if rule_id in excluded:
            continue
        was, now = before_states.get(identity), after_states.get(identity)
        kind, detail = (
            _left_scan(after, location)
            if was is not None
            and now is None
            and listed_after is not None
            and location
            and not _is_listed(location, listed_after)
            else _classify(was, now, static=static)
        )
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
    stopped_applying = _stopped_applying(before, after, ran_before - ran_after)
    changes.extend(_coverage_changes(ran_before - stopped_applying.keys(), ran_after))
    measurement = measure(
        [a for a in before.assessments if a.rule_id not in excluded],
        [a for a in after.assessments if a.rule_id not in excluded],
        before_trials=before.trials_per_case,
        after_trials=after.trials_per_case,
    )
    return RunDiff(
        changes=tuple(changes),
        unchanged=unchanged,
        notes=(
            *_notes(shared, before_context, after_context),
            *(
                f"{rule_id} reported nothing in the first run and did not apply in the "
                f"second, so it is not counted as coverage lost: {skip.detail}"
                for rule_id, skip in sorted(stopped_applying.items())
            ),
            *measurement.notes(),
        ),
        measurement=measurement,
        incomplete=(
            *_incomplete(before, after),
            *_fixtures_changed(before_context, after_context),
            *(
                f"{rule_id}: trials changed {was} → {now}, so its results are not answers "
                f"to one question and it was not compared"
                for rule_id, (was, now) in sorted(retried.items())
            ),
            *_regraded_reason(regraded),
        ),
    )


def _listed(result: ScanResult, root: str) -> frozenset[str] | None:
    """Every file the run listed, keyed like a finding's location; None when it did not say."""
    if result.scope is None:
        return None
    return frozenset(_within(path, root) for path in result.scope.files)


def _is_listed(location: str, listed: frozenset[str]) -> bool:
    """Whether the file a location names was listed, a cell or fragment after it allowed.

    A notebook rule names `nb.ipynb:cell3`, which `split_ref` keeps because the part
    after the colon is not a line number.
    """
    head = location.split("#", 1)[0]
    return location in listed or head in listed or head.rsplit(":", 1)[0] in listed


def _left_scan(after: ScanResult, location: str) -> tuple[ChangeKind, str]:
    scope = after.scope
    reason = None if scope is None else scope.exclusion_of(location.split("#", 1)[0])
    if reason is not None:
        return (
            ChangeKind.LEFT_SCAN,
            f"the second run did not list this file ({reason}), so whether the problem "
            f"remains is unknown rather than resolved",
        )
    return (
        ChangeKind.LEFT_SCAN,
        "the second run did not list this file — it was deleted, moved, renamed or left the "
        "scanned tree — so whether the problem went with it is unknown rather than resolved",
    )


def _trials_changed(
    before: ScanResult, after: ScanResult, shared: frozenset[str]
) -> dict[str, tuple[int, int]]:
    """Map each rule both runs ran to its attempts per case, where that number moved.

    A rule absent from `trials_per_case` made one attempt per case: it does not repeat,
    or the run was recorded before trials existed.
    """
    moved = {}
    for rule_id in shared:
        was = before.trials_per_case.get(rule_id, 1)
        now = after.trials_per_case.get(rule_id, 1)
        if was != now:
            moved[rule_id] = (was, now)
    return moved


def _grading_changed(
    shared: frozenset[str],
    before: Mapping[str, Mapping[str, Grader]],
    after: Mapping[str, Mapping[str, Grader]],
) -> frozenset[str]:
    """Return the rules both runs ran whose grading is known on both sides and differs."""
    return frozenset(
        rule_id
        for rule_id in shared
        if _graded_differently(before.get(rule_id, {}), after.get(rule_id, {}))
    )


def _graded_differently(before: Mapping[str, Grader], after: Mapping[str, Grader]) -> bool:
    """Whether one rule's graders moved between two runs.

    A grader one run has and the other lacks is not enough on its own: a scenario
    that stopped early graded fewer steps, so one side's set inside the other's is
    the system's doing. Each side holding a grader the other lacks is a swap.
    """
    if not before or not after:
        return False
    if before.keys() - after.keys() and after.keys() - before.keys():
        return True
    return any(_differs(before[name], after[name]) for name in before.keys() & after.keys())


def _differs(was: Grader, now: Grader) -> bool:
    pairs = ((was.version, now.version), (was.digest, now.digest), (was.judge, now.judge))
    return any(a is not None and b is not None and a != b for a, b in pairs)


def _regraded_reason(regraded: frozenset[str]) -> tuple[str, ...]:
    if not regraded:
        return ()
    ordered = sorted(regraded)
    named = f"{', '.join(ordered[:3])}{'…' if len(ordered) > 3 else ''}"  # noqa: PLR2004
    return (
        f"{len(ordered)} rule(s) were graded differently ({named}) — a different evaluator "
        f"or judge — so their findings and measurements are not compared",
    )


_STOP_EXPLANATIONS = {
    StopReason.BUDGET_EXHAUSTED: (
        "ran out of its budget and stopped early, so what it did not reach is unknown "
        "rather than absent — raise the budget before reading this comparison"
    ),
    StopReason.INTERRUPTED: (
        "was interrupted, so what it did not reach is unknown rather than absent"
    ),
    StopReason.TARGET_UNAVAILABLE: (
        "stopped because the target became unavailable, so what it did not reach is unknown "
        "rather than absent — make the target answer before reading this comparison"
    ),
    StopReason.TARGET_CHANGED: (
        "stopped because the target changed under it, no longer accepting the protocol "
        "revision the run agreed, so what it did not reach is unknown rather than absent"
    ),
}


def _incomplete(before: ScanResult, after: ScanResult) -> tuple[str, ...]:
    """Say which side never finished, and why.

    A truncated run reports fewer findings than a complete one, and subtracting
    two lists cannot tell that from a fix. Naming the reason matters as much as
    naming the fact: the remedy for a spent budget is a bigger budget, not a
    re-enabled rule.

    **Coverage the run's verdict needs and did not get counts here too**, and it is the
    case a comparison hides most quietly. A run that could not check the contract
    somebody wrote produces the same finding list as one where the contract held, so
    subtracting them yields no change at all — and `diff` would report "no
    regression" over a run that is `indeterminate` on its own. That is the false
    green this project refuses from every direction, including from a comparison.

    **So does a recorded error**, with no policy switch in front of it: a refused pack
    or a rule that raised left its findings out of the run, and the comparison cannot
    tell those absent findings from fixed ones. **And so does a run whose every rule
    declined**: it executed rules, so it passes the "executed nothing" refusal, and it
    established exactly as much as a run that did not.
    """
    sides = (("first", before), ("second", after))
    return (
        *(
            f"the {label} run {_STOP_EXPLANATIONS[result.stopped_by]}"
            for label, result in sides
            if result.stopped_by is not None
        ),
        *(
            f"the {label} run is missing coverage its verdict needs "
            f"({', '.join(gap.name for gap in result.coverage_shortfall)}), so what needed "
            f"that evidence is unknown rather than clean"
            for label, result in sides
            if result.coverage_shortfall
        ),
        *(
            f"the {label} run recorded {len(result.errors)} error(s) "
            f"({_error_sources(result)}), so what those checks would have found is unknown "
            f"rather than clean"
            for label, result in sides
            if result.errors
        ),
        *(
            f"every rule the {label} run executed declined, so it verified nothing and "
            f"an unchanged result is unknown rather than clean"
            for label, result in sides
            if result.rules_run and result.verified_nothing
        ),
    )


def _fixtures_changed(before_context: RunContext, after_context: RunContext) -> tuple[str, ...]:
    """Say when the two runs asked about different seeded data.

    An item one fixtures file declares and the other does not was asked about by one
    run only, so a finding on it that disappears reads as a fixed leak when it was
    never asked again. The same file under another markers algorithm seeds other
    markers, which an index seeded for one run does not hold for the other.
    """
    before, after = before_context.fixtures, after_context.fixtures
    if before == after:
        if before is None or before_context.markers == after_context.markers:
            return ()
        return (
            f"the runs derived the markers of the same fixtures with different algorithms "
            f"({before_context.markers} and {after_context.markers}), so they asked about "
            f"different seeded text and are not comparable",
        )
    if before is None or after is None:
        given = "first" if after is None else "second"
        return (
            f"only the {given} run was given fixtures, so the checks they feed asked about "
            f"seeded data the other run never had and are not comparable",
        )
    return (
        f"the runs were given different fixtures ({before} and {after}), so an item one "
        f"declares and the other does not was asked about by one run only, and its "
        f"absence is unknown rather than fixed",
    )


def _error_sources(result: ScanResult) -> str:
    sources = sorted({error.source for error in result.errors})
    return f"{', '.join(sources[:3])}{'…' if len(sources) > 3 else ''}"  # noqa: PLR2004


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
        unwaived=sum(1 for _f, w in relevant if not w),
        evidence=tuple(sorted((f.evidence.summary, w) for f, w in relevant)),
    )


def _confidence(finding: Finding) -> float:
    return _NO_VERDICT_CONFIDENCE if finding.verdict is None else finding.verdict.confidence


def _classify(
    was: CheckState | None, now: CheckState | None, *, static: bool
) -> tuple[ChangeKind | None, str]:
    if was is None and now is not None:
        return _appeared(now)
    if was is not None and now is None:
        return _cleared(was)
    if was is not None and now is not None:
        return _moved(was, now, static=static)
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


def _moved(was: CheckState, now: CheckState, *, static: bool) -> tuple[ChangeKind | None, str]:
    """Classify a check that is present in both runs."""
    if was.outcome == "unverified" and now.outcome == "fail":
        return ChangeKind.PROVEN, "a check that could not grade now proves the problem"
    if was.outcome == "fail" and now.outcome == "unverified":
        return ChangeKind.BLINDED, "a proven problem can no longer be graded, not fixed"
    return _same_outcome(was, now, static=static)


def _same_outcome(
    was: CheckState, now: CheckState, *, static: bool
) -> tuple[ChangeKind | None, str]:
    """Classify a check whose verdict held, by whatever else moved around it.

    Between two file scans, more findings in one place than before, more of them
    unwaived, is a new problem there: `APPEARED`, whatever the waiver flag says. So is
    an unwaived finding whose evidence the earlier run never reported there, which is
    how a new secret that replaced a removed one keeps the count.
    """
    if now.severity > was.severity:
        return (
            ChangeKind.ESCALATED,
            f"severity rose from {was.severity.name} to {now.severity.name}",
        )
    appeared = _new_here(was, now) if static and now.outcome == "fail" else None
    if appeared is not None:
        return ChangeKind.APPEARED, appeared
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


def _new_here(was: CheckState, now: CheckState) -> str | None:
    """Say what is new in one place between two file scans, or None when nothing is."""
    if now.count > was.count and now.unwaived > was.unwaived:
        return (
            f"{now.count - was.count} more {now.severity.name} finding(s) of this rule here "
            f"than before ({was.count} became {now.count}, {now.unwaived} not waived)"
        )
    reported = Counter(summary for summary, _waived in was.evidence)
    new = Counter(summary for summary, waived in now.evidence if not waived) - reported
    if new:
        return (
            f"{new.total()} {now.severity.name} finding(s) of this rule here that the earlier "
            f"run did not report, though the count stayed {now.count}"
        )
    return None


def _stopped_applying(
    before: ScanResult, after: ScanResult, dropped: frozenset[str]
) -> dict[str, SkippedRule]:
    """Return the rules of `dropped` that reported nothing before and did not apply after.

    Such a rule has nothing to grade on the second target, and the first run held no
    problem it could hide. One that reported anything before, a measured case or a suite
    conclusion included, stays coverage lost: what it said disappearing because the rule
    stopped applying is not a fix.
    """
    reported = {
        *(
            finding.rule_id
            for channel in (before.findings, before.unverified, before.waived)
            for finding in channel
        ),
        *(assessment.rule_id for assessment in before.assessments),
        *before.suites,
    }
    return {
        skip.rule_id: skip
        for skip in after.rules_skipped
        if skip.reason is SkipReason.NOT_APPLICABLE
        and skip.rule_id in dropped
        and skip.rule_id not in reported
    }


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
    shared: frozenset[str],
    before: RunContext,
    after: RunContext,
) -> tuple[str, ...]:
    """Say which rules were not the same test in both runs, and how sure that is.

    Across two runs of one build, a changed digest means a changed rule. Across a
    version boundary it means one of two things — the rule changed, or what a
    digest covers changed — and the note says so rather than asserting the first.
    Removing the framework mapping from the digest was such a change, and it moved
    every digest in the release it shipped in: a note reading "19 rules changed
    definition" there would have buried the one rule whose corpus actually moved.
    """
    changed = sorted(r for r in shared if _rule_changed(r, before.rules, after.rules))
    if not changed:
        return ()
    named = f"{', '.join(changed[:3])}{'…' if len(changed) > 3 else ''}"  # noqa: PLR2004
    if before.tool_version and after.tool_version and before.tool_version != after.tool_version:
        return (
            f"{len(changed)} rule(s) have a different digest ({named}), and the runs came "
            f"from different Guardana versions ({before.tool_version} and "
            f"{after.tool_version}) — across a version boundary a digest moves when the "
            f"rule changes and also when what a digest covers changes, so this alone says "
            f"nothing about either system",
        )
    return (
        f"{len(changed)} rule(s) changed definition between these runs ({named}) — a "
        f"different result there may be the sharper test rather than a worse system",
    )
