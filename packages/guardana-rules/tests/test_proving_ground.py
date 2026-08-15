"""What a scan finds, and what it says about a repository that has nothing to hide.

Two numbers, and the second is the one nothing measured before. Recall: every planted
finding is still found, so coverage cannot quietly leave between releases. Precision:
nothing is reported anywhere else — not on a documentation page quoting AWS's example
key, not on a docstring warning against a dangerous flag, not on a test fixture's
obviously fabricated token.

Precision is a security property here rather than a nicety. A scanner that cries wolf on
a team's own documentation gets excluded from their pipeline, and an excluded scanner is
an organisation-level fail-open — the same reasoning that makes performance a security
property in this codebase.

The dogfood scan cannot answer either question. It proves Guardana finds nothing in
Guardana, and Guardana does not look like the repositories people point a scanner at.
"""

import pytest
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.runner import Runner
from guardana.core.target import ArtifactTarget
from proving_ground import DECOYS, MISSED, PLANTED, build


@pytest.fixture(scope="module")
def findings(tmp_path_factory: pytest.TempPathFactory) -> tuple[Finding, ...]:
    """Scan the proving ground once, the way `guardana scan <path>` does."""
    root = build(tmp_path_factory.mktemp("proving-ground"))
    result = Runner(
        registry=Registry.discover(), profile=Profile(name="proving-ground", policy=Policy())
    ).run(ArtifactTarget(root))
    return tuple(result.findings)


def _reported(findings: tuple[Finding, ...], path: str) -> set[str]:
    """Which rules fired on this file, by id."""
    return {f.rule_id for f in findings if f.target_ref and path in f.target_ref}


@pytest.mark.parametrize("planted", PLANTED, ids=lambda p: f"{p.path}:{p.rule_id}")
def test_every_planted_finding_is_still_found(
    planted: object, findings: tuple[Finding, ...]
) -> None:
    """A plant nobody finds is coverage that went away without anyone noticing."""
    assert isinstance(planted, type(PLANTED[0]))
    assert planted.rule_id in _reported(findings, planted.path), planted.why


@pytest.mark.parametrize("decoy", DECOYS, ids=lambda d: d.path)
def test_no_decoy_produces_a_finding(decoy: object, findings: tuple[Finding, ...]) -> None:
    """Each of these looks like a finding to a rule that reads a little too eagerly."""
    assert isinstance(decoy, type(DECOYS[0]))
    assert _reported(findings, decoy.path) == set(), decoy.why


@pytest.mark.parametrize("missed", MISSED, ids=lambda m: f"{m.path}:{m.rule_id}")
def test_a_recorded_gap_is_still_a_gap(missed: object, findings: tuple[Finding, ...]) -> None:
    """Asserted in the direction it is true, so closing it fails here and gets relabelled.

    A gap left out of the list reads as coverage. A gap asserted the other way round
    would go green the day somebody widened a rule and nobody would learn that the
    widening happened.
    """
    assert isinstance(missed, type(MISSED[0]))
    assert missed.rule_id not in _reported(findings, missed.path), missed.why


def test_nothing_outside_the_labels_is_reported(findings: tuple[Finding, ...]) -> None:
    """An alarm on an unlabelled file is one nobody has explained, which is the whole point.

    Written against the labels rather than a total count: a count would go green again
    the moment somebody adjusted it, and this has to fail with the *name* of whatever
    started firing.
    """
    labelled = {planted.path for planted in PLANTED} | {gap.path for gap in MISSED}
    unexplained = sorted(
        f"{finding.rule_id} on {finding.target_ref}"
        for finding in findings
        if not any(path in (finding.target_ref or "") for path in labelled)
    )

    assert unexplained == []


def test_no_file_carries_two_labels() -> None:
    """A file cannot be two of these, and a label contradicting another is one nobody trusts."""
    planted = {item.path for item in PLANTED}
    missed = {item.path for item in MISSED}
    decoys = {item.path for item in DECOYS}

    assert planted & decoys == set()
    assert missed & decoys == set()
    assert planted & missed == set()
