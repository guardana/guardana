"""Turning an imported observation into the one finding shape everything downstream reads.

In the engine rather than in the CLI, because the collector, `diff` and every renderer
consume `Finding` and none of them should learn a second shape for "somebody else said
so". What makes it *theirs* rather than ours is the verdict: `inconclusive`, with the
producer named in `evaluator_id`.
"""

from guardana.core.evaluator.base import Verdict
from guardana.core.report import Evidence, Finding
from guardana.core.trace.observations import (
    ImportedObservation,
    ObservationRead,
    ObservedOutcome,
)

RULE_ID_PREFIX = "imported"
"""One rule id per producer (`imported.garak`), so a profile can exclude one with a glob.

Per producer rather than per test: a rule id per foreign test would make the namespace
grow with somebody else's corpus, and the finding fingerprint already covers the
evidence summary — which carries the test id — so waivers stay per claim either way.
"""

_NOT_A_VERDICT = (
    "This is {producer}'s result, not a Guardana verdict: Guardana did not send the "
    "prompt and did not see the reply, so it cannot grade it."
)


def claims_of(read: ObservationRead, target_ref: str) -> tuple[Finding, ...]:
    """Render every imported claim as an unverified finding, provenance intact.

    Only claims — a result the producer marked as passing never gets here, because
    `read_observations` counts those instead of importing them.
    """
    return tuple(_claim(observation, read, target_ref) for observation in read.observations)


def _claim(observation: ImportedObservation, read: ObservationRead, target_ref: str) -> Finding:
    producer = read.provenance.producer
    why = _NOT_A_VERDICT.format(producer=producer)
    return Finding(
        rule_id=f"{RULE_ID_PREFIX}.{producer}",
        severity=observation.reported_severity,
        title=observation.title,
        # Deliberately empty. Attaching a framework reference to somebody else's result
        # would be Guardana vouching for a mapping it did not make; the producer's own
        # category travels in the evidence, where it reads as a quotation.
        taxonomy=(),
        target_ref=observation.target or target_ref,
        evidence=Evidence(
            summary=_summary(observation, producer), detail=_detail(observation, read)
        ),
        verdict=Verdict("inconclusive", 0.0, why, f"{RULE_ID_PREFIX}:{producer}"),
    )


def _summary(observation: ImportedObservation, producer: str) -> str:
    """State whose claim this is, what they concluded, and about what.

    The producer's verb, not ours. `FAILED` means *their* check did not hold — whether
    that is an attack succeeding depends on what the check was, and only whoever wrote
    it knows.
    """
    stated = {
        ObservedOutcome.FAILED: "reported a failing check",
        ObservedOutcome.ERRORED: "could not run a check",
        ObservedOutcome.UNDECIDED: "ran a check and could not decide",
        ObservedOutcome.PASSED: "reported a passing check",
    }[observation.outcome]
    category = f" [{observation.category}]" if observation.category else ""
    return f"{producer} {stated}: {observation.id}{category}"


def _detail(observation: ImportedObservation, read: ObservationRead) -> str:
    lines = [f"source: {read.provenance.describe()}"]
    if observation.severity is not None:
        lines.append(
            f"severity as reported by {read.provenance.producer}: {observation.severity.name}"
        )
    else:
        lines.append(
            f"{read.provenance.producer} reported no severity, so this is filed at INFO — "
            f"a floor, not a judgement"
        )
    if observation.detail:
        lines.append(observation.detail)
    if read.provenance.document_digest:
        lines.append(f"document digest: {read.provenance.document_digest}")
    return "\n".join(lines)
