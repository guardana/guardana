"""A low-confidence "lead" verdict for genuinely probabilistic static signals.

A slopsquat import or an unsigned/unpinned model is a lead worth a look, not a
proven compromise. Attaching a low confidence lets a policy's `min_confidence`
treat it as a lead — while unambiguous detections (a malicious pickle opcode)
stay verdict-free and at effective certainty, never diluted by a made-up number.
"""

from guardana.core.evaluator.base import Verdict

LEAD_CONFIDENCE = 0.4
_LEAD_EVALUATOR_ID = "heuristic.lead"
_UNSCANNED_EVALUATOR_ID = "heuristic.unscanned"


def lead_verdict(rationale: str) -> Verdict:
    """Build a flagged-but-low-confidence verdict for a probabilistic static lead."""
    return Verdict("fail", LEAD_CONFIDENCE, rationale, _LEAD_EVALUATOR_ID)


def unscanned_verdict(rationale: str) -> Verdict:
    """Build the verdict for an artifact this build could not read.

    Not a lead, and not a finding of any size. A lead says "this looks wrong and I
    am not certain"; this says "I did not look, so nothing here is evidence either
    way". Grading it as a low-confidence failure put an answer where there is none:
    severity asks how bad a problem is, and an artifact nobody read is not a problem
    of a size — which is how a profile failing on `medium` promoted a model store
    holding a hundred members it could not parse.
    """
    return Verdict("inconclusive", 0.0, rationale, _UNSCANNED_EVALUATOR_ID)
