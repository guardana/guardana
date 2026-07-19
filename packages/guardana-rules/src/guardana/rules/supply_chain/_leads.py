"""A low-confidence "lead" verdict for genuinely probabilistic static signals.

A slopsquat import or an unsigned/unpinned model is a lead worth a look, not a
proven compromise. Attaching a low confidence lets a policy's `min_confidence`
treat it as a lead — while unambiguous detections (a malicious pickle opcode)
stay verdict-free and at effective certainty, never diluted by a made-up number.
"""

from guardana.core.evaluator.base import Verdict

LEAD_CONFIDENCE = 0.4
_LEAD_EVALUATOR_ID = "heuristic.lead"


def lead_verdict(rationale: str) -> Verdict:
    """Build a flagged-but-low-confidence verdict for a probabilistic static lead."""
    return Verdict("fail", LEAD_CONFIDENCE, rationale, _LEAD_EVALUATOR_ID)
