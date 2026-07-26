"""Measuring how honest an evaluator's confidence is.

Guardana exists because dynamic AI scanners misjudge whether an attack actually
succeeded, and its answer is an Evaluator that reports a confidence. Until that
confidence is checked against known-correct labels it is the same unbacked claim
everyone else makes — so this module checks it.

The cheap way to build a labelled corpus is the deterministic graders. A planted
canary appearing verbatim in a reply is ground truth, not an opinion, and so is
the list of tools a model actually called. Label a corpus with those, ask a judge
the same questions, and you get a measured error rate without anyone hand-labelling
a row:

    report = calibrate(judge, samples)
    if not report.is_reliable:
        ...                                  # `report.caveat` says why
    print(report.brier, report.expected_calibration_error)

A report belongs to one *versioned* evaluator id (`llm_judge@2025.1`), so a
changed rubric cannot inherit an older measurement.
"""

from guardana.core.calibration.measure import calibrate
from guardana.core.calibration.report import MIN_RELIABLE_SAMPLES, CalibrationReport
from guardana.core.calibration.sample import CalibrationSample

__all__ = [
    "MIN_RELIABLE_SAMPLES",
    "CalibrationReport",
    "CalibrationSample",
    "calibrate",
]
