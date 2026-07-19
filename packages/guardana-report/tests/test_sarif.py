import json

from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity
from guardana.report import get_renderer


def _result() -> ScanResult:
    f = Finding(
        "guardana.sc.pickle",
        Severity.HIGH,
        "Dangerous opcode",
        (),
        "model.pkl",
        Evidence(summary="REDUCE"),
    )
    return ScanResult((f,), 1, ())


def test_sarif_is_valid_2_1_0_shape() -> None:
    doc = json.loads(get_renderer("sarif").render(_result()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Guardana"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["ruleId"] == "guardana.sc.pickle"
