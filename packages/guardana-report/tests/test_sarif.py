import json

from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity
from guardana.report import get_renderer


def _result(target_ref: str = "src/deser.py:2") -> ScanResult:
    finding = Finding(
        "guardana.sc.pickle",
        Severity.HIGH,
        "Dangerous opcode",
        (),
        target_ref,
        Evidence(summary="REDUCE"),
    )
    return ScanResult((finding,), 1, ())


def test_sarif_is_valid_2_1_0_shape() -> None:
    doc = json.loads(get_renderer("sarif").render(_result()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Guardana"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["ruleId"] == "guardana.sc.pickle"


def test_sarif_location_has_relative_uri_and_region_start_line() -> None:
    # F-A: GitHub code scanning attaches an alert via a repo-relative uri (no line
    # glued on) and an integer region.startLine — not "src/deser.py:2" in the uri.
    result = json.loads(get_renderer("sarif").render(_result()))["runs"][0]["results"][0]
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "src/deser.py"
    assert physical["region"]["startLine"] == 2


def test_sarif_emits_partial_fingerprints_and_rule_index() -> None:
    result = json.loads(get_renderer("sarif").render(_result()))["runs"][0]["results"][0]
    assert result["partialFingerprints"]  # non-empty — lets code scanning track alerts
    assert result["ruleIndex"] == 0


def test_sarif_driver_lists_the_rules() -> None:
    # An empty driver.rules[] makes code scanning drop every result.
    run = json.loads(get_renderer("sarif").render(_result()))["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert rules[0]["id"] == "guardana.sc.pickle"
    assert rules[0]["defaultConfiguration"]["level"] == "error"
    assert rules[0]["helpUri"]


def test_sarif_ref_without_line_has_no_region() -> None:
    result = json.loads(get_renderer("sarif").render(_result("model.pkl")))["runs"][0]["results"][0]
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "model.pkl"
    assert "region" not in physical
