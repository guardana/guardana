import json

from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity
from guardana.core.testing import manifest_for
from guardana.report import get_renderer


def _result() -> ScanResult:
    f = Finding(
        "guardana.sc.pickle",
        Severity.CRITICAL,
        "Dangerous pickle opcode",
        (),
        "model.pkl",
        Evidence(summary="REDUCE calls os.system"),
    )
    return ScanResult((f,), rules_run=("r0",), rules_skipped=())


def test_json_renderer_is_machine_readable() -> None:
    result = _result()
    out = json.loads(get_renderer("json", run=manifest_for(result)).render(result))
    assert out["findings"][0]["rule_id"] == "guardana.sc.pickle"
    assert out["findings"][0]["severity"] == "CRITICAL"
    assert out["run"]["result_summary"]["rules_run"] == ["r0"]


def test_human_renderer_mentions_rule_and_severity() -> None:
    out = get_renderer("human").render(_result())
    assert "guardana.sc.pickle" in out
    assert "CRITICAL" in out
