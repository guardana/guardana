"""A check that could not run must be visible in every output format.

The three channels are deliberately distinct, and each renderer keeps them that
way: a *finding* is "a check ran and found something", *unverified* is "a check
ran and could not tell", and an *error* is "a check never ran at all". The last
one used to be invisible, which is what let a crashed rule read as a clean one.
"""

import json
from xml.etree.ElementTree import fromstring

from guardana.core.report import CheckError, ScanResult
from guardana.report import HumanRenderer, JsonRenderer, JUnitRenderer, SarifRenderer

_ERRORS = (
    CheckError(source="acme.buggy", stage="run", reason="ValueError: typo"),
    CheckError(source="broken-pack", stage="discovery", reason="ImportError: no module"),
)
_RESULT = ScanResult(findings=(), rules_run=3, rules_skipped=(), errors=_ERRORS)
_CLEAN = ScanResult(findings=(), rules_run=3, rules_skipped=())


def test_human_names_the_check_and_the_stage() -> None:
    text = HumanRenderer().render(_RESULT)
    assert "[ERROR]" in text
    assert "acme.buggy" in text
    assert "discovery" in text
    assert "2 check(s) could not run." in text


def test_human_stays_quiet_when_everything_ran() -> None:
    text = HumanRenderer().render(_CLEAN)
    assert "ERROR" not in text
    assert "could not run" not in text


def test_json_carries_the_errors_and_their_count() -> None:
    doc = json.loads(JsonRenderer().render(_RESULT))
    assert doc["summary"]["errors"] == 2
    assert doc["errors"][0] == {
        "source": "acme.buggy",
        "stage": "run",
        "reason": "ValueError: typo",
    }


def test_junit_uses_error_not_failure() -> None:
    # CI tooling reads <error> as "could not run" and <failure> as "ran and
    # failed". Reporting a crashed check as a failure would misattribute it.
    root = fromstring(JUnitRenderer().render(_RESULT))  # noqa: S314 — our own output
    assert root.get("errors") == "2"
    assert root.get("failures") == "0"
    errors = root.findall(".//error")
    assert len(errors) == 2
    assert errors[0].get("message") == "check did not run"


def test_sarif_marks_the_invocation_unsuccessful() -> None:
    # An empty `results` array with `executionSuccessful: true` is exactly the
    # false all-clear this channel exists to prevent.
    run = json.loads(SarifRenderer().render(_RESULT))["runs"][0]
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert len(invocation["toolExecutionNotifications"]) == 2
    assert (
        "acme.buggy did not run" in invocation["toolExecutionNotifications"][0]["message"]["text"]
    )


def test_sarif_reports_a_successful_invocation_when_nothing_errored() -> None:
    run = json.loads(SarifRenderer().render(_CLEAN))["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["invocations"][0]["toolExecutionNotifications"] == []
