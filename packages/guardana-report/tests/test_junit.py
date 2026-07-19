import defusedxml.minidom
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity
from guardana.report import get_renderer


def test_junit_escapes_quotes_no_injection() -> None:
    """Test that JUnit renderer prevents XML injection via unescaped quotes in attributes."""
    malicious_rule_id = 'x" evil="yes'
    f = Finding(
        malicious_rule_id,
        Severity.HIGH,
        "Test finding",
        (),
        "target.py",
        Evidence(summary="Test evidence"),
    )
    result = ScanResult((f,), 1, ())
    renderer = get_renderer("junit")
    output = renderer.render(result)

    # Parse the XML to ensure it's valid (no injection breaks the structure)
    doc = defusedxml.minidom.parseString(output)

    # Extract the testcase element and verify the name attribute was escaped
    testcases = doc.getElementsByTagName("testcase")
    assert len(testcases) == 1
    testcase = testcases[0]

    # The name attribute should equal the original malicious string, proving it was
    # treated as data (escaped) rather than interpreted as markup
    assert testcase.getAttribute("name") == malicious_rule_id
    # Ensure the injected 'evil' attribute was NOT added
    assert not testcase.hasAttribute("evil")
