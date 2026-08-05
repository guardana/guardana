"""`monitor` must honour the run's privacy policy, on screen and on the wire.

`scan` and `probe` redact before they emit anything. `monitor` did not — it
printed through a renderer built with no policy (so the library default, `full`)
and handed `submit_safely` a result that had passed through no redactor at all.
That is the mode that runs unattended for hours and ships every alert to a
central collector, so it is the worst of the three to have missed.

Asserted at both exits, because they are separate code paths and only one of them
is visible to whoever is watching the terminal.
"""

import guardana.cli.monitor as monitor_module
import pytest
from guardana.cli.monitor import alert_handler
from guardana.core.manifest.settings import EvidenceMode
from guardana.core.monitor import Alert
from guardana.core.redaction import EvidenceRedactor, RedactionPolicy
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity
from guardana.core.testing import fake_aws_key

_FAKE_KEY = fake_aws_key()
_PRIVATE_EMAIL = "oncall@example.com"


def _leaky_alert() -> Alert:
    finding = Finding(
        rule_id="acme.leaky.rule",
        severity=Severity.CRITICAL,
        title="model returned credentials",
        taxonomy=(),
        target_ref="http://x#m",
        # Both the key and the address are in the *summary*, because that is the
        # field the human renderer prints. With the address only in `detail`, the
        # printed-output test could not tell an unredacted run from a redacted one
        # and would have stayed green through the very bug it is named after.
        evidence=Evidence(
            summary=f"the model replied with {_FAKE_KEY} and mailed it to {_PRIVATE_EMAIL}",
            detail=f"full reply, addressed to {_PRIVATE_EMAIL}",
        ),
    )
    return Alert(
        cycle=0,
        reason="new finding",
        result=ScanResult(findings=(finding,), rules_run=("acme.leaky.rule",), rules_skipped=()),
    )


def _collect_submissions(monkeypatch: pytest.MonkeyPatch) -> list[ScanResult]:
    """Replace the collector call with a recorder, so nothing leaves the test."""
    submissions: list[ScanResult] = []

    def record(
        _url: str, result: ScanResult, *, source: str, deployment: object | None = None
    ) -> None:
        assert source
        submissions.append(result)

    monkeypatch.setattr(monitor_module, "submit_safely", record)
    return submissions


def _handler(mode: EvidenceMode, reporter: str | None) -> object:
    return alert_handler(EvidenceRedactor(RedactionPolicy(mode=mode)), reporter, "http://x#m")


def test_the_printed_alert_is_redacted(capsys: pytest.CaptureFixture[str]) -> None:
    handler = _handler(EvidenceMode.REDACTED, None)

    handler(_leaky_alert())  # type: ignore[operator]

    printed = capsys.readouterr().out
    assert _FAKE_KEY not in printed
    assert _PRIVATE_EMAIL not in printed, "the profile said to redact addresses and it did not"
    assert "acme.leaky.rule" in printed, "redaction must not become suppression"


def test_the_alert_sent_to_the_collector_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    submissions = _collect_submissions(monkeypatch)

    _handler(EvidenceMode.REDACTED, "http://collector")(_leaky_alert())  # type: ignore[operator]

    assert submissions, "the alert never reached the collector path"
    text = "".join(f.evidence.summary + f.evidence.detail for f in submissions[0].findings)
    assert _FAKE_KEY not in text
    assert _PRIVATE_EMAIL not in text


def test_metadata_only_reaches_the_collector_as_metadata_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The strictest mode a profile can set, and the one whose whole purpose is
    # that no model text leaves the machine.
    submissions = _collect_submissions(monkeypatch)

    _handler(EvidenceMode.METADATA_ONLY, "http://collector")(_leaky_alert())  # type: ignore[operator]

    finding = submissions[0].findings[0]
    assert finding.evidence.detail == ""
    assert "withheld" in finding.evidence.summary
    assert finding.rule_id == "acme.leaky.rule"


def test_a_monitor_run_that_names_no_handler_still_redacts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The default handler resolves from the profile, not from a module-level default.

    A default argument would have to name a redactor before the profile exists,
    which is how the unredacted one got in. `run_monitor` therefore builds it from
    the profile it was handed.
    """
    from dataclasses import replace  # noqa: PLC0415

    from guardana.cli._probe_run import Connection  # noqa: PLC0415
    from guardana.cli.monitor import run_monitor  # noqa: PLC0415
    from guardana.core.profile import default_profile  # noqa: PLC0415
    from guardana.core.registry import Registry  # noqa: PLC0415

    profile = replace(default_profile(), privacy=RedactionPolicy(mode=EvidenceMode.METADATA_ONLY))
    alert = _leaky_alert()

    run_monitor(
        Registry(),
        profile,
        Connection(url="http://fake", model="m"),
        max_cycles=1,
        sleep=lambda _s: None,
    )
    # The loop above ran no rules, so nothing alerted; call the resolved handler
    # directly to assert what it would have printed.
    monitor_module.alert_handler(EvidenceRedactor(profile.privacy), None, "http://fake")(alert)

    assert _FAKE_KEY not in capsys.readouterr().out
