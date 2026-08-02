"""A live-looking credential must not reach any output path intact. Per path.

Asserted once, centrally, this test would pass while one renderer quietly bypassed
the redactor — which is exactly how a policy applied in thirty places ends up with
thirty exceptions. So every registered renderer is enumerated from the registry
itself: a renderer added later is covered without anybody remembering to add it
here, and one that skips the seam fails immediately.

Fixtures are crafted, obviously-fake credentials built in code. No real key has
ever been in this repository and this is not where that starts.
"""

import pytest
from guardana.core.redaction import EvidenceRedactor, RedactionPolicy
from guardana.core.report import Evidence, Finding, ScanResult, serialize_baseline
from guardana.core.reporter import HttpReporter
from guardana.core.severity import Severity
from guardana.core.testing import fake_aws_key, fake_jwt, fake_llm_key, fake_secrets, manifest_for
from guardana.report import RENDERER_NAMES, get_renderer

# Built in code, never written down: a secret-shaped literal in a test file is a
# secret-shaped literal in the repository, and the dogfood scan is right to say so.
_FAKE_AWS = fake_aws_key()
_FAKE_OPENAI = fake_llm_key()
_FAKE_JWT = fake_jwt()
_SECRETS = fake_secrets()


def _leaky_finding() -> Finding:
    """What a third-party rule can hand the engine — and used to hand every output."""
    return Finding(
        rule_id="acme.leaky.rule",
        severity=Severity.CRITICAL,
        title="model returned credentials",
        taxonomy=(),
        target_ref="http://x#m",
        evidence=Evidence(
            summary=f"the model replied with {_FAKE_AWS}",
            detail=f"full reply: here is my key {_FAKE_OPENAI} and a token {_FAKE_JWT}",
        ),
    )


def _leaky_result() -> ScanResult:
    finding = _leaky_finding()
    return ScanResult(
        findings=(finding,),
        rules_run=("acme.leaky.rule",),
        rules_skipped=(),
        unverified=(finding,),
        waived=(finding,),
    )


def _contains_any_secret(text: str) -> list[str]:
    return [secret for secret in _SECRETS if secret in text]


@pytest.mark.parametrize("name", sorted(RENDERER_NAMES))
def test_no_renderer_can_emit_a_live_looking_credential(name: str) -> None:
    result = _leaky_result()

    rendered = get_renderer(name, run=manifest_for(result)).render(result)

    assert not _contains_any_secret(rendered), (
        f"the {name} renderer emitted a credential; every output path goes through "
        f"the redactor, and this one does not"
    )


@pytest.mark.parametrize("name", sorted(RENDERER_NAMES))
def test_every_renderer_still_reports_that_the_finding_happened(name: str) -> None:
    # Redaction must not become suppression. The finding is that a credential
    # appeared; the value is what must not be stored.
    result = _leaky_result()

    rendered = get_renderer(name, run=manifest_for(result)).render(result)

    assert "acme.leaky.rule" in rendered


def test_the_collector_envelope_cannot_carry_a_credential() -> None:
    # The path that leaves the machine entirely, and the one a convention-based
    # policy is least likely to have covered.
    sent: list[bytes] = []
    reporter = HttpReporter("http://collector", transport=lambda _url, body: sent.append(body))

    reporter.submit(_leaky_result(), source="test")

    assert not _contains_any_secret(sent[0].decode("utf-8"))


def test_a_baseline_cannot_carry_a_credential() -> None:
    # A baseline is committed to a repository, which makes it the worst place of
    # all for a live key to end up.
    serialized = serialize_baseline(_leaky_result())

    assert not _contains_any_secret(serialized)


def test_full_evidence_mode_still_removes_secrets() -> None:
    # `full` means "keep the model's words", never "store a live credential".
    # There is no useful reading of the second, and no flag should offer it.
    redactor = EvidenceRedactor(RedactionPolicy(mode="full"))  # type: ignore[arg-type]

    cleaned = redactor.redact(_leaky_finding())

    assert not _contains_any_secret(cleaned.evidence.summary + cleaned.evidence.detail)


def test_redaction_says_that_it_happened() -> None:
    redactor = EvidenceRedactor()

    cleaned = redactor.redact(_leaky_finding())

    assert "[redacted:" in cleaned.evidence.summary


def test_the_same_secret_redacts_to_the_same_placeholder() -> None:
    # So a finding's fingerprint stays stable across runs and a baseline waiver
    # keeps matching — without the value ever being stored.
    redactor = EvidenceRedactor()

    first = redactor.redact_text(f"key {_FAKE_AWS} here")
    second = redactor.redact_text(f"and again {_FAKE_AWS}")

    placeholder = first.split("key ")[1].split(" here")[0]
    assert placeholder in second


def test_different_secrets_redact_to_different_placeholders() -> None:
    redactor = EvidenceRedactor()

    assert redactor.redact_text(_FAKE_AWS) != redactor.redact_text(_FAKE_OPENAI)


def test_oversized_evidence_is_truncated_and_says_so() -> None:
    redactor = EvidenceRedactor(RedactionPolicy(max_evidence_bytes=64))

    cleaned = redactor.redact_text("a" * 500)

    assert len(cleaned.encode("utf-8")) < 500
    assert "truncated" in cleaned


def test_metadata_only_keeps_the_finding_and_drops_the_text() -> None:
    from guardana.core.manifest.settings import EvidenceMode  # noqa: PLC0415

    redactor = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.METADATA_ONLY))

    cleaned = redactor.redact(_leaky_finding())

    assert cleaned.rule_id == "acme.leaky.rule"
    assert "withheld" in cleaned.evidence.summary
    assert cleaned.evidence.detail == ""


def test_redaction_is_idempotent() -> None:
    """It runs at the output seam *and* once in the command; applying it twice must be safe.

    Otherwise a placeholder would be re-redacted into a placeholder of a
    placeholder, and the finding fingerprint — which is computed from the evidence
    summary — would differ depending on how many times the text had passed
    through.
    """
    redactor = EvidenceRedactor()

    once = redactor.redact_text(f"key {_FAKE_AWS} here")
    twice = redactor.redact_text(once)

    assert once == twice


def test_a_baseline_written_from_redacted_findings_still_waives_them() -> None:
    """The trap underneath this whole change.

    A finding's fingerprint includes its evidence summary. Redacting changes the
    summary, so a baseline written from redacted findings and applied to raw ones
    would silently stop matching — every waiver would quietly expire and the gate
    would go red for reasons nobody could see.
    """
    from guardana.core.report import apply_baseline, load_baseline  # noqa: PLC0415

    redactor = EvidenceRedactor()
    redacted = redactor.redact_result(_leaky_result())
    written = serialize_baseline(redacted).replace("REPLACE ME", "accepted for this test")

    waived = apply_baseline(redacted, load_baseline_from_text(written))

    assert waived.findings == (), "the waiver written from these findings must match them"
    assert waived.waived, "and the finding must still be reported, just not gated"
    assert load_baseline is not None  # the import is the point of the test


def load_baseline_from_text(text: str) -> frozenset[str]:
    """Parse a baseline from text, the way the CLI parses one from a file."""
    import tempfile  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    from guardana.core.report import load_baseline  # noqa: PLC0415

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "baseline.yaml"
        path.write_text(text, encoding="utf-8")
        return load_baseline(path)
