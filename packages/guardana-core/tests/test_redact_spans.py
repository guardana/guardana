"""Span redaction: matched spans replaced, every other character kept, nothing withheld or cut."""

import pytest
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy
from guardana.core.testing import fake_aws_key
from guardana.core.testing.secrets import fake_github_pat

_EMAIL = "someone" + "@" + "example.com"
_PEM_BODY = "\n".join(["MIIEow" + "IBAAKCAQEA" + "Q" * 54] * 3)
_RSA = "RSA PRIVATE KEY-----"


def test_metadata_only_replaces_spans_instead_of_withholding_the_text() -> None:
    redactor = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.METADATA_ONLY))

    assert redactor.redact_spans(f"mail {_EMAIL} now").startswith("mail [redacted:email:")
    assert redactor.redact_text(f"mail {_EMAIL} now") == ""


def test_span_redaction_is_never_truncated() -> None:
    redactor = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED, max_evidence_bytes=32))
    text = f"{fake_aws_key()} " + "word " * 100

    redacted = redactor.redact_spans(text)

    assert redacted.endswith("word " * 100)
    assert fake_aws_key() not in redacted


@pytest.mark.parametrize(
    "secret",
    [
        fake_github_pat(),
        "-----BEGIN " + _RSA + "\n" + _PEM_BODY + "\n-----END " + _RSA,
    ],
    ids=["github-pat", "pem-block"],
)
def test_a_second_pass_leaves_the_first_pass_placeholder_alone(secret: str) -> None:
    redactor = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED))

    once = redactor.redact_spans(f"here: {secret}\nthat was all")
    twice = redactor.redact_spans(once)

    assert once == twice == redactor.redact_text(once)
    assert once.startswith("here: [redacted:")
    assert once.endswith("\nthat was all")
    assert "MIIE" not in once
    assert "PRIVATE" not in once


def test_a_key_body_holding_a_shorter_secret_shape_is_still_removed_whole() -> None:
    redactor = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED))
    body = _PEM_BODY + "\n" + fake_aws_key() + "Q" * 44 + "\n" + _PEM_BODY
    block = "-----BEGIN " + "PRIVATE KEY-----\n" + body + "\n-----END " + "PRIVATE KEY-----"

    redacted = redactor.redact_spans(block)

    assert redacted.startswith("[redacted:private-key:")
    assert "MIIE" not in redacted


def test_a_header_left_open_takes_every_later_header_with_it_in_one_match() -> None:
    """A key with no END runs to the end of the text, so the headers after it add no scan."""
    first = "-----BEGIN PRIVATE KEY----- left open\n"
    second = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBg\n-----END PRIVATE KEY-----"
    redacted = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED)).redact_spans(
        first + second
    )

    assert redacted.count("[redacted:") == 1
    assert redacted.startswith("[redacted:private-key:")
    assert redacted.endswith("]")


@pytest.mark.parametrize(
    "opened",
    [
        "-----BEGIN " + "PRIVATE KEY-----\n" + _PEM_BODY + "\n!\n" + _PEM_BODY,
        "-----BEGIN " + "PRIVATE KEY-----\n" + _PEM_BODY + "\nnot base64 at all\n" + _PEM_BODY,
        "-----BEGIN " + _RSA + "\n" + _PEM_BODY + "\n-----BEGIN CERTIFICATE-----\n" + _PEM_BODY,
        "-----BEGIN " + "PRIVATE KEY-----\n" + _PEM_BODY,
        "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----",
    ],
    ids=["bang-line", "prose-line", "other-header", "cut-short", "pgp-header"],
)
def test_a_key_with_no_end_is_redacted_to_the_end_of_the_text(opened: str) -> None:
    redactor = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED))

    once = redactor.redact_spans(f"here: {opened}\nthat was all")

    assert once.startswith("here: [redacted:private-key:")
    assert once.endswith("]")
    assert once.count("[redacted:") == 1
    assert redactor.redact_spans(once) == once == redactor.redact_text(once)


@pytest.mark.parametrize(
    "header",
    [
        "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00FF\n\n",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n",
    ],
    ids=["pem-encrypted", "pgp"],
)
def test_a_key_block_cut_before_its_end_loses_its_body_too(header: str) -> None:
    body = "\n".join("Q" * 64 for _ in range(4))
    redacted = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED)).redact_spans(
        f"here it is: {header}{body}"
    )

    assert "Q" * 64 not in redacted
    assert redacted.startswith("here it is: [redacted:private-key")
