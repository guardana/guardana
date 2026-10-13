"""Every secret shape the reply rule detects is one the core redactor removes.

A reply the output rule flags as leaking a credential is written to run.json, SARIF, the
collector and a kept-exchanges sidecar; if the redactor misses that shape, the report that
says a secret leaked carries the secret itself.
"""

import pytest
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy
from guardana.rules._secrets import REPLY_SECRET_PATTERNS

# Assembled from fragments so the repository never holds a secret-shaped literal.
_PEM_BODY = "\n".join(["MIIEow" + "IBAAKCAQEA" + "Q" * 54] * 3)
_SAMPLES: dict[str, tuple[str, ...]] = {
    "private key header": (
        "-----BEGIN " + "RSA PRIVATE KEY-----",
        "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
        "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----",
        "-----BEGIN " + "PRIVATE KEY-----\n" + _PEM_BODY + "\n-----END " + "PRIVATE KEY-----",
    ),
    "AWS access key ID": ("AK" + "IA" + "Z" * 12 + "FAKE",),
    "GitHub token": (
        "gh" + "p_" + "F" * 36,
        "gh" + "s_" + "0" * 36,
        "gh" + "p_" + "F" * 36 + "_v2",
    ),
    "GitHub fine-grained token": ("github" + "_pat_" + "11FAKE" + "0" * 16 + "_" + "Z" * 59,),
    "Slack token": ("xo" + "xb-" + "1234567890-" + "FAKE" * 4,),
    "Google API key": ("AI" + "za" + "Sy" + "F" * 33,),
    "LLM provider API key": (
        "s" + "k-" + "d" * 32,
        "s" + "k-proj-" + "a" * 48,
        "s" + "k-svcacct-" + "b" * 48,
        "s" + "k-ant-api03-" + "c" * 40,
    ),
}

_CASES = [
    (label, sample) for label, _ in REPLY_SECRET_PATTERNS for sample in _SAMPLES.get(label, ())
]
_IDS = [f"{label}-{index}" for index, (label, _) in enumerate(_CASES)]


def _redactor() -> EvidenceRedactor:
    return EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED))


def test_every_reply_secret_pattern_has_a_sample() -> None:
    assert set(_SAMPLES) == {label for label, _ in REPLY_SECRET_PATTERNS}


@pytest.mark.parametrize(("label", "sample"), _CASES, ids=_IDS)
def test_the_sample_is_one_the_reply_rule_detects(label: str, sample: str) -> None:
    pattern = dict(REPLY_SECRET_PATTERNS)[label]
    assert pattern.search(f"the model said {sample} and stopped") is not None


_SURROUNDINGS = [
    ("the model said ", " and stopped"),
    ("您的密钥", "。"),
    ("clé:é", "é"),
    ("", ""),
]
"""Text around a sample: a reply in any language may write a token straight after a letter."""


@pytest.mark.parametrize(("label", "sample"), _CASES, ids=_IDS)
@pytest.mark.parametrize(("before", "after"), _SURROUNDINGS)
def test_the_finding_text_path_removes_the_secret(
    label: str, sample: str, before: str, after: str
) -> None:
    text = f"{before}{sample}{after}"
    assert dict(REPLY_SECRET_PATTERNS)[label].search(text) is not None
    redacted = _redactor().redact_text(text)
    assert _secret_of(label, sample) not in redacted
    assert "[redacted:" in redacted
    assert redacted.endswith(_kept_after(sample, after))


@pytest.mark.parametrize(("label", "sample"), _CASES, ids=_IDS)
@pytest.mark.parametrize(("before", "after"), _SURROUNDINGS)
def test_the_span_path_removes_the_secret(label: str, sample: str, before: str, after: str) -> None:
    text = f"{before}{sample}{after}"
    redacted = _redactor().redact_spans(text)
    assert _secret_of(label, sample) not in redacted
    assert "[redacted:" in redacted
    assert redacted.endswith(_kept_after(sample, after))


def _kept_after(sample: str, after: str) -> str:
    """What survives after `sample`: nothing when it opens a private key it never closes."""
    opens_a_key = sample.startswith("-----BEGIN ") and "-----END " not in sample
    return "]" if opens_a_key else after


def _secret_of(label: str, sample: str) -> str:
    """The part of `sample` that must not survive: what the rule's pattern matched.

    For a full PEM block the key material matters more than the header the rule
    matches, so the body is what has to be gone.
    """
    if _PEM_BODY in sample:
        return _PEM_BODY.splitlines()[0]
    match = dict(REPLY_SECRET_PATTERNS)[label].search(sample)
    if match is None:
        raise AssertionError(f"{label!r} does not match its own sample {sample!r}")
    return match.group(0)
