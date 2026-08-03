"""A redacted secret must keep the label that says what kind of secret it was.

The pattern list is ordered most specific first so that a GitHub token is
labelled `github-token` rather than as whatever generic rule also matches it.
Substituting one pattern at a time defeated that ordering: each pattern read the
*output* of the previous one, and the generic "token = value" pattern matched the
label of the placeholder that had just replaced the secret. The result was
`[redacted:github-[redacted:credential-assignment:…]]` — stable, hashed, and
useless to the person who has to decide whether to rotate a key.

Nothing in the suite noticed, because the only secret it exercised was an AWS key
whose label contains no word the generic pattern looks for.
"""

import pytest
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy

_SAMPLES = {
    "github-token": "ghp_" + "a1b2c3d4e5f6g7h8",
    "slack-token": "xoxb-" + "1234567890-abcdef",
    "bearer-token": "Bearer " + "abcdefghijklmnopqrst",
    "aws-key": "AKIA" + "1234567890ABCDEF",
    "credential-assignment": "api_key = " + "abcdefghijkl0123",
}


def _redactor(mode: EvidenceMode = EvidenceMode.REDACTED) -> EvidenceRedactor:
    return EvidenceRedactor(RedactionPolicy(mode=mode))


@pytest.mark.parametrize(("label", "sample"), sorted(_SAMPLES.items()))
def test_a_secret_is_labelled_as_the_kind_of_secret_it_is(label: str, sample: str) -> None:
    cleaned = _redactor().redact_text(f"the model said: {sample}")

    assert f"[redacted:{label}:" in cleaned, (
        f"expected the {label} label; a later pattern rewrote it into {cleaned!r}"
    )


@pytest.mark.parametrize(("label", "sample"), sorted(_SAMPLES.items()))
def test_no_placeholder_is_ever_nested_inside_another(label: str, sample: str) -> None:
    cleaned = _redactor().redact_text(f"the model said: {sample}")

    assert cleaned.count("[redacted:") == 1, f"{label} produced a nested placeholder: {cleaned!r}"


@pytest.mark.parametrize(("label", "sample"), sorted(_SAMPLES.items()))
def test_redacting_twice_produces_the_same_text_as_redacting_once(label: str, sample: str) -> None:
    """The command redacts, and then the renderer redacts again.

    So a placeholder has to survive being read as input. It does because a
    placeholder claims its own span before any pattern is offered the text —
    without that, the second pass would find `token:` followed by twelve
    characters inside the label the first pass wrote.
    """
    redactor = _redactor()

    once = redactor.redact_text(f"the model said: {sample}")

    assert redactor.redact_text(once) == once, label


@pytest.mark.parametrize(("label", "sample"), sorted(_SAMPLES.items()))
def test_a_secret_goes_at_full_evidence_mode_too(label: str, sample: str) -> None:
    # `full` keeps the model's words. It has never been a way to keep its keys,
    # and there is no longer a setting that claims otherwise.
    cleaned = _redactor(EvidenceMode.FULL).redact_text(f"the model said: {sample}")

    assert sample.rsplit(maxsplit=1)[-1] not in cleaned, label


def test_two_secrets_in_one_string_are_each_labelled_correctly() -> None:
    cleaned = _redactor().redact_text(
        f"first {_SAMPLES['github-token']} then {_SAMPLES['aws-key']}"
    )

    assert "[redacted:github-token:" in cleaned
    assert "[redacted:aws-key:" in cleaned


def test_the_digest_still_identifies_the_same_secret_across_runs() -> None:
    # What makes a finding fingerprint stable, and the property the nesting bug
    # preserved by accident. Asserted so the next change to `_apply` cannot lose it.
    redactor = _redactor()
    sample = _SAMPLES["github-token"]

    assert redactor.redact_text(f"a {sample}").split("a ")[1] == redactor.redact_text(sample)
