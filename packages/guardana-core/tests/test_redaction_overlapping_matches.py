"""A generic match around a key keeps the key's placeholder; one reaching past it leaves nothing."""

import pytest
from guardana.core.fingerprint import digest_of
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy
from guardana.core.testing import fake_aws_key, fake_jwt

_GITHUB = "gh" + "p_" + "FAKE" * 5
_OPENAI = "sk" + "-" + "FAKE" * 5
_ANTHROPIC = "sk" + "-ant-" + "fake" * 5
_TAIL = "rest-of-the-credential-xyz"
_PEM_BODY = "MIIEow" + "IBAAKCAQEA" + "Q" * 54
_BEGIN = "-----BEGIN " + "PRIVATE KEY-----"
_END = "-----END " + "PRIVATE KEY-----"


def _redactor() -> EvidenceRedactor:
    return EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED))


def _placeholder(label: str, value: str) -> str:
    return f"[redacted:{label}:{digest_of(value)[7:19]}]"


@pytest.mark.parametrize(
    ("keyword", "key", "label", "after"),
    [
        ("tok" + "en = ", _GITHUB, "github-token", ""),
        ("Authorization: Bearer ", fake_jwt(), "jwt", ""),
        ("api_" + "key: ", _OPENAI, "openai-key", ""),
        ("pass" + "word=", fake_aws_key(), "aws-key", ""),
        ("sec" + 'ret: "', _ANTHROPIC, "anthropic-key", '"'),
    ],
    ids=["token-github", "bearer-jwt", "api-key-openai", "password-aws", "secret-anthropic"],
)
def test_a_generic_match_around_a_specific_key_keeps_the_key_s_placeholder(
    keyword: str, key: str, label: str, after: str
) -> None:
    """Byte for byte what the redactor wrote before overlaps merged, so waivers keep matching."""
    redacted = _redactor().redact_spans(f"seen {keyword}{key}{after} done")

    assert redacted == f"seen {keyword}{_placeholder(label, key)}{after} done"


@pytest.mark.parametrize(
    ("keyword", "value", "label"),
    [
        ("pass" + "word=", _GITHUB + "_PRIVATE_PASSWORD_SUFFIX", "github-token"),
        ("Bearer ", _GITHUB + "." + _TAIL, "github-token"),
        ("api_" + "key=", fake_aws_key() + "AREALLYLONGTAILSECRET", "aws-key"),
        ("tok" + "en: ", _OPENAI + "/PLUS+SLASH-tail", "openai-key"),
        ("sec" + "ret=", "xo" + "xb-" + "FAKE" * 3 + ".dotted.tail.value", "slack-token"),
    ],
    ids=["assignment-token", "bearer-token", "assignment-aws", "colon", "dots"],
)
def test_a_value_reaching_past_a_key_is_replaced_whole(
    keyword: str, value: str, label: str
) -> None:
    redacted = _redactor().redact_spans(f"seen {keyword}{value} done")

    assert redacted == f"seen {keyword}{_placeholder(label, value)} done"


def test_a_union_redacted_once_is_left_alone_by_a_second_pass() -> None:
    redactor = _redactor()
    once = redactor.redact_spans("Bearer " + _GITHUB + "." + _TAIL)

    assert redactor.redact_spans(once) == once == redactor.redact_text(once)


def test_a_placeholder_inside_a_key_does_not_shelter_the_rest_of_the_key() -> None:
    placeholder = "[redacted:email:0123456789ab]"
    block = f"{_BEGIN}\n{_PEM_BODY}\n{placeholder}\n{_PEM_BODY}\n{_END}"

    redacted = _redactor().redact_spans(f"key: {block}")

    assert "MIIE" not in redacted
    assert "PRIVATE" not in redacted
    assert redacted.startswith("key: [redacted:private-key:")
    assert placeholder in redacted


@pytest.mark.parametrize(
    "shield",
    [
        "[redacted:" + _OPENAI.lower() + "]",
        "[redacted:" + "xo" + "xb-1234567890-abcdefghijkl]",
        "[redacted:note:" + _OPENAI.lower() + "]",
    ],
    ids=["secret-as-label", "slack-as-label", "unknown-label"],
)
def test_a_bracket_the_redactor_never_writes_does_not_shield_a_secret(shield: str) -> None:
    redacted = _redactor().redact_spans(f"here {shield} done")

    assert shield not in redacted
    assert "fake" not in redacted.lower().replace("redacted", "")
    assert "abcdefghijkl" not in redacted


@pytest.mark.parametrize(
    "written",
    [
        "[redacted:github-token:0123456789ab]",
        "[redacted:credential]",
        "[redacted:custom-3:0123456789ab]",
        "[redacted:email]",
        "[redacted:query:0123456789ab]",
    ],
)
def test_a_placeholder_the_engine_writes_is_kept_as_written(written: str) -> None:
    assert _redactor().redact_spans(f"seen {written} done") == f"seen {written} done"


def test_matches_that_only_touch_keep_their_own_placeholders() -> None:
    redacted = _redactor().redact_spans(f"{fake_aws_key()}{_BEGIN}")

    assert redacted == _placeholder("aws-key", fake_aws_key()) + _placeholder("private-key", _BEGIN)
