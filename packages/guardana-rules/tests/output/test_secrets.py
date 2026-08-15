from collections.abc import Sequence

from guardana.core.rule import RuleContext
from guardana.core.target.endpoint import ChatMessage, EndpointTarget
from guardana.rules.output.secrets import OutputSecretsRule

# A realistic (fabricated) key shape — deliberately NOT the allowlisted AWS
# docs example key. Assembled at runtime so Guardana's own hardcoded_secret
# file scan never sees the full pattern in this test's source.
_RAW_AWS_KEY = "AKIA" + "IOSFODNN7RE4LKEY"
_EXAMPLE_AWS_KEY = "AKIAIOSFODNN7" + "EXAMPLE"


class _LeaksKey:
    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        return f"Here is the key: {_RAW_AWS_KEY}"


class _EchoesDocsExample:
    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        return f"AWS docs use {_EXAMPLE_AWS_KEY} as the canonical example."


class _LeaksPrivateKey:
    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        return (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
            "-----END PRIVATE KEY-----"
        )


class _Clean:
    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        return "The water cycle is evaporation, condensation, precipitation."


class _LeaksGitSha:
    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        return "The fix landed in commit a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 yesterday."


def test_flags_aws_key_in_output() -> None:
    target = EndpointTarget("http://x", "m", transport=_LeaksKey())
    findings = list(OutputSecretsRule().run(target, RuleContext()))

    assert findings
    assert any("AKIA" in f.evidence.summary or "AWS" in f.title for f in findings)
    assert all(_RAW_AWS_KEY not in f.evidence.summary for f in findings)
    assert all(_RAW_AWS_KEY not in f.evidence.detail for f in findings)


def test_flags_private_key_header() -> None:
    target = EndpointTarget("http://x", "m", transport=_LeaksPrivateKey())
    findings = list(OutputSecretsRule().run(target, RuleContext()))

    assert any("private key" in f.evidence.summary.lower() for f in findings)


def test_clean_output_no_findings() -> None:
    target = EndpointTarget("http://x", "m", transport=_Clean())
    findings = list(OutputSecretsRule().run(target, RuleContext()))

    assert findings == []


class _SaysNothing:
    """A model that answers every prompt with an empty message.

    Not hypothetical: an Azure content filter returns exactly this, and so does a
    rate-limited gateway. `Exchange.reply_text` already treats a blank turn as
    silence for every evaluator; this rule reads the raw string and never asked.
    """

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        return ""


def test_a_reply_that_never_arrived_is_unverified_not_a_clean_output() -> None:
    """ "No secret in the output" needs an output. Nothing was inspected here."""
    target = EndpointTarget("http://x", "m", transport=_SaysNothing())

    findings = list(OutputSecretsRule().run(target, RuleContext()))

    assert findings
    assert all(f.verdict is not None and f.verdict.outcome == "inconclusive" for f in findings)


def test_git_sha_not_flagged() -> None:
    target = EndpointTarget("http://x", "m", transport=_LeaksGitSha())
    findings = list(OutputSecretsRule().run(target, RuleContext()))

    assert findings == []


def test_public_example_key_not_flagged() -> None:
    # A reply quoting AWS's documented example key is citation, not leakage —
    # same allowlist policy as the hardcoded_secret file scan (no theater).
    target = EndpointTarget("http://x", "m", transport=_EchoesDocsExample())
    findings = list(OutputSecretsRule().run(target, RuleContext()))

    assert findings == []
