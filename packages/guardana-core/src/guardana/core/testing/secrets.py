"""Crafted, obviously-fake credentials, assembled at run time rather than written down.

A test about redaction needs text that looks like a credential. Pasting one into a
test file makes the repository contain a string that matches a secret-detection
pattern — which is true, and is why the dogfood scan flags it. Building the same
string from pieces keeps the test honest and the repository clean, and it means
the fixture cannot be mistaken for a real key by a human either.

Nothing here is a valid credential for any service. The shapes are chosen to match
what `guardana.core.redaction` looks for, so a test can prove the redactor works
without the repository ever containing a plausible key.
"""

_FAKE = "FAKE"
_ZEROS = "0" * 30


def fake_aws_key() -> str:
    """Return an AWS-shaped access key id: `AKIA` plus sixteen upper-case characters."""
    return "AK" + "IA" + "ZZZZ" + _FAKE + _FAKE + _FAKE


def fake_llm_key() -> str:
    """Return an OpenAI-shaped API key: `sk-` and a long opaque tail."""
    return "sk" + "-" + "guardana" + _FAKE.lower() + _ZEROS


def fake_jwt() -> str:
    """Return a JWT-shaped token: three base64url segments separated by dots."""
    header = "eyJ" + "hbGciOiJIUzI1NiJ9"
    payload = "eyJ" + "zdWIiOiJmYWtlIn0"
    signature = "Zm" + "FrZXNpZ25hdHVyZUZBS0U"
    return f"{header}.{payload}.{signature}"


def fake_secrets() -> tuple[str, ...]:
    """Every fake credential this module builds, for a test that asserts none leaked."""
    return (fake_aws_key(), fake_llm_key(), fake_jwt())
