"""The secret patterns are the heart of a security tool: a missed modern key is
a silent failure. These pin the shapes that matter most in AI repos."""

import re

import pytest
from guardana.rules._secrets import (
    ALLOWLIST,
    FILE_SECRET_PATTERNS,
    REPLY_SECRET_PATTERNS,
)


def _match(patterns: tuple[tuple[str, re.Pattern[str]], ...], text: str) -> str | None:
    for label, pattern in patterns:
        if pattern.search(text):
            return label
    return None


# Fabricated but structurally-real key shapes. Assembled from fragments so this
# test file never trips Guardana's own hardcoded_secret scan.
_MODERN_KEYS = [
    ("OpenAI project key", "sk-proj-" + "a" * 48),
    ("OpenAI service-account key", "sk-svcacct-" + "b" * 48),
    ("Anthropic API key", "sk-ant-api03-" + "c" * 40),
    ("legacy OpenAI key", "sk-" + "d" * 32),
    ("GitHub OAuth token", "gho_" + "e" * 36),
    ("GitHub user-to-server token", "ghu_" + "f" * 36),
    ("GitHub server-to-server token", "ghs_" + "0" * 36),
    ("AWS access key ID", "AKIA" + "1" * 16),
]


@pytest.mark.parametrize(("what", "key"), _MODERN_KEYS, ids=[k[0] for k in _MODERN_KEYS])
def test_modern_keys_are_detected_in_a_reply(what: str, key: str) -> None:
    assert _match(REPLY_SECRET_PATTERNS, f"the key is {key}") is not None, what


@pytest.mark.parametrize(("what", "key"), _MODERN_KEYS, ids=[k[0] for k in _MODERN_KEYS])
def test_modern_keys_are_detected_in_a_file(what: str, key: str) -> None:
    assert _match(FILE_SECRET_PATTERNS, f"API_KEY = '{key}'") is not None, what


@pytest.mark.parametrize(
    "header",
    [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ],
)
def test_private_key_variants_are_detected_in_a_reply(header: str) -> None:
    assert _match(REPLY_SECRET_PATTERNS, header) == "private key header"


def test_a_normal_sentence_is_not_flagged() -> None:
    text = "The commit sk-ipped the tests and the ghost wrote no docs."
    assert _match(REPLY_SECRET_PATTERNS, text) is None
    assert _match(FILE_SECRET_PATTERNS, text) is None


def test_a_long_kebab_slug_is_not_mistaken_for_an_llm_key() -> None:
    # A real OpenAI/Anthropic key body is alphanumeric; a hyphenated identifier
    # (config slug, cache key, header name) is not a secret. Matching one is the
    # false positive the module's "precision over recall" promise rules out.
    slug = "sk-this-is-a-very-long-kebab-slug-name"
    assert _match(REPLY_SECRET_PATTERNS, slug) is None
    assert _match(FILE_SECRET_PATTERNS, slug) is None


def test_every_allowlist_entry_is_matchable_by_some_pattern() -> None:
    # A dead allowlist entry (one no pattern can ever emit) is a sign the two
    # were never checked against each other.
    for example in ALLOWLIST:
        assert _match(FILE_SECRET_PATTERNS, example) is not None, example
