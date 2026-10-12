"""A profile's redaction pattern runs within a time and a size bound; missing either withholds.

A custom pattern is the operator's regex applied to the target's text, so one that
backtracks catastrophically would otherwise stall the run after every check had finished.
It runs in the regex worker process, killed at the bound; a bound hit raises, so the text
it was meant to clean is never released as it was.
"""

import threading
from collections.abc import Callable

import pytest
from guardana.core import redaction
from guardana.core.redaction import (
    EvidenceMode,
    EvidenceRedactor,
    RedactionBoundError,
    RedactionPolicy,
)
from guardana.core.testing import fake_aws_key

_GRACE_SECONDS = 20
_SHORT_BOUND = 0.3
_BACKTRACKS = "(a+)+$"
_RUNAWAY = "a" * 24 + "!"
"""Seconds of backtracking for `(a+)+$`, many times the bound.

Long enough that only a killed search ends within the bound, short enough that matching on
the test's own thread, which holds the interpreter lock throughout, still ends.
"""


def _redactor(*patterns: str) -> EvidenceRedactor:
    return EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED, custom_patterns=patterns))


def _within_grace(call: Callable[[], str]) -> list[object]:
    """Run `call` on a thread, so a worker that never answers fails the test, not hangs it."""
    outcome: list[object] = []

    def run() -> None:
        try:
            outcome.append(call())
        except Exception as exc:
            outcome.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(_GRACE_SECONDS)
    assert not worker.is_alive(), "custom pattern matching is still running"
    return outcome


@pytest.fixture
def short_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redaction, "CUSTOM_PATTERN_TIMEOUT_SECONDS", _SHORT_BOUND)


@pytest.mark.usefixtures("short_bound")
def test_a_custom_pattern_that_backtracks_without_end_raises_rather_than_hangs() -> None:
    outcome = _within_grace(lambda: _redactor(_BACKTRACKS).redact_text(_RUNAWAY))

    assert len(outcome) == 1
    assert isinstance(outcome[0], RedactionBoundError)
    assert outcome[0].pattern == "custom_patterns[0]"
    assert outcome[0].failure == f"did not finish within {_SHORT_BOUND:g} s on one text"
    assert _RUNAWAY not in str(outcome[0]), "the refusal must not quote the text it withholds"


@pytest.mark.usefixtures("short_bound")
def test_a_bound_hit_on_a_name_raises_too_never_returns_the_name_as_given() -> None:
    outcome = _within_grace(lambda: _redactor(_BACKTRACKS).redact_spans(_RUNAWAY))

    assert len(outcome) == 1
    assert isinstance(outcome[0], RedactionBoundError)


def test_text_over_the_size_bound_raises_before_any_matching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(redaction, "MAX_CUSTOM_PATTERN_CHARS", 16)

    with pytest.raises(RedactionBoundError, match="16-character"):
        _redactor("secret").redact_text("x" * 17)


def test_a_custom_pattern_still_redacts_what_it_matches() -> None:
    redacted = _redactor(r"ACME-\d{4}").redact_text("ticket ACME-1234 and ACME-5678 closed")

    assert "ACME-1234" not in redacted
    assert "ACME-5678" not in redacted
    assert redacted.count("[redacted:custom-0:") == 2
    assert redacted.startswith("ticket ")


def test_a_custom_value_group_colliding_with_a_secret_keeps_the_secrets_label() -> None:
    key = fake_aws_key()
    redacted = _redactor(r"key (?P<value>AKIA\w+)").redact_text(f"key {key}")

    assert key not in redacted
    assert "[redacted:aws-key:" in redacted
    assert "custom-0" not in redacted


def test_text_without_a_match_comes_back_unchanged() -> None:
    assert _redactor(r"ACME-\d{4}").redact_text("nothing to see") == "nothing to see"


def test_an_optional_value_group_that_did_not_match_claims_the_whole_match() -> None:
    key = fake_aws_key()
    redacted = _redactor(r"ACME (?P<value>z)?\S+").redact_text(f"ACME {key}SECRETTAIL end")

    assert key not in redacted
    assert "SECRETTAIL" not in redacted
    assert redacted.endswith(" end")
