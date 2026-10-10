"""The collector removes recognisable secrets from a submission before it stores one.

An agent redacts what it sends, but anything holding an ingest key can submit, so
`POST /findings` redacts again with the engine's own patterns and placeholder. The
collector cannot import the engine, so the parity tests here are what keep the two
copies of those patterns the same.
"""

import json
import re
from collections.abc import Iterable
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from guardana.core import redaction as engine
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy
from guardana.core.testing import fake_aws_key, fake_github_pat, fake_jwt, fake_llm_key
from guardana.server import create_app
from guardana.server import redaction as collector
from guardana.server.db.migrations import apply_pending
from guardana.server.envelope import MAX_STRING_LENGTH, SCHEMA_VERSION, Submission
from guardana.server.redaction import redact_submission, redact_text
from guardana.server.store import InMemoryStore
from test_historical_envelopes import bearer, serve, tenant

_OK = 200
_UNPROCESSABLE = 422


def _github_token() -> str:
    return "gh" + "p_" + "FAKE" * 5


def _private_key() -> str:
    return "-----BEGIN " + "PRIVATE KEY-----\n" + "FAKE" * 8 + "\n-----END " + "PRIVATE KEY-----"


_SECRETS = (
    fake_llm_key(),
    _github_token(),
    fake_aws_key(),
    fake_github_pat(),
    fake_jwt(),
    "pass" + "word=" + "FAKEFAKEFAKEFAKE",
    _private_key(),
)


def _finding(text: str, identity: str) -> dict[str, Any]:
    return {
        "identity": identity,
        "rule_id": "acme.leaky.rule",
        "severity": "HIGH",
        "title": f"title {text}",
        "taxonomy": [{"framework": "OWASP-LLM", "id": "LLM02", "title": "Sensitive disclosure"}],
        "target_ref": f"configs/{text}/settings.py:12",
        "evidence": {"summary": f"summary {text}", "detail": f"detail {text}"},
        "verdict": {
            "outcome": "fail",
            "confidence": 0.9,
            "rationale": f"rationale {text}",
            "evaluator_id": "llm_judge",
        },
    }


def _envelope(text: str, run_id: str = "run-1") -> dict[str, Any]:
    """A v8 envelope carrying `text` in every free-text field the collector stores."""
    return {
        "schema_version": SCHEMA_VERSION,
        "source": f"https://target#{text}",
        "findings": [_finding(text, "sha256:" + "a" * 64)],
        "unverified": [_finding(text, "sha256:" + "b" * 64)],
        "errors": [{"source": f"acme {text}", "stage": f"run {text}", "reason": f"reason {text}"}],
        "summary": {
            "rules_run": 1,
            "rules_executed": ["acme.leaky.rule"],
            "rules_skipped": [
                {
                    "rule_id": "acme.skipped.rule",
                    "reason": "missing_capability",
                    "missing": ["list_tools", f"capability {text}"],
                }
            ],
            "max_severity": "HIGH",
            "unverified": 1,
            "errors": 1,
        },
        "deployment": {"ai_system": "support", "environment": "prod", "commit_sha": "abc123"},
        "run": {
            "run_id": run_id,
            "started_at": None,
            "completed_at": None,
            "tool_version": "0.9.0",
            "gate": "fail",
            "evidence_mode": "redacted",
            "requests": 1,
            "input_tokens": None,
            "output_tokens": None,
            "wall_time_seconds": 0.5,
        },
    }


def _client() -> TestClient:
    return TestClient(create_app(store=InMemoryStore(), allow_unauthenticated=True))


def test_the_collector_uses_the_engine_s_secret_patterns() -> None:
    def shape(patterns: Iterable[tuple[str, re.Pattern[str]]]) -> list[tuple[str, str, int]]:
        return [(label, pattern.pattern, pattern.flags) for label, pattern in patterns]

    assert shape(collector._SECRET_PATTERNS) == shape(engine._SECRET_PATTERNS)
    assert collector._ALREADY_REDACTED.pattern == engine._ALREADY_REDACTED.pattern


@pytest.mark.parametrize(
    "text",
    [
        f"key {secret} and again {secret}, then {fake_aws_key()}"
        for secret in (*_SECRETS, "[redacted:openai-key:0123456789ab]")
    ]
    + ["nothing secret here", ""],
)
def test_the_collector_writes_the_placeholder_the_engine_writes(text: str) -> None:
    """Byte for byte, so a finding redacted twice reads the same on either side."""
    expected = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.FULL)).redact_spans(text)

    assert redact_text(text) == expected


def test_a_submission_is_stored_without_the_secrets_it_carried() -> None:
    client = _client()
    text = " ".join(_SECRETS)

    assert client.post("/findings", json=_envelope(text)).status_code == _OK
    (stored,) = client.get("/findings").json()

    held = json.dumps(stored)
    for secret in _SECRETS:
        assert secret not in held
    for finding in (*stored["findings"], *stored["unverified"]):
        for value in (
            finding["title"],
            finding["target_ref"],
            finding["evidence"]["summary"],
            finding["evidence"]["detail"],
            finding["verdict"]["rationale"],
        ):
            assert "[redacted:openai-key:" in value
    assert "[redacted:aws-key:" in stored["source"]
    assert "[redacted:private-key:" in stored["errors"][0]["reason"]
    assert "[redacted:github-token:" in stored["errors"][0]["source"]
    assert "[redacted:jwt:" in stored["errors"][0]["stage"]
    (skipped,) = stored["summary"]["rules_skipped"]
    assert skipped["missing"][0] == "list_tools"
    assert "[redacted:aws-key:" in skipped["missing"][1]


def test_redaction_leaves_ids_and_labels_as_sent() -> None:
    client = _client()
    sent = _envelope(" ".join(_SECRETS))

    client.post("/findings", json=sent)
    (stored,) = client.get("/findings").json()

    for channel in ("findings", "unverified"):
        assert stored[channel][0]["identity"] == sent[channel][0]["identity"]
        assert stored[channel][0]["rule_id"] == sent[channel][0]["rule_id"]
        assert stored[channel][0]["taxonomy"] == sent[channel][0]["taxonomy"]
        assert stored[channel][0]["verdict"]["evaluator_id"] == "llm_judge"
    (skipped,) = stored["summary"]["rules_skipped"]
    assert (skipped["rule_id"], skipped["reason"]) == ("acme.skipped.rule", "missing_capability")
    assert stored["run"] == sent["run"]
    assert {**stored["summary"], "rules_skipped": None} == {
        **sent["summary"],
        "rules_skipped": None,
    }
    assert (
        stored["deployment"]
        == Submission.model_validate(sent).model_dump(mode="json")["deployment"]
    )


def test_a_clean_submission_is_stored_exactly_as_sent() -> None:
    """Placeholders an agent already wrote are kept, not redacted a second time."""
    client = _client()
    sent = _envelope("[redacted:openai-key:0123456789ab] and [redacted:credential]")

    client.post("/findings", json=sent)
    (stored,) = client.get("/findings").json()

    assert stored == Submission.model_validate(sent).model_dump(mode="json")


def test_a_clean_submission_is_not_copied() -> None:
    submission = Submission.model_validate(_envelope("nothing secret"))

    assert redact_submission(submission) is submission


def test_a_retried_run_is_still_a_duplicate_after_redaction() -> None:
    client = _client()
    sent = _envelope(" ".join(_SECRETS))

    first = client.post("/findings", json=sent).json()
    second = client.post("/findings", json=sent).json()

    assert (first["duplicate"], second["duplicate"]) == (False, True)
    assert len(client.get("/findings").json()) == 1


def test_a_field_redaction_pushes_past_its_bound_is_refused_and_nothing_is_stored() -> None:
    """A stored value the envelope would refuse could never be read back."""
    client = _client()
    assignment = "token=" + "FAKEFAKEFAKE"
    sent = _envelope("x")
    sent["source"] = (assignment + " ") * (MAX_STRING_LENGTH // (len(assignment) + 1))

    response = client.post("/findings", json=sent)

    assert response.status_code == _UNPROCESSABLE
    assert "nothing was stored" in response.json()["detail"]
    assert client.get("/findings").json() == []


def test_the_durable_store_holds_the_redacted_submission(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
    served = serve(database_url, tenant(database_url), monkeypatch)

    response = served.client.post(
        "/findings", json=_envelope(" ".join(_SECRETS)), headers=bearer(served.token)
    )

    assert response.status_code == _OK, response.text
    (record,) = served.store.records(served.scope)
    held = record.submission.model_dump_json()
    for secret in _SECRETS:
        assert secret not in held
    assert "[redacted:openai-key:" in record.submission.findings[0].evidence.summary
