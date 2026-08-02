"""What settings produced this result, what limits it ran under, what it stored."""

from dataclasses import dataclass
from enum import StrEnum


@dataclass(frozen=True, slots=True)
class ConfigurationRef:
    """The configuration behind a run, by digest rather than by content.

    Digests, not contents, and deliberately. A manifest is an evidence record
    that may leave the machine that produced it, and a system prompt is
    frequently the most sensitive text in a deployment. The digest answers "did
    this change between runs", which is the question a manifest exists to answer;
    storing the prompt itself would answer a question nobody asked and create a
    liability nobody agreed to.
    """

    profile_name: str
    profile_digest: str | None = None
    system_prompt_digest: str | None = None
    tool_manifest_digest: str | None = None
    retriever_digest: str | None = None
    dataset_digest: str | None = None
    adapter_digest: str | None = None


@dataclass(frozen=True, slots=True)
class ExecutionSettings:
    """The limits a run was given, recorded whether or not it hit them.

    Recorded next to what the run actually spent, so a team that lowered a budget
    until the run started ending early can see it in the document rather than
    only in an exit code somebody may have ignored.

    `seed` and `temperature` mirror `gen_ai.request.seed` and
    `gen_ai.request.temperature` in the OpenTelemetry GenAI conventions.

    `concurrency` and `timeout_seconds` are nullable only because a document
    migrated from schema version 1 never recorded them. A run written today
    always knows both.
    """

    concurrency: int | None
    timeout_seconds: int | None
    seed: int | None = None
    temperature: float | None = None
    max_requests: int | None = None
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    max_duration_seconds: float | None = None


class EvidenceMode(StrEnum):
    """How much of what the target said is kept in the evidence."""

    METADATA_ONLY = "metadata_only"
    REDACTED = "redacted"
    FULL = "full"


@dataclass(frozen=True, slots=True)
class PrivacyRecord:
    """What evidence policy was in force when this run was written.

    The default is `FULL` because that is what this build actually does — central
    redaction is designed and not yet built. Defaulting to `REDACTED` would make
    every manifest claim a protection that is not applied, which is worse than
    the missing feature: it would be the report lying about itself. The default
    changes when the redactor lands, not before.
    """

    evidence_mode: EvidenceMode = EvidenceMode.FULL
    redaction_policy_digest: str | None = None
