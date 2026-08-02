"""Who ran this, with what software, against what, on behalf of which deployment."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from guardana.core.target import TargetKind


class SourceKind(StrEnum):
    """How a run was started.

    A laptop run and a pipeline run are different evidence: one is somebody
    looking, the other is a gate that was supposed to hold. A dashboard that
    cannot tell them apart reports a developer's experiment as a deployment
    check.
    """

    LOCAL = "local"
    CI = "ci"
    SCHEDULED = "scheduled"
    IMPORTED_TRACE = "imported_trace"
    REPLAY = "replay"


@dataclass(frozen=True, slots=True)
class RunSource:
    """Where the run came from: a laptop, a pipeline, a schedule, a replay."""

    kind: SourceKind = SourceKind.LOCAL
    provider: str | None = None
    run_url: str | None = None


@dataclass(frozen=True, slots=True)
class ToolInfo:
    """Which software produced this run.

    `distribution_versions` covers the case the single version cannot: a user
    with `guardana-cli` 0.7.0 and a stale `guardana-rules` is running a different
    tool than the version string suggests, and a comparison that blames the model
    for it blames the wrong thing.
    """

    version: str
    commit: str | None = None
    distribution_versions: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TargetIdentity:
    """What was examined, identified as stably as the engine honestly can.

    `fingerprint_inputs` names the fields the fingerprint was computed from, and
    exists so nobody builds a guarantee on it that it does not give. A digest of
    a URL and a model name identifies a *declared* target; it says nothing about
    the weights behind it. Without this field the document would be silent on the
    difference, and silence is how a reader invents the stronger reading.
    """

    kind: TargetKind
    ref: str
    fingerprint: str | None = None
    fingerprint_inputs: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DeploymentRef:
    """Which deployment of which AI system this run verifies.

    Every field is nullable and null means "not known", never "not applicable". A
    laptop run has no commit; a consumer must be able to tell that from a commit
    of all zeroes.
    """

    ai_system: str | None = None
    environment: str | None = None
    deployment_id: str | None = None
    commit_sha: str | None = None
    image_digest: str | None = None
    model_digest: str | None = None
    model_name: str | None = None
    model_revision: str | None = None
