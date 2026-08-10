"""The domain model for an execution Guardana did not conduct.

`Trajectory` is a run Guardana drove: it sent the prompts, offered the tool doubles,
read the replies. `Trace` is the other case — a recording of what actually happened in
somebody's production agent, which nobody can reproduce from outside because the
retrieved documents were whatever the index held that morning and the credential that
reached the third server came from a delegation chain no prompt can recreate.

Two halves, and the split is the design. **Messages with typed content parts, tools,
retrieval, memory and the model call** are what the OpenTelemetry GenAI semantic
conventions carry, so any instrumented framework fills them. **Identity, delegation,
consent, policy decisions, approvals and side effects** are what those conventions
have no field for — and that is where the interesting failures live.

Which makes `Trace.instrumented` the most important field here. A trace records what
an application *chose* to record, so an absent approval has three explanations: none
was sought, the framework does not emit them, or the trace was cut short. Reading the
absence as the first fires on every well-governed system; reading it as the second
passes on the one that skipped it. So a dimension the producer does not record is
stated, and the rules that need it do not run.

**This package is a leaf on purpose.** It imports nothing from `guardana.core.target`,
`guardana.core.report` or `guardana.core.evaluator`, because `TraceTarget` lives in the
target package and importing a trace submodule runs this file — so a dependency back
would be a cycle that only shows up when somebody runs the command. The two adapters
that *do* reach into those layers are deliberately not re-exported here and are
imported from their own modules: `guardana.core.trace.bridge.as_trajectory` and
`guardana.core.trace.claims.claims_of`. A test pins the direction.

See `docs/design/trace-domain-model.md`.
"""

from guardana.core.trace.agent import AgentRef
from guardana.core.trace.authorization import (
    Approval,
    ApprovalOutcome,
    Consent,
    PolicyDecision,
    PolicyOutcome,
)
from guardana.core.trace.content import Blob, ContentPart, PartKind
from guardana.core.trace.coverage import DimensionCoverage, evidence_matrix
from guardana.core.trace.effect import EffectStatus, SideEffect, SinkKind
from guardana.core.trace.handoff import Handoff
from guardana.core.trace.identity import (
    CredentialKind,
    CredentialRef,
    Delegation,
    Identity,
    SessionRef,
)
from guardana.core.trace.limits import MAX_RECORD_BYTES, MAX_SPANS, MAX_TRACE_BYTES
from guardana.core.trace.load import (
    Dialect,
    TraceRead,
    UnreadableRecord,
    detect_dialect,
    read_trace,
)
from guardana.core.trace.memory import MemoryAction, MemoryOperation
from guardana.core.trace.message import Message, Role
from guardana.core.trace.model import (
    TRACE_SCHEMA_VERSION,
    Dimension,
    Provenance,
    Trace,
    TraceTruncation,
)
from guardana.core.trace.observations import (
    OBSERVATIONS_SCHEMA_VERSION,
    ImportedObservation,
    ObservationDialect,
    ObservationRead,
    ObservedOutcome,
    detect_observation_dialect,
    read_observations,
)
from guardana.core.trace.retrieval import Retrieval, RetrievedDocument
from guardana.core.trace.serialize import serialize_trace
from guardana.core.trace.span import ModelCall, Span, SpanKind
from guardana.core.trace.tool import ToolDeclaration, ToolExecution, ToolStatus

from guardana.core.trace._parse import TraceLoadError  # isort: skip — the error the readers raise

__all__ = [
    "MAX_RECORD_BYTES",
    "MAX_SPANS",
    "MAX_TRACE_BYTES",
    "OBSERVATIONS_SCHEMA_VERSION",
    "TRACE_SCHEMA_VERSION",
    "AgentRef",
    "Approval",
    "ApprovalOutcome",
    "Blob",
    "Consent",
    "ContentPart",
    "CredentialKind",
    "CredentialRef",
    "Delegation",
    "Dialect",
    "Dimension",
    "DimensionCoverage",
    "EffectStatus",
    "Handoff",
    "Identity",
    "ImportedObservation",
    "MemoryAction",
    "MemoryOperation",
    "Message",
    "ModelCall",
    "ObservationDialect",
    "ObservationRead",
    "ObservedOutcome",
    "PartKind",
    "PolicyDecision",
    "PolicyOutcome",
    "Provenance",
    "Retrieval",
    "RetrievedDocument",
    "Role",
    "SessionRef",
    "SideEffect",
    "SinkKind",
    "Span",
    "SpanKind",
    "ToolDeclaration",
    "ToolExecution",
    "ToolStatus",
    "Trace",
    "TraceLoadError",
    "TraceRead",
    "TraceTruncation",
    "UnreadableRecord",
    "detect_dialect",
    "detect_observation_dialect",
    "evidence_matrix",
    "read_observations",
    "read_trace",
    "serialize_trace",
]
