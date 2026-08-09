from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from guardana.core.trace.agent import AgentRef
from guardana.core.trace.authorization import Approval, Consent, PolicyDecision
from guardana.core.trace.content import ContentPart
from guardana.core.trace.effect import EffectStatus, SideEffect
from guardana.core.trace.handoff import Handoff
from guardana.core.trace.identity import Delegation, Identity
from guardana.core.trace.memory import MemoryOperation
from guardana.core.trace.message import Message
from guardana.core.trace.retrieval import Retrieval
from guardana.core.trace.tool import ToolDeclaration, ToolExecution


class SpanKind(StrEnum):
    """What one step of an execution was.

    Named after what the step *did*, and deliberately close to
    `gen_ai.operation.name` so a mapping from the OpenTelemetry conventions is a
    lookup rather than an interpretation. `OTHER` keeps a step this build does not
    recognise in the trace, because a step nobody classified still happened.
    """

    MODEL_CALL = "model_call"
    TOOL_EXECUTION = "tool_execution"
    AGENT_INVOCATION = "agent_invocation"
    RETRIEVAL = "retrieval"
    MEMORY = "memory"
    HANDOFF = "handoff"
    EMBEDDINGS = "embeddings"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class ModelCall:
    """What a model call asked for and what it cost, as the producer recorded it."""

    provider: str | None = None
    request_model: str | None = None
    response_model: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    finish_reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Span:
    """One step of a recorded execution, with the domain content hanging off it.

    Two halves, and the split is the point. The first — messages, tools, retrieval,
    memory, the model call — is what the OpenTelemetry GenAI conventions carry, so a
    trace exported from any instrumented framework fills it. The second — identity,
    delegations, consents, policy decisions, approvals, effects — is what those
    conventions have no field for, which is why an OTel-only trace leaves it empty
    and why "empty" must never be read as "nothing happened".

    There is no `attributes: dict` escape hatch, on purpose. It would make every
    later mapping easy and the 1.0 freeze meaningless: a framework's quirk would land
    in a bag instead of forcing the question of whether the model is missing
    something.
    """

    span_id: str
    kind: SpanKind
    name: str
    parent_span_id: str | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    error: str | None = None
    # what the conventions carry
    agent: AgentRef | None = None
    model: ModelCall | None = None
    messages: tuple[Message, ...] = ()
    system_instructions: tuple[ContentPart, ...] = ()
    tool_offers: tuple[ToolDeclaration, ...] = ()
    tool: ToolExecution | None = None
    retrieval: Retrieval | None = None
    memory: MemoryOperation | None = None
    handoff: Handoff | None = None
    conversation_id: str | None = None
    # what they do not
    identity: Identity | None = None
    delegations: tuple[Delegation, ...] = ()
    consents: tuple[Consent, ...] = ()
    policy_decisions: tuple[PolicyDecision, ...] = ()
    approvals: tuple[Approval, ...] = ()
    effects: tuple[SideEffect, ...] = ()

    def executed_effects(self) -> tuple[SideEffect, ...]:
        """Effects that demonstrably happened — never the ones that were merely attempted."""
        return tuple(e for e in self.effects if e.status is EffectStatus.EXECUTED)

    def changes_something(self) -> bool:
        """Whether this step demonstrably altered anything outside the conversation.

        Deliberately conservative: an executed effect, or a tool the producer stated
        mutates. A tool whose `mutates` is unknown does not count, because guessing
        from a name ("delete_user" surely writes) would put a rule's verdict on a
        heuristic nobody measured.
        """
        return bool(self.executed_effects()) or (
            self.tool is not None and self.tool.mutates is True
        )

    def credentialed_delegations(self) -> tuple[Delegation, ...]:
        """Return the delegations carrying a credential this build can compare against another."""
        return tuple(
            d for d in self.delegations if d.credential is not None and d.credential.digest
        )

    def render(self) -> str:
        """Render this step as readable lines — the evidence a human reads on a finding."""
        actor = f" by {self.agent.describe()}" if self.agent is not None else ""
        lines = [f"[{self.span_id}] {self.kind}: {self.name}{actor}"]
        lines.extend(f"  {m.render()}" for m in self.messages)
        if self.tool is not None:
            lines.append(
                f"  tool {self.tool.name}({self.tool.arguments or ''}) → {self.tool.status}"
            )
        if self.retrieval is not None:
            lines.append(
                f"  retrieved {len(self.retrieval.documents)} document(s) from "
                f"{self.retrieval.source or 'an unnamed source'}"
            )
        if self.memory is not None:
            lines.append(f"  memory {self.memory.action} on {self.memory.store or 'a store'}")
        if self.handoff is not None:
            lines.append(f"  handoff {self.handoff.from_agent} → {self.handoff.to_agent}")
        lines.extend(f"  effect {e.describe()}" for e in self.effects)
        lines.extend(
            f"  policy {d.policy or 'unnamed'} → {d.outcome} on {d.action}"
            for d in self.policy_decisions
        )
        lines.extend(f"  approval {a.action} → {a.outcome}" for a in self.approvals)
        if self.error:
            lines.append(f"  error: {self.error}")
        return "\n".join(lines)
