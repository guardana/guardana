"""Which dimensions a span actually carries — one table, read from both ends.

The reader derives a producer's coverage from this when a header declares none. The
writer holds a header's declaration against it. They have to be the same table: a
writer that refused a block the reader would not have counted, or accepted one it
would have dropped, is two builds disagreeing about what a file says.
"""

from collections.abc import Callable

from guardana.core.trace.model import Dimension
from guardana.core.trace.span import Span


def dimensions_of(span: Span) -> frozenset[Dimension]:
    """Name the dimensions this one span records."""
    return frozenset(dimension for dimension, present in _PRESENCE if present(span))


def dimensions_present(spans: list[Span]) -> frozenset[Dimension]:
    """Work out what a producer records from what it actually recorded.

    Presence implies instrumentation; absence never implies anything. That asymmetry
    is the whole point: derivation can only ever *reduce* what runs.
    """
    return frozenset(
        dimension for dimension, present in _PRESENCE for span in spans if present(span)
    )


def _records_identity(span: Span) -> bool:
    """Whether this span records an identity — which a session id alone does not.

    The one derivation worth its own function, because it is the trap. An
    OpenTelemetry MCP span carries `mcp.session.id` and nothing else identity-shaped,
    and treating that as identity coverage would let the session-as-authentication rule
    accuse a properly authenticated deployment of the thing its instrumentation simply
    never mentioned.
    """
    identity = span.identity
    return identity is not None and (
        identity.credential is not None or identity.claimed_resource is not None
    )


_PRESENCE: tuple[tuple[Dimension, Callable[[Span], bool]], ...] = (
    (Dimension.MESSAGES, lambda s: bool(s.messages or s.system_instructions)),
    (Dimension.TOOLS, lambda s: s.tool is not None or bool(s.tool_offers)),
    (Dimension.RETRIEVAL, lambda s: s.retrieval is not None),
    (Dimension.MEMORY, lambda s: s.memory is not None),
    (Dimension.HANDOFF, lambda s: s.handoff is not None),
    (Dimension.IDENTITY, _records_identity),
    (Dimension.DELEGATION, lambda s: bool(s.delegations)),
    (Dimension.CONSENT, lambda s: bool(s.consents)),
    (Dimension.POLICY, lambda s: bool(s.policy_decisions)),
    (Dimension.APPROVAL, lambda s: bool(s.approvals)),
    (Dimension.EFFECTS, lambda s: bool(s.effects)),
)
