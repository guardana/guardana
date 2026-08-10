"""The five things an application can assert about its own recorded executions.

Each kind is deterministic, offline, and provable from what the domain model
already carries — no kind here needs a field `Trace` does not have. What a kind
*does* need is a dimension, and that is the hinge this whole release turns on: an
assertion whose dimension the producer never records is unverifiable, and an
unverifiable assertion is `indeterminate` rather than either verdict.

See `docs/design/security-contracts.md`.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum

from guardana.core.severity import Severity
from guardana.core.trace.effect import EffectStatus
from guardana.core.trace.model import Dimension


class AssertionKind(StrEnum):
    """What an assertion checks.

    A closed list, for the reason `Capability` and `SinkKind` are closed: an
    unknown kind read leniently would be an invariant the team wrote down and
    nothing ever checked, which is the quietest way a security control stops
    existing.
    """

    TENANT_BOUNDARY = "tenant_boundary"
    APPROVAL_REQUIRED = "approval_required"
    ALLOWED_SCOPES = "allowed_scopes"
    CREDENTIAL_BOUNDARY = "credential_boundary"
    FORBIDDEN_SINK = "forbidden_sink"


_KIND_DIMENSIONS: dict[AssertionKind, tuple[Dimension, ...]] = {
    AssertionKind.TENANT_BOUNDARY: (Dimension.RETRIEVAL,),
    AssertionKind.APPROVAL_REQUIRED: (Dimension.APPROVAL, Dimension.EFFECTS),
    AssertionKind.ALLOWED_SCOPES: (Dimension.DELEGATION,),
    AssertionKind.CREDENTIAL_BOUNDARY: (Dimension.DELEGATION,),
    AssertionKind.FORBIDDEN_SINK: (Dimension.EFFECTS,),
}
"""Which evidence each kind needs before it can conclude anything.

**One table, read from two directions**, and that is deliberate. The compiler turns
it into the rule's `required_capabilities`, so an assertion whose dimension is
missing is skipped rather than run against nothing. The gate turns it into a
required-evidence set, so the same absence makes the run `indeterminate` instead of
letting the skip pass quietly at the default `fail_on_skipped: false`. Two tables
would eventually disagree, and the disagreement would be an assertion that is
skipped *and* reported clean.
"""


def dimensions_for(kind: AssertionKind) -> tuple[Dimension, ...]:
    """Which dimensions an assertion of this kind needs recorded to reach a verdict."""
    return _KIND_DIMENSIONS[kind]


@dataclass(frozen=True, slots=True, kw_only=True)
class Assertion(ABC):
    """One invariant an application states about itself.

    `severity` is the team's own judgement and is not defaulted per kind: how bad a
    crossed tenant boundary is depends on whose data is on the other side, which is
    exactly the knowledge a generic scanner does not have and this document does.
    """

    id: str
    title: str
    severity: Severity

    @property
    @abstractmethod
    def kind(self) -> AssertionKind:
        """Which kind this is — the value the document's `type:` named."""

    @property
    def dimensions(self) -> tuple[Dimension, ...]:
        """Which dimensions must be recorded for this assertion to be checkable at all."""
        return dimensions_for(self.kind)

    @abstractmethod
    def parameters(self) -> tuple[tuple[str, str], ...]:
        """Report this assertion's own settings, as sorted name/value pairs.

        Feeds the compiled rule's digest, so editing an allow-list is visible in
        `diff` as a changed test rather than as a target that improved. A kind that
        forgot to report a parameter here would let a weakened contract read as the
        contract it replaced.
        """


@dataclass(frozen=True, slots=True, kw_only=True)
class TenantBoundary(Assertion):
    """One execution serves one tenant, and every document it read belongs to that tenant.

    Deliberately wider than `guardana.trace.cross_tenant_retrieval`, which compares
    one retrieval against the documents that retrieval returned. An agent that
    retrieves for tenant A and then for tenant B in the same run breaks no single
    retrieval and is invisible to the built-in; whether that is allowed is a fact
    about the application, which is why it is stated here rather than assumed there.
    """

    sources: tuple[str, ...] = ()
    """Globs limiting which stores this governs. Empty means every retrieval in the run."""

    @property
    def kind(self) -> AssertionKind:
        """Identify this assertion as a tenant boundary."""
        return AssertionKind.TENANT_BOUNDARY

    def parameters(self) -> tuple[tuple[str, str], ...]:
        """Report the source globs this boundary is scoped to."""
        return (("sources", ",".join(self.sources)),)


@dataclass(frozen=True, slots=True, kw_only=True)
class ApprovalRequired(Assertion):
    """An action matching these selectors happened only after an approval was *granted*.

    Granted, not merely recorded: `denied`, `timed_out` and `not_requested` are all
    the absence of authority, and a check that accepted any approval record would
    pass an execution that went ahead after a refusal.
    """

    actions: tuple[str, ...] = ()
    """Globs matched against a side effect's action. Empty means every action in scope."""

    sinks: tuple[str, ...] = ()
    """Sink names this applies to. Empty means every sink."""

    approvers: tuple[str, ...] = ()
    """Globs the approver must match. Empty accepts any approver the producer recorded."""

    @property
    def kind(self) -> AssertionKind:
        """Identify this assertion as an approval requirement."""
        return AssertionKind.APPROVAL_REQUIRED

    def parameters(self) -> tuple[tuple[str, str], ...]:
        """Report the action, sink and approver selectors this requirement is scoped to."""
        return (
            ("actions", ",".join(self.actions)),
            ("approvers", ",".join(self.approvers)),
            ("sinks", ",".join(self.sinks)),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class AllowedScopes(Assertion):
    """A hop across a named boundary exercised only scopes on the allow list.

    An allow list rather than a deny list, because the failure this catches is a
    scope nobody anticipated — and a deny list cannot name what nobody anticipated.
    """

    boundaries: tuple[str, ...] = ()
    """Globs selecting which delegation boundaries this governs. Empty means all of them."""

    allow: tuple[str, ...] = ()
    """The scopes permitted on those hops. Globs, so `payments.*` is expressible."""

    @property
    def kind(self) -> AssertionKind:
        """Identify this assertion as a scope allow-list."""
        return AssertionKind.ALLOWED_SCOPES

    def parameters(self) -> tuple[tuple[str, str], ...]:
        """Report the boundaries governed and the scopes permitted on them."""
        return (("allow", ",".join(self.allow)), ("boundaries", ",".join(self.boundaries)))


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialBoundary(Assertion):
    """A named boundary never received a credential at all.

    The strongest statement an application can make about a hop, and the cheapest
    to prove: the question is whether a credential is present, not which one. A
    boundary that must receive *no* credential is how "this agent talks to the
    public internet" is expressed, and a token that reaches it is a finding whether
    or not anybody can say where it came from.
    """

    boundaries: tuple[str, ...] = ()
    """Globs naming the boundaries that must stay credential-free. Never empty."""

    @property
    def kind(self) -> AssertionKind:
        """Identify this assertion as a credential boundary."""
        return AssertionKind.CREDENTIAL_BOUNDARY

    def parameters(self) -> tuple[tuple[str, str], ...]:
        """Report which boundaries must never carry a credential."""
        return (("boundaries", ",".join(self.boundaries)),)


@dataclass(frozen=True, slots=True, kw_only=True)
class ForbiddenSink(Assertion):
    """No side effect of this application landed on a sink it forbids.

    `attempted` counts by default alongside `executed`. An agent that tried to open
    a shell and was stopped is still an agent that tried, and a contract saying
    "never shell" is violated by the attempt. `failed` is off by default because a
    failure is the system refusing — reporting it would turn every working guardrail
    into a finding.
    """

    sinks: tuple[str, ...] = ()
    """Sink names that are off-limits. Never empty."""

    actions: tuple[str, ...] = ()
    """Globs narrowing which actions on those sinks are forbidden. Empty means all."""

    statuses: tuple[EffectStatus, ...] = (EffectStatus.EXECUTED, EffectStatus.ATTEMPTED)
    """Which effect statuses count as a violation."""

    @property
    def kind(self) -> AssertionKind:
        """Identify this assertion as a forbidden sink."""
        return AssertionKind.FORBIDDEN_SINK

    def parameters(self) -> tuple[tuple[str, str], ...]:
        """Report the sinks forbidden, the actions narrowed to, and the statuses that count."""
        return (
            ("actions", ",".join(self.actions)),
            ("sinks", ",".join(self.sinks)),
            ("statuses", ",".join(sorted(str(s) for s in self.statuses))),
        )
