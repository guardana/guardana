from dataclasses import dataclass
from enum import StrEnum

from guardana.core.fingerprint import digest_of


class CredentialKind(StrEnum):
    """What sort of credential a hop presented."""

    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"
    MTLS = "mtls"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class CredentialRef:
    """A credential named, never carried.

    **There is deliberately no field for the value.** A trace can hold a raw bearer
    token, and a type with somewhere to put it would carry it into evidence, a SARIF
    file and a collector envelope. `of_value` digests and discards instead, and the
    digest is enough for the question rules actually ask: *is this the same
    credential as the one on that other hop?*

    An empty `audience` means nobody recorded one. That is the same fact as a token
    whose audience claim was never written down, and a rule that needs an audience
    declines on both rather than inventing a difference between them.
    """

    kind: CredentialKind = CredentialKind.OTHER
    digest: str | None = None
    audience: tuple[str, ...] = ()
    issuer: str | None = None
    subject: str | None = None
    scopes: tuple[str, ...] | None = None
    """Scopes this credential carries. `None` means not recorded, `()` means none."""

    @classmethod
    def of_value(cls, value: str, kind: CredentialKind = CredentialKind.BEARER) -> "CredentialRef":
        """Digest a credential a trace recorded in the clear, and keep only the digest."""
        return cls(kind=kind, digest=digest_of(value))

    def is_same_as(self, other: "CredentialRef") -> bool:
        """Whether these two references are demonstrably the same credential.

        False when either digest is missing, which is the fail-closed direction for
        the one rule that asks: two credentials nobody digested are not evidence of
        a credential being reused, and reporting them as one would turn every
        two-hop trace into a finding.
        """
        return self.digest is not None and self.digest == other.digest


@dataclass(frozen=True, slots=True)
class SessionRef:
    """A session id — which is not an identity, and is a separate type so it cannot become one.

    The MCP specification forbids sessions as authentication in a sentence, and a
    model that let a session id sit in a `credential` field would have made the
    forbidden thing unrepresentable as a defect.
    """

    id: str
    protocol: str | None = None


@dataclass(frozen=True, slots=True)
class Identity:
    """Who a step acted as: three claims that can disagree, and a session that is not one.

    - `credential` — what the caller presented, and what its token claims.
    - `claimed_resource` — what the callee says it is.
    - `session` — which connection this was, and nothing more than that.

    The interesting failures are exactly where the first two diverge, which is why
    they are separate fields rather than one `credential` string. See
    `docs/design/mcp-authorization-depth.md`.
    """

    actor: str | None = None
    credential: CredentialRef | None = None
    claimed_resource: str | None = None
    session: SessionRef | None = None

    @property
    def is_session_only(self) -> bool:
        """Whether this step identified itself with a session and nothing else."""
        return self.session is not None and self.credential is None


@dataclass(frozen=True, slots=True)
class Delegation:
    """One hop of authority: who acted, on whose behalf, across which boundary, with what.

    Direction and boundary are both fields because the failure they describe needs
    both. A credential that arrives at an agent and leaves it unchanged toward an
    upstream API is token passthrough — and a model with one credential per call
    cannot say that the two are the same one.
    """

    actor: str
    boundary: str
    on_behalf_of: str | None = None
    credential: CredentialRef | None = None
    scopes: tuple[str, ...] | None = None
    """Scopes exercised on this hop. `None` means not recorded, `()` means none."""
