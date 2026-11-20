"""Whether a chat completions route runs the model for a caller that presents no credential.

A transport sends one request and classifies what came back; a rule decides what the two
answers it asked for mean together. Nothing here holds a reply body or a credential.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from guardana.core.usage import TokenUsage


class AccessAnswer(StrEnum):
    """What one access request got back."""

    COMPLETION = "completion"
    """A chat completion: the route ran the model for this caller."""

    REFUSED = "refused"
    """HTTP 401 or 403: the route refused this caller."""

    UNDECIDED = "undecided"
    """Anything else: a redirect, another status, no answer, or a reply that is not a completion."""


@dataclass(frozen=True, slots=True)
class AccessReply:
    """One access request, classified.

    `reason` says what the route did, worded to follow "the route" ("answered HTTP 503"),
    or, for a request never sent, why not. It names a status or a shape, never the reply.
    """

    answer: AccessAnswer
    status: int | None
    reason: str
    usage: TokenUsage | None = None
    sent: bool = True
    """Whether a request left the runner; False when the check was refused before sending."""
    via_proxy: bool = False
    """Whether the request went through a proxy the runner's environment configures."""


@runtime_checkable
class AccessCheckingTransport(Protocol):
    """A transport that sends one chat completion request and classifies the reply.

    Optional, as `ToolCallingTransport` is: adding it to `ChatTransport` would break every
    transport anyone else has written. A transport implements it only if the request is
    sent once, follows no redirect, and carries no credential at all when `api_key` is
    None: no header, cookie or user part the transport would otherwise add.
    """

    def check_access(self, base_url: str, model: str, api_key: str | None) -> AccessReply:
        """Send one short, non-streaming chat completion request and classify the reply."""
        raise NotImplementedError
