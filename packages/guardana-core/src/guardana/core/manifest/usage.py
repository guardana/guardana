"""What a run actually consumed — and, just as importantly, what it could not know.

Field names follow the OpenTelemetry GenAI semantic conventions
(`gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`) minus the namespace,
so a team already collecting those does not have to translate ours.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """What one request cost in tokens, as the provider reported it.

    Both fields are nullable because providers disagree about what they return —
    the same reason NVIDIA's garak closed its token-tracking request as not
    planned ("output token counts are entirely target specific"). A provider that
    reports neither gives `None` twice, and that is recorded rather than rounded
    to zero.
    """

    input_tokens: int | None = None
    output_tokens: int | None = None


@dataclass(frozen=True, slots=True)
class TargetUsage:
    """What one target spent. Returned by targets that meter themselves.

    `requests` is a plain integer here, not nullable: a target that returns this
    object at all is claiming it counts. A target that does not count returns
    `None` from `Target.usage()` instead, which is a different statement.

    `requests_missing_token_counts` is what keeps a partial sum honest. Ten
    requests where three reported tokens would otherwise present those three as
    the whole bill.
    """

    requests: int = 0
    input_tokens: int | None = None
    output_tokens: int | None = None
    requests_missing_token_counts: int = 0


@dataclass(frozen=True, slots=True)
class RunUsage:
    """What the whole run spent, as far as anyone could tell.

    Every field defaults to `None`, and that default is the point. A run against
    a target that does not meter itself must not look like a run that cost
    nothing — "nobody counted" and "it was free" are different facts, and only
    one of them lets a team set next month's budget.

    `estimated_cost` stays `None` until a price table exists as profile data.
    Guardana does not ship provider prices: the engine knows no vendor, and an
    invented cost is worse than no cost.
    """

    requests: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    requests_missing_token_counts: int | None = None
    estimated_cost: float | None = None
    wall_time_seconds: float | None = None
