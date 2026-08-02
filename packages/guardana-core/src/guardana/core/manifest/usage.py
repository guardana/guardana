"""What a run consumed, as the manifest records it.

Field names follow the OpenTelemetry GenAI semantic conventions
(`gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`) minus the namespace,
so a team already collecting those does not have to translate ours.

The per-request and per-target shapes live in `guardana.core.usage`, next to the
meter that produces them: a target has to be able to count without importing the
document format its numbers eventually land in.
"""

from dataclasses import dataclass


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
