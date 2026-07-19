from collections.abc import Callable

from guardana.core.target import ChatTransport, EndpointTarget

transport_factory: Callable[[], ChatTransport] | None = None
"""The single transport seam: when set, its product backs every endpoint the CLI builds.

Tests substitute a fake transport here; production leaves it None so `EndpointTarget`
uses its real network transport.
"""


def build_endpoint(
    url: str,
    model: str,
    *,
    api_key: str | None = None,
    system_prompt: str | None = None,
    provider: str = "openai",
) -> EndpointTarget:
    """Construct the `EndpointTarget` a probe or monitor run talks to."""
    transport = transport_factory() if transport_factory is not None else None
    return EndpointTarget(
        url,
        model,
        api_key=api_key,
        system_prompt=system_prompt,
        provider=provider,
        transport=transport,
    )
