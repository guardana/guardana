from collections.abc import Callable

from guardana.core.target import ChatTransport, EndpointTarget

transport_factory: Callable[[], ChatTransport] | None = None
"""The single transport seam: when set, its product backs every endpoint the CLI builds.

Tests substitute a fake transport here; production leaves it None so `EndpointTarget`
uses its real network transport.
"""


def build_endpoint(  # noqa: PLR0913 — each is a distinct endpoint config knob, keyword-only
    url: str,
    model: str,
    *,
    api_key: str | None = None,
    system_prompt: str | None = None,
    provider: str = "openai",
    transport: ChatTransport | None = None,
) -> EndpointTarget:
    """Construct the `EndpointTarget` a probe or monitor run talks to.

    An explicit `transport` (e.g. a custom-endpoint adapter) wins; otherwise the
    test seam `transport_factory` is used if set; otherwise `EndpointTarget` builds
    its real network transport for the named provider.
    """
    if transport is None and transport_factory is not None:
        transport = transport_factory()
    return EndpointTarget(
        url,
        model,
        api_key=api_key,
        system_prompt=system_prompt,
        provider=provider,
        transport=transport,
    )
