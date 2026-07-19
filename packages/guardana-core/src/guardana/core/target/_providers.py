"""Named chat transports for self-hosted backends, selected by provider name.

The default `openai` transport (`UrllibTransport`) already covers any
OpenAI-compatible server — vLLM, llamafile, Ollama's `/v1`. These reach the two
backends that speak their own wire shape instead: Ollama's native `/api/chat`
and Hugging Face TGI's `/generate`. A provider is simply *which* `ChatTransport`
an `EndpointTarget` uses — no new entry-point group; a genuinely custom backend
still ships a `Target` through `guardana.targets`.
"""

from collections.abc import Callable, Sequence

from guardana.core.target.endpoint import (
    ChatMessage,
    ChatTransport,
    EndpointError,
    UrllibTransport,
    post_json,
)


class OllamaTransport:
    """POSTs to Ollama's native `/api/chat` (non-streaming)."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """POST an Ollama chat request and return the reply text."""
        ref = f"{base_url}#{model}"
        payload = post_json(
            f"{base_url}/api/chat",
            {
                "model": model,
                "messages": [{"role": m.role, "content": m.content} for m in messages],
                "stream": False,
            },
            api_key,
            ref,
        )
        if isinstance(payload, dict):
            message = payload.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str):
                    return content
        raise EndpointError(f"unexpected Ollama response from {ref}: {payload!r}")


class TgiTransport:
    """POSTs to Hugging Face TGI `/generate` with the conversation flattened to a prompt."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """POST a TGI generate request and return the generated text."""
        ref = f"{base_url}#{model}"
        prompt = "\n".join(f"{m.role}: {m.content}" for m in messages)
        payload = post_json(
            f"{base_url}/generate", {"inputs": prompt, "parameters": {}}, api_key, ref
        )
        if isinstance(payload, list) and payload:
            payload = payload[0]
        if isinstance(payload, dict):
            text = payload.get("generated_text")
            if isinstance(text, str):
                return text
        raise EndpointError(f"unexpected TGI response from {ref}: {payload!r}")


_PROVIDERS: dict[str, Callable[[], ChatTransport]] = {
    "openai": UrllibTransport,
    "ollama": OllamaTransport,
    "tgi": TgiTransport,
}


def select_transport(provider: str) -> ChatTransport:
    """Return a fresh transport for a named provider, failing loudly on an unknown one."""
    factory = _PROVIDERS.get(provider)
    if factory is None:
        raise EndpointError(
            f"unknown provider {provider!r}; known: {', '.join(sorted(_PROVIDERS))}"
        )
    return factory()
