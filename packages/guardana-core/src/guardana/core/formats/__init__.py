"""Bounded, offline readers for the model file formats rules need to inspect.

These are *plumbing*, deliberately kept free of security opinions: a reader
returns what the file says, and a `Rule` decides what that means. That split is
what lets a third-party pack ship threat knowledge — "this operator domain is
not on our allowlist" — without first writing a GGUF parser.

Every reader in this package honours the same four promises:

* **offline** — it reads the one file it was given and nothing else;
* **bounded** — sizes claimed inside the file are checked against `Limits`
  before anything is allocated, so a crafted artifact cannot stall or exhaust
  the scan;
* **deterministic** — same bytes, same result, on every platform and locale;
* **fail-closed** — anything it cannot parse raises `FormatError`. A reader
  never returns "empty" to mean "clean", because a rule that cannot read an
  artifact must report an open question, not an all-clear.

    from guardana.core.formats import FormatError, read_gguf_metadata

    try:
        metadata = read_gguf_metadata(path)
    except FormatError as exc:
        ...                                    # report "not scanned", never silence
    template = metadata.text("tokenizer.chat_template")
"""

from guardana.core.formats.errors import FormatError
from guardana.core.formats.gguf import GgufMetadata, GgufValue, read_gguf_metadata
from guardana.core.formats.limits import DEFAULT_LIMITS, Limits
from guardana.core.formats.onnx import STANDARD_ONNX_DOMAINS, OnnxSummary, read_onnx_summary
from guardana.core.formats.safetensors import SafetensorsHeader, read_safetensors_header

__all__ = [
    "DEFAULT_LIMITS",
    "STANDARD_ONNX_DOMAINS",
    "FormatError",
    "GgufMetadata",
    "GgufValue",
    "Limits",
    "OnnxSummary",
    "SafetensorsHeader",
    "read_gguf_metadata",
    "read_onnx_summary",
    "read_safetensors_header",
]
