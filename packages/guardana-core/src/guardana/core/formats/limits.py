from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    """Hard bounds every format reader honours.

    A scanned model file is untrusted input, and every one of these numbers is
    attacker-controlled inside the file itself: a header can claim to hold 2^64
    entries, a string can claim to be an exabyte long. The reader checks the
    claim against these bounds *before* allocating, so a crafted artifact costs
    a `FormatError` rather than the scan.

    Defaults are sized off real models, not guesswork: a 20k-tensor safetensors
    index is ~1.5 MiB of JSON and a 256k-token GGUF vocabulary is a few MiB, so
    honest files stay far inside the bounds.
    """

    max_header_bytes: int = 64 * 1024 * 1024
    max_entries: int = 100_000
    max_string_bytes: int = 8 * 1024 * 1024
    max_array_items: int = 2_000_000


DEFAULT_LIMITS = Limits()
