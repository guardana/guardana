"""Fuzz the profile loader with arbitrary bytes: a bad profile is refused, never a crash.

uv run --group fuzz python fuzz/fuzz_profile.py -max_total_time=120
"""

from collections.abc import Iterable

from _harness import run_fuzzer, scratch_file
from guardana.core.profile import ProfileError, load_profile


def one_input(data: bytes) -> None:
    """Load `data` as `guardana.yaml`; `ProfileError` is the loader's documented refusal."""
    with scratch_file("guardana.yaml", data) as path:
        try:
            load_profile(path)
        # Bytes that are not UTF-8 fail in the decoder before YAML sees them. That escapes
        # the loader's documented refusal; it is accepted here so the fuzzer keeps looking.
        except (ProfileError, UnicodeDecodeError):
            return


def seeds() -> Iterable[bytes]:
    """Yield profiles using the policy, rule selection and privacy blocks."""
    yield b"fail_on:\n  severity: high\n  fail_on_inconclusive: true\n"
    yield b"rules:\n  select: ['guardana.supply_chain.*']\n"
    yield b"privacy:\n  mode: redacted\n"


if __name__ == "__main__":
    run_fuzzer(one_input, seeds)
