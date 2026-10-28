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
        except ProfileError:
            return


def seeds() -> Iterable[bytes]:
    """Yield profiles covering policy, privacy, non-UTF-8 bytes, non-text keys, bad scalars."""
    yield b"fail_on:\n  severity: high\n  fail_on_inconclusive: true\n"
    yield b"rules:\n  select: ['guardana.supply_chain.*']\n"
    yield b"privacy:\n  mode: redacted\n"
    yield b"\xe9fail_on:\n  severity: high\n"
    yield b"1: x\n"
    yield b"1: x\nunrecognised: x\n"
    yield b"rules:\n  1: x\n"
    for scalar in (
        b"!!int high",
        b"!!int",
        b"!!int +",
        b"!!float nope",
        b"!!float",
        b"!!bool perhaps",
        b"!!timestamp x",
        b"!!timestamp 2025-99-99",
        b'!!binary "a"',
    ):
        yield b"name: " + scalar + b"\n"


if __name__ == "__main__":
    run_fuzzer(one_input, seeds)
