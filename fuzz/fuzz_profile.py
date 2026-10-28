"""Fuzz the profile loader with arbitrary bytes: a bad profile is refused, never a crash.

uv run --group fuzz python fuzz/fuzz_profile.py -max_total_time=120
"""

from collections.abc import Iterable

import yaml
from _harness import run_fuzzer, scratch_file
from guardana.core.profile import ProfileError, load_profile

# What PyYAML's constructors raise for a tagged scalar they cannot build (`!!int high`,
# `!!timestamp x`), and what a key that is not text raises in the loader's messages.
_CONSTRUCTION_ERRORS = (AttributeError, IndexError, TypeError, ValueError)


def one_input(data: bytes) -> None:
    """Load `data` as `guardana.yaml`; `ProfileError` is the loader's documented refusal."""
    with scratch_file("guardana.yaml", data) as path:
        try:
            load_profile(path)
        # Bytes that are not UTF-8 fail in the decoder before YAML sees them. That escapes
        # the loader's documented refusal; it is accepted here so the fuzzer keeps looking.
        except (ProfileError, UnicodeDecodeError):
            return
        # The same holds for YAML that PyYAML cannot construct or that has a key which is not
        # text (`on:`, `1:`, `null:`); the same exception on any other document is a crash.
        except _CONSTRUCTION_ERRORS:
            if not _escapes_the_loader_known_way(data):
                raise


def _escapes_the_loader_known_way(data: bytes) -> bool:
    """Whether PyYAML cannot construct `data`, or builds a mapping with a key that is not text."""
    try:
        document = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        return False
    except _CONSTRUCTION_ERRORS:
        return True
    seen: set[int] = set()
    pending: list[object] = [document]
    while pending:
        node = pending.pop()
        # Aliases can make a node contain itself.
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, dict):
            if any(not isinstance(key, str) for key in node):
                return True
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return False


def seeds() -> Iterable[bytes]:
    """Yield profiles using the policy, rule selection and privacy blocks."""
    yield b"fail_on:\n  severity: high\n  fail_on_inconclusive: true\n"
    yield b"rules:\n  select: ['guardana.supply_chain.*']\n"
    yield b"privacy:\n  mode: redacted\n"


if __name__ == "__main__":
    run_fuzzer(one_input, seeds)
