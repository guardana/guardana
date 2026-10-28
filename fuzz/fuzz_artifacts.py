"""Fuzz the artifact rules with arbitrary bytes as a pickle, a PyTorch zip and a safetensors file.

    uv run --group fuzz python fuzz/fuzz_artifacts.py -max_total_time=120

Each input is scanned through `Verifier.scan` with every built-in artifact rule. A rule
that raises is recorded by the run as an error rather than crashing it, so the target turns
every recorded error back into a crash except an input the run could not read: on hostile
bytes a rule may find, decline or report coverage it lacked, but never fail.
"""

import io
import pickle
import zipfile
from collections.abc import Iterable

from _harness import run_fuzzer, scratch_file
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry
from guardana.core.report import ScanResult
from guardana.core.verify import Verifier

_NAMES = ("model.pkl", "model.pt", "model.safetensors", "model.bin")


class RuleRaisedError(Exception):
    """A built-in rule raised on an input instead of answering it."""


def loaded_registry(registry: Registry) -> Registry:
    """Return `registry`, refusing one that could not load a rule."""
    # A rule that failed to load is never run, so every input would pass without fuzzing it.
    if registry.load_errors:
        raise RuleRaisedError(
            "; ".join(f"{error.source}: {error.reason}" for error in registry.load_errors)
        )
    return registry


def raise_on_rule_failures(result: ScanResult) -> None:
    """Raise when the run recorded any error other than an input it could not read."""
    failed = [error for error in result.errors if error.stage != "read"]
    if failed:
        raise RuleRaisedError("; ".join(f"{error.source}: {error.reason}" for error in failed))


_TRUST = PluginTrust(mode=PluginMode.BUILTINS)
_VERIFIER = Verifier(trust=_TRUST, registry=loaded_registry(Registry.discover(_TRUST)))


def one_input(data: bytes) -> None:
    """Scan `data` under a file name its first byte picks."""
    name = _NAMES[data[0] % len(_NAMES)] if data else _NAMES[0]
    with scratch_file(name, data[1:]) as path:
        raise_on_rule_failures(_VERIFIER.scan(path).result)


def _torch_zip(payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("archive/data.pkl", payload)
        archive.writestr("archive/data/0", b"\x00" * 16)
        archive.writestr("archive/version", b"3\n")
    return buffer.getvalue()


def seeds() -> Iterable[bytes]:
    """Yield benign pickles of every protocol, and each inside a PyTorch-style zip."""
    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
        payload = pickle.dumps({"weights": [1.0, 2.0], "name": "seed"}, protocol=protocol)
        yield bytes([0]) + payload
        yield bytes([1]) + _torch_zip(payload)


if __name__ == "__main__":
    run_fuzzer(one_input, seeds)
