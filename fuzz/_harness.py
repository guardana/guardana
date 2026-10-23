"""What every fuzz target shares: one scratch file per input, and the hand-over to Atheris.

The targets read hostile files, so a refusal is the expected answer to most inputs; only
an exception the reader does not document is a defect. Atheris ships wheels for Linux
x86_64 only, so it is imported where the fuzzer starts, never by the harness tests.
"""

import sys
import tempfile
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def scratch_file(name: str, data: bytes) -> Iterator[Path]:
    """Write `data` to a fresh file called `name`, removed when the block ends."""
    with tempfile.TemporaryDirectory(prefix="guardana-fuzz-") as directory:
        path = Path(directory) / name
        path.write_bytes(data)
        yield path


def run_fuzzer(one_input: Callable[[bytes], None], seeds: Callable[[], Iterable[bytes]]) -> None:
    """Fuzz `one_input` from `seeds`, with the libFuzzer flags on the command line."""
    import atheris  # noqa: PLC0415 — the `fuzz` dependency group, Linux x86_64 only

    with tempfile.TemporaryDirectory(prefix="guardana-corpus-") as corpus:
        for index, seed in enumerate(seeds()):
            (Path(corpus) / f"seed-{index}").write_bytes(seed)
        atheris.instrument_all()
        atheris.Setup([*sys.argv, corpus], one_input)
        atheris.Fuzz()
