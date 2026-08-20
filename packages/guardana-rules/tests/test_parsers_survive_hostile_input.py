"""Every parser that reads a file an attacker chose, against bytes nobody wrote.

The threat model listed "the binary parsers are not fuzzed" as an open gap from
v0.7 onward, and example-based tests cannot close it: an example proves the case
its author thought of, and the case that matters is the length field one byte
short of the file, the count that multiplies past `sys.maxsize`, the header that
declares a section starting after the end.

Two invariants, and neither is about finding anything:

**Nothing escapes.** A rule may return findings or return nothing. It may not
raise: the runner records a raised rule as an error, which is coverage the scan
claimed and did not have. `RuleError` is the one permitted exception, because it
is the declared way to say "this rule cannot run here".

**It terminates.** A parser that loops on a crafted length turns a scan into a
hang, and a scan nobody waits for is a scan nobody runs — which the second
product principle calls a security property, not a performance one.

Deliberately run over the *rules*, not their private helpers. A helper that is
robust behind a caller that is not has been tested in the wrong place.
"""

import contextlib
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from guardana.core.registry import Registry
from guardana.core.rule import Rule, RuleContext
from guardana.core.rule.errors import RuleError
from guardana.core.target import ArtifactTarget, TargetKind
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

_DEADLINE_SECONDS = 5.0
"""A generous ceiling. It is here to catch a hang, not to measure performance."""

_HOSTILE_SUFFIXES = (
    ".ckpt",
    ".dill",
    ".hdf5",
    ".j2",
    ".joblib",
    ".md",
    ".pickle",
    ".xml",
    ".pkl",
    ".bin",
    ".pt",
    ".pth",
    ".gguf",
    ".onnx",
    ".safetensors",
    ".h5",
    ".keras",
    ".pmml",
    ".pb",
    ".npy",
    ".ipynb",
    ".json",
    ".yaml",
    ".jinja",
    ".txt",
    ".py",
)
"""Every extension a built-in artifact rule opens and reads the contents of.

Kept honest by the last test in this file, which *measures* what the rules ask
for rather than trusting this tuple. Eight of these entries are here because it
failed the first time it ran.
"""

# Enough structure to reach the parsers rather than bouncing off a magic-number
# check: a real header followed by whatever the generator produced. Plain random
# bytes are also generated, because a parser that only survives well-formed
# prefixes has not survived anything.
_MAGICS = (
    b"",
    b"GGUF",
    b"\x80\x04\x95",  # pickle protocol 4
    b"\x08\x01\x12",  # protobuf-ish, as ONNX and SavedModel begin
    b"\x89HDF\r\n\x1a\n",  # HDF5, as Keras .h5 begins
    b"PK\x03\x04",  # zip, as .keras and torch archives begin
    b"\x93NUMPY",
    b'{"__metadata__":',
    b"<PMML>",
)


def _artifact_rules() -> tuple[Rule, ...]:
    return tuple(
        rule for rule in Registry.discover().rules() if rule.meta.target_kind is TargetKind.ARTIFACT
    )


_RULES = _artifact_rules()


@settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(
    magic=st.sampled_from(_MAGICS),
    body=st.binary(min_size=0, max_size=4096),
    suffix=st.sampled_from(_HOSTILE_SUFFIXES),
)
def test_no_artifact_rule_raises_on_bytes_nobody_wrote(
    tmp_path: Path, magic: bytes, body: bytes, suffix: str
) -> None:
    """A rule that raises is coverage the scan reported and did not have.

    Not "a rule that finds nothing" — that is a fine outcome for garbage. The
    failure this catches is the scan going `indeterminate` because a struct
    unpacked short, and the file that did it being one an attacker uploaded.
    """
    (tmp_path / f"model{suffix}").write_bytes(magic + body)
    target = ArtifactTarget(tmp_path)
    ctx = RuleContext()

    for rule in _RULES:
        try:
            list(rule.run(target, ctx))
        except RuleError:
            # The declared way for a rule to say it cannot run here. Recorded as a
            # skip, visible in the report, and not a crash.
            continue
        except Exception as exc:
            pytest.fail(f"{rule.meta.id} raised {type(exc).__name__} on {suffix}: {exc}")


@settings(
    max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(
    declared=st.integers(min_value=0, max_value=2**63 - 1),
    actual=st.binary(min_size=0, max_size=256),
)
def test_a_declared_length_larger_than_the_file_does_not_hang_or_allocate(
    tmp_path: Path, declared: int, actual: bytes
) -> None:
    """The header field an attacker controls, pointed past the end of the file.

    safetensors opens with an 8-byte little-endian header length; GGUF counts its
    tensors and its metadata entries the same way. Every one of those is a number
    a crafted file chooses, and the two failure modes are a read that allocates it
    and a loop that iterates it.
    """
    header = declared.to_bytes(8, "little")
    for name in ("model.safetensors", "model.gguf"):
        (tmp_path / name).write_bytes(header + actual)
    target = ArtifactTarget(tmp_path)
    ctx = RuleContext()

    started = time.monotonic()
    for rule in _RULES:
        try:
            list(rule.run(target, ctx))
        except RuleError:
            continue
        except Exception as exc:
            pytest.fail(f"{rule.meta.id} raised {type(exc).__name__}: {exc}")
    elapsed = time.monotonic() - started

    assert elapsed < _DEADLINE_SECONDS, (
        f"scanning a file that declares {declared} bytes took {elapsed:.1f}s — "
        f"a crafted length must not become a hang"
    )


@settings(
    max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(text=st.text(max_size=2048))
def test_the_text_parsers_survive_arbitrary_unicode(tmp_path: Path, text: str) -> None:
    """Bidi controls, lone surrogates, unassigned planes — the hidden-instruction surface.

    These rules exist *because* text can carry what a reader cannot see, so the
    input they are pointed at is exactly the input most likely to be malformed.
    """
    for name in ("config.json", "chat_template.jinja", "README.txt", "loader.py"):
        (tmp_path / name).write_text(text, encoding="utf-8", errors="surrogatepass")
    target = ArtifactTarget(tmp_path)
    ctx = RuleContext()

    for rule in _RULES:
        try:
            list(rule.run(target, ctx))
        except RuleError:
            continue
        except Exception as exc:
            pytest.fail(f"{rule.meta.id} raised {type(exc).__name__}: {exc}")


def test_the_corpus_covers_every_extension_a_built_in_rule_opens(tmp_path: Path) -> None:
    """The seed corpus is only as good as the extensions in it.

    A rule added for a new format brings a new parser, and a suite that never
    feeds it reports green about code it did not run. So the list is *measured*,
    not written down: the target below records every suffix tuple the rules
    actually ask for while they run, which is the only version of this that
    survives the next rule.
    """
    asked: set[str] = set()

    class _RecordingTarget(ArtifactTarget):
        def iter_files(self, suffixes: tuple[str, ...] | None = None) -> Iterator[Path]:
            asked.update(suffixes or ())
            return super().iter_files(suffixes)

    (tmp_path / "any.txt").write_text("x")
    target = _RecordingTarget(tmp_path)
    for rule in _RULES:
        with contextlib.suppress(RuleError):
            list(rule.run(target, RuleContext()))

    assert asked, "no rule asked for a suffix, so this test is measuring nothing"
    missing = sorted(asked - set(_HOSTILE_SUFFIXES))
    assert not missing, f"extensions a rule reads and the corpus never feeds it: {missing}"
