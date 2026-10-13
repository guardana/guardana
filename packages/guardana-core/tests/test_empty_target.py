"""A file target whose scope holds no file to scan is a coverage shortfall, never a pass.

A scan that read nothing found nothing, which is not the target found clean. Ignore
files do not count, wherever they sit; any other file does. The run and the plan read
the same function, so a plan refuses the scan the run would not pass.
"""

from collections.abc import Iterable, Iterator
from pathlib import Path

import pytest
from guardana.core.gate import GateOutcome, OpenQuestion, gate_outcome
from guardana.core.plan import build_plan
from guardana.core.profile import Profile, default_profile
from guardana.core.profile.presets import preset
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.report.shortfall import CoverageShortfall, ShortfallKind
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner, empty_target
from guardana.core.severity import Severity
from guardana.core.source import PythonSource, UnreadSource
from guardana.core.target import ArtifactTarget, Capability, EndpointTarget, Target, TargetKind
from guardana.core.testing import ScriptedTransport


class _Quiet(Rule):
    """A file rule that reads every file and finds nothing."""

    meta = RuleMeta(
        "acme.test.quiet",
        "quiet",
        Severity.HIGH,
        TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Find nothing."""
        return ()


class _ThirdPartyFiles(Target):
    """A file target from a pack, listing a directory itself and reporting no excludes."""

    kind = TargetKind.ARTIFACT

    def __init__(self, root: Path) -> None:
        self._root = root

    def capabilities(self) -> set[Capability]:
        return {Capability.READ_FILES}

    @property
    def ref(self) -> str:
        return f"acme-files://{self._root}"

    def iter_files(self, suffixes: tuple[str, ...] | None = None) -> Iterator[Path]:
        yield from sorted(p for p in self._root.rglob("*") if p.is_file())

    def python_source(self, path: Path) -> PythonSource | None:
        return None

    def unread_sources(self) -> tuple[UnreadSource, ...]:
        return ()


def _registry() -> Registry:
    registry = Registry()
    registry.register_rule(_Quiet())
    return registry


def _shortfall(target: Target, profile: Profile | None = None) -> tuple[CoverageShortfall, ...]:
    result = Runner(_registry(), profile or default_profile()).run(target)
    return tuple(g for g in result.coverage_shortfall if g.kind is ShortfallKind.EMPTY_TARGET)


@pytest.mark.parametrize("profile", ["default", "ci", "release"])
def test_an_empty_directory_is_indeterminate_under_every_preset(
    tmp_path: Path, profile: str
) -> None:
    chosen = default_profile() if profile == "default" else preset(profile)
    target = ArtifactTarget(tmp_path)

    result = Runner(_registry(), chosen).run(target)

    assert result.rules_run == ("acme.test.quiet",)
    assert result.coverage_shortfall == (
        CoverageShortfall(
            kind=ShortfallKind.EMPTY_TARGET,
            name=str(tmp_path),
            detail=(
                f"{tmp_path} holds no file to scan — check the path, or the excludes "
                f"that removed every file"
            ),
        ),
    )
    assert gate_outcome(result, chosen.policy) is GateOutcome.INDETERMINATE


def test_a_directory_whose_every_file_is_excluded_is_empty(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_text("x")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text("x")

    assert _shortfall(ArtifactTarget(tmp_path, excludes=("*.pkl", "vendor")))


def test_a_directory_emptied_by_its_ignore_file_is_empty(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("x")
    (tmp_path / ".guardanaignore").write_text("*.txt\n")

    assert _shortfall(ArtifactTarget(tmp_path))


def test_a_directory_holding_only_ignore_files_is_empty(tmp_path: Path) -> None:
    (tmp_path / ".guardanaignore").write_text("# nothing\n")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / ".guardanaignore").write_text("# nothing\n")

    assert _shortfall(ArtifactTarget(tmp_path))


def test_any_other_file_counts_as_listed(tmp_path: Path) -> None:
    (tmp_path / ".guardanaignore").write_text("# nothing\n")
    (tmp_path / ".DS_Store").write_bytes(b"\0")

    assert not _shortfall(ArtifactTarget(tmp_path))


def test_a_directory_holding_only_a_dangling_symlink_is_empty_and_says_so(
    tmp_path: Path,
) -> None:
    (tmp_path / "notes.txt").symlink_to(tmp_path / "gone.txt")

    result = Runner(_registry(), default_profile()).run(ArtifactTarget(tmp_path))

    assert [g.kind for g in result.coverage_shortfall] == [ShortfallKind.EMPTY_TARGET]
    assert [(e.source, e.stage) for e in result.errors] == [("guardana.core.source", "read")]
    assert "notes.txt" in result.errors[0].reason


def test_a_single_file_path_is_not_empty(tmp_path: Path) -> None:
    model = tmp_path / "model.pkl"
    model.write_text("x")

    assert not _shortfall(ArtifactTarget(model, excludes=("*.pkl",)))


def test_a_third_party_file_target_with_no_file_is_empty(tmp_path: Path) -> None:
    target = _ThirdPartyFiles(tmp_path)

    gaps = _shortfall(target)

    assert [gap.name for gap in gaps] == [target.ref]


def test_a_third_party_file_target_with_a_file_is_not_empty(tmp_path: Path) -> None:
    (tmp_path / "prompt.txt").write_text("x")

    assert not _shortfall(_ThirdPartyFiles(tmp_path))


def test_a_target_that_reads_no_files_is_never_empty() -> None:
    target = EndpointTarget("http://model.test", "m", transport=ScriptedTransport("ok"))

    assert empty_target(target) == ()


def test_the_plan_carries_the_shortfall_the_run_records(tmp_path: Path) -> None:
    profile = preset("ci")
    target = ArtifactTarget(tmp_path)

    plan = build_plan(_registry(), profile, target)
    result = Runner(_registry(), profile).run(ArtifactTarget(tmp_path))

    assert plan.shortfall == result.coverage_shortfall == empty_target(target)
    assert OpenQuestion.COVERAGE_SHORTFALL in plan.blockers(profile.policy.fail_on)


def test_a_plan_of_a_directory_with_a_file_is_not_refused_for_it(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("x\n")
    profile = preset("ci")

    plan = build_plan(_registry(), profile, ArtifactTarget(tmp_path))

    assert plan.shortfall == ()
    assert plan.blockers(profile.policy.fail_on) == ()
