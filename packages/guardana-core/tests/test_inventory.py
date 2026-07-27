"""Guards for the observation channel — what a scan *saw*, apart from what it found.

Rules produce findings, which is a record of problems, not a record of components.
An evidence pack, a run-to-run diff, and a fleet dashboard all need the second
thing, and none of them should have to re-walk the tree to get it.

Two properties make it trustworthy, and both are pinned here: the inventory does
not depend on which rules are enabled (or the act of excluding a rule would
quietly shrink the component list), and a component the scan could not read is
still listed — marked unread rather than omitted.
"""

from pathlib import Path

from guardana.core.inventory import observe
from guardana.core.observation import Observation, ObservationKind
from guardana.core.profile.model import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import relativize_findings
from guardana.core.runner import Runner
from guardana.core.target import ArtifactTarget, EndpointTarget
from guardana.core.testing import ScriptedTransport


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "model.gguf").write_bytes(b"GGUF" + b"\x00" * 16)
    (tmp_path / "weights.safetensors").write_bytes(b"\x08\x00\x00\x00\x00\x00\x00\x00{}")
    (tmp_path / "requirements.txt").write_text("torch==2.6.0\n", encoding="utf-8")
    (tmp_path / "train.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("hello\n", encoding="utf-8")
    return tmp_path


def _kinds(observations: tuple[Observation, ...]) -> dict[str, set[str]]:
    grouped: dict[str, set[str]] = {}
    for item in observations:
        grouped.setdefault(item.kind, set()).add(item.name)
    return grouped


def test_models_and_manifests_are_observed(tmp_path: Path) -> None:
    grouped = _kinds(observe(ArtifactTarget(_repo(tmp_path))))
    assert grouped[ObservationKind.MODEL] == {"model.gguf", "weights.safetensors"}
    assert grouped[ObservationKind.DEPENDENCY_MANIFEST] == {"requirements.txt"}


def test_unremarkable_files_are_not_inventory(tmp_path: Path) -> None:
    # An inventory of every file is not an inventory. Source and prose are read by
    # rules; they are not components a reviewer asks about.
    names = {item.name for item in observe(ArtifactTarget(_repo(tmp_path)))}
    assert "notes.md" not in names
    assert "train.py" not in names


def test_a_model_carries_its_format_and_size(tmp_path: Path) -> None:
    gguf = next(
        item for item in observe(ArtifactTarget(_repo(tmp_path))) if item.name == "model.gguf"
    )
    assert gguf.attributes["format"] == "gguf"
    assert int(gguf.attributes["size_bytes"]) == 20


def test_an_unreadable_component_is_listed_as_unread_not_dropped(tmp_path: Path) -> None:
    # Omitting it would silently shrink the inventory — the same class of lie as a
    # check that could not run reporting clean. `stat()` is not the test: it
    # succeeds on a file whose contents cannot be opened, which would let an
    # unreadable component sit in the report wearing a size, looking examined.
    root = _repo(tmp_path)
    unreadable = root / "locked.onnx"
    unreadable.write_bytes(b"\x08\x01")
    unreadable.chmod(0o000)
    try:
        found = next(item for item in observe(ArtifactTarget(root)) if item.name == "locked.onnx")
        assert found.attributes.get("read") == "failed"
        assert "size_bytes" not in found.attributes
    finally:
        unreadable.chmod(0o644)


def test_observation_refs_are_relativized_with_the_findings(tmp_path: Path) -> None:
    # One report must not mix repo-relative finding paths with absolute component
    # paths: the run-to-run diff this channel exists for would call every
    # component changed as soon as the checkout moved, and an uploaded report
    # would leak the checkout path the findings were scrubbed of.
    root = _repo(tmp_path)
    result = Runner(registry=Registry.discover(), profile=Profile(name="t", policy=Policy())).run(
        ArtifactTarget(root)
    )
    relativized = relativize_findings(result, root)
    refs = {item.ref for item in relativized.observations}
    assert "model.gguf" in refs
    assert not any(ref.startswith("/") for ref in refs)


def test_the_inventory_is_deterministic(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    first = observe(ArtifactTarget(root))
    second = observe(ArtifactTarget(root))
    assert [item.ref for item in first] == [item.ref for item in second]


def test_excluded_paths_are_not_observed(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    (root / "vendor").mkdir()
    (root / "vendor" / "other.gguf").write_bytes(b"GGUF")
    names = {item.name for item in observe(ArtifactTarget(root, excludes=("vendor",)))}
    assert "other.gguf" not in names
    assert "model.gguf" in names


def test_an_endpoint_observes_the_model_under_test() -> None:
    target = EndpointTarget("http://x", "llama-3", transport=ScriptedTransport("ok"))
    observations = observe(target)
    assert [item.kind for item in observations] == [ObservationKind.MODEL]
    assert observations[0].name == "llama-3"


def test_the_runner_attaches_observations_to_the_result(tmp_path: Path) -> None:
    result = Runner(registry=Registry.discover(), profile=Profile(name="t", policy=Policy())).run(
        ArtifactTarget(_repo(tmp_path))
    )
    assert {item.name for item in result.observations} >= {"model.gguf", "requirements.txt"}


def test_the_inventory_does_not_depend_on_which_rules_run(tmp_path: Path) -> None:
    # If disabling a rule shrank the component list, an evidence pack built from a
    # narrowed profile would quietly under-report what is deployed.
    root = _repo(tmp_path)
    everything = Runner(
        registry=Registry.discover(), profile=Profile(name="t", policy=Policy())
    ).run(ArtifactTarget(root))
    nothing = Runner(
        registry=Registry.discover(),
        profile=Profile(name="t", policy=Policy(include=("nonexistent.*",))),
    ).run(ArtifactTarget(root))
    assert nothing.rules_run == 0
    assert {i.ref for i in nothing.observations} == {i.ref for i in everything.observations}
