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
from guardana.core.plugins import PluginMode, PluginTrust
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


def test_numpy_array_files_are_models_since_they_can_hold_a_pickle(tmp_path: Path) -> None:
    (tmp_path / "weights.npy").write_bytes(b"\x93NUMPY\x01\x00")
    (tmp_path / "bundle.npz").write_bytes(b"PK\x05\x06" + bytes(18))

    formats = {
        item.name: item.attributes["format"]
        for item in observe(ArtifactTarget(tmp_path))
        if item.kind is ObservationKind.MODEL
    }

    assert formats == {"weights.npy": "numpy", "bundle.npz": "numpy-zip"}


def test_a_model_named_by_more_than_its_last_suffix_is_listed_by_its_whole_name(
    tmp_path: Path,
) -> None:
    for name in ("m.pth.tar", "m.pt.gz", "m.pth.gz", "m.joblib.lz4", "m.pkl.gz", "model.tar.gz"):
        (tmp_path / name).write_bytes(b"\x00")
    for name in ("release.tar.gz", "flax_model.msgpack", "variables.index", "notes.p"):
        (tmp_path / name).write_bytes(b"\x00")

    formats = {
        item.name: item.attributes["format"]
        for item in observe(ArtifactTarget(tmp_path))
        if item.kind is ObservationKind.MODEL
    }

    assert formats == {
        "m.pth.tar": "pytorch",
        "m.pt.gz": "compressed-pytorch",
        "m.pth.gz": "compressed-pytorch",
        "m.joblib.lz4": "compressed-pickle",
        "m.pkl.gz": "compressed-pickle",
        "model.tar.gz": "sagemaker-model",
    }


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
    result = Runner(
        registry=Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
        profile=Profile(name="t", policy=Policy()),
    ).run(ArtifactTarget(root))
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
    result = Runner(
        registry=Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
        profile=Profile(name="t", policy=Policy()),
    ).run(ArtifactTarget(_repo(tmp_path)))
    assert {item.name for item in result.observations} >= {"model.gguf", "requirements.txt"}


def test_the_inventory_does_not_depend_on_which_rules_run(tmp_path: Path) -> None:
    # If disabling a rule shrank the component list, an evidence pack built from a
    # narrowed profile would quietly under-report what is deployed.
    root = _repo(tmp_path)
    everything = Runner(
        registry=Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
        profile=Profile(name="t", policy=Policy()),
    ).run(ArtifactTarget(root))
    nothing = Runner(
        registry=Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
        profile=Profile(name="t", policy=Policy(exclude=("*",))),
    ).run(ArtifactTarget(root))
    assert nothing.rules_run_count == 0
    assert {i.ref for i in nothing.observations} == {i.ref for i in everything.observations}


def _model_formats(root: Path) -> dict[str, str]:
    return {
        item.name: item.attributes["format"]
        for item in observe(ArtifactTarget(root))
        if item.kind is ObservationKind.MODEL
    }


def test_an_hdf5_file_under_a_shared_name_is_a_model(tmp_path: Path) -> None:
    for name in ("model.bin", "model.hdf", "model.weights", "model.tf", "x.model"):
        (tmp_path / name).write_bytes(b"\x89HDF\r\n\x1a\n" + bytes(16))
    (tmp_path / "main.tf").write_text('resource "x" "y" {}\n', encoding="utf-8")
    (tmp_path / "data.hdf").write_bytes(b"\x0e\x03\x13\x01" + bytes(16))

    assert _model_formats(tmp_path) == dict.fromkeys(
        ("model.bin", "model.hdf", "model.weights", "model.tf", "x.model"), "keras-hdf5"
    )


def test_a_config_json_is_a_model_only_inside_a_keras_model_directory(tmp_path: Path) -> None:
    model = tmp_path / "my_model"
    model.mkdir()
    (model / "config.json").write_text("{}", encoding="utf-8")
    (model / "metadata.json").write_text("{}", encoding="utf-8")
    (tmp_path / "config.json").write_text("{}", encoding="utf-8")
    (tmp_path / "tokenizer.json").write_text("{}", encoding="utf-8")

    observed = {
        item.ref: item.attributes["format"]
        for item in observe(ArtifactTarget(tmp_path))
        if item.kind is ObservationKind.MODEL
    }

    assert observed == {str(model / "config.json"): "keras-directory"}


def test_a_config_json_beside_npz_weights_is_a_keras_model_directory(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text("{}", encoding="utf-8")
    (tmp_path / "model.weights.npz").write_bytes(b"PK\x05\x06" + bytes(18))

    assert _model_formats(tmp_path) == {
        "config.json": "keras-directory",
        "model.weights.npz": "numpy-zip",
    }


def test_an_hdf5_file_behind_a_userblock_is_a_model(tmp_path: Path) -> None:
    (tmp_path / "near.bin").write_bytes(bytes(1024) + b"\x89HDF\r\n\x1a\n" + bytes(16))
    with (tmp_path / "far.weights").open("wb") as handle:
        handle.seek(32 * 1024 * 1024)
        handle.write(b"\x89HDF\r\n\x1a\n" + bytes(16))
    (tmp_path / "odd.bin").write_bytes(bytes(1000) + b"\x89HDF\r\n\x1a\n" + bytes(16))

    assert _model_formats(tmp_path) == {"near.bin": "keras-hdf5", "far.weights": "keras-hdf5"}


def test_a_keras_model_directory_is_recognised_whatever_the_case_of_its_names(
    tmp_path: Path,
) -> None:
    (tmp_path / "Config.json").write_text("{}", encoding="utf-8")
    (tmp_path / "METADATA.JSON").write_text("{}", encoding="utf-8")

    assert _model_formats(tmp_path) == {"Config.json": "keras-directory"}


def test_a_tensorflow_savedmodel_graph_is_listed_by_its_exact_name(tmp_path: Path) -> None:
    (tmp_path / "binary").mkdir()
    (tmp_path / "binary" / "saved_model.pb").write_bytes(b"\x08\x01")
    (tmp_path / "text").mkdir()
    (tmp_path / "text" / "saved_model.pbtxt").write_text("meta_graphs {}\n")
    (tmp_path / "graph.pb").write_bytes(b"\x08\x01")
    (tmp_path / "label_map.pbtxt").write_text("item {}\n")

    formats = {
        item.name: item.attributes["format"]
        for item in observe(ArtifactTarget(tmp_path))
        if item.kind is ObservationKind.MODEL
    }

    assert formats == {
        "saved_model.pb": "tensorflow-savedmodel",
        "saved_model.pbtxt": "tensorflow-savedmodel",
    }


def test_a_pickle_under_a_name_a_loader_opens_is_a_model(tmp_path: Path) -> None:
    for name in ("model.th", "clf.pkl3", "model.mdl"):
        (tmp_path / name).write_bytes(b"\x00")
    for name in ("model.pkl.gzip", "model.ckpt.gz", "arr.npy.gz"):
        (tmp_path / name).write_bytes(b"\x1f\x8b")
    for name in ("model.dat", "model"):
        (tmp_path / name).write_bytes(b"\x80\x04\x95" + bytes(16))
    (tmp_path / "my_model").write_bytes(bytes(1024) + b"\x89HDF\r\n\x1a\n" + bytes(16))

    assert _model_formats(tmp_path) == {
        "model.th": "pytorch",
        "clf.pkl3": "pickle",
        "model.mdl": "pickle",
        "model.pkl.gzip": "compressed-pickle",
        "model.ckpt.gz": "compressed-pytorch",
        "arr.npy.gz": "compressed-numpy",
        "model.dat": "pickle",
        "model": "pickle",
        "my_model": "keras-hdf5",
    }


def test_a_data_file_under_a_name_that_says_nothing_is_not_a_model(tmp_path: Path) -> None:
    (tmp_path / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    (tmp_path / "table.dat").write_bytes(bytes(range(256)))
    (tmp_path / "values.dat.gz").write_bytes(b"\x1f\x8b" + bytes(16))
    (tmp_path / "data.dat").write_bytes(b"\x89HDF\r\n\x1a\n" + bytes(16))

    assert _model_formats(tmp_path) == {}
