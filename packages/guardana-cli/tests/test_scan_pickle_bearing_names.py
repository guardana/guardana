"""A pickle that runs code on load never scans as a pass, whatever the file is named.

Each case puts the same malicious pickle where a loader for that name would unpickle
it. A rule that reads the format reports it (exit 1); a format no rule reads is an
unexamined component (exit 2). The controls are files of the same names that hold no
model, and they stay clean. Every payload is bytes built here; nothing is unpickled.
"""

import gzip
import io
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()

_SYSTEM = b"\x80\x02cos\nsystem\nX\x02\x00\x00\x00id\x85R."
"""Protocol 2: GLOBAL os.system, one string argument, REDUCE."""

_TEXT = b"A readme, not a model.\n"


def _npy(descr: str, body: bytes) -> bytes:
    header = f"{{'descr': '{descr}', 'fortran_order': False, 'shape': (1,), }}\n".encode()
    return b"\x93NUMPY\x01\x00" + len(header).to_bytes(2, "little") + header + body


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _tar(members: dict[str, bytes], mode: str = "w") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:  # type: ignore[call-overload]
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


_LEGACY_TORCH_TAR = {
    "sys_info": b"\x80\x02}q\x00.",
    "pickle": _SYSTEM,
    "storages": b"\x80\x02K\x00.",
    "tensors": b"\x80\x02K\x00.",
}

_CASES: dict[str, tuple[str, Callable[[], bytes], ExitCode]] = {
    "pth-tar": ("model_best.pth.tar", lambda: _SYSTEM, ExitCode.POLICY_FAILED),
    "pt-tar-legacy-tar": ("model.pt.tar", lambda: _tar(_LEGACY_TORCH_TAR), ExitCode.POLICY_FAILED),
    "sav": ("model.sav", lambda: _SYSTEM, ExitCode.POLICY_FAILED),
    "p": ("data.p", lambda: _SYSTEM, ExitCode.POLICY_FAILED),
    "gensim-model": ("word2vec.model", lambda: _SYSTEM, ExitCode.POLICY_FAILED),
    "pdparams": ("model.pdparams", lambda: _SYSTEM, ExitCode.POLICY_FAILED),
    "npy": ("weights.npy", lambda: _npy("|O", _SYSTEM), ExitCode.POLICY_FAILED),
    "npz": ("arrays.npz", lambda: _zip({"arr_0.npy": _npy("|O", _SYSTEM)}), ExitCode.POLICY_FAILED),
    "zip": ("bundle.zip", lambda: _zip({"model.pkl": _SYSTEM}), ExitCode.POLICY_FAILED),
    "legacy-torch-tar": (
        "checkpoint.tar",
        lambda: _tar(_LEGACY_TORCH_TAR),
        ExitCode.POLICY_FAILED,
    ),
    "torchscript-ptl": (
        "model.ptl",
        lambda: _zip({"model/data.pkl": _SYSTEM, "model/version": b"3"}),
        ExitCode.POLICY_FAILED,
    ),
    "pkl-gz": ("model.pkl.gz", lambda: gzip.compress(_SYSTEM), ExitCode.POLICY_FAILED),
    "joblib-gz": ("model.joblib.gz", lambda: gzip.compress(_SYSTEM), ExitCode.POLICY_FAILED),
    "torchserve-mar": (
        "model.mar",
        lambda: _zip({"model.pkl": _SYSTEM, "handler.py": b"import os\n"}),
        ExitCode.INDETERMINATE,
    ),
    "nemo": (
        "model.nemo",
        lambda: _tar({"model_weights.ckpt": _SYSTEM}, mode="w:gz"),
        ExitCode.INDETERMINATE,
    ),
    "llamafile": ("model.llamafile", lambda: _SYSTEM, ExitCode.INDETERMINATE),
    "pt-gz": ("model.pt.gz", lambda: gzip.compress(_SYSTEM), ExitCode.POLICY_FAILED),
    "joblib-lz4": ("model.joblib.lz4", lambda: _SYSTEM, ExitCode.POLICY_FAILED),
    "sagemaker": (
        "model.tar.gz",
        lambda: _tar({"model.pkl": _SYSTEM}, mode="w:gz"),
        ExitCode.POLICY_FAILED,
    ),
    "torch-tar-in-zip": (
        "release.zip",
        lambda: _zip({"checkpoints/model_best.pth.tar": _tar(_LEGACY_TORCH_TAR)}),
        ExitCode.INDETERMINATE,
    ),
    "npy-named-bin": ("features.bin", lambda: _npy("|O", _SYSTEM), ExitCode.POLICY_FAILED),
}


@pytest.mark.parametrize("case", list(_CASES.values()), ids=list(_CASES))
def test_a_malicious_pickle_under_a_model_name_never_scans_as_a_pass(
    tmp_path: Path, case: tuple[str, Callable[[], bytes], ExitCode]
) -> None:
    name, build, expected = case
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build())

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == expected, result.output


_CONTROLS: dict[str, tuple[str, Callable[[], bytes]]] = {
    "numeric-npy": ("weights.npy", lambda: _npy("<f4", _SYSTEM)),
    "zip-of-text": ("docs.zip", lambda: _zip({"README.txt": _TEXT, "src/app.py": b"x = 1\n"})),
    "tar-of-text": ("docs.tar", lambda: _tar({"README.txt": _TEXT})),
    "sentencepiece-model": ("tokenizer.model", lambda: b"\n\x0b\n\x05<unk>\x15\x00\x00\x00\x00"),
    "spss-sav": ("survey.sav", lambda: b"$FL2@(#) SPSS DATA FILE" + bytes(64)),
    "prolog-in-zip": ("src.zip", lambda: _zip({"prolog/family.p": b"cat(tom).\n"})),
    "release-tar-gz": ("release.tar.gz", lambda: _tar({"README.txt": _TEXT}, mode="w:gz")),
    "flax-msgpack": ("flax_model.msgpack", lambda: b"\x81\xa6params\x80"),
    "tf-variables": ("variables/variables.index", lambda: b"\x00" * 16),
}


@pytest.mark.parametrize("case", list(_CONTROLS.values()), ids=list(_CONTROLS))
def test_a_file_under_those_names_that_holds_no_model_stays_clean(
    tmp_path: Path, case: tuple[str, Callable[[], bytes]]
) -> None:
    name, build = case
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build())

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == ExitCode.OK, result.output
