"""Build the component inventory for one target — independent of which rules ran.

Independence is the point. If the inventory came from the rules, then excluding a
rule would quietly shrink the list of components, and a narrowed profile would
under-report what is actually deployed. So this walks the target itself, reuses
the listing the scan already has, and asks nothing of the registry.

It stays shallow on purpose: a name, a location, a format, a size. Anything
deeper (a model's architecture, a manifest's resolved versions) costs reads that
a scan should not pay for twice, and belongs to whoever needs the depth.
"""

import os
from collections.abc import Callable, Collection, Iterable, Iterator
from pathlib import Path, PurePath

from guardana.core.formats.hdf5 import (
    HDF5_HEAD_BYTES,
    find_hdf5_signature,
    find_hdf5_signature_in_head,
)
from guardana.core.observation import Observation, ObservationKind
from guardana.core.target import Target
from guardana.core.target.protocols import ChatEndpoint, FileReader

_MODEL_SUFFIXES: dict[str, str] = {
    ".gguf": "gguf",
    ".safetensors": "safetensors",
    ".onnx": "onnx",
    ".pt": "pytorch",
    ".pth": "pytorch",
    ".th": "pytorch",
    ".ckpt": "pytorch",
    ".h5": "keras-hdf5",
    ".hdf5": "keras-hdf5",
    ".keras": "keras",
    ".pkl": "pickle",
    ".pkl3": "pickle",
    ".mdl": "pickle",
    ".pickle": "pickle",
    ".dill": "pickle",
    ".joblib": "joblib",
    ".npy": "numpy",
    ".npz": "numpy-zip",
    ".pdparams": "paddle",
    ".ptl": "pytorch",
    ".mar": "torchserve",
    ".nemo": "nemo",
    ".llamafile": "llamafile",
    ".pmml": "pmml",
    ".tflite": "tflite",
}
_MODEL_NAME_ENDINGS: tuple[tuple[str, str], ...] = (
    (".pth.tar", "pytorch"),
    (".pt.tar", "pytorch"),
    (".pt.gz", "compressed-pytorch"),
    (".pth.gz", "compressed-pytorch"),
    (".ckpt.gz", "compressed-pytorch"),
    (".npy.gz", "compressed-numpy"),
    (".joblib.lz4", "compressed-pickle"),
    *(
        (f"{base}{codec}", "compressed-pickle")
        for base in (".pkl", ".pickle", ".joblib")
        for codec in (".gz", ".gzip", ".z", ".xz", ".bz2", ".lzma")
    ),
)
"""Model files named by more than their last suffix, matched against the whole name."""
_MODEL_NAMES: dict[str, str] = {
    "model.tar.gz": "sagemaker-model",
    "saved_model.pb": "tensorflow-savedmodel",
    "saved_model.pbtxt": "tensorflow-savedmodel",
}
"""Model files known by their exact name: a SageMaker model is uploaded as `model.tar.gz`,
while any other `.tar.gz` is as likely a source release, and TensorFlow loads a SavedModel
graph only from `saved_model.pb` or, without one, its text form `saved_model.pbtxt`."""
_MANIFEST_NAMES = frozenset(
    {
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "uv.lock",
        "pipfile",
        "pipfile.lock",
        "environment.yml",
        "conda.yaml",
    }
)
_BIN_SUFFIX = ".bin"
_BIN_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "pytorch"),
    (b"\x80\x02", "pickle"),
    (b"\x80\x03", "pickle"),
    (b"\x80\x04", "pickle"),
    (b"\x80\x05", "pickle"),
    (b"GGUF", "gguf"),
    (b"lmgg", "ggml"),
    (b"fmgg", "ggml"),
    (b"tjgg", "ggml"),
)
"""What a `.bin` holds when it is a model, by its first bytes.

`.bin` names model weights, firmware and test data alike, so it is a component only
when its first bytes say which model container it is; one that says nothing is not
listed."""
_PICKLE_SIGNATURES = tuple(entry for entry in _BIN_SIGNATURES if entry[1] == "pickle")
_SNIFFED_SUFFIXES: dict[str, tuple[tuple[bytes, str], ...]] = {
    _BIN_SUFFIX: _BIN_SIGNATURES,
    ".sav": _PICKLE_SIGNATURES,
    ".p": _PICKLE_SIGNATURES,
    ".model": _PICKLE_SIGNATURES,
    ".dat": _PICKLE_SIGNATURES,
    "": _PICKLE_SIGNATURES,
    ".hdf": (),
    ".weights": (),
    ".tf": (),
}
"""Suffixes other formats share, listed only when the first bytes name a model container."""
_HDF5_SNIFFED_SUFFIXES = frozenset({".bin", ".model", ".hdf", ".weights", ".tf", ""})
"""Suffixes also listed when they hold an HDF5 file, which a Keras loader opens by content."""
_HEAD_SNIFFED_SUFFIXES = frozenset({""})
"""Suffixes that name nothing at all, so the HDF5 signature is looked for in one bounded read
of the file's head rather than wherever a userblock may put it."""
_KERAS_HDF5 = "keras-hdf5"
_MODEL_DIRECTORY_FILES: dict[str, tuple[tuple[str, ...], str]] = {
    "config.json": (("metadata.json", "model.weights.h5", "model.weights.npz"), "keras-directory"),
}
"""Files that are a model only beside one of the named siblings: an unzipped Keras model
keeps its `config.json` next to Keras' own files, while a lone `config.json` is anyone's."""
_ARCHIVE_SUFFIXES = frozenset(
    {
        ".zip",
        ".tar",
        ".tgz",
        ".tbz2",
        ".tbz",
        ".txz",
        ".gz",
        ".gzip",
        ".z",
        ".xz",
        ".bz2",
        ".lzma",
        ".lz4",
    }
)
"""Archives and compressed files, which the artifact scan opens by their content whatever
they are named, since a model ships in one as often as in a `model.tar.gz`."""
_LOADER_FILE_ENDING = "config.json"
_LOADER_FILE_NAMES = frozenset({"keras_metadata.pb", "chat_template.json"})
_TEMPLATE_STEM = "chat_template"
_TEMPLATE_SUFFIXES = frozenset({".jinja", ".j2"})
_TEMPLATE_DIRECTORY = "additional_chat_templates"
_TOKENIZER_FILES = frozenset({"tokenizer_config.json", "tokenizer.json"})
"""A tokenizer is loaded on its own, chat templates and all, with no weights beside it."""
_NAMED_LIKE_MODEL_SUFFIXES = frozenset({".bin", ".model", ".sav"})
"""Suffixes the inventory lists only by their first bytes, counted by name where no file
is opened: model weights carry them as often as anything else does."""
_DATASET_SUFFIXES = frozenset({".parquet", ".jsonl", ".arrow"})
_MANIFEST_PREFIX = "requirements"


def _size_attributes(path: Path) -> dict[str, str]:
    # Opened, not just `stat`ed. `stat()` needs only traverse permission on the
    # parent, so it happily reports a size for a file whose contents nobody can
    # read — and the component would then sit in the report wearing that size,
    # looking examined, while every rule had silently skipped it. Listed anyway
    # when the open fails: an inventory that drops what it could not read lies by
    # omission, which is the same failure as a check reporting clean.
    if not _regular_file(path):
        # A FIFO or a device named like a model blocks a plain open for ever.
        return {"read": "failed"}
    try:
        with path.open("rb"):
            return {"size_bytes": str(path.stat().st_size)}
    except OSError:
        return {"read": "failed"}


def _regular_file(path: Path) -> bool:
    """Whether `path` is a regular file this process may open; False when it cannot tell.

    `is_file` raises for an entry inside a directory that can be listed and not entered.
    """
    try:
        return path.is_file()
    except OSError:
        return False


def _sniffed_format(
    path: Path, signatures: tuple[tuple[bytes, str], ...], *, hdf5: bool, head_only: bool
) -> str | None:
    if not _regular_file(path):
        return None
    try:
        with path.open("rb") as handle:
            head = handle.read(HDF5_HEAD_BYTES if head_only else 4)
            named = next((name for magic, name in signatures if head.startswith(magic)), None)
            if named is not None or not hdf5:
                return named
            if head_only:
                found = find_hdf5_signature_in_head(head)
            else:
                found = find_hdf5_signature(handle, os.fstat(handle.fileno()).st_size)
            return _KERAS_HDF5 if found is not None else None
    except OSError:
        return None


def _named_format(suffix: str, name: str) -> str | None:
    """Return the model format a lower-cased file name alone says, without opening the file.

    Judged by the whole name, since `model.pkl.gz` is a compressed pickle and not a
    gzip of anything.
    """
    ending = next((fmt for end, fmt in _MODEL_NAME_ENDINGS if name.endswith(end)), None)
    if ending is not None:
        return ending
    if suffix in _MODEL_SUFFIXES:
        return _MODEL_SUFFIXES[suffix]
    return _MODEL_NAMES.get(name)


def _model_format(path: Path, suffix: str, name: str) -> str | None:
    """Return the model format `path` holds, or None when it is not a model file.

    Judged by the name, and by the first bytes where the name says nothing certain.
    """
    named = _named_format(suffix, name)
    if named is not None:
        return named
    if suffix in _SNIFFED_SUFFIXES:
        return _sniffed_format(
            path,
            _SNIFFED_SUFFIXES[suffix],
            hdf5=suffix in _HDF5_SNIFFED_SUFFIXES,
            head_only=suffix in _HEAD_SNIFFED_SUFFIXES,
        )
    return None


def _directory_format(path: Path, listed: frozenset[tuple[Path, str]]) -> str | None:
    """Return the model format a file holds by the siblings listed beside it, any case."""
    entry = _MODEL_DIRECTORY_FILES.get(path.name.lower())
    if entry is None:
        return None
    siblings, model_format = entry
    return model_format if any((path.parent, name) in listed for name in siblings) else None


def named_as_model(name: str) -> bool:
    """Whether a file's name alone makes the inventory count it as a model.

    Never opens the file, so a name-only pass over a tree the scan does not walk
    stays a listing.
    """
    lowered = name.lower()
    return _named_format(PurePath(lowered).suffix, lowered) is not None


def named_like_model(name: str) -> bool:
    """Whether a file's name alone says it may be a model, for a pass that opens no file.

    Wider than `named_as_model`: a `.bin` counts here, although the inventory lists one
    only when its first bytes name a model container.
    """
    return named_as_model(name) or PurePath(name.lower()).suffix in _NAMED_LIKE_MODEL_SUFFIXES


def loaded_with_model_in(path: Path) -> Path | None:
    """Return the directory whose model a loader reads `path` with, or None.

    A configuration, a chat template and Keras metadata are read with the model in the
    directory that holds them; a named template in `additional_chat_templates/`, with the
    model one directory up.
    """
    name = path.name.lower()
    suffix = path.suffix.lower()
    if path.parent.name.lower() == _TEMPLATE_DIRECTORY and suffix == ".jinja":
        return path.parent.parent
    if (
        name.endswith(_LOADER_FILE_ENDING)
        or name in _LOADER_FILE_NAMES
        or (name.startswith(_TEMPLATE_STEM) and suffix in _TEMPLATE_SUFFIXES)
    ):
        return path.parent
    return None


def holds_model(directory: Path, names: Collection[str]) -> bool:
    """Whether a directory listing `names` holds a model or a tokenizer a loader reads.

    A model file counts only when it is no link, so nothing outside the directory is
    opened to decide.
    """
    lowered = frozenset(name.lower() for name in names)
    if lowered & _TOKENIZER_FILES:
        return True
    return any(
        not os.path.islink(directory / name)  # noqa: PTH114
        and counts_as_model(directory / name, lowered)
        for name in names
    )


def read_by_model_loaders(
    path: Path,
    siblings: Collection[str],
    holds_a_model: Callable[[Path], bool],
    *,
    by_name: bool = False,
) -> bool:
    """Whether a model loader reads `path`, which the scanned target may then not exclude.

    A model file, an archive or compressed file, and a file read with the model beside
    it, when `holds_a_model` says that directory holds one. `siblings` are the lower-cased
    names beside `path`; `by_name` judges by the name alone, opening nothing.
    """
    name = path.name.lower()
    if path.suffix.lower() in _ARCHIVE_SUFFIXES:
        return True
    model = named_like_model(name) if by_name else counts_as_model(path, siblings)
    if model:
        return True
    directory = loaded_with_model_in(path)
    return directory is not None and holds_a_model(directory)


def counts_as_model(path: Path, siblings: Collection[str]) -> bool:
    """Whether the inventory counts `path` as a model, `siblings` the lower-cased names beside it.

    A model directory's marker files count with it, so `metadata.json` beside a Keras
    `config.json` is as much the model as the configuration it describes.
    """
    name = path.name.lower()
    if _model_format(path, path.suffix.lower(), name) is not None:
        return True
    for directory_file, (markers, _format) in _MODEL_DIRECTORY_FILES.items():
        members = {directory_file, *markers}
        if name in members and directory_file in siblings and any(m in siblings for m in markers):
            return True
    return False


def _classify(
    path: Path, listed: frozenset[tuple[Path, str]]
) -> tuple[ObservationKind, dict[str, str]] | None:
    suffix = path.suffix.lower()
    name = path.name.lower()
    model_format = _model_format(path, suffix, name) or _directory_format(path, listed)
    if model_format is not None:
        return ObservationKind.MODEL, {"format": model_format}
    if name in _MANIFEST_NAMES or (name.startswith(_MANIFEST_PREFIX) and suffix == ".txt"):
        return ObservationKind.DEPENDENCY_MANIFEST, {}
    if suffix in _DATASET_SUFFIXES:
        return ObservationKind.DATASET, {"format": suffix.lstrip(".")}
    if suffix == ".ipynb":
        return ObservationKind.NOTEBOOK, {}
    return None


def _observe_artifacts(target: FileReader, files: Iterable[Path] | None) -> Iterator[Observation]:
    paths = tuple(target.iter_files() if files is None else files)
    listed = frozenset((path.parent, path.name.lower()) for path in paths)
    for path in paths:
        classified = _classify(path, listed)
        if classified is None:
            continue
        kind, attributes = classified
        yield Observation(
            kind=kind,
            name=path.name,
            ref=str(path),
            attributes={**attributes, **_size_attributes(path)},
        )


def observe(target: Target, files: Iterable[Path] | None = None) -> tuple[Observation, ...]:
    """Return every component this target exposes, in a stable order.

    `files` is the target's listing when the caller already took it, so a file target
    that does not cache its listing is walked once.

    Returns nothing for a target type it does not recognise, which is the honest
    answer: a custom `Target` knows its own components and can report them, but
    this must never invent an inventory for one it cannot see into.
    """
    if isinstance(target, FileReader):
        return tuple(_observe_artifacts(target, files))
    if isinstance(target, ChatEndpoint):
        return (Observation(kind=ObservationKind.MODEL, name=target.model, ref=target.ref),)
    return ()
