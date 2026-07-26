"""Build the component inventory for one target — independent of which rules ran.

Independence is the point. If the inventory came from the rules, then excluding a
rule would quietly shrink the list of components, and a narrowed profile would
under-report what is actually deployed. So this walks the target itself, reuses
the listing the scan already has, and asks nothing of the registry.

It stays shallow on purpose: a name, a location, a format, a size. Anything
deeper (a model's architecture, a manifest's resolved versions) costs reads that
a scan should not pay for twice, and belongs to whoever needs the depth.
"""

from collections.abc import Iterator
from pathlib import Path

from guardana.core.observation import Observation, ObservationKind
from guardana.core.target import ArtifactTarget, EndpointTarget, Target

_MODEL_SUFFIXES: dict[str, str] = {
    ".gguf": "gguf",
    ".safetensors": "safetensors",
    ".onnx": "onnx",
    ".pt": "pytorch",
    ".pth": "pytorch",
    ".ckpt": "pytorch",
    ".h5": "keras-hdf5",
    ".hdf5": "keras-hdf5",
    ".keras": "keras",
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".joblib": "joblib",
    ".pmml": "pmml",
    ".tflite": "tflite",
}
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
_DATASET_SUFFIXES = frozenset({".parquet", ".jsonl", ".arrow"})
_MANIFEST_PREFIX = "requirements"


def _size_attributes(path: Path) -> dict[str, str]:
    try:
        return {"size_bytes": str(path.stat().st_size)}
    except OSError:
        # Listed anyway, marked unread: an inventory that drops what it could not
        # open is an inventory that lies by omission.
        return {"read": "failed"}


def _classify(path: Path) -> tuple[ObservationKind, dict[str, str]] | None:
    suffix = path.suffix.lower()
    name = path.name.lower()
    if suffix in _MODEL_SUFFIXES:
        return ObservationKind.MODEL, {"format": _MODEL_SUFFIXES[suffix]}
    if name in _MANIFEST_NAMES or (name.startswith(_MANIFEST_PREFIX) and suffix == ".txt"):
        return ObservationKind.DEPENDENCY_MANIFEST, {}
    if suffix in _DATASET_SUFFIXES:
        return ObservationKind.DATASET, {"format": suffix.lstrip(".")}
    if suffix == ".ipynb":
        return ObservationKind.NOTEBOOK, {}
    return None


def _observe_artifacts(target: ArtifactTarget) -> Iterator[Observation]:
    for path in target.iter_files():
        classified = _classify(path)
        if classified is None:
            continue
        kind, attributes = classified
        yield Observation(
            kind=kind,
            name=path.name,
            ref=str(path),
            attributes={**attributes, **_size_attributes(path)},
        )


def observe(target: Target) -> tuple[Observation, ...]:
    """Return every component this target exposes, in a stable order.

    Returns nothing for a target type it does not recognise, which is the honest
    answer: a custom `Target` knows its own components and can report them, but
    this must never invent an inventory for one it cannot see into.
    """
    if isinstance(target, ArtifactTarget):
        return tuple(_observe_artifacts(target))
    if isinstance(target, EndpointTarget):
        return (Observation(kind=ObservationKind.MODEL, name=target.model, ref=target.ref),)
    return ()
