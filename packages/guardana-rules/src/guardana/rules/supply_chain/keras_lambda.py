import io
import json
import os
import re
import struct
import zipfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from guardana.core.formats import (
    HDF5_HEAD_BYTES,
    find_hdf5_signature,
    find_hdf5_signature_in_head,
)
from guardana.core.report import Evidence, Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection
from guardana.core.severity import Severity
from guardana.core.target import Capability, FileReader, Target, TargetKind
from guardana.core.taxonomy import (
    ATLAS_T0018,
    NIST_SUPPLY_CHAIN,
    OWASP_ASI05_2026,
    OWASP_LLM05_2025,
    OWASP_LLM10_2026,
    OWASP_ML06_2023,
)
from guardana.rules._base import ArtifactRule
from guardana.rules.supply_chain import _samples
from guardana.rules.supply_chain._leads import lead_verdict, unread_component, unscanned_verdict
from guardana.rules.supply_chain._reading import (
    LFS_POINTER_REASON,
    is_lfs_pointer,
    open_regular,
    read_bytes_bounded,
)
from guardana.rules.supply_chain._zip import (
    ARCHIVE_MAX_ENTRIES,
    ZIP_DIRECTORY_MAX_BYTES,
    ZIP_ERRORS,
    listing_refusal,
)
from guardana.rules.supply_chain.saved_model_ops import SavedModelOpsRule, names_a_file_elsewhere

# A Keras `Lambda` layer wraps an arbitrary Python callable that runs on
# `load_model` — a code-execution primitive, no inference needed. `safe_mode` is
# bypassable (CVE-2025-1550, and CVE-2025-9905 shows load_model ignores it for
# `.h5`), so the layer's mere presence is the signal.
_LAMBDA = "Lambda"
# If a Lambda's serialized body references one of these, it is almost certainly
# malicious rather than a benign in-graph tensor op — Keras 3.9's own fix draws
# the same line by whitelisting Keras-internal modules only.
_DANGEROUS_MODULES = ("os", "subprocess", "sys", "socket", "shutil", "pty", "importlib")
_MAX_CONFIG_BYTES = 16 * 1024 * 1024
# A fractal heap header (signature, version 0, heap id length) declaring I/O filters: the
# HDF5 library decompresses the attributes stored in it, which a byte search never sees.
_FILTERED_HEAP = re.compile(rb"FRHP\x00[\s\S]{2}(?!\x00\x00)[\s\S]{2}")
# The module hint on a byte-level match is best-effort: the finding never depends
# on it, so its decoding is bounded per marker and in total parsed characters.
_ATTEMPTS_PER_MARKER = 16
_DECODE_BUDGET_FACTOR = 2
_DECODER = json.JSONDecoder()
_UNSCANNED_TITLE = "Keras model not scanned"
_HDF5_SUFFIXES = (".h5", ".hdf5")
# tf_keras loads any HDF5 file as a model whatever it is called, so these names,
# which other formats share, are read when their bytes are an HDF5 file.
_HDF5_SNIFFED_SUFFIXES = (".bin", ".model", ".hdf", ".weights", ".tf")
# tf_keras loads a file with no suffix as a model when it is an HDF5 file, so one whose
# first bytes hold the signature is read; finding out costs one bounded read.
_NO_SUFFIX = ("",)
# An unzipped Keras model is a directory holding `config.json`; one beside any of
# Keras' own files is read, while a lone `config.json` belongs to anything.
_DIRECTORY_CONFIG = "config.json"
_DIRECTORY_SIBLINGS = ("metadata.json", "model.weights.h5", "model.weights.npz")
# tf_keras revives a SavedModel's layers from the JSON this file holds, and never in
# safe mode; protobuf keeps each string as written, so the class markers find it.
_TF_KERAS_METADATA = "keras_metadata.pb"
# Keras 3 deserialises this object anywhere in a config by unmarshalling its bytecode
# and calling it, whatever layer holds it.
_MARSHALLED = "__lambda__"
# Keras before 3.9 imports the module an object names and resolves the callable in it
# (CVE-2025-1550); a model has no use for a callable from any of these modules.
_UNSAFE_MODULES = frozenset(
    {*_DANGEROUS_MODULES, "builtins", "posix", "nt", "runpy", "ctypes", "pickle", "marshal", "code"}
)
# `TFSMLayer` loads the SavedModel its `filepath` names when the layer is built, which
# `load_model` in Keras through 3.11 does without consulting safe_mode.
_TFSM_LAYER = "TFSMLayer"
_MAX_PATH_SHOWN = 200
# Keras 3.8 builds the attribute of `module` that `registered_name` names when
# `class_name` resolves to nothing there, so either key can name the class built.
_CLASS_KEY = "class_name"
_RESOLVED_NAME_KEYS = (_CLASS_KEY, "registered_name")
# These layers read the file a string `vocabulary` names, through TensorFlow's file
# systems, while the layer is built on load, whatever `safe_mode` says.
_LOOKUP_LAYERS = ("StringLookup", "IntegerLookup", "TextVectorization")


def _json_spelling(word: str) -> bytes:
    """Build a pattern matching every spelling inside a JSON string that decodes to `word`."""
    alternatives = []
    for char in word:
        hex_digits = b"".join(
            b"[" + digit.encode() + digit.upper().encode() + b"]"
            if digit.isalpha()
            else digit.encode()
            for digit in f"{ord(char):04x}"
        )
        alternatives.append(b"(?:" + re.escape(char.encode()) + rb"|\\u" + hex_digits + b")")
    return b"".join(alternatives)


_JSON_STRING_CHAR = rb'(?:[^"\\]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))'


def _class_marker(
    *words: str, dotted: bool = True, keys: tuple[str, ...] = (_CLASS_KEY,)
) -> re.Pattern[bytes]:
    """Build the pattern of a pair under one of `keys` naming one of `words`, bare or dotted."""
    prefix = b"(?:" + _JSON_STRING_CHAR + b"*" + _json_spelling(".") + b")?" if dotted else b""
    return re.compile(
        b'"(?:'
        + b"|".join(_json_spelling(key) for key in keys)
        + b')"[ \t\n\r]*:[ \t\n\r]*"'
        + prefix
        + b"(?:"
        + b"|".join(_json_spelling(word) for word in words)
        + b')"'
    )


# A Lambda layer declares itself with this key/value pair; matching the bare word
# "Lambda" reported any layer a user happened to *name* "Lambda". Keras resolves a
# dotted class name through its export registry (`layers.Lambda` under module
# `keras`), and reads the config with `json.loads`, so the pattern accepts any
# dotted prefix and every spelling that decoder turns into the pair: any character
# as a unicode escape, JSON whitespace around the colon.
_CLASS_MARKER = _class_marker(_LAMBDA, keys=_RESOLVED_NAME_KEYS)
_CLASS_MARKER_TEXT = re.compile(_CLASS_MARKER.pattern.decode("ascii"))
# tf_keras rebuilds these layers by looking the TensorFlow function their config names up
# in the `tf` namespace and calling it, so the config chooses what runs; `ClassMethod`
# does the same with a class and the name of a method called on it.
_TF_OP_LAYERS = ("TFOpLambda", "SlicingOpLambda")
_CLASS_METHOD_LAYER = "ClassMethod"
_TF_OP_MARKER = _class_marker(*_TF_OP_LAYERS, _CLASS_METHOD_LAYER)
_TF_OP_MARKER_TEXT = re.compile(_TF_OP_MARKER.pattern.decode("ascii"))
_MARSHALLED_MARKER = _class_marker(_MARSHALLED, dotted=False)
_TFSM_MARKER = _class_marker(_TFSM_LAYER, keys=_RESOLVED_NAME_KEYS)
_TFSM_MARKER_TEXT = re.compile(_TFSM_MARKER.pattern.decode("ascii"))
_LOOKUP_MARKER = _class_marker(*_LOOKUP_LAYERS, keys=_RESOLVED_NAME_KEYS)
_LOOKUP_MARKER_TEXT = re.compile(_LOOKUP_MARKER.pattern.decode("ascii"))
# The value is captured whole so it decodes as the JSON string Keras reads.
_UNSAFE_MODULE_MARKER = re.compile(
    b'"'
    + _json_spelling("module")
    + b'"[ \t\n\r]*:[ \t\n\r]*("(?:'
    + b"|".join(_json_spelling(module) for module in sorted(_UNSAFE_MODULES))
    + b")(?:"
    + _json_spelling(".")
    + _JSON_STRING_CHAR
    + b'*)?")'
)
_TF_SYMBOL = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")
_TF_COMPAT_PREFIXES = ("compat.v1.", "compat.v2.")
_PURE_TF_NAMESPACES = (
    "__operators__.",
    "bitwise.",
    "dtypes.",
    "experimental.numpy.",
    "image.",
    "linalg.",
    "math.",
    "nn.",
    "quantization.",
    "ragged.",
    "random.",
    "sets.",
    "signal.",
    "sparse.",
    "strings.",
)
"""TensorFlow namespaces of tensor arithmetic only: nothing in them reads or writes a file,
starts a process or calls back into Python."""
_PURE_TF_FUNCTIONS = frozenset(
    {
        "abs", "add", "add_n", "argmax", "argmin", "argsort", "batch_to_space", "bitcast",
        "boolean_mask", "broadcast_dynamic_shape", "broadcast_static_shape", "broadcast_to",
        "cast", "clip_by_global_norm", "clip_by_norm", "clip_by_value", "complex", "concat",
        "constant", "convert_to_tensor", "cos", "cumsum", "depth_to_space", "divide",
        "dynamic_partition", "dynamic_stitch", "einsum", "ensure_shape", "equal", "exp",
        "expand_dims", "extract_volume_patches", "eye", "fill", "floor", "floordiv",
        "gather", "gather_nd", "greater", "greater_equal", "histogram_fixed_width",
        "identity", "identity_n", "less", "less_equal", "linspace", "logical_and",
        "logical_not", "logical_or", "matmul", "maximum", "meshgrid", "minimum", "multiply",
        "negative", "norm", "not_equal", "one_hot", "ones", "ones_like", "pad", "pow",
        "range", "rank", "realdiv", "reduce_all", "reduce_any", "reduce_logsumexp",
        "reduce_max", "reduce_mean", "reduce_min", "reduce_prod", "reduce_std",
        "reduce_sum", "reduce_variance", "repeat", "reshape", "reverse", "reverse_sequence",
        "roll", "round", "scatter_nd", "searchsorted", "sequence_mask", "shape", "shape_n",
        "sigmoid", "sign", "sin", "size", "slice", "sort", "space_to_batch",
        "space_to_batch_nd", "space_to_depth", "split", "sqrt", "square", "squeeze",
        "stack", "stop_gradient", "strided_slice", "subtract", "tan", "tanh",
        "tensor_scatter_nd_add", "tensor_scatter_nd_max", "tensor_scatter_nd_min",
        "tensor_scatter_nd_sub", "tensor_scatter_nd_update", "tensordot", "tile",
        "transpose", "truediv", "unique", "unravel_index", "unstack", "where", "zeros",
        "zeros_like",
    }
)  # fmt: skip
"""Top-level TensorFlow functions that only compute on tensors."""
_PURE_TF_CLASS_METHODS = {
    "RaggedTensor": frozenset(
        {
            "from_nested_row_lengths",
            "from_nested_row_splits",
            "from_nested_value_rowids",
            "from_row_lengths",
            "from_row_limits",
            "from_row_splits",
            "from_row_starts",
            "from_sparse",
            "from_tensor",
            "from_uniform_row_length",
            "from_value_rowids",
        }
    ),
    "SparseTensor": frozenset({"from_value"}),
}
"""Class methods that only build a tensor from tensors: the ones tf_keras records for a
`ClassMethod` layer."""


def _is_lambda_class(class_name: object) -> bool:
    """Whether a `class_name` names the Lambda layer, bare or by a dotted export path."""
    return isinstance(class_name, str) and (
        class_name == _LAMBDA or class_name.endswith("." + _LAMBDA)
    )


def _is_tfsm_class(class_name: object) -> bool:
    """Whether a `class_name` names the TFSMLayer, bare or by a dotted export path."""
    return isinstance(class_name, str) and (
        class_name == _TFSM_LAYER or class_name.endswith("." + _TFSM_LAYER)
    )


def _lookup_class(name: object) -> str | None:
    """Return which lookup layer a class name names, bare or dotted; None for any other."""
    if not isinstance(name, str):
        return None
    return next(
        (layer for layer in _LOOKUP_LAYERS if name == layer or name.endswith("." + layer)),
        None,
    )


def _is_lookup_class(name: object) -> bool:
    """Whether a class name names a layer that reads a vocabulary file it is given."""
    return _lookup_class(name) is not None


def _names_class(node: dict[object, object], is_class: Callable[[object], bool]) -> bool:
    """Whether an object's `class_name` or `registered_name` names a class `is_class` accepts."""
    return any(is_class(node.get(key)) for key in _RESOLVED_NAME_KEYS)


def _unsafe_module(module: object) -> str | None:
    """Return the top-level package of `module` when it is one a model has no use for."""
    if not isinstance(module, str):
        return None
    package = module.split(".", 1)[0]
    return package if package in _UNSAFE_MODULES else None


def _iter_load_callables(node: object) -> Iterator[str]:
    """Yield what each object outside a Lambda layer makes Keras call when it loads.

    A marshalled function, and a callable named in a module a model has no use for; a
    Lambda layer's own function is the Lambda layer's finding.
    """
    if isinstance(node, dict):
        class_name = node.get("class_name")
        if _names_class(node, _is_lambda_class):
            return
        if class_name == _MARSHALLED:
            yield (
                "model config holds a marshalled Python function (`__lambda__`), which "
                "Keras runs on load"
            )
        module = node.get("module")
        if _unsafe_module(module) is not None:
            name = node.get("config") if class_name == "function" else class_name
            named = f"{module}.{name}" if isinstance(name, str) else str(module)
            yield f"model config names {named!r}, which Keras before 3.9 imports on load"
        for value in node.values():
            yield from _iter_load_callables(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_load_callables(item)


def _marked_load_callables(data: bytes) -> list[str]:
    """Return what the class and module markers in raw bytes make Keras call on load."""
    found = []
    if _MARSHALLED_MARKER.search(data) is not None:
        found.append(
            "model config holds a marshalled Python function (`__lambda__`), which Keras "
            "runs on load"
        )
    modules = dict.fromkeys(
        module
        for match in _UNSAFE_MODULE_MARKER.finditer(data)
        if (module := _unsafe_module(_decoded_string(match.group(1)))) is not None
    )
    found += [
        f"model config names a callable in the {module!r} module, which Keras before 3.9 "
        "imports on load"
        for module in modules
    ]
    return found


def _decoded_string(literal: bytes) -> object:
    """Decode a JSON string literal the markers matched; None if it does not decode."""
    try:
        decoded: object = json.loads(literal)
    except ValueError:
        return None
    return decoded


def _tfsm_path(layer: object) -> str | None:
    """Return the SavedModel path a TFSMLayer's config names, or None when it names none."""
    config = layer.get("config") if isinstance(layer, dict) else None
    filepath = config.get("filepath") if isinstance(config, dict) else None
    return filepath if isinstance(filepath, str) and filepath else None


def _layer_class(class_name: object) -> str | None:
    """Return which TF call layer a `class_name` names, bare or dotted; None for any other."""
    if not isinstance(class_name, str):
        return None
    return next(
        (
            layer
            for layer in (*_TF_OP_LAYERS, _CLASS_METHOD_LAYER)
            if class_name == layer or class_name.endswith("." + layer)
        ),
        None,
    )


def _is_tf_call_class(class_name: object) -> bool:
    """Whether a `class_name` names a layer that calls the TensorFlow callable it names."""
    return _layer_class(class_name) is not None


def _without_compat(symbol: str) -> str:
    for prefix in _TF_COMPAT_PREFIXES:
        symbol = symbol.removeprefix(prefix)
    return symbol


def _is_pure_tf_op(symbol: str) -> bool:
    """Whether a TensorFlow name is a function that only computes on tensors."""
    symbol = _without_compat(symbol)
    return symbol in _PURE_TF_FUNCTIONS or (
        symbol.startswith(_PURE_TF_NAMESPACES) and not symbol.endswith(".")
    )


@dataclass(frozen=True, slots=True)
class _TfCall:
    """What one TF call layer calls: its class, and the callable's `tf.` name, if it names one."""

    layer: str
    symbol: str | None
    pure: bool = False


def _tf_call(node: object) -> _TfCall:
    """Read what a TF call layer's config makes tf_keras call when the model loads."""
    layer = _layer_class(node.get("class_name")) if isinstance(node, dict) else None
    config = node.get("config") if isinstance(node, dict) else None
    if layer is None or not isinstance(config, dict):
        return _TfCall(layer or _TF_OP_LAYERS[0], None)
    if layer == _CLASS_METHOD_LAYER:
        owner, method = config.get("cls_symbol"), config.get("method_name")
        if not (
            isinstance(owner, str)
            and _TF_SYMBOL.fullmatch(owner)
            and isinstance(method, str)
            and method.isidentifier()
        ):
            return _TfCall(layer, None)
        pure = method in _PURE_TF_CLASS_METHODS.get(_without_compat(owner), frozenset())
        return _TfCall(layer, f"{owner}.{method}", pure)
    function = config.get("function")
    if not (isinstance(function, str) and _TF_SYMBOL.fullmatch(function)):
        return _TfCall(layer, None)
    return _TfCall(layer, function, _is_pure_tf_op(function))


# Not None: a config whose JSON is `null` was read, and is no model either.
_UNREADABLE = object()
_PARTLY_READ = f"only the first {_MAX_CONFIG_BYTES} bytes were read"


@dataclass(frozen=True, slots=True)
class _OversizedConfig:
    """A `config.json` longer than the read bound, of which only `prefix` was read."""

    prefix: bytes


def _iter_class_nodes(
    node: object, is_class: Callable[[object], bool], *, resolved: bool = False
) -> Iterator[object]:
    """Yield every object in the tree whose `class_name` `is_class` accepts.

    With `resolved`, an object whose `registered_name` it accepts is yielded too.
    """
    if isinstance(node, dict):
        if is_class(node.get(_CLASS_KEY)) or (resolved and _names_class(node, is_class)):
            yield node
        for value in node.values():
            yield from _iter_class_nodes(value, is_class, resolved=resolved)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_class_nodes(item, is_class, resolved=resolved)


def _iter_lambda_configs(node: object) -> Iterator[object]:
    """Yield the `config` of every object in the tree that Keras may build as a Lambda."""
    for found in _iter_class_nodes(node, _is_lambda_class, resolved=True):
        yield found.get("config") if isinstance(found, dict) else None


def _iter_tfsm_layers(node: object) -> Iterator[object]:
    """Yield every object in the tree that Keras may build as a TFSMLayer."""
    return _iter_class_nodes(node, _is_tfsm_class, resolved=True)


def _iter_lookup_layers(node: object) -> Iterator[object]:
    """Yield every object in the tree that Keras may build as a lookup layer."""
    return _iter_class_nodes(node, _is_lookup_class, resolved=True)


@dataclass(frozen=True, slots=True)
class _Vocabulary:
    """A lookup layer's vocabulary file named outside the model."""

    layer: str
    path: str


def _outside_vocabulary(layer: object) -> _Vocabulary | None:
    """Return the vocabulary file a lookup layer reads from outside the model, if it names one.

    A model built from a vocabulary file keeps that file's path, so the path is judged as
    `saved_model_ops` judges a table's file: absolute, `..` or a URL is elsewhere.
    """
    if not isinstance(layer, dict):
        return None
    name = next(filter(None, (_lookup_class(layer.get(key)) for key in _RESOLVED_NAME_KEYS)), None)
    config = layer.get("config")
    vocabulary = config.get("vocabulary") if isinstance(config, dict) else None
    if name is None or not isinstance(vocabulary, str):
        return None
    if not names_a_file_elsewhere(vocabulary, frozenset()):
        return None
    return _Vocabulary(name, vocabulary)


def _dangerous_module(config: object) -> str | None:
    """Return a dangerous module name referenced in a Lambda's serialized body, if any."""
    blob = json.dumps(config)
    for module in _DANGEROUS_MODULES:
        if f"'{module}'" in blob or f'"{module}"' in blob or f"import {module}" in blob:
            return module
    return None


def _decode_from(text: str, start: int) -> tuple[object | None, int]:
    """Decode the object opening at `start`; return it, or None, and the characters spent.

    A failed attempt is charged up to where the decoder stopped, or to the end of the
    text when the decoder does not say, so the charge never undercounts the work.
    """
    try:
        value, end = _DECODER.raw_decode(text, start)
    except json.JSONDecodeError as exc:
        return None, exc.pos - start + 1
    except (ValueError, RecursionError):
        return None, len(text) - start
    return value, end - start


def _last_brace(text: str, low: int, high: int) -> int:
    """Return the offset of the last `{` in `text[low:high]`, or -1 if there is none."""
    return text.rfind("{", low, high)


def _marked_layer_configs(
    text: str, marker: re.Pattern[str], select: Callable[[object], Iterator[object]]
) -> Iterator[list[object]]:
    """Yield, for each marker in `text`, what `select` takes from the marked layers around it.

    Walks back from the marker to the nearest `{` whose object decodes and holds such a
    layer, the layer itself, so its body is read the way Keras reads it; an empty list
    where none does within the bounds. No search reaches below the previous marker and
    the decoder parses a bounded multiple of the text, so the work stays linear in it.
    """
    budget = _DECODE_BUDGET_FACTOR * len(text)
    floor = 0
    for found in marker.finditer(text):
        brace = found.start()
        configs: list[object] = []
        for _ in range(_ATTEMPTS_PER_MARKER):
            if budget <= 0:
                break
            brace = _last_brace(text, floor, brace)
            if brace < 0:
                break
            layer, spent = _decode_from(text, brace)
            budget -= spent
            if layer is None:
                continue
            try:
                configs = list(select(layer))
            except RecursionError:
                break
            if configs:
                break
        yield configs
        floor = found.start()


def _module_in_marked_layers(data: bytes) -> str | None:
    """Return a dangerous module a marked Lambda layer references, if one decodes."""
    text = data.decode("utf-8", errors="replace")
    for configs in _marked_layer_configs(text, _CLASS_MARKER_TEXT, _iter_lambda_configs):
        try:
            module = next(filter(None, map(_dangerous_module, configs)), None)
        except RecursionError:
            continue
        if module is not None:
            return module
    return None


class KerasLambdaRule(ArtifactRule):
    """Flag a Keras `Lambda` layer — arbitrary Python that runs when the model loads.

    So is a marshalled function (`__lambda__`) anywhere in a config, a callable named in
    a module such as `os` or `builtins`, and a `TFSMLayer`, which loads the SavedModel
    its config names. A `TFOpLambda` or `ClassMethod` layer, which calls the TensorFlow
    function or class method its config names, is flagged when that callable is more than
    tensor arithmetic or construction, and reported unread when it names none. An HDF5
    model is found by its signature under a shared name or none; one holding a compressed
    heap, which a byte search cannot read, is reported unread. A tf_keras SavedModel's
    `keras_metadata.pb` is searched like an HDF5 model. A layer is taken for a Lambda or a
    `TFSMLayer` when its `registered_name` names one, and a lookup layer reading its
    vocabulary from a file outside the model is a lead.
    """

    meta = RuleMeta(
        id="guardana.supply_chain.keras_lambda",
        title="Keras Lambda layer (arbitrary code on model load)",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM05_2025,
            OWASP_LLM10_2026,
            OWASP_ML06_2023,
            ATLAS_T0018,
            NIST_SUPPLY_CHAIN,
            OWASP_ASI05_2026,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
        detection=Detection.INVARIANT,
    )

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a `.keras` model with a Lambda layer, one without and one that is no archive."""
        return materialise(
            (
                _samples.sample(
                    "a .keras model declaring a Lambda layer",
                    FixtureOutcome.FINDING,
                    {
                        "model.keras": _samples.keras_archive(
                            [
                                {
                                    "class_name": "Lambda",
                                    "config": {"name": "fn", "function": "lambda x: x"},
                                }
                            ]
                        )
                    },
                ),
                _samples.sample(
                    "a .keras model of Dense layers only",
                    FixtureOutcome.CLEAN,
                    {
                        "model.keras": _samples.keras_archive(
                            [{"class_name": "Dense", "config": {"name": "dense", "units": 1}}]
                        )
                    },
                ),
                _samples.sample(
                    "a .keras file that is not a readable archive",
                    FixtureOutcome.INCONCLUSIVE,
                    {"model.keras": b"not a zip archive"},
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Parse Keras configs structurally; scan HDF5 models for the class markers."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files((".keras",)):
            yield from self._scan_keras(path, ctx)
            ctx.examined(path)
        for path in _directory_configs(target):
            config = _read_json_file(path)
            yield from self._scan_config(path, config, ctx, "not a readable Keras config")
            ctx.examined(path)
        for path in target.iter_files(_HDF5_SUFFIXES):
            yield from self._byte_scan(path, ctx, fallback_reason=None, hdf5=True)
            ctx.examined(path)
        for path in target.iter_files(_HDF5_SNIFFED_SUFFIXES):
            if _holds_hdf5_signature(path):
                yield from self._byte_scan(path, ctx, fallback_reason=None, hdf5=True)
                ctx.examined(path)
        for path in target.iter_files(_NO_SUFFIX):
            if _hdf5_in_head(path):
                yield from self._byte_scan(path, ctx, fallback_reason=None, hdf5=True)
                ctx.examined(path)
        yield from self._scan_tf_keras_metadata(target, ctx)

    def _scan_tf_keras_metadata(self, target: FileReader, ctx: RuleContext) -> Iterator[Finding]:
        """Search the layer metadata a tf_keras SavedModel is revived from."""
        for path in target.iter_files((".pb",)):
            if path.name.lower() == _TF_KERAS_METADATA:
                yield from self._byte_scan(path, ctx, fallback_reason=None)
                ctx.examined(path)

    def _scan_keras(self, path: Path, ctx: RuleContext) -> Iterator[Finding]:
        refusal, config = _checked_keras_config(path)
        if refusal is not None:
            # Listing an archive that declares this much costs more than any model does,
            # so it is never opened; its first bytes are still searched for the marker.
            yield from self._byte_scan(path, ctx, fallback_reason=refusal)
            return
        if isinstance(config, _OversizedConfig):
            # A prefix that parses is not the document Keras parses, which may go on to
            # declare anything, so the part read is searched and the rest named unread.
            yield from self._judge_bytes(
                path,
                config.prefix,
                ctx,
                fallback_reason=None,
                cut=f"its config.json is larger than {_MAX_CONFIG_BYTES} bytes; {_PARTLY_READ}",
            )
            return
        # Real `.keras` files are zip archives. A file that is not one is malformed, so
        # the byte marker is searched instead: a payload inside a deliberately broken
        # archive must not become invisible.
        yield from self._scan_config(path, config, ctx, "not a readable .keras archive")

    def _scan_config(
        self, path: Path, config: object, ctx: RuleContext, unreadable: str
    ) -> Iterator[Finding]:
        if config is _UNREADABLE:
            yield from self._byte_scan(path, ctx, fallback_reason=unreadable)
            return
        try:
            modules = [_dangerous_module(found) for found in _iter_lambda_configs(config)]
            tf_ops = list(_iter_class_nodes(config, _is_tf_call_class))
            callables = list(dict.fromkeys(_iter_load_callables(config)))
            saved_models = list(_iter_tfsm_layers(config))
            lookups = list(_iter_lookup_layers(config))
        except RecursionError:
            reason = "its model config is nested too deeply to walk"
            yield from self._byte_scan(path, ctx, fallback_reason=reason)
            return
        for module in modules:
            summary = "Keras Lambda layer runs arbitrary code on load"
            if module is not None:
                summary += f"; references the {module!r} module (near-certain malicious)"
            yield self._finding(path, summary)
        for summary in callables:
            yield self._finding(path, summary)
        yield from self._judge_tf_ops(path, tf_ops, ctx)
        yield from self._judge_saved_model_layers(path, saved_models, ctx)
        yield from self._judge_vocabularies(path, lookups)
        layers = modules or tf_ops or callables or saved_models or lookups
        if not layers and not isinstance(config, dict):
            # Keras writes the model as one object; any other root holds no layer to clear.
            yield self._unscanned(path, "the model config is not a JSON object", ctx)

    def _judge_tf_ops(
        self, path: Path, layers: list[object], ctx: RuleContext
    ) -> Iterator[Finding]:
        """Report each TF call layer that calls more than tensor arithmetic, or names nothing.

        Severity is the Lambda layer's: the config picks the code that runs on load, and a
        callable outside the arithmetic allowlist can read or write files or run a process.
        """
        calls = dict.fromkeys(_tf_call(layer) for layer in layers)
        for call in calls:
            if call.symbol is not None and not call.pure:
                yield self._finding(
                    path,
                    f"Keras {call.layer} layer calls tf.{call.symbol} on load, which is not a "
                    "pure math or array op",
                )
        for layer in dict.fromkeys(call.layer for call in calls if call.symbol is None):
            yield self._unscanned(
                path, f"a {layer} layer names no TensorFlow callable it could be judged by", ctx
            )

    def _byte_scan(
        self, path: Path, ctx: RuleContext, *, fallback_reason: str | None, hdf5: bool = False
    ) -> Iterator[Finding]:
        """Search a file's first bytes for the class markers.

        An `hdf5` file holding a compressed heap, where an attribute is stored as bytes no
        search can read, is reported unread beside whatever the search found.
        """
        prefix = read_bytes_bounded(path, _MAX_CONFIG_BYTES)
        if prefix is None:
            yield self._unscanned(path, "file could not be read", ctx)
            return
        data, truncated = prefix
        yield from self._judge_bytes(
            path,
            data,
            ctx,
            fallback_reason=fallback_reason,
            cut=_PARTLY_READ if truncated else None,
        )
        if hdf5 and _FILTERED_HEAP.search(data) is not None:
            yield self._unscanned(
                path,
                "it holds an HDF5 heap stored compressed, where its model config may sit unread",
                ctx,
            )

    def _judge_bytes(
        self,
        path: Path,
        data: bytes,
        ctx: RuleContext,
        *,
        fallback_reason: str | None,
        cut: str | None,
    ) -> Iterator[Finding]:
        """Search bytes read from `path` for class markers; `cut` says why the rest was not read.

        A Lambda found in the part read says nothing about the part that was not, so a cut
        is reported beside the finding.
        """
        found = _CLASS_MARKER.search(data) is not None
        # A Lambda layer holds its own marshalled function, so the other markers are
        # read only where no Lambda layer already accounts for them.
        callables = [] if found else _marked_load_callables(data)
        if found:
            # Firm, not a lead: the config declares the layer, and `load_model`
            # ignores `safe_mode` for the legacy format (CVE-2025-9905), so this
            # will execute.
            summary = "model config declares a Lambda layer, which runs on load"
            module = _module_in_marked_layers(data)
            if module is not None:
                summary += f"; references the {module!r} module (near-certain malicious)"
            yield self._finding(path, summary)
        elif callables:
            for summary in callables:
                yield self._finding(path, summary)
        elif cut is None and is_lfs_pointer(data):
            yield self._unscanned(path, LFS_POINTER_REASON, ctx)
        elif fallback_reason is not None:
            yield self._unscanned(path, fallback_reason, ctx)
        yield from self._judge_marked_layers(path, data, ctx)
        if cut is not None and (found or callables or fallback_reason is None):
            yield self._unscanned(path, cut, ctx)

    def _judge_marked_layers(self, path: Path, data: bytes, ctx: RuleContext) -> Iterator[Finding]:
        """Judge the TF call, TFSMLayer and lookup layers whose markers the bytes hold."""
        judges = (
            (_TF_OP_MARKER, self._judge_marked_tf_ops),
            (_TFSM_MARKER, self._judge_marked_saved_model_layers),
            (_LOOKUP_MARKER, self._judge_marked_vocabularies),
        )
        for marker, judge in judges:
            if marker.search(data) is not None:
                yield from judge(path, data, ctx)

    def _judge_marked_tf_ops(self, path: Path, data: bytes, ctx: RuleContext) -> Iterator[Finding]:
        """Judge the TF op layers marked in raw bytes; one whose layer does not decode is unread."""
        text = data.decode("utf-8", errors="replace")
        marked = list(
            _marked_layer_configs(
                text, _TF_OP_MARKER_TEXT, lambda layer: _iter_class_nodes(layer, _is_tf_call_class)
            )
        )
        yield from self._judge_tf_ops(path, [layer for each in marked for layer in each], ctx)
        if not all(marked):
            yield self._unscanned(
                path, "a TFOpLambda, SlicingOpLambda or ClassMethod layer could not be decoded", ctx
            )

    def _judge_saved_model_layers(
        self, path: Path, layers: list[object], ctx: RuleContext
    ) -> Iterator[Finding]:
        """Report the SavedModel each TFSMLayer loads; one naming no path is not scanned.

        Severity is the Lambda layer's: the graph loaded is chosen by the config, sits
        outside what was scanned, and its operators can read and write files.
        """
        paths = [_tfsm_path(layer) for layer in layers]
        for filepath in dict.fromkeys(found for found in paths if found is not None):
            shown = filepath[:_MAX_PATH_SHOWN] + ("..." if len(filepath) > _MAX_PATH_SHOWN else "")
            yield self._finding(
                path,
                f"Keras TFSMLayer loads the SavedModel at {shown!r} when the model loads, "
                "which Keras through 3.11 does whatever safe_mode says",
            )
        if None in paths:
            yield self._unscanned(path, "a TFSMLayer layer names no SavedModel path", ctx)

    def _judge_marked_saved_model_layers(
        self, path: Path, data: bytes, ctx: RuleContext
    ) -> Iterator[Finding]:
        """Judge the TFSMLayer layers marked in raw bytes; one that does not decode is unread."""
        text = data.decode("utf-8", errors="replace")
        marked = list(_marked_layer_configs(text, _TFSM_MARKER_TEXT, _iter_tfsm_layers))
        yield from self._judge_saved_model_layers(
            path, [layer for each in marked for layer in each], ctx
        )
        if not all(marked):
            yield self._unscanned(path, "a TFSMLayer layer could not be decoded", ctx)

    def _judge_vocabularies(self, path: Path, layers: list[object]) -> Iterator[Finding]:
        """Report each vocabulary file a lookup layer reads from outside the model, as a lead."""
        found = (_outside_vocabulary(layer) for layer in layers)
        for vocabulary in dict.fromkeys(each for each in found if each is not None):
            shown = vocabulary.path[:_MAX_PATH_SHOWN] + (
                "..." if len(vocabulary.path) > _MAX_PATH_SHOWN else ""
            )
            yield Finding(
                rule_id=self.meta.id,
                severity=SavedModelOpsRule.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=str(path),
                evidence=Evidence(
                    summary=(
                        f"Keras {vocabulary.layer} layer reads its vocabulary from {shown!r}, "
                        "outside the model, when the model loads"
                    ),
                    detail=f"file={path.name}",
                ),
                verdict=lead_verdict(
                    f"{vocabulary.layer} names that file; a model built from a vocabulary "
                    "file keeps its path, so a lead, not a verdict"
                ),
            )

    def _judge_marked_vocabularies(
        self, path: Path, data: bytes, ctx: RuleContext
    ) -> Iterator[Finding]:
        """Judge the lookup layers marked in raw bytes; one that does not decode is unread."""
        text = data.decode("utf-8", errors="replace")
        marked = list(_marked_layer_configs(text, _LOOKUP_MARKER_TEXT, _iter_lookup_layers))
        yield from self._judge_vocabularies(path, [layer for each in marked for layer in each])
        if not all(marked):
            layers = f"{', '.join(_LOOKUP_LAYERS[:-1])} or {_LOOKUP_LAYERS[-1]}"
            yield self._unscanned(path, f"a {layers} layer could not be decoded", ctx)

    def _finding(self, path: Path, summary: str) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(summary=summary, detail=f"file={path.name}"),
        )

    def _unscanned(self, path: Path, reason: str, ctx: RuleContext) -> Finding:
        ctx.shortfall(unread_component(self.meta.id, path, reason))
        return Finding(
            rule_id=self.meta.id,
            severity=Severity.LOW,
            title=_UNSCANNED_TITLE,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=f"Keras model not scanned for Lambda layers: {reason}",
                detail=f"file={path.name}",
            ),
            verdict=unscanned_verdict("the model config could not be read, so nothing was cleared"),
        )


def _directory_configs(target: FileReader) -> list[Path]:
    """Return each `config.json` the listing holds beside a file only Keras writes, any case."""
    listed = {
        (path.parent, path.name.lower()) for path in target.iter_files((".json", ".h5", ".npz"))
    }
    return [
        path
        for path in target.iter_files((".json",))
        if path.name.lower() == _DIRECTORY_CONFIG
        and any((path.parent, sibling) in listed for sibling in _DIRECTORY_SIBLINGS)
    ]


def _hdf5_in_head(path: Path) -> bool:
    """Whether the first bytes of a file with no suffix hold the HDF5 signature; one read."""
    head = read_bytes_bounded(path, HDF5_HEAD_BYTES)
    return head is not None and find_hdf5_signature_in_head(head[0]) is not None


def _holds_hdf5_signature(path: Path) -> bool:
    """Whether the HDF5 library would open `path`, wherever its userblock puts the signature.

    A signature past the read bound still counts: the byte scan then reports the file
    as read only in part instead of passing over it.
    """
    try:
        if not path.is_file():
            return False
        with path.open("rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            return find_hdf5_signature(handle, size) is not None
    except OSError:
        return False


def _read_json_file(path: Path) -> object:
    """Read and parse a JSON file within the read bound; `_UNREADABLE` if unreadable or cut."""
    prefix = read_bytes_bounded(path, _MAX_CONFIG_BYTES)
    if prefix is None or prefix[1]:
        return _UNREADABLE
    try:
        parsed: object = json.loads(prefix[0])
    except (ValueError, RecursionError):
        return _UNREADABLE
    return parsed


def _checked_keras_config(path: Path) -> tuple[str | None, object]:
    """Why a `.keras` archive must not be listed, else its parsed `config.json`.

    Both come from one open handle, so the archive `zipfile` lists is the one the bounds
    were checked on. The config is `_UNREADABLE` when the archive was refused, is not a
    regular file or cannot be read, and an `_OversizedConfig` when it is longer than the
    read bound.
    """
    try:
        with io.BufferedReader(open_regular(path)) as handle:
            refusal = listing_refusal(
                handle, max_entries=ARCHIVE_MAX_ENTRIES, max_directory_bytes=ZIP_DIRECTORY_MAX_BYTES
            )
            if refusal is not None:
                return refusal, _UNREADABLE
            return None, _read_keras_config(handle)
    except (OSError, ValueError, OverflowError, struct.error):
        return None, _UNREADABLE


def _read_keras_config(handle: BinaryIO) -> object:
    """Read and parse `config.json` from a `.keras` archive; see `_checked_keras_config`."""
    try:
        with zipfile.ZipFile(handle) as archive:
            if "config.json" not in archive.namelist():
                return _UNREADABLE
            with archive.open("config.json") as member:
                raw = member.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES:
            return _OversizedConfig(raw[:_MAX_CONFIG_BYTES])
        parsed: object = json.loads(raw)
    except (*ZIP_ERRORS, RecursionError):
        return _UNREADABLE
    else:
        return parsed
