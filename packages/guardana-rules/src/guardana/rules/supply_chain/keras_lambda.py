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
from guardana.rules.supply_chain._leads import unread_component, unscanned_verdict
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
# An unzipped Keras model is a directory holding `config.json`; one beside either
# of Keras' own files is read, while a lone `config.json` belongs to anything.
_DIRECTORY_CONFIG = "config.json"
_DIRECTORY_SIBLINGS = ("metadata.json", "model.weights.h5")


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


def _class_marker(*words: str) -> re.Pattern[bytes]:
    """Build the pattern of a `class_name` pair naming one of `words`, bare or dotted."""
    return re.compile(
        b'"'
        + _json_spelling("class_name")
        + b'"[ \t\n\r]*:[ \t\n\r]*"(?:'
        + _JSON_STRING_CHAR
        + b"*"
        + _json_spelling(".")
        + b")?(?:"
        + b"|".join(_json_spelling(word) for word in words)
        + b')"'
    )


# A Lambda layer declares itself with this key/value pair; matching the bare word
# "Lambda" reported any layer a user happened to *name* "Lambda". Keras resolves a
# dotted class name through its export registry (`layers.Lambda` under module
# `keras`), and reads the config with `json.loads`, so the pattern accepts any
# dotted prefix and every spelling that decoder turns into the pair: any character
# as a unicode escape, JSON whitespace around the colon.
_CLASS_MARKER = _class_marker(_LAMBDA)
_CLASS_MARKER_TEXT = re.compile(_CLASS_MARKER.pattern.decode("ascii"))
# tf_keras rebuilds these layers by looking the TensorFlow function their config names up
# in the `tf` namespace and calling it, so the config chooses what runs; `ClassMethod`
# does the same with a class and the name of a method called on it.
_TF_OP_LAYERS = ("TFOpLambda", "SlicingOpLambda")
_CLASS_METHOD_LAYER = "ClassMethod"
_TF_OP_MARKER = _class_marker(*_TF_OP_LAYERS, _CLASS_METHOD_LAYER)
_TF_OP_MARKER_TEXT = re.compile(_TF_OP_MARKER.pattern.decode("ascii"))
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


def _iter_class_nodes(node: object, is_class: Callable[[object], bool]) -> Iterator[object]:
    """Yield every object in the tree whose `class_name` `is_class` accepts."""
    if isinstance(node, dict):
        if is_class(node.get("class_name")):
            yield node
        for value in node.values():
            yield from _iter_class_nodes(value, is_class)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_class_nodes(item, is_class)


def _iter_class_configs(node: object, is_class: Callable[[object], bool]) -> Iterator[object]:
    """Yield the `config` of every object in the tree whose `class_name` `is_class` accepts."""
    for found in _iter_class_nodes(node, is_class):
        yield found.get("config") if isinstance(found, dict) else None


def _iter_lambda_configs(node: object) -> Iterator[object]:
    """Yield the `config` of every object in the tree whose `class_name` is Lambda."""
    return _iter_class_configs(node, _is_lambda_class)


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

    A `TFOpLambda` or `ClassMethod` layer, which calls the TensorFlow function or class
    method its config names, is flagged when that callable is more than tensor arithmetic
    or construction, and reported unread when it names none. An HDF5 model is found by its
    signature under a shared name or none; one holding a compressed heap, which a byte
    search cannot read, is reported unread.
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
        except RecursionError:
            reason = "its model config is nested too deeply to walk"
            yield from self._byte_scan(path, ctx, fallback_reason=reason)
            return
        for module in modules:
            summary = "Keras Lambda layer runs arbitrary code on load"
            if module is not None:
                summary += f"; references the {module!r} module (near-certain malicious)"
            yield self._finding(path, summary)
        yield from self._judge_tf_ops(path, tf_ops, ctx)
        if not modules and not tf_ops and not isinstance(config, dict):
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
        if found:
            # Firm, not a lead: the config declares the layer, and `load_model`
            # ignores `safe_mode` for the legacy format (CVE-2025-9905), so this
            # will execute.
            summary = "model config declares a Lambda layer, which runs on load"
            module = _module_in_marked_layers(data)
            if module is not None:
                summary += f"; references the {module!r} module (near-certain malicious)"
            yield self._finding(path, summary)
        elif cut is None and is_lfs_pointer(data):
            yield self._unscanned(path, LFS_POINTER_REASON, ctx)
        elif fallback_reason is not None:
            yield self._unscanned(path, fallback_reason, ctx)
        if _TF_OP_MARKER.search(data) is not None:
            yield from self._judge_marked_tf_ops(path, data, ctx)
        if cut is not None and (found or fallback_reason is None):
            yield self._unscanned(path, cut, ctx)

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
    listed = {(path.parent, path.name.lower()) for path in target.iter_files((".json", ".h5"))}
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
