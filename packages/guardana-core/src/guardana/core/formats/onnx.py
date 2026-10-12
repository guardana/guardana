import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from guardana.core.formats._protobuf import WIRE_LENGTH, ProtoField, ProtoReader
from guardana.core.formats._stream import open_regular
from guardana.core.formats.errors import FormatError
from guardana.core.formats.limits import DEFAULT_LIMITS, Limits

# ONNX field numbers, from the published `onnx.proto` schema. Only the handful a
# static check needs are named — everything else is skipped without being read.
_MODEL_PRODUCER = 2
_MODEL_GRAPH = 7
_MODEL_OPSET = 8
_MODEL_METADATA = 14
_MODEL_TRAINING_INFO = 20
_MODEL_FUNCTIONS = 25
_OPSET_DOMAIN = 1
_GRAPH_NODE = 1
_GRAPH_INITIALIZER = 5
_GRAPH_SPARSE_INITIALIZER = 15
_NODE_ATTRIBUTE = 5
_NODE_DOMAIN = 7
_ATTRIBUTE_TENSORS = frozenset({5, 10})  # t, tensors
_ATTRIBUTE_GRAPHS = frozenset({6, 11})  # g, graphs
_ATTRIBUTE_SPARSE_TENSORS = frozenset({22, 23})  # sparse_tensor, sparse_tensors
_SPARSE_TENSOR_PARTS = frozenset({1, 2})  # values, indices
_FUNCTION_NODE = 7
_FUNCTION_ATTRIBUTE_DEFAULT = 11
_TRAINING_GRAPHS = frozenset({1, 2})  # initialization, algorithm
_TENSOR_EXTERNAL_DATA = 13
_ENTRY_KEY = 1
_ENTRY_VALUE = 2
_EXTERNAL_LOCATION_KEY = "location"

# Subgraphs nest through node attributes (`If`, `Loop`, `Scan`), three messages per
# level. Protobuf's default parser stops at 100 nested messages, so a model the onnx
# package can load stays inside this bound and a deeper one is a partial walk.
_MAX_GRAPH_DEPTH = 32

# The operator domains every ONNX runtime implements natively. Anything else
# means the model needs a custom operator library registered before it can run —
# i.e. machine code loaded at inference time.
STANDARD_ONNX_DOMAINS = frozenset(
    {"", "ai.onnx", "ai.onnx.ml", "ai.onnx.training", "ai.onnx.preview.training"}
)


@dataclass(frozen=True)
class OnnxSummary:
    """What a static check needs from an ONNX model, without loading the graph.

    Node domains and external-data paths are gathered from every graph the model
    carries: the main graph, subgraphs held in node attributes, model-local
    functions and training graphs. `truncated` reports a partial view — the field
    budget ran out, subgraphs nested past the depth bound, or metadata exceeded
    `max_header_bytes` — which a caller must not mistake for a complete one. A node
    or opset import that states its domain more than once contributes every value,
    and a metadata key stated more than once keeps every value, newline-joined.
    """

    producer: str
    opset_domains: tuple[str, ...]
    node_domains: tuple[str, ...]
    metadata_props: Mapping[str, str]
    external_data_paths: tuple[str, ...]
    truncated: bool


def read_onnx_summary(path: Path, *, limits: Limits = DEFAULT_LIMITS) -> OnnxSummary:
    """Summarise an ONNX model's structure, bounded by `limits`.

    Streams from disk and seeks past tensor payloads, so a multi-gigabyte model
    costs a few kilobytes of reading. Raises `FormatError` when the bytes are not
    a walkable protobuf message, or when a message walked in full holds no graph:
    an empty file parses as an empty message, and that is no model.
    """
    with open_regular(path) as handle:
        size = os.fstat(handle.fileno()).st_size
        walk = _GraphWalk(ProtoReader(handle, max_fields=limits.max_entries), limits)
        reader = walk.reader
        producer = ""
        opset_domains: list[str] = []
        metadata: dict[str, list[str]] = {}
        metadata_bytes = 0
        has_graph = False
        for field in reader.fields(0, size):
            if field.wire_type != WIRE_LENGTH:
                continue
            if field.number == _MODEL_PRODUCER:
                producer = reader.text(field, limits.max_string_bytes)
            elif field.number == _MODEL_OPSET:
                opset_domains.extend(_sub_texts(reader, field, _OPSET_DOMAIN, limits))
            elif field.number == _MODEL_METADATA:
                metadata_bytes += field.end - field.start
                if metadata_bytes > limits.max_header_bytes:
                    walk.truncated = True
                    continue
                key, value = _entry(reader, field, limits)
                # A repeated field: the onnx package keeps every entry, so a key stated
                # twice keeps every value, and one cannot hide the other.
                metadata.setdefault(key, []).append(value)
            elif field.number == _MODEL_GRAPH:
                has_graph = True
                walk.graph(field, depth=0)
            elif field.number == _MODEL_FUNCTIONS:
                walk.function(field)
            elif field.number == _MODEL_TRAINING_INFO:
                walk.training_info(field)
        _require_graph(has_graph=has_graph, partial=reader.truncated)
        return OnnxSummary(
            producer=producer,
            opset_domains=tuple(opset_domains),
            node_domains=tuple(walk.node_domains),
            metadata_props=MappingProxyType(
                {key: "\n".join(values) for key, values in metadata.items()}
            ),
            external_data_paths=tuple(walk.external),
            truncated=walk.truncated or reader.truncated,
        )


def _require_graph(*, has_graph: bool, partial: bool) -> None:
    """Refuse a model walked in full that holds no graph.

    A walk the field budget cut short may have stopped before the graph, and it is
    already reported as partial.
    """
    if not has_graph and not partial:
        raise FormatError("ONNX model without a graph")


class _GraphWalk:
    """Collects node domains and external-data paths from every graph a model holds."""

    def __init__(self, reader: ProtoReader, limits: Limits) -> None:
        self.reader = reader
        self.limits = limits
        self.node_domains: list[str] = []
        self.external: list[str] = []
        self.truncated = False

    def graph(self, graph: ProtoField, *, depth: int) -> None:
        """Walk a `GraphProto`'s nodes and initializers, nested subgraphs included."""
        if depth > _MAX_GRAPH_DEPTH:
            self.truncated = True
            return
        for field in self._messages(graph):
            if field.number == _GRAPH_NODE:
                self.node(field, depth=depth)
            elif field.number == _GRAPH_INITIALIZER:
                self.tensor(field)
            elif field.number == _GRAPH_SPARSE_INITIALIZER:
                self.sparse_tensor(field)

    def node(self, node: ProtoField, *, depth: int) -> None:
        """Record a `NodeProto`'s domain and walk the tensors and graphs its attributes hold."""
        domains: list[str] = []
        attributes: list[ProtoField] = []
        for field in self._messages(node):
            if field.number == _NODE_DOMAIN:
                domains.append(self.reader.text(field, self.limits.max_string_bytes))
            elif field.number == _NODE_ATTRIBUTE:
                attributes.append(field)
        self.node_domains.extend(domains or ("",))
        for attribute in attributes:
            self.attribute(attribute, depth=depth)

    def attribute(self, attribute: ProtoField, *, depth: int) -> None:
        """Walk the tensors, sparse tensors and subgraphs an `AttributeProto` carries."""
        for field in self._messages(attribute):
            if field.number in _ATTRIBUTE_TENSORS:
                self.tensor(field)
            elif field.number in _ATTRIBUTE_GRAPHS:
                self.graph(field, depth=depth + 1)
            elif field.number in _ATTRIBUTE_SPARSE_TENSORS:
                self.sparse_tensor(field)

    def function(self, function: ProtoField) -> None:
        """Walk a model-local `FunctionProto`'s nodes and default attribute values."""
        for field in self._messages(function):
            if field.number == _FUNCTION_NODE:
                self.node(field, depth=0)
            elif field.number == _FUNCTION_ATTRIBUTE_DEFAULT:
                self.attribute(field, depth=0)

    def training_info(self, info: ProtoField) -> None:
        """Walk a `TrainingInfoProto`'s initialization and algorithm graphs."""
        for field in self._messages(info):
            if field.number in _TRAINING_GRAPHS:
                self.graph(field, depth=0)

    def sparse_tensor(self, sparse: ProtoField) -> None:
        """Walk the values and indices tensors of a `SparseTensorProto`."""
        for field in self._messages(sparse):
            if field.number in _SPARSE_TENSOR_PARTS:
                self.tensor(field)

    def tensor(self, tensor: ProtoField) -> None:
        """Record the file a `TensorProto` keeps its data in, if it names one."""
        for field in self._messages(tensor):
            if field.number == _TENSOR_EXTERNAL_DATA:
                key, value = _entry(self.reader, field, self.limits)
                if key == _EXTERNAL_LOCATION_KEY:
                    self.external.append(value)

    def _messages(self, parent: ProtoField) -> Iterator[ProtoField]:
        return (
            field
            for field in self.reader.fields(parent.start, parent.end)
            if field.wire_type == WIRE_LENGTH
        )


def _entry(reader: ProtoReader, entry: ProtoField, limits: Limits) -> tuple[str, str]:
    key = value = ""
    for field in reader.fields(entry.start, entry.end):
        if field.wire_type != WIRE_LENGTH:
            continue
        if field.number == _ENTRY_KEY:
            key = reader.text(field, limits.max_string_bytes)
        elif field.number == _ENTRY_VALUE:
            value = reader.text(field, limits.max_string_bytes)
    return key, value


def _sub_texts(
    reader: ProtoReader, parent: ProtoField, number: int, limits: Limits
) -> tuple[str, ...]:
    """Read every occurrence of a string sub-field; an absent one is the empty default.

    Protobuf keeps the last of a repeated singular field and other parsers the first,
    so each stated value is reported rather than betting on one of them.
    """
    texts = tuple(
        reader.text(field, limits.max_string_bytes)
        for field in reader.fields(parent.start, parent.end)
        if field.wire_type == WIRE_LENGTH and field.number == number
    )
    return texts or ("",)
