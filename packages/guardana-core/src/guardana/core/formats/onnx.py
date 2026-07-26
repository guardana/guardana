import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from guardana.core.formats._protobuf import WIRE_LENGTH, ProtoField, ProtoReader
from guardana.core.formats._stream import open_regular
from guardana.core.formats.limits import DEFAULT_LIMITS, Limits

# ONNX field numbers, from the published `onnx.proto` schema. Only the handful a
# static check needs are named — everything else is skipped without being read.
_MODEL_PRODUCER = 2
_MODEL_GRAPH = 7
_MODEL_OPSET = 8
_MODEL_METADATA = 14
_OPSET_DOMAIN = 1
_GRAPH_NODE = 1
_GRAPH_INITIALIZER = 5
_NODE_DOMAIN = 7
_TENSOR_EXTERNAL_DATA = 13
_ENTRY_KEY = 1
_ENTRY_VALUE = 2
_EXTERNAL_LOCATION_KEY = "location"

# The operator domains every ONNX runtime implements natively. Anything else
# means the model needs a custom operator library registered before it can run —
# i.e. machine code loaded at inference time.
STANDARD_ONNX_DOMAINS = frozenset(
    {"", "ai.onnx", "ai.onnx.ml", "ai.onnx.training", "ai.onnx.preview.training"}
)


@dataclass(frozen=True)
class OnnxSummary:
    """What a static check needs from an ONNX model, without loading the graph.

    `truncated` reports that the field budget ran out before the walk finished —
    a partial view, which a caller must not mistake for a complete one.
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
    a walkable protobuf message.
    """
    with open_regular(path) as handle:
        size = os.fstat(handle.fileno()).st_size
        reader = ProtoReader(handle, max_fields=limits.max_entries)
        producer = ""
        opset_domains: list[str] = []
        node_domains: list[str] = []
        metadata: dict[str, str] = {}
        external: list[str] = []
        for field in reader.fields(0, size):
            if field.wire_type != WIRE_LENGTH:
                continue
            if field.number == _MODEL_PRODUCER:
                producer = reader.text(field, limits.max_string_bytes)
            elif field.number == _MODEL_OPSET:
                opset_domains.append(_sub_text(reader, field, _OPSET_DOMAIN, limits))
            elif field.number == _MODEL_METADATA:
                key, value = _entry(reader, field, limits)
                metadata[key] = value
            elif field.number == _MODEL_GRAPH:
                _walk_graph(reader, field, limits, node_domains, external)
        return OnnxSummary(
            producer=producer,
            opset_domains=tuple(opset_domains),
            node_domains=tuple(node_domains),
            metadata_props=MappingProxyType(metadata),
            external_data_paths=tuple(external),
            truncated=reader.truncated,
        )


def _walk_graph(
    reader: ProtoReader,
    graph: ProtoField,
    limits: Limits,
    node_domains: list[str],
    external: list[str],
) -> None:
    for field in reader.fields(graph.start, graph.end):
        if field.wire_type != WIRE_LENGTH:
            continue
        if field.number == _GRAPH_NODE:
            node_domains.append(_sub_text(reader, field, _NODE_DOMAIN, limits))
        elif field.number == _GRAPH_INITIALIZER:
            external.extend(_external_locations(reader, field, limits))


def _external_locations(reader: ProtoReader, tensor: ProtoField, limits: Limits) -> Iterator[str]:
    for field in reader.fields(tensor.start, tensor.end):
        if field.wire_type == WIRE_LENGTH and field.number == _TENSOR_EXTERNAL_DATA:
            key, value = _entry(reader, field, limits)
            if key == _EXTERNAL_LOCATION_KEY:
                yield value


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


def _sub_text(reader: ProtoReader, parent: ProtoField, number: int, limits: Limits) -> str:
    """Read one string sub-field; an absent one is the empty protobuf default."""
    for field in reader.fields(parent.start, parent.end):
        if field.wire_type == WIRE_LENGTH and field.number == number:
            return reader.text(field, limits.max_string_bytes)
    return ""
