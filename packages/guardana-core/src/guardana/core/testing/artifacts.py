import json
import struct
from collections.abc import Mapping, Sequence
from typing import Final

from guardana.core.formats.gguf import GgufValue

_MAGIC: Final = b"GGUF"
_DEFAULT_VERSION: Final = 3
_TYPE_BOOL: Final = 7
_TYPE_STRING: Final = 8
_TYPE_ARRAY: Final = 9
_TYPE_INT64: Final = 11
_TYPE_FLOAT64: Final = 12

_PROTO_WIRE_LENGTH: Final = 2
_ONNX_MODEL_PRODUCER: Final = 2
_ONNX_MODEL_GRAPH: Final = 7
_ONNX_MODEL_OPSET: Final = 8
_ONNX_MODEL_METADATA: Final = 14
_ONNX_OPSET_DOMAIN: Final = 1
_ONNX_GRAPH_NODE: Final = 1
_ONNX_GRAPH_INITIALIZER: Final = 5
_ONNX_NODE_OP_TYPE: Final = 4
_ONNX_NODE_DOMAIN: Final = 7
_ONNX_TENSOR_EXTERNAL_DATA: Final = 13
_ONNX_ENTRY_KEY: Final = 1
_ONNX_ENTRY_VALUE: Final = 2
_ONNX_LOCATION_KEY: Final = "location"

_DEFAULT_TENSORS: Final[Mapping[str, Mapping[str, object]]] = {
    "weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}
}


def build_gguf(
    entries: Mapping[str, GgufValue],
    *,
    version: int = _DEFAULT_VERSION,
    tensor_count: int = 0,
) -> bytes:
    """Build a well-formed GGUF file carrying `entries` as its metadata block.

    The fixture builder for any rule that inspects GGUF metadata — a malicious
    chat template is one dict entry away, with no binary hand-crafting:

        payload = "{{ lipsum.__globals__['os'].popen('id').read() }}"
        (tmp_path / "m.gguf").write_bytes(build_gguf({"tokenizer.chat_template": payload}))

    Value types are inferred: `str`, `bool`, `int`, `float`, and a homogeneous
    `tuple` (an array; an empty one is written as an array of strings).
    """
    body = b"".join(_packed_string(key) + _packed_value(value) for key, value in entries.items())
    header = (
        _MAGIC
        + struct.pack("<I", version)
        + struct.pack("<Q", tensor_count)
        + struct.pack("<Q", len(entries))
    )
    return header + body


def build_safetensors(
    tensors: Mapping[str, Mapping[str, object]] | None = None,
    *,
    metadata: Mapping[str, str] | None = None,
    data: bytes = b"\x00\x00\x00\x00",
) -> bytes:
    """Build a well-formed safetensors file, optionally carrying a `__metadata__` block.

    The negative fixture for any artifact rule (a safetensors file has no
    code-execution surface, so a rule must stay silent on one) and the positive
    fixture for anything that inspects `__metadata__`.
    """
    header: dict[str, object] = dict(tensors if tensors is not None else _DEFAULT_TENSORS)
    if metadata is not None:
        header["__metadata__"] = dict(metadata)
    raw = json.dumps(header).encode()
    return len(raw).to_bytes(8, "little") + raw + data


def _packed_string(text: str) -> bytes:
    raw = text.encode()
    return struct.pack("<Q", len(raw)) + raw


def _packed_value(value: GgufValue) -> bytes:
    return struct.pack("<I", _type_code(value)) + _payload(value)


def _type_code(value: GgufValue) -> int:
    if isinstance(value, bool):  # checked before int: bool is an int subclass
        return _TYPE_BOOL
    if isinstance(value, str):
        return _TYPE_STRING
    if isinstance(value, int):
        return _TYPE_INT64
    if isinstance(value, float):
        return _TYPE_FLOAT64
    if isinstance(value, tuple):
        return _TYPE_ARRAY
    raise TypeError(f"cannot encode {type(value).__name__} as a GGUF value")


def _payload(value: GgufValue) -> bytes:
    if isinstance(value, bool):
        return b"\x01" if value else b"\x00"
    if isinstance(value, str):
        return _packed_string(value)
    if isinstance(value, int):
        return struct.pack("<q", value)
    if isinstance(value, float):
        return struct.pack("<d", value)
    element_type = _type_code(value[0]) if value else _TYPE_STRING
    items = b"".join(_payload(item) for item in value)
    return struct.pack("<I", element_type) + struct.pack("<Q", len(value)) + items


def build_onnx(
    *,
    nodes: Sequence[tuple[str, str]] = (),
    producer: str = "",
    opset_domains: Sequence[str] = (),
    metadata: Mapping[str, str] | None = None,
    external_paths: Sequence[str] = (),
) -> bytes:
    """Build a walkable ONNX `ModelProto` carrying the structure a rule inspects.

    `nodes` are `(op_type, domain)` pairs — an empty domain is the default ONNX
    one. The fixture builder for operator-domain, metadata, and external-data
    checks, with no protobuf toolchain required:

        payload = build_onnx(nodes=(("Conv", ""),), external_paths=("../../etc/passwd",))
    """
    graph = b"".join(
        _proto_delimited(_ONNX_GRAPH_NODE, _onnx_node(op, domain)) for op, domain in nodes
    )
    graph += b"".join(
        _proto_delimited(_ONNX_GRAPH_INITIALIZER, _onnx_tensor(path)) for path in external_paths
    )
    model = _proto_string(_ONNX_MODEL_PRODUCER, producer) if producer else b""
    model += _proto_delimited(_ONNX_MODEL_GRAPH, graph)
    model += b"".join(
        _proto_delimited(_ONNX_MODEL_OPSET, _proto_string(_ONNX_OPSET_DOMAIN, domain))
        for domain in opset_domains
    )
    model += b"".join(
        _proto_delimited(_ONNX_MODEL_METADATA, _proto_entry(key, value))
        for key, value in (metadata or {}).items()
    )
    return model


def _onnx_node(op_type: str, domain: str) -> bytes:
    node = _proto_string(_ONNX_NODE_OP_TYPE, op_type)
    return node + (_proto_string(_ONNX_NODE_DOMAIN, domain) if domain else b"")


def _onnx_tensor(location: str) -> bytes:
    return _proto_delimited(_ONNX_TENSOR_EXTERNAL_DATA, _proto_entry(_ONNX_LOCATION_KEY, location))


def _proto_entry(key: str, value: str) -> bytes:
    return _proto_string(_ONNX_ENTRY_KEY, key) + _proto_string(_ONNX_ENTRY_VALUE, value)


def _proto_string(number: int, text: str) -> bytes:
    return _proto_delimited(number, text.encode())


def _proto_delimited(number: int, payload: bytes) -> bytes:
    return _proto_varint(number << 3 | _PROTO_WIRE_LENGTH) + _proto_varint(len(payload)) + payload


def _proto_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)
