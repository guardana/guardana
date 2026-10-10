"""ONNX models that hide an external-data path or a custom operator domain off the top level.

Each carrier is a place the ONNX loader or runtime reaches that a walk of only the
top-level nodes and initializers never reads. Shared by the format reader's tests and
the rule's, so a carrier added here is checked at both seams.
"""

from typing import Final, NamedTuple

__all__ = [
    "CARRIERS",
    "CUSTOM_DOMAIN",
    "OUTSIDE_PATH",
    "Carrier",
    "attribute",
    "delimited",
    "graph_of",
    "large_honest_model",
    "model_with_graph",
    "nested_subgraphs",
    "node",
    "text",
]

OUTSIDE_PATH: Final = "../../outside.bin"
CUSTOM_DOMAIN: Final = "com.evil.ops"

_WIRE_LENGTH: Final = 2


class Carrier(NamedTuple):
    """A model and what a complete walk of it must report."""

    name: str
    model: bytes
    external_path: str | None
    custom_domain: str | None


def varint(value: int) -> bytes:
    """Encode `value` as a protobuf varint."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def delimited(number: int, payload: bytes) -> bytes:
    """A length-delimited protobuf field."""
    return varint(number << 3 | _WIRE_LENGTH) + varint(len(payload)) + payload


def text(number: int, value: str) -> bytes:
    """A string protobuf field."""
    return delimited(number, value.encode())


def external_tensor(location: str = OUTSIDE_PATH) -> bytes:
    """A `TensorProto` whose data lives in the file `location` names."""
    return delimited(13, text(1, "location") + text(2, location))


def node(domain: str = "", *attributes: bytes) -> bytes:
    """A `NodeProto` in `domain`, carrying each `AttributeProto` given."""
    head = text(4, "Op") + (text(7, domain) if domain else b"")
    return head + b"".join(delimited(5, attribute) for attribute in attributes)


def attribute(number: int, payload: bytes) -> bytes:
    """An `AttributeProto` with `payload` in field `number` (t=5, g=6, tensors=10, ...)."""
    return text(1, "value") + delimited(number, payload)


def graph_of(*nodes: bytes) -> bytes:
    """A `GraphProto` body holding `nodes`."""
    return b"".join(delimited(1, item) for item in nodes)


def model_with_graph(graph: bytes) -> bytes:
    """A `ModelProto` whose main graph is `graph`."""
    return delimited(7, graph)


def nested_subgraphs(depth: int, innermost: bytes) -> bytes:
    """A main graph whose node holds a subgraph `depth` levels deep, ending in `innermost`."""
    graph = graph_of(innermost)
    for _ in range(depth):
        graph = graph_of(node("", attribute(6, graph)))
    return model_with_graph(graph)


_EXTERNAL = external_tensor()
_CUSTOM_NODE = node(CUSTOM_DOMAIN)

CARRIERS: Final = (
    Carrier(
        "Constant node attribute tensor",
        model_with_graph(graph_of(node("", attribute(5, _EXTERNAL)))),
        OUTSIDE_PATH,
        None,
    ),
    Carrier(
        "attribute tensor list",
        model_with_graph(graph_of(node("", attribute(10, _EXTERNAL)))),
        OUTSIDE_PATH,
        None,
    ),
    Carrier(
        "attribute sparse tensor values",
        model_with_graph(graph_of(node("", attribute(22, delimited(1, _EXTERNAL))))),
        OUTSIDE_PATH,
        None,
    ),
    Carrier(
        "attribute sparse tensor list indices",
        model_with_graph(graph_of(node("", attribute(23, delimited(2, _EXTERNAL))))),
        OUTSIDE_PATH,
        None,
    ),
    Carrier(
        "graph sparse initializer",
        model_with_graph(delimited(15, delimited(1, _EXTERNAL))),
        OUTSIDE_PATH,
        None,
    ),
    Carrier(
        "If then_branch subgraph initializer",
        model_with_graph(graph_of(node("", attribute(6, delimited(5, _EXTERNAL))))),
        OUTSIDE_PATH,
        None,
    ),
    Carrier(
        "If then_branch subgraph node",
        model_with_graph(graph_of(node("", attribute(6, graph_of(_CUSTOM_NODE))))),
        None,
        CUSTOM_DOMAIN,
    ),
    Carrier(
        "Loop body in an attribute graph list",
        model_with_graph(graph_of(node("", attribute(11, graph_of(_CUSTOM_NODE))))),
        None,
        CUSTOM_DOMAIN,
    ),
    Carrier(
        "model-local function node",
        delimited(25, text(1, "fn") + delimited(7, _CUSTOM_NODE)),
        None,
        CUSTOM_DOMAIN,
    ),
    Carrier(
        "model-local function node attribute tensor",
        delimited(25, text(1, "fn") + delimited(7, node("", attribute(5, _EXTERNAL)))),
        OUTSIDE_PATH,
        None,
    ),
    Carrier(
        "model-local function default attribute tensor",
        delimited(25, text(1, "fn") + delimited(11, attribute(5, _EXTERNAL))),
        OUTSIDE_PATH,
        None,
    ),
    Carrier(
        "training initialization graph",
        delimited(20, delimited(1, delimited(5, _EXTERNAL))),
        OUTSIDE_PATH,
        None,
    ),
    Carrier(
        "training algorithm graph",
        delimited(20, delimited(2, graph_of(_CUSTOM_NODE))),
        None,
        CUSTOM_DOMAIN,
    ),
)


_OPERATORS: Final = ("MatMul", "Add", "Mul", "Reshape", "Transpose", "Softmax", "Gather", "Concat")


def _honest_attribute(index: int, kind: int) -> bytes:
    """An `AttributeProto` of one of five common shapes, with its `type` (field 20)."""
    name = text(1, ("axis", "perm", "alpha", "mode", "keepdims")[kind])
    if kind == 1:
        value = b"".join(varint(8 << 3) + varint(item) for item in (0, 2, 1, 3))
        type_code = 7
    elif kind == 2:
        value, type_code = varint(2 << 3 | 5) + b"\x00\x00\x80\x3f", 1
    elif kind == 3:
        value, type_code = text(4, "constant"), 3
    else:
        value, type_code = varint(3 << 3) + varint(index % 3), 2
    return name + value + varint(20 << 3) + varint(type_code)


def large_honest_model(node_count: int, initializer_count: int) -> bytes:
    """A transformer-shaped export: long node names, 3-5 attributes per node, inline weights.

    Standard domains and no external data, so every finding or partial walk on it is
    a false alarm.
    """
    attribute_sets = [
        b"".join(delimited(5, _honest_attribute(variant, kind)) for kind in range(3 + variant))
        for variant in range(3)
    ]
    nodes = []
    for index in range(node_count):
        layer, op = index // 40, _OPERATORS[index % len(_OPERATORS)]
        prefix = f"/model/layers.{layer}/block/{op}_{index}"
        nodes.append(
            text(1, f"{prefix}_input_0")
            + text(1, f"onnx::{op}_{index + 1}")
            + text(2, f"{prefix}_output_0")
            + text(3, prefix)
            + text(4, op)
            + attribute_sets[index % 3]
        )
    initializers = [
        delimited(
            5,
            bytes([1 << 3, 64, 1 << 3, 64, 2 << 3, 1])
            + text(8, f"model.layers.{index}.weight")
            + delimited(9, bytes(256)),
        )
        for index in range(initializer_count)
    ]
    graph = b"".join(delimited(1, item) for item in nodes) + b"".join(initializers)
    opset = delimited(8, text(1, "") + bytes([2 << 3, 17]))
    return bytes([1 << 3, 8]) + text(2, "pytorch") + model_with_graph(graph) + opset
