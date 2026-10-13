import time
from pathlib import Path

import pytest
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile.model import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.runner import Runner
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import saved_model_ops
from guardana.rules.supply_chain.saved_model_ops import SavedModelOpsRule


def _findings(tmp_path: Path) -> list[tuple[str, str]]:
    rule = SavedModelOpsRule()
    return [
        (f.severity.name, f.evidence.summary)
        for f in rule.run(ArtifactTarget(tmp_path), RuleContext())
    ]


def _unread(root: Path) -> list[str]:
    """The files the rule names as unread components when run over `root`."""
    ctx = RuleContext()
    list(SavedModelOpsRule().run(ArtifactTarget(root), ctx))
    return [
        gap.name
        for gap in ctx.shortfalls()
        if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT
        and gap.detail.startswith("guardana.supply_chain.saved_model_ops could not read it: ")
    ]


def test_flags_readfile_op(tmp_path: Path) -> None:
    (tmp_path / "saved_model.pb").write_bytes(b"\x08\x01tensorflow...ReadFile...\x00")
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert findings[0][0] == "MEDIUM"
    assert "ReadFile" in findings[0][1]


def test_flags_writefile_op(tmp_path: Path) -> None:
    (tmp_path / "saved_model.pb").write_bytes(b"tensorflow graph WriteFile op here")
    assert any("WriteFile" in s for _, s in _findings(tmp_path))


def test_reports_each_dangerous_op_once(tmp_path: Path) -> None:
    (tmp_path / "saved_model.pb").write_bytes(b"tensorflow ReadFile ... WriteFile ... ReadFile")
    ops = sorted(s.split()[0] for _, s in _findings(tmp_path))
    assert ops == ["ReadFile", "WriteFile"]


def test_clean_graph_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "saved_model.pb").write_bytes(b"tensorflow MatMul BiasAdd Relu Softmax")
    assert _findings(tmp_path) == []


def test_non_tf_pb_without_ops_is_clean(tmp_path: Path) -> None:
    (tmp_path / "data.pb").write_bytes(b"some other protobuf payload")
    assert _findings(tmp_path) == []


def test_a_graph_past_the_read_bound_is_unverified_and_a_named_shortfall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(saved_model_ops, "_MAX_SCAN_BYTES", 64)
    (tmp_path / "saved_model.pb").write_bytes(b"\x08\x01" + b"\x00" * 128 + b"WriteFile")

    findings = list(SavedModelOpsRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.title for f in findings] == ["SavedModel not scanned"]
    assert findings[0].verdict is not None
    assert findings[0].verdict.outcome == "inconclusive"
    assert _unread(tmp_path) == [str(tmp_path / "saved_model.pb")]


def test_a_graph_read_whole_is_no_shortfall(tmp_path: Path) -> None:
    (tmp_path / "saved_model.pb").write_bytes(b"\x08\x01 WriteFile")

    assert _unread(tmp_path) == []


def test_an_unreadable_graph_is_unverified_and_a_named_shortfall(tmp_path: Path) -> None:
    path = tmp_path / "saved_model.pb"
    path.write_bytes(b"\x08\x01 WriteFile")
    path.chmod(0)
    ctx = RuleContext()
    try:
        findings = list(SavedModelOpsRule().run(ArtifactTarget(tmp_path), ctx))
    finally:
        path.chmod(0o600)

    assert [(f.title, f.evidence.summary) for f in findings] == [
        ("SavedModel not scanned", "the file could not be read")
    ]
    assert findings[0].verdict is not None
    assert findings[0].verdict.outcome == "inconclusive"
    assert [gap.name for gap in ctx.shortfalls()] == [str(path)]


def _graph_text(op_field: str) -> str:
    return (
        'meta_graphs {\n  graph_def {\n    node {\n      name: "save/Write"\n'
        f"      {op_field}\n    }}\n  }}\n}}\n"
    )


@pytest.mark.parametrize(
    "op_field",
    [
        'op: "WriteFile"',
        "op: 'ReadFile'",
        'op: "Write" "File"',
        'op: "Writ\\145File"',
        'op: "\\x57riteFile"',
        'op : # the operator\n  "WriteFile"',
    ],
    ids=["double-quoted", "single-quoted", "concatenated", "octal-escape", "hex-escape", "comment"],
)
def test_a_filesystem_op_in_a_text_savedmodel_is_flagged(tmp_path: Path, op_field: str) -> None:
    (tmp_path / "saved_model.pbtxt").write_text(_graph_text(op_field))
    findings = _findings(tmp_path)
    assert [sev for sev, _ in findings] == ["MEDIUM"]
    assert findings[0][1].split()[0] in {"ReadFile", "WriteFile"}


def test_a_text_savedmodel_without_file_ops_is_clean_and_examined(tmp_path: Path) -> None:
    (tmp_path / "saved_model.pbtxt").write_text(
        _graph_text('op: "MatMul"') + '# a WriteFile op would be flagged\nname: "ReadFile"\n'
    )
    ctx = RuleContext()
    assert list(SavedModelOpsRule().run(ArtifactTarget(tmp_path), ctx)) == []
    assert ctx.examined_paths() == {str(tmp_path / "saved_model.pbtxt")}


def test_another_text_protobuf_is_not_read_as_a_savedmodel(tmp_path: Path) -> None:
    (tmp_path / "label_map.pbtxt").write_text('item { op: "WriteFile" }\n')
    assert _findings(tmp_path) == []


def test_an_unreadable_text_savedmodel_is_unverified_and_a_named_shortfall(
    tmp_path: Path,
) -> None:
    path = tmp_path / "saved_model.pbtxt"
    path.write_text(_graph_text('op: "WriteFile"'))
    path.chmod(0)
    ctx = RuleContext()
    try:
        findings = list(SavedModelOpsRule().run(ArtifactTarget(tmp_path), ctx))
    finally:
        path.chmod(0o600)

    assert [f.title for f in findings] == ["SavedModel not scanned"]
    assert [gap.name for gap in ctx.shortfalls()] == [str(path)]


def test_a_text_savedmodel_past_the_read_bound_is_a_named_shortfall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(saved_model_ops, "_MAX_SCAN_BYTES", 64)
    (tmp_path / "saved_model.pbtxt").write_text("#" * 128 + "\n" + _graph_text('op: "WriteFile"'))

    findings = list(SavedModelOpsRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.title for f in findings] == ["SavedModel not scanned"]
    assert _unread(tmp_path) == [str(tmp_path / "saved_model.pbtxt")]


def test_a_graph_read_whole_is_examined(tmp_path: Path) -> None:
    (tmp_path / "saved_model.pb").write_bytes(b"\n\x05const\x12\x05Const")
    ctx = RuleContext()
    assert list(SavedModelOpsRule().run(ArtifactTarget(tmp_path), ctx)) == []
    assert ctx.examined_paths() == {str(tmp_path / "saved_model.pb")}


@pytest.mark.parametrize("name", ["saved_model.pb", "saved_model.pbtxt"])
def test_a_savedmodel_no_rule_reads_is_a_coverage_shortfall(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_bytes(b"\x08\x01")
    profile = Profile(name="t", policy=Policy(exclude=("guardana.supply_chain.saved_model_ops",)))
    result = Runner(
        registry=Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)), profile=profile
    ).run(ArtifactTarget(tmp_path))

    assert [gap.name for gap in result.coverage_shortfall] == ["tensorflow-savedmodel"]


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("saved_model.pb", b"\n\x05const\x12\x05Const"),
        ("saved_model.pbtxt", b'node { op: "Const" }\n'),
    ],
)
def test_a_savedmodel_without_file_ops_is_read_and_leaves_no_shortfall(
    tmp_path: Path, name: str, content: bytes
) -> None:
    (tmp_path / name).write_bytes(content)
    result = Runner(
        registry=Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
        profile=Profile(name="t", policy=Policy()),
    ).run(ArtifactTarget(tmp_path))

    assert result.coverage_shortfall == ()
    assert result.findings == ()


@pytest.mark.parametrize(
    "tail",
    [b"#" * 4096, b"# x " * 4096, b'"a" ' * 4096 + b"#" * 4096],
    ids=["comment-run", "comment-words", "strings-then-comment"],
)
def test_a_crafted_text_graph_is_read_in_bounded_time(tmp_path: Path, tail: bytes) -> None:
    (tmp_path / "saved_model.pbtxt").write_bytes(b"node { op: " + tail)

    started = time.monotonic()
    assert _findings(tmp_path) == []
    assert time.monotonic() - started < 5.0


@pytest.mark.parametrize(
    "op_field",
    [
        'op:\x1c"WriteFile"',
        'op\xa0: "WriteFile"',
        'op:　"WriteFile"',
        'op : "WriteFile"',
        'op: "\\N{LATIN CAPITAL LETTER W}riteFile"',
        'op: "Write\\u0046ile"',
    ],
    ids=["info-separator", "no-break-space", "ideographic-space", "space", "named", "unicode"],
)
def test_a_spelling_protobuf_parses_as_a_filesystem_op_is_flagged(
    tmp_path: Path, op_field: str
) -> None:
    (tmp_path / "saved_model.pbtxt").write_text(_graph_text(op_field), encoding="utf-8")
    assert [sev for sev, _ in _findings(tmp_path)] == ["MEDIUM"]


@pytest.mark.parametrize(
    "op_field",
    ['op: "\\N{NO SUCH CHARACTER NAME}"', 'op: "Write\\u12File"'],
    ids=["unknown-name", "short-unicode"],
)
def test_an_op_value_that_cannot_be_decoded_is_unscanned(tmp_path: Path, op_field: str) -> None:
    (tmp_path / "saved_model.pbtxt").write_text(_graph_text(op_field), encoding="utf-8")
    ctx = RuleContext()
    findings = list(SavedModelOpsRule().run(ArtifactTarget(tmp_path), ctx))
    assert [f.title for f in findings] == ["SavedModel not scanned"]
    assert [gap.name for gap in ctx.shortfalls()] == [str(tmp_path / "saved_model.pbtxt")]


def test_an_ordinary_op_with_unicode_spacing_is_clean(tmp_path: Path) -> None:
    (tmp_path / "saved_model.pbtxt").write_text(_graph_text('op:\xa0"MatMul"'), encoding="utf-8")
    assert _findings(tmp_path) == []


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        low, value = value & 0x7F, value >> 7
        out.append(low | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _field(number: int, payload: bytes | str) -> bytes:
    """A length-delimited protobuf field."""
    raw = payload.encode() if isinstance(payload, str) else payload
    return _varint(number << 3 | 2) + _varint(len(raw)) + raw


def _entry(key: str, value: bytes) -> bytes:
    return _field(1, key) + _field(2, value)


def _node(name: str, op: str, *inputs: str, attrs: tuple[tuple[str, bytes], ...] = ()) -> bytes:
    """A `NodeDef`; each attribute value is an encoded `AttrValue`."""
    return (
        _field(1, name)
        + _field(2, op)
        + b"".join(_field(3, ref) for ref in inputs)
        + b"".join(_field(5, _entry(key, value)) for key, value in attrs)
    )


def _string_const(name: str, value: str, *, long_length: bool = False) -> bytes:
    """A string `Const` node; `long_length` writes the value's length in two bytes."""
    raw = value.encode()
    string_val = b"\x42" + bytes([len(raw) | 0x80, 0x00]) + raw if long_length else _field(8, raw)
    tensor = _varint(1 << 3) + _varint(7) + string_val
    return _node(name, "Const", attrs=(("value", _field(8, tensor)),))


def _print(stream: str) -> bytes:
    return _node("print", "PrintV2", "msg", attrs=(("output_stream", _field(2, stream)),))


def _saved_model(*nodes: bytes, init_op: str = "init") -> bytes:
    """A binary SavedModel of one meta graph whose init op signature names `init_op`."""
    meta_graph = _field(2, b"".join(_field(1, node) for node in nodes))
    signature = _field(2, _entry("__saved_model_init_op", _field(1, init_op)))
    meta_graph += _field(5, _entry("__saved_model_init_op", signature))
    return _varint(1 << 3) + _varint(1) + _field(2, meta_graph)


def _honest_nodes() -> tuple[bytes, ...]:
    """A saver, a vocabulary table read from the model's assets and a print to stderr."""
    return (
        _string_const("save/Const", "model"),
        _node("save/SaveV2", "SaveV2", "save/Const"),
        _node("save/MergeV2Checkpoints", "MergeV2Checkpoints", "save/Const", "^save/SaveV2"),
        _node("save/RestoreV2", "RestoreV2", "save/Const"),
        _string_const("vocab", "assets/vocab.txt"),
        _node("table", "HashTableV2"),
        _node("init_table", "InitializeTableFromTextFileV2", "table", "vocab"),
        _node("files", "MatchingFiles", "vocab"),
        _node("placed", "Identity", "vocab") + _field(4, "/job:localhost/replica:0/device:CPU:0"),
        _print("stderr"),
        _node("init", "NoOp", "^init_table", "^print"),
    )


def _lead_ops(tmp_path: Path) -> list[str]:
    findings = list(SavedModelOpsRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert all(f.severity.name == "MEDIUM" for f in findings), findings
    assert all(f.verdict is not None and f.verdict.outcome == "fail" for f in findings)
    return sorted(f.evidence.summary.split()[0] for f in findings)


def test_an_honest_binary_savedmodel_with_a_saver_and_an_asset_table_is_clean(
    tmp_path: Path,
) -> None:
    (tmp_path / "saved_model.pb").write_bytes(_saved_model(*_honest_nodes()))
    ctx = RuleContext()
    assert list(SavedModelOpsRule().run(ArtifactTarget(tmp_path), ctx)) == []
    assert ctx.examined_paths() == {str(tmp_path / "saved_model.pb")}


@pytest.mark.parametrize(
    "op", ["InitializeTableFromTextFile", "InitializeTableFromTextFileV2", "MatchingFiles"]
)
@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "../../etc/passwd",
        "file:///etc/passwd",
        "C:\\Windows\\win.ini",
        "gs://bucket/vocab.txt",
    ],
)
def test_an_op_reading_a_file_named_outside_the_model_is_a_lead(
    tmp_path: Path, op: str, path: str
) -> None:
    nodes = (_string_const("fname", path), _node("read", op, "table", "fname"))
    (tmp_path / "saved_model.pb").write_bytes(_saved_model(*nodes, init_op="read"))
    findings = list(SavedModelOpsRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert [f.evidence.summary.split()[0] for f in findings] == [op]
    assert repr(path) in findings[0].evidence.summary
    assert _lead_ops(tmp_path) == [op]


def test_a_path_constant_whose_length_is_written_long_is_read(tmp_path: Path) -> None:
    nodes = (
        _string_const("fname", "/etc/passwd", long_length=True),
        _node("init_table", "InitializeTableFromTextFileV2", "table", "fname"),
    )
    (tmp_path / "saved_model.pb").write_bytes(b"B" + _saved_model(*nodes))
    assert _lead_ops(tmp_path) == ["InitializeTableFromTextFileV2"]


def test_an_absolute_path_naming_a_file_the_model_ships_as_an_asset_is_quiet(
    tmp_path: Path,
) -> None:
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "vocab.txt").write_text("a\nb\n")
    nodes = (
        _string_const("fname", "/home/exporter/data/vocab.txt"),
        _node("init_table", "InitializeTableFromTextFileV2", "table", "fname"),
    )
    (tmp_path / "saved_model.pb").write_bytes(_saved_model(*nodes))
    assert _findings(tmp_path) == []


def test_a_path_constant_without_an_op_reading_it_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "saved_model.pb").write_bytes(_saved_model(_string_const("p", "/etc/passwd")))
    assert _findings(tmp_path) == []


def test_the_hunt_shape_of_a_table_and_a_print_to_a_file_are_leads(tmp_path: Path) -> None:
    nodes = (
        _string_const("fname", "/etc/passwd"),
        _node("init_table", "InitializeTableFromTextFileV2", "table", "fname"),
        _print("file:///tmp/out"),
        _node("init", "NoOp", "^init_table", "^print"),
    )
    (tmp_path / "saved_model.pb").write_bytes(_saved_model(*nodes))
    assert _lead_ops(tmp_path) == ["InitializeTableFromTextFileV2", "PrintV2"]


@pytest.mark.parametrize("stream", ["stderr", "stdout", "log(info)"])
def test_a_print_to_a_standard_stream_is_quiet(tmp_path: Path, stream: str) -> None:
    (tmp_path / "saved_model.pb").write_bytes(_saved_model(_print(stream)))
    assert _findings(tmp_path) == []


_HONEST_TEXT_GRAPH = """\
meta_graphs {
  graph_def {
    node { name: "save/Const" op: "Const" attr { key: "value" value { tensor {
      dtype: DT_STRING string_val: "model" } } } }
    node { name: "save/SaveV2" op: "SaveV2" input: "save/Const" }
    node { name: "save/MergeV2Checkpoints" op: "MergeV2Checkpoints" input: "save/Const" }
    node { name: "vocab" op: "Const" device: "/job:localhost/replica:0/task:0/device:CPU:0"
      attr { key: "value" value { tensor { dtype: DT_STRING string_val: "assets/vocab.txt" } } } }
    node { name: "init_table" op: "InitializeTableFromTextFileV2" input: "table" input: "vocab" }
    node { name: "print" op: "PrintV2" attr { key: "output_stream" value { s: "stderr" } } }
  }
}
"""


def test_an_honest_text_savedmodel_is_clean(tmp_path: Path) -> None:
    (tmp_path / "saved_model.pbtxt").write_text(_HONEST_TEXT_GRAPH)
    ctx = RuleContext()
    assert list(SavedModelOpsRule().run(ArtifactTarget(tmp_path), ctx)) == []
    assert ctx.examined_paths() == {str(tmp_path / "saved_model.pbtxt")}


@pytest.mark.parametrize(
    ("old", "new", "op"),
    [
        ('"assets/vocab.txt"', '"/etc/" "passwd"', "InitializeTableFromTextFileV2"),
        ('"assets/vocab.txt"', '"\\x2fetc/passwd"', "InitializeTableFromTextFileV2"),
        ('s: "stderr"', 's: "file:///tmp/out"', "PrintV2"),
        ('s: "stderr"', 's: "fi" # split\n "le:///tmp/out"', "PrintV2"),
    ],
    ids=["concatenated-path", "escaped-path", "file-stream", "split-file-stream"],
)
def test_a_text_savedmodel_naming_a_file_elsewhere_is_a_lead(
    tmp_path: Path, old: str, new: str, op: str
) -> None:
    (tmp_path / "saved_model.pbtxt").write_text(_HONEST_TEXT_GRAPH.replace(old, new))
    assert _lead_ops(tmp_path) == [op]
