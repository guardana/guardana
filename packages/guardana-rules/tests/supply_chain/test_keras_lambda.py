import json
import os
import zipfile
from collections.abc import Mapping
from pathlib import Path

import pytest
from guardana.core.report import ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import keras_lambda
from guardana.rules.supply_chain.keras_lambda import KerasLambdaRule
from guardana.rules.supply_chain.model_format import ModelFormatRule
from hypothesis import given, settings
from hypothesis import strategies as st


def _write_keras(path: Path, config: Mapping[str, object]) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))


def _findings(tmp_path: Path) -> list[tuple[str, str]]:
    rule = KerasLambdaRule()
    return [
        (f.severity.name, f.evidence.summary)
        for f in rule.run(ArtifactTarget(tmp_path), RuleContext())
    ]


def _unread(root: Path) -> list[str]:
    """The files the rule names as unread components when run over `root`."""
    ctx = RuleContext()
    list(KerasLambdaRule().run(ArtifactTarget(root), ctx))
    return [
        gap.name
        for gap in ctx.shortfalls()
        if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT
        and gap.detail.startswith("guardana.supply_chain.keras_lambda could not read it: ")
    ]


def test_flags_lambda_layer_in_keras(tmp_path: Path) -> None:
    _write_keras(
        tmp_path / "model.keras",
        {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {"class_name": "Dense", "config": {"units": 8}},
                    {"class_name": "Lambda", "config": {"function": "some_fn"}},
                ]
            },
        },
    )
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert findings[0][0] == "HIGH"
    assert "Lambda" in findings[0][1]


def test_escalates_lambda_referencing_a_dangerous_module(tmp_path: Path) -> None:
    _write_keras(
        tmp_path / "model.keras",
        {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"function": {"code": "lambda x: __import__('os').system('id')"}},
                    }
                ]
            },
        },
    )
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert findings[0][0] == "HIGH"
    assert "os" in findings[0][1]


def test_no_lambda_no_finding(tmp_path: Path) -> None:
    _write_keras(
        tmp_path / "model.keras",
        {"class_name": "Sequential", "config": {"layers": [{"class_name": "Dense"}]}},
    )
    assert _findings(tmp_path) == []


def test_h5_without_marker_is_clean(tmp_path: Path) -> None:
    (tmp_path / "model.h5").write_bytes(b"\x89HDF\r\n" + b'{"class_name": "Dense"}' + b"\x00")
    assert _findings(tmp_path) == []


def _verdicts(tmp_path: Path) -> list[object]:
    rule = KerasLambdaRule()
    return [f.verdict for f in rule.run(ArtifactTarget(tmp_path), RuleContext())]


def test_h5_lambda_is_a_firm_finding_not_a_lead(tmp_path: Path) -> None:
    # CVE-2025-9905: load_model silently ignores safe_mode for .h5, so a Lambda
    # in a legacy file *will* execute. The strict class marker is deterministic
    # evidence that one is declared — there is nothing probabilistic left to hedge.
    blob = b"\x89HDF\r\n" + b'...{"class_name": "Lambda", "config": {}}...' + b"\x00\x00"
    (tmp_path / "model.h5").write_bytes(blob)
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["HIGH"]
    assert _verdicts(tmp_path) == [None]


def test_a_layer_merely_named_lambda_is_not_a_lambda_layer(tmp_path: Path) -> None:
    # The old loose marker matched the bare word, so a Dense layer a user happened
    # to name "Lambda" was reported as arbitrary code execution.
    blob = b"\x89HDF\r\n" + b'{"class_name": "Dense", "name": "Lambda"}' + b"\x00"
    (tmp_path / "model.h5").write_bytes(blob)
    assert _findings(tmp_path) == []


def test_a_keras_file_that_is_not_an_archive_still_gets_scanned(tmp_path: Path) -> None:
    # Real .keras files are zip archives; a plain-JSON one is malformed. Falling
    # back to the byte marker keeps a payload in a malformed archive visible.
    (tmp_path / "model.keras").write_bytes(b'{"class_name": "Lambda", "config": {}}')
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]
    assert _unread(tmp_path) == []


def test_an_unreadable_keras_archive_is_reported_as_unscanned(tmp_path: Path) -> None:
    (tmp_path / "model.keras").write_bytes(b"not a zip file at all")
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["LOW"]
    assert "not scanned" in findings[0][1]
    assert _unread(tmp_path) == [str(tmp_path / "model.keras")]


def test_model_format_no_longer_reports_on_keras_or_h5(tmp_path: Path) -> None:
    _write_keras(
        tmp_path / "model.keras",
        {"class_name": "Sequential", "config": {"layers": [{"class_name": "Lambda"}]}},
    )
    (tmp_path / "model.h5").write_bytes(b'{"class_name": "Lambda"}')
    assert list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext())) == []


def test_a_file_larger_than_the_scan_bound_is_not_cleared(tmp_path: Path) -> None:
    # The config attribute of a multi-GB HDF5 model may sit past the read bound.
    # Reporting "no Lambda" after reading a prefix would be clearing a file we
    # never finished looking at.
    (tmp_path / "big.h5").write_bytes(b"\x89HDF\r\n" + b"\x00" * (16 * 1024 * 1024))
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["LOW"]
    assert "first" in findings[0][1]
    assert _unread(tmp_path) == [str(tmp_path / "big.h5")]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is POSIX-only")
def test_an_unreadable_h5_is_reported_as_unscanned(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "model.h5")
    assert [severity for severity, _ in _findings(tmp_path)] == ["LOW"]
    assert _unread(tmp_path) == [str(tmp_path / "model.h5")]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is POSIX-only")
def test_a_keras_file_that_is_not_a_regular_file_is_reported_as_unscanned(
    tmp_path: Path,
) -> None:
    os.mkfifo(tmp_path / "model.keras")
    assert [severity for severity, _ in _findings(tmp_path)] == ["LOW"]
    assert _unread(tmp_path) == [str(tmp_path / "model.keras")]


_HDF5_SIGNATURE = b"\x89HDF\r\n\x1a\n"
_BACKSLASH = "\\"


def _escaped(text: str, *, upper: bool = False) -> str:
    """Spell every character of `text` as a JSON unicode escape."""
    digits = "{:04X}" if upper else "{:04x}"
    return "".join(_BACKSLASH + "u" + digits.format(ord(char)) for char in text)


def _hdf5_with_config(config_text: str) -> bytes:
    """An HDF5-like file whose model config attribute is `config_text`, built as bytes."""
    return _HDF5_SIGNATURE + b"\x00" * 64 + config_text.encode() + b"\x00" * 8


def _sequential(*layers: str) -> str:
    return '{"class_name": "Sequential", "config": {"layers": [' + ", ".join(layers) + "]}}"


def _class_names(config_text: str) -> list[str]:
    """Every `class_name` the JSON decoder Keras uses reads out of `config_text`."""
    names: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if isinstance(node.get("class_name"), str):
                names.append(node["class_name"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(json.loads(config_text))
    return names


def test_an_escaped_lambda_class_name_in_h5_is_found(tmp_path: Path) -> None:
    config = _sequential('{"class_name": "' + _escaped("L") + 'ambda", "config": {}}')
    assert "Lambda" in _class_names(config)
    (tmp_path / "model.h5").write_bytes(_hdf5_with_config(config))
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]
    assert _unread(tmp_path) == []


def test_an_escaped_class_name_key_in_h5_is_found(tmp_path: Path) -> None:
    config = _sequential('{"' + _escaped("class_name") + '": "Lambda", "config": {}}')
    assert "Lambda" in _class_names(config)
    (tmp_path / "model.h5").write_bytes(_hdf5_with_config(config))
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]


def test_mixed_escapes_whitespace_and_key_order_in_h5_are_found(tmp_path: Path) -> None:
    key = "cl" + _escaped("a") + "ss" + _escaped("_", upper=True) + "name"
    value = _escaped("La", upper=True) + "mbd" + _escaped("a")
    config = _sequential('{"config": {"name": "fn"}, "' + key + '"\t:\r\n "' + value + '"}')
    assert "Lambda" in _class_names(config)
    (tmp_path / "model.hdf5").write_bytes(_hdf5_with_config(config))
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]


def test_an_escaped_lambda_referencing_a_dangerous_module_is_escalated(tmp_path: Path) -> None:
    code = "lambda x: __import__('" + _escaped("os") + "').system('id')"
    layer = (
        '{"class_name": "' + _escaped("Lambda") + '", '
        '"config": {"function": {"code": "' + code + '"}}}'
    )
    config = _sequential('{"class_name": "Dense", "config": {"units": 8}}', layer)
    assert "Lambda" in _class_names(config)
    (tmp_path / "model.h5").write_bytes(_hdf5_with_config(config))
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["HIGH"]
    assert "'os'" in findings[0][1]


def test_an_escaped_lambda_in_a_keras_file_that_is_not_an_archive_is_found(
    tmp_path: Path,
) -> None:
    config = '{"' + _escaped("class_name") + '": "' + _escaped("Lambda") + '", "config": {}}'
    assert _class_names(config) == ["Lambda"]
    (tmp_path / "model.keras").write_bytes(config.encode())
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]
    assert _unread(tmp_path) == []


_SPELLINGS = st.sampled_from(("literal", "lower", "upper"))
_JSON_WHITESPACE = st.text(alphabet=" \t\r\n", max_size=3)


def _spell(word: str, choices: list[str]) -> str:
    return "".join(
        char if choice == "literal" else _escaped(char, upper=choice == "upper")
        for char, choice in zip(word, choices, strict=True)
    )


@settings(max_examples=60, deadline=None)
@given(
    key_spelling=st.lists(_SPELLINGS, min_size=10, max_size=10),
    value_spelling=st.lists(_SPELLINGS, min_size=6, max_size=6),
    before=_JSON_WHITESPACE,
    after=_JSON_WHITESPACE,
)
def test_every_spelling_the_decoder_reads_as_a_lambda_layer_is_found(
    tmp_path_factory: pytest.TempPathFactory,
    key_spelling: list[str],
    value_spelling: list[str],
    before: str,
    after: str,
) -> None:
    key = _spell("class_name", key_spelling)
    value = _spell("Lambda", value_spelling)
    pair = f'"{key}"{before}:{after}"{value}"'
    config = _sequential("{" + pair + ', "config": {}}')
    assert "Lambda" in _class_names(config)
    root = tmp_path_factory.mktemp("spelling")
    (root / "model.h5").write_bytes(_hdf5_with_config(config))
    assert [severity for severity, _ in _findings(root)] == ["HIGH"]


def test_an_honest_h5_model_with_escaped_strings_is_clean(tmp_path: Path) -> None:
    config = _sequential(
        '{"class_name": "Dense", "config": {"name": "dense' + _escaped("_") + '1", "units": 8}}',
        '{"'
        + _escaped("class_name")
        + '": "Dense", "config": {"name": "'
        + _escaped("Lambda")
        + '"}}',
    )
    assert "Lambda" not in _class_names(config)
    (tmp_path / "model.h5").write_bytes(_hdf5_with_config(config))
    assert _findings(tmp_path) == []
    assert _unread(tmp_path) == []


def test_an_hdf5_data_file_without_a_model_config_is_clean_and_examined(tmp_path: Path) -> None:
    blob = (
        _HDF5_SIGNATURE
        + bytes(range(256)) * 16
        + b'{"units": "m/s", "label": "'
        + _escaped("Lambda").encode()
        + b'"}'
        + b'"\\'
        + b"{" * 32
        + b"\x00" * 128
    )
    (tmp_path / "readings.h5").write_bytes(blob)
    assert _findings(tmp_path) == []
    assert _unread(tmp_path) == []


def test_a_lambda_whose_object_does_not_decode_keeps_its_finding(tmp_path: Path) -> None:
    depth = 100_000
    layer = '{"class_name": "' + _escaped("Lambda") + '", "config": ' + "[" * depth + "]" * depth
    (tmp_path / "model.h5").write_bytes(_hdf5_with_config(_sequential(layer + "}")))
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]


def test_many_harmless_lambdas_do_not_hide_a_dangerous_one(tmp_path: Path) -> None:
    harmless = '{"class_name": "Lambda", "config": {"function": "lambda x: x"}}'
    dangerous = (
        '{"class_name": "Lambda", '
        '"config": {"function": {"code": "lambda x: __import__(\'os\').system(\'id\')"}}}'
    )
    config = _sequential(*([harmless] * 100), dangerous)
    (tmp_path / "model.h5").write_bytes(_hdf5_with_config(config))
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["HIGH"]
    assert "'os'" in findings[0][1]


def test_marker_only_input_searches_each_character_at_most_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    searched = 0
    original = keras_lambda._last_brace

    def counting(text: str, low: int, high: int) -> int:
        nonlocal searched
        searched += high - low
        return original(text, low, high)

    monkeypatch.setattr(keras_lambda, "_last_brace", counting)
    blob = _HDF5_SIGNATURE + b'"class_name":"Lambda"' * 2000
    (tmp_path / "model.h5").write_bytes(blob)
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]
    assert 0 < searched <= len(blob)


def test_unterminated_layers_parse_a_bounded_multiple_of_the_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spent = 0
    original = keras_lambda._decode_from

    def counting(text: str, start: int) -> tuple[object | None, int]:
        nonlocal spent
        layer, charged = original(text, start)
        spent += charged
        return layer, charged

    monkeypatch.setattr(keras_lambda, "_decode_from", counting)
    blob = _HDF5_SIGNATURE + b'{"class_name": "Lambda", "w": [' * 2000
    (tmp_path / "model.h5").write_bytes(blob)
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]
    assert 0 < spent <= 3 * len(blob)


@pytest.mark.parametrize("depth", [2_000, 50_000])
def test_a_keras_config_nested_too_deeply_is_reported_unscanned(tmp_path: Path, depth: int) -> None:
    with zipfile.ZipFile(tmp_path / "model.keras", "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config.json", '{"layers": ' + "[" * depth + "]" * depth + "}")
    assert [severity for severity, _ in _findings(tmp_path)] == ["LOW"]
    assert _unread(tmp_path) == [str(tmp_path / "model.keras")]


_DIRECTORY_LAMBDA = _sequential('{"class_name": "Lambda", "config": {"function": "len"}}')


_EMPTY_ZIP = b"PK\x05\x06" + bytes(18)
_SIBLING_BYTES = {
    "metadata.json": b"{}",
    "model.weights.h5": _HDF5_SIGNATURE,
    "model.weights.npz": _EMPTY_ZIP,
}


@pytest.mark.parametrize("sibling", sorted(_SIBLING_BYTES))
def test_an_unzipped_keras_model_directory_is_read(tmp_path: Path, sibling: str) -> None:
    model = tmp_path / "my_model"
    model.mkdir()
    (model / "config.json").write_text(_DIRECTORY_LAMBDA, encoding="utf-8")
    (model / sibling).write_bytes(_SIBLING_BYTES[sibling])
    rule = KerasLambdaRule()
    ctx = RuleContext()
    findings = list(rule.run(ArtifactTarget(tmp_path), ctx))
    assert [(f.severity.name, f.target_ref) for f in findings] == [
        ("HIGH", str(model / "config.json"))
    ]
    assert str(model / "config.json") in ctx.examined_paths()


def test_a_config_json_outside_a_keras_model_directory_is_not_read(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text(_DIRECTORY_LAMBDA, encoding="utf-8")
    (tmp_path / "tokenizer.json").write_text("{}", encoding="utf-8")
    other = tmp_path / "app"
    other.mkdir()
    (other / "config.json").write_text("{not json", encoding="utf-8")
    (other / "settings.json").write_text("{}", encoding="utf-8")
    assert _findings(tmp_path) == []
    assert _unread(tmp_path) == []


def test_an_unreadable_keras_directory_config_is_reported_unscanned(tmp_path: Path) -> None:
    model = tmp_path / "my_model"
    model.mkdir()
    (model / "config.json").write_text("{not json", encoding="utf-8")
    (model / "metadata.json").write_text("{}", encoding="utf-8")
    assert [severity for severity, _ in _findings(tmp_path)] == ["LOW"]
    assert _unread(tmp_path) == [str(model / "config.json")]


_EXPORT_PATHS = ["layers.Lambda", "keras.layers.Lambda", "src.layers.core.lambda_layer.Lambda"]


def _export_path_layer(class_name: str) -> dict[str, object]:
    return {"module": "keras", "class_name": class_name, "config": {"name": "fn"}}


@pytest.mark.parametrize("class_name", _EXPORT_PATHS)
def test_a_lambda_named_by_its_export_path_in_keras_is_found(
    tmp_path: Path, class_name: str
) -> None:
    _write_keras(
        tmp_path / "model.keras",
        {"class_name": "Sequential", "config": {"layers": [_export_path_layer(class_name)]}},
    )
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]


@pytest.mark.parametrize("class_name", _EXPORT_PATHS)
def test_a_lambda_named_by_its_export_path_in_h5_is_found(tmp_path: Path, class_name: str) -> None:
    config = _sequential(json.dumps(_export_path_layer(class_name)))
    (tmp_path / "model.h5").write_bytes(_hdf5_with_config(config))
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]


def test_an_escaped_export_path_in_h5_is_found(tmp_path: Path) -> None:
    value = "layers" + _escaped(".") + _escaped("L") + "ambda"
    config = _sequential('{"module": "keras", "class_name": "' + value + '", "config": {}}')
    assert "layers.Lambda" in _class_names(config)
    (tmp_path / "model.h5").write_bytes(_hdf5_with_config(config))
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]


@pytest.mark.parametrize("class_name", ["MyLambda", "layers.LambdaLike", "Lambda.layers"])
def test_a_class_merely_containing_lambda_is_not_a_lambda_layer(
    tmp_path: Path, class_name: str
) -> None:
    layer = _export_path_layer(class_name)
    _write_keras(
        tmp_path / "model.keras",
        {"class_name": "Sequential", "config": {"layers": [layer]}},
    )
    (tmp_path / "model.h5").write_bytes(_hdf5_with_config(_sequential(json.dumps(layer))))
    assert _findings(tmp_path) == []


@pytest.mark.parametrize("name", ["model.bin", "model.hdf", "model.weights", "model.tf", "x.model"])
def test_an_hdf5_model_under_another_name_is_read(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_bytes(_hdf5_with_config(_DIRECTORY_LAMBDA))
    rule = KerasLambdaRule()
    ctx = RuleContext()
    assert [f.severity.name for f in rule.run(ArtifactTarget(tmp_path), ctx)] == ["HIGH"]
    assert str(tmp_path / name) in ctx.examined_paths()


def test_an_hdf5_model_behind_a_userblock_is_read(tmp_path: Path) -> None:
    (tmp_path / "model.bin").write_bytes(b"\x00" * 1024 + _hdf5_with_config(_DIRECTORY_LAMBDA))
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]


def test_files_under_those_names_that_are_not_hdf5_are_not_read(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        'resource "x" "y" { "class_name": "Lambda" }\n', encoding="utf-8"
    )
    (tmp_path / "firmware.bin").write_bytes(b"\x7fELF" + _DIRECTORY_LAMBDA.encode())
    rule = KerasLambdaRule()
    ctx = RuleContext()
    assert list(rule.run(ArtifactTarget(tmp_path), ctx)) == []
    assert ctx.examined_paths() == frozenset()
    assert _unread(tmp_path) == []


def test_an_hdf5_signature_past_the_read_bound_is_not_cleared(tmp_path: Path) -> None:
    path = tmp_path / "model.bin"
    with path.open("wb") as handle:
        handle.seek(32 * 1024 * 1024)
        handle.write(_hdf5_with_config(_DIRECTORY_LAMBDA))
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["LOW"]
    assert "first" in findings[0][1]
    assert _unread(tmp_path) == [str(path)]


_BOUND = 16 * 1024 * 1024


def _write_keras_config(path: Path, config: bytes) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config.json", config)
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))


def test_a_keras_config_past_the_read_bound_is_not_cleared(tmp_path: Path) -> None:
    complete = json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode()
    config = complete + b" " * _BOUND + b'{"class_name": "Lambda"}'
    _write_keras_config(tmp_path / "model.keras", config)

    findings = _findings(tmp_path)

    assert [severity for severity, _ in findings] == ["LOW"]
    assert f"larger than {_BOUND} bytes" in findings[0][1]
    assert _unread(tmp_path) == [str(tmp_path / "model.keras")]


def test_a_keras_config_of_exactly_the_read_bound_is_read_whole(tmp_path: Path) -> None:
    complete = json.dumps({"class_name": "Sequential", "config": {"layers": []}}).encode()
    _write_keras_config(tmp_path / "model.keras", complete + b" " * (_BOUND - len(complete)))

    assert _findings(tmp_path) == []
    assert _unread(tmp_path) == []


def test_a_lambda_before_the_bound_of_a_long_keras_config_keeps_both_outcomes(
    tmp_path: Path,
) -> None:
    lambda_layer = b'{"class_name": "Lambda", "config": {"function": "len"}}'
    _write_keras_config(tmp_path / "model.keras", lambda_layer + b" " * _BOUND + b"]")

    findings = _findings(tmp_path)

    assert [severity for severity, _ in findings] == ["HIGH", "LOW"]
    assert f"larger than {_BOUND} bytes" in findings[1][1]
    assert _unread(tmp_path) == [str(tmp_path / "model.keras")]


def test_a_lambda_in_the_read_part_of_a_long_h5_does_not_hide_the_unread_rest(
    tmp_path: Path,
) -> None:
    path = tmp_path / "model.h5"
    with path.open("wb") as handle:
        handle.write(_hdf5_with_config(_DIRECTORY_LAMBDA))
        handle.seek(_BOUND + 1024)
        handle.write(b"\x00")

    findings = _findings(tmp_path)

    assert [severity for severity, _ in findings] == ["HIGH", "LOW"]
    assert "first" in findings[1][1]
    assert _unread(tmp_path) == [str(path)]


def test_an_hdf5_model_with_no_suffix_is_read(tmp_path: Path) -> None:
    (tmp_path / "my_model").write_bytes(_hdf5_with_config(_DIRECTORY_LAMBDA))
    (tmp_path / "behind_a_userblock").write_bytes(
        b"\x00" * 2048 + _hdf5_with_config(_DIRECTORY_LAMBDA)
    )
    rule = KerasLambdaRule()
    ctx = RuleContext()
    assert [f.severity.name for f in rule.run(ArtifactTarget(tmp_path), ctx)] == ["HIGH", "HIGH"]
    assert ctx.examined_paths() == {
        str(tmp_path / "my_model"),
        str(tmp_path / "behind_a_userblock"),
    }


def test_a_file_with_no_suffix_that_is_not_hdf5_is_not_read(tmp_path: Path) -> None:
    (tmp_path / "LICENSE").write_text('"class_name": "Lambda"\n', encoding="utf-8")
    (tmp_path / "Makefile").write_bytes(b"\x7fELF" + _DIRECTORY_LAMBDA.encode())
    rule = KerasLambdaRule()
    ctx = RuleContext()
    assert list(rule.run(ArtifactTarget(tmp_path), ctx)) == []
    assert ctx.examined_paths() == frozenset()


def _tf_op_layer(function: object, class_name: str = "TFOpLambda") -> dict[str, object]:
    return {"class_name": class_name, "config": {"name": "op", "function": function}}


@pytest.mark.parametrize(
    "function", ["io.write_file", "compat.v1.io.write_file", "raw_ops.WriteFile", "py_function"]
)
def test_a_tf_op_layer_calling_more_than_array_math_is_a_finding(
    tmp_path: Path, function: str
) -> None:
    _write_keras(
        tmp_path / "model.keras",
        {"class_name": "Functional", "config": {"layers": [_tf_op_layer(function)]}},
    )
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["HIGH"]
    assert f"tf.{function}" in findings[0][1]


@pytest.mark.parametrize(
    "layer",
    [
        _tf_op_layer("math.add"),
        _tf_op_layer("reshape"),
        _tf_op_layer("compat.v1.nn.relu"),
        _tf_op_layer("__operators__.getitem", "SlicingOpLambda"),
        _tf_op_layer("linalg.matmul", "keras.layers.TFOpLambda"),
    ],
)
def test_a_tf_op_layer_doing_array_math_is_clean(tmp_path: Path, layer: dict[str, object]) -> None:
    _write_keras(
        tmp_path / "model.keras", {"class_name": "Functional", "config": {"layers": [layer]}}
    )
    (tmp_path / "model.h5").write_bytes(_hdf5_with_config(_sequential(json.dumps(layer))))
    assert _findings(tmp_path) == []


@pytest.mark.parametrize("function", [None, 42, "", "math..add", ["io.write_file"]])
def test_a_tf_op_layer_whose_function_is_not_a_name_is_not_scanned(
    tmp_path: Path, function: object
) -> None:
    _write_keras(
        tmp_path / "model.keras",
        {"class_name": "Functional", "config": {"layers": [_tf_op_layer(function)]}},
    )
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["LOW"]
    assert "TFOpLambda" in findings[0][1]
    assert _unread(tmp_path) == [str(tmp_path / "model.keras")]


def test_a_tf_op_layer_in_h5_calling_a_file_op_is_a_finding(tmp_path: Path) -> None:
    layer = json.dumps(_tf_op_layer("io.write_file"))
    (tmp_path / "model.h5").write_bytes(_hdf5_with_config(_sequential(layer)))
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["HIGH"]
    assert "tf.io.write_file" in findings[0][1]


def test_a_tf_op_layer_in_h5_whose_config_does_not_decode_is_not_scanned(tmp_path: Path) -> None:
    (tmp_path / "model.h5").write_bytes(
        _hdf5_with_config('{"class_name": "TFOpLambda", "config": {"function": "io.wr')
    )
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["LOW"]
    assert "TFOpLambda" in findings[0][1]
    assert _unread(tmp_path) == [str(tmp_path / "model.h5")]


def _fractal_heap(filter_bytes: int) -> bytes:
    """A fractal heap header as HDF5 writes it, declaring `filter_bytes` of I/O filters."""
    return b"FRHP\x00" + (8).to_bytes(2, "little") + filter_bytes.to_bytes(2, "little") + bytes(64)


def test_an_hdf5_model_with_a_compressed_heap_is_not_cleared(tmp_path: Path) -> None:
    (tmp_path / "model.h5").write_bytes(
        _hdf5_with_config(_sequential('{"class_name": "Dense"}')) + _fractal_heap(12)
    )
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["LOW"]
    assert "compressed" in findings[0][1]
    assert _unread(tmp_path) == [str(tmp_path / "model.h5")]


def test_an_hdf5_model_with_an_uncompressed_heap_is_clean(tmp_path: Path) -> None:
    (tmp_path / "model.h5").write_bytes(
        _hdf5_with_config(_sequential('{"class_name": "Dense"}')) + _fractal_heap(0)
    )
    assert _findings(tmp_path) == []


def _class_method_layer(owner: object, method: object) -> dict[str, object]:
    return {
        "class_name": "ClassMethod",
        "config": {"name": "call", "cls_symbol": owner, "method_name": method},
    }


@pytest.mark.parametrize(
    ("owner", "method"),
    [("io.gfile.GFile", "write"), ("saved_model", "load"), ("RaggedTensor", "numpy")],
)
def test_a_class_method_layer_calling_more_than_tensor_construction_is_a_finding(
    tmp_path: Path, owner: str, method: str
) -> None:
    layer = _class_method_layer(owner, method)
    _write_keras(
        tmp_path / "model.keras", {"class_name": "Functional", "config": {"layers": [layer]}}
    )
    (tmp_path / "model.h5").write_bytes(_hdf5_with_config(_sequential(json.dumps(layer))))
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["HIGH", "HIGH"]
    assert all(f"tf.{owner}.{method}" in summary for _, summary in findings)


@pytest.mark.parametrize(
    ("owner", "method"),
    [
        ("RaggedTensor", "from_row_splits"),
        ("compat.v1.RaggedTensor", "from_tensor"),
        ("SparseTensor", "from_value"),
    ],
)
def test_a_class_method_layer_building_a_tensor_is_clean(
    tmp_path: Path, owner: str, method: str
) -> None:
    layer = _class_method_layer(owner, method)
    _write_keras(
        tmp_path / "model.keras", {"class_name": "Functional", "config": {"layers": [layer]}}
    )
    (tmp_path / "model.h5").write_bytes(_hdf5_with_config(_sequential(json.dumps(layer))))
    assert _findings(tmp_path) == []


@pytest.mark.parametrize(
    ("owner", "method"), [(None, "from_tensor"), ("RaggedTensor", None), ("RaggedTensor", "a.b")]
)
def test_a_class_method_layer_that_names_no_callable_is_not_scanned(
    tmp_path: Path, owner: object, method: object
) -> None:
    _write_keras(
        tmp_path / "model.keras",
        {"class_name": "Functional", "config": {"layers": [_class_method_layer(owner, method)]}},
    )
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["LOW"]
    assert "ClassMethod" in findings[0][1]
    assert _unread(tmp_path) == [str(tmp_path / "model.keras")]


def test_a_class_method_layer_in_h5_whose_config_does_not_decode_is_not_scanned(
    tmp_path: Path,
) -> None:
    (tmp_path / "model.h5").write_bytes(
        _hdf5_with_config('{"class_name": "ClassMethod", "config": {"cls_symbol": "io.gf')
    )
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["LOW"]
    assert "ClassMethod" in findings[0][1]
    assert _unread(tmp_path) == [str(tmp_path / "model.h5")]


_MARSHALLED = {"class_name": "__lambda__", "config": {"value": ["AAAA", None, None]}}


def _dense(activation: object) -> dict[str, object]:
    return {
        "module": "keras.layers",
        "class_name": "Dense",
        "config": {"name": "dense", "units": 2, "activation": activation},
    }


def _write_container(root: Path, container: str, config: Mapping[str, object]) -> Path:
    """Write `config` as Keras saves it in `container`; return the file the rule reports."""
    if container == "keras":
        _write_keras(root / "model.keras", config)
        return root / "model.keras"
    if container == "h5":
        (root / "model.h5").write_bytes(_hdf5_with_config(json.dumps(config)))
        return root / "model.h5"
    model = root / "my_model"
    model.mkdir()
    (model / "config.json").write_text(json.dumps(config), encoding="utf-8")
    (model / "model.weights.npz").write_bytes(_EMPTY_ZIP)
    return model / "config.json"


_CONTAINERS = ["keras", "directory", "h5"]


@pytest.mark.parametrize("container", _CONTAINERS)
def test_a_marshalled_function_outside_a_lambda_layer_is_a_finding(
    tmp_path: Path, container: str
) -> None:
    config = {"class_name": "Sequential", "config": {"layers": [_dense(_MARSHALLED)]}}
    reported = _write_container(tmp_path, container, config)
    rule = KerasLambdaRule()
    findings = list(rule.run(ArtifactTarget(tmp_path), RuleContext()))
    assert [(f.severity.name, f.target_ref) for f in findings] == [("HIGH", str(reported))]
    assert "__lambda__" in findings[0].evidence.summary


def test_an_escaped_marshalled_function_in_h5_is_found(tmp_path: Path) -> None:
    value = _escaped("__") + "lambda" + _escaped("__", upper=True)
    layer = json.dumps(_dense({"class_name": "PLACEHOLDER", "config": {}}))
    config = _sequential(layer.replace("PLACEHOLDER", value))
    assert "__lambda__" in _class_names(config)
    (tmp_path / "model.h5").write_bytes(_hdf5_with_config(config))
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]


@pytest.mark.parametrize("container", ["keras", "h5"])
def test_a_lambda_layer_holding_its_marshalled_function_is_one_finding(
    tmp_path: Path, container: str
) -> None:
    layer = {"class_name": "Lambda", "config": {"name": "fn", "function": _MARSHALLED}}
    _write_container(
        tmp_path, container, {"class_name": "Sequential", "config": {"layers": [layer]}}
    )
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["HIGH"]
    assert "Lambda layer" in findings[0][1]


_UNSAFE_CALLABLES = [
    ({"module": "os", "class_name": "function", "config": "system"}, "os.system", "os"),
    (
        {"module": "builtins", "class_name": "function", "config": "exec"},
        "builtins.exec",
        "builtins",
    ),
    (
        {"module": "subprocess", "class_name": "Popen", "config": {}},
        "subprocess.Popen",
        "subprocess",
    ),
    ({"module": "os.path", "class_name": "function", "config": "join"}, "os.path.join", "os"),
]


@pytest.mark.parametrize("container", _CONTAINERS)
@pytest.mark.parametrize(("activation", "named", "module"), _UNSAFE_CALLABLES)
def test_a_callable_named_in_an_unsafe_module_is_a_finding(
    tmp_path: Path, container: str, activation: dict[str, object], named: str, module: str
) -> None:
    config = {"class_name": "Sequential", "config": {"layers": [_dense(activation)]}}
    _write_container(tmp_path, container, config)
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["HIGH"]
    assert (named if container != "h5" else repr(module)) in findings[0][1]


@pytest.mark.parametrize("container", _CONTAINERS)
@pytest.mark.parametrize(
    "module", ["keras.activations", "keras_hub.src.layers", "my_project.layers", "osmosis", "os_x"]
)
def test_a_callable_named_in_keras_or_another_package_is_clean(
    tmp_path: Path, container: str, module: str
) -> None:
    activation = {"module": module, "class_name": "function", "config": "relu"}
    config = {"class_name": "Sequential", "config": {"layers": [_dense(activation)]}}
    _write_container(tmp_path, container, config)
    assert _findings(tmp_path) == []


def _tfsm_layer(class_name: str = "TFSMLayer", **config: object) -> dict[str, object]:
    return {
        "module": "keras.layers",
        "class_name": class_name,
        "config": {"name": "tfsm", "call_endpoint": "serve", **config},
    }


@pytest.mark.parametrize("container", _CONTAINERS)
@pytest.mark.parametrize("class_name", ["TFSMLayer", "keras.layers.TFSMLayer"])
def test_a_tfsm_layer_is_a_finding_naming_the_savedmodel_it_loads(
    tmp_path: Path, container: str, class_name: str
) -> None:
    layer = _tfsm_layer(class_name, filepath="/srv/elsewhere/saved_model")
    _write_container(
        tmp_path, container, {"class_name": "Sequential", "config": {"layers": [layer]}}
    )
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["HIGH"]
    assert "TFSMLayer" in findings[0][1]
    assert "/srv/elsewhere/saved_model" in findings[0][1]


@pytest.mark.parametrize("container", _CONTAINERS)
@pytest.mark.parametrize("filepath", [None, 7, ""])
def test_a_tfsm_layer_naming_no_path_is_not_scanned(
    tmp_path: Path, container: str, filepath: object
) -> None:
    layer = _tfsm_layer(filepath=filepath)
    reported = _write_container(
        tmp_path, container, {"class_name": "Sequential", "config": {"layers": [layer]}}
    )
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["LOW"]
    assert "TFSMLayer" in findings[0][1]
    assert _unread(tmp_path) == [str(reported)]


def test_a_tfsm_layer_in_h5_whose_config_does_not_decode_is_not_scanned(tmp_path: Path) -> None:
    (tmp_path / "model.h5").write_bytes(
        _hdf5_with_config('{"class_name": "TFSMLayer", "config": {"filepath": "/sr')
    )
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["LOW"]
    assert "TFSMLayer" in findings[0][1]
    assert _unread(tmp_path) == [str(tmp_path / "model.h5")]


@pytest.mark.parametrize("container", _CONTAINERS)
def test_a_layer_merely_ending_in_tfsm_layer_is_clean(tmp_path: Path, container: str) -> None:
    layer = _tfsm_layer("MyTFSMLayer", filepath="/srv/elsewhere")
    _write_container(
        tmp_path, container, {"class_name": "Sequential", "config": {"layers": [layer]}}
    )
    assert _findings(tmp_path) == []


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        low, value = value & 0x7F, value >> 7
        out.append(low | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _length_field(number: int, payload: bytes) -> bytes:
    return _varint(number << 3 | 2) + _varint(len(payload)) + payload


def _keras_metadata(*layers: Mapping[str, object]) -> bytes:
    """A tf_keras `keras_metadata.pb`: one saved object per layer, its metadata as JSON."""
    return b"".join(
        _length_field(
            1,
            _varint(2 << 3)
            + _varint(index)
            + _length_field(3, f"root.layer-{index}".encode())
            + _length_field(4, b"_tf_keras_layer")
            + _length_field(5, json.dumps(layer).encode()),
        )
        for index, layer in enumerate(layers)
    )


def _tf_keras_savedmodel(root: Path, *layers: Mapping[str, object]) -> Path:
    model = root / "my_model"
    (model / "variables").mkdir(parents=True)
    (model / "saved_model.pb").write_bytes(b"\x08\x01")
    (model / "keras_metadata.pb").write_bytes(_keras_metadata(*layers))
    return model / "keras_metadata.pb"


_TF_KERAS_LAMBDA = {
    "class_name": "Lambda",
    "name": "fn",
    "config": {"name": "fn", "function": ["AAAA", None, None], "function_type": "lambda"},
}


def test_a_tf_keras_savedmodel_declaring_a_lambda_is_a_finding(tmp_path: Path) -> None:
    metadata = _tf_keras_savedmodel(
        tmp_path, {"class_name": "Dense", "name": "d"}, _TF_KERAS_LAMBDA
    )
    rule = KerasLambdaRule()
    ctx = RuleContext()
    findings = list(rule.run(ArtifactTarget(tmp_path), ctx))
    assert [(f.severity.name, f.target_ref) for f in findings] == [("HIGH", str(metadata))]
    assert str(metadata) in ctx.examined_paths()


def test_a_tf_keras_savedmodel_of_dense_layers_is_clean_and_examined(tmp_path: Path) -> None:
    metadata = _tf_keras_savedmodel(tmp_path, {"class_name": "Dense", "name": "d"})
    ctx = RuleContext()
    assert list(KerasLambdaRule().run(ArtifactTarget(tmp_path), ctx)) == []
    assert ctx.examined_paths() == {str(metadata)}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is POSIX-only")
def test_an_unreadable_tf_keras_metadata_is_not_scanned(tmp_path: Path) -> None:
    model = tmp_path / "my_model"
    model.mkdir()
    os.mkfifo(model / "keras_metadata.pb")
    assert [severity for severity, _ in _findings(tmp_path)] == ["LOW"]
    assert _unread(tmp_path) == [str(model / "keras_metadata.pb")]


def test_another_protobuf_is_not_read_for_keras_layers(tmp_path: Path) -> None:
    (tmp_path / "graph.pb").write_bytes(_keras_metadata(_TF_KERAS_LAMBDA))
    assert _findings(tmp_path) == []


def _write_layer(root: Path, container: str, layer: Mapping[str, object]) -> Path:
    """Write one layer as Keras saves it in `container`; return the file the rule reports."""
    if container == "metadata":
        return _tf_keras_savedmodel(root, layer)
    return _write_container(
        root, container, {"class_name": "Sequential", "config": {"layers": [layer]}}
    )


_LAYER_CONTAINERS = [*_CONTAINERS, "metadata"]


def _registered(registered_name: str, **config: object) -> dict[str, object]:
    return {
        "module": "keras.layers",
        "class_name": "Bogus",
        "config": {"name": "x", **config},
        "registered_name": registered_name,
    }


@pytest.mark.parametrize("container", _LAYER_CONTAINERS)
def test_a_lambda_built_through_its_registered_name_is_a_finding(
    tmp_path: Path, container: str
) -> None:
    """Keras 3.8 builds `vars(module)[registered_name]` when `class_name` resolves to nothing."""
    reported = _write_layer(tmp_path, container, _registered("Lambda", function="lambda x: x"))
    findings = list(KerasLambdaRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert [(f.severity.name, f.target_ref) for f in findings] == [("HIGH", str(reported))]
    assert "Lambda" in findings[0].evidence.summary


@pytest.mark.parametrize("container", _LAYER_CONTAINERS)
def test_a_tfsm_layer_built_through_its_registered_name_is_a_finding(
    tmp_path: Path, container: str
) -> None:
    layer = _registered("TFSMLayer", filepath="/srv/elsewhere/saved_model", call_endpoint="serve")
    _write_layer(tmp_path, container, layer)
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["HIGH"]
    assert "/srv/elsewhere/saved_model" in findings[0][1]


@pytest.mark.parametrize("container", _LAYER_CONTAINERS)
@pytest.mark.parametrize("registered_name", [None, "Dense", "Custom>Lambda", "Custom>TFSMLayer"])
def test_an_honest_registered_name_is_clean(
    tmp_path: Path, container: str, registered_name: str | None
) -> None:
    layer = {
        "module": "keras.layers",
        "class_name": "Dense",
        "config": {"name": "dense", "units": 2, "filepath": "/srv/x", "function": "f"},
        "registered_name": registered_name,
    }
    _write_layer(tmp_path, container, layer)
    assert _findings(tmp_path) == []


def _lookup(class_name: str, vocabulary: object) -> dict[str, object]:
    return {
        "module": "keras.layers",
        "class_name": class_name,
        "config": {"name": "lookup", "vocabulary": vocabulary, "num_oov_indices": 1},
        "registered_name": None,
    }


@pytest.mark.parametrize("container", _LAYER_CONTAINERS)
@pytest.mark.parametrize("class_name", ["StringLookup", "IntegerLookup", "TextVectorization"])
@pytest.mark.parametrize(
    "vocabulary",
    ["/etc/passwd", "../../secrets/vocab.txt", "gs://bucket/vocab.txt", "file:///etc/passwd"],
)
def test_a_lookup_layer_reading_a_vocabulary_outside_the_model_is_a_lead(
    tmp_path: Path, container: str, class_name: str, vocabulary: str
) -> None:
    """Keras reads a string `vocabulary` with `tf.io.gfile` while the layer is built."""
    reported = _write_layer(tmp_path, container, _lookup(class_name, vocabulary))
    findings = list(KerasLambdaRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert [(f.severity.name, f.target_ref) for f in findings] == [("MEDIUM", str(reported))]
    assert class_name in findings[0].evidence.summary
    assert repr(vocabulary) in findings[0].evidence.summary
    verdict = findings[0].verdict
    assert verdict is not None
    assert verdict.outcome == "fail"
    assert verdict.confidence < 1


@pytest.mark.parametrize("container", _LAYER_CONTAINERS)
def test_a_lookup_layer_built_through_its_registered_name_is_read(
    tmp_path: Path, container: str
) -> None:
    layer = {**_lookup("Bogus", "/etc/passwd"), "registered_name": "StringLookup"}
    _write_layer(tmp_path, container, layer)
    assert [severity for severity, _ in _findings(tmp_path)] == ["MEDIUM"]


@pytest.mark.parametrize("container", _LAYER_CONTAINERS)
@pytest.mark.parametrize("vocabulary", [["a", "b"], "vocab.txt", "assets/vocabulary.txt", None, 7])
def test_a_lookup_layer_with_its_own_vocabulary_is_clean(
    tmp_path: Path, container: str, vocabulary: object
) -> None:
    _write_layer(tmp_path, container, _lookup("StringLookup", vocabulary))
    assert _findings(tmp_path) == []


def test_a_lookup_layer_in_h5_whose_config_does_not_decode_is_not_scanned(tmp_path: Path) -> None:
    (tmp_path / "model.h5").write_bytes(
        _hdf5_with_config('{"class_name": "StringLookup", "config": {"vocabulary": "/et')
    )
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["LOW"]
    assert "StringLookup" in findings[0][1]
    assert _unread(tmp_path) == [str(tmp_path / "model.h5")]
