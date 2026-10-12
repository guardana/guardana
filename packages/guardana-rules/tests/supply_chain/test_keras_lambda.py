import json
import os
import zipfile
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


def _write_keras(path: Path, config: dict[str, object]) -> None:
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


@pytest.mark.parametrize("sibling", ["metadata.json", "model.weights.h5"])
def test_an_unzipped_keras_model_directory_is_read(tmp_path: Path, sibling: str) -> None:
    model = tmp_path / "my_model"
    model.mkdir()
    (model / "config.json").write_text(_DIRECTORY_LAMBDA, encoding="utf-8")
    (model / sibling).write_bytes(b"{}" if sibling.endswith(".json") else _HDF5_SIGNATURE)
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
