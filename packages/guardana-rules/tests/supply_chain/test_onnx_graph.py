from pathlib import Path

import pytest
from _onnx_carriers import (
    CARRIERS,
    CUSTOM_DOMAIN,
    Carrier,
    large_honest_model,
    nested_subgraphs,
    node,
)
from guardana.core.formats import Limits, OnnxSummary
from guardana.core.report import ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget
from guardana.core.testing import build_onnx
from guardana.rules.supply_chain import onnx_graph
from guardana.rules.supply_chain.onnx_graph import OnnxGraphRule

_TAG = "\U000e0074\U000e0065\U000e0073\U000e0074"  # "test" in the invisible Tags block


def _findings(tmp_path: Path) -> list[tuple[str, str]]:
    rule = OnnxGraphRule()
    return [
        (f.severity.name, f.evidence.summary)
        for f in rule.run(ArtifactTarget(tmp_path), RuleContext())
    ]


def _unread(root: Path) -> list[str]:
    """The files the rule names as unread components when run over `root`."""
    ctx = RuleContext()
    list(OnnxGraphRule().run(ArtifactTarget(root), ctx))
    return [
        gap.name
        for gap in ctx.shortfalls()
        if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT
        and gap.detail.startswith("guardana.supply_chain.onnx_graph could not read it: ")
    ]


def _write(tmp_path: Path, payload: bytes) -> None:
    (tmp_path / "model.onnx").write_bytes(payload)


def test_a_standard_graph_is_clean(tmp_path: Path) -> None:
    _write(
        tmp_path,
        build_onnx(
            nodes=(("Conv", ""), ("Relu", "ai.onnx"), ("Scaler", "ai.onnx.ml")),
            producer="pytorch",
            external_paths=("model.weights",),
            metadata={"author": "acme"},
        ),
    )
    assert _findings(tmp_path) == []


def test_flags_a_custom_operator_domain(tmp_path: Path) -> None:
    # A domain outside the standard set means the runtime must load a native
    # operator library to run this model — machine code at inference time.
    _write(tmp_path, build_onnx(nodes=(("Conv", ""), ("SecretOp", "com.evil.ops"))))
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["MEDIUM"]
    assert "com.evil.ops" in findings[0][1]


def test_flags_a_custom_opset_import_even_without_a_node(tmp_path: Path) -> None:
    _write(tmp_path, build_onnx(nodes=(("Conv", ""),), opset_domains=("", "com.evil.ops")))
    assert [severity for severity, _ in _findings(tmp_path)] == ["MEDIUM"]


def test_flags_external_data_path_traversal(tmp_path: Path) -> None:
    # `external_data` is a file path the loader opens. `..` in it is an arbitrary
    # file read primitive, and there is nothing ambiguous about it.
    _write(tmp_path, build_onnx(nodes=(("Conv", ""),), external_paths=("../../etc/passwd",)))
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["HIGH"]
    assert "etc/passwd" in findings[0][1]


def test_flags_an_absolute_external_data_path(tmp_path: Path) -> None:
    _write(tmp_path, build_onnx(nodes=(("Conv", ""),), external_paths=("/etc/shadow",)))
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]


def test_a_relative_external_data_path_is_normal(tmp_path: Path) -> None:
    _write(tmp_path, build_onnx(nodes=(("Conv", ""),), external_paths=("data/weights.bin",)))
    assert _findings(tmp_path) == []


def test_flags_a_smuggled_character_in_metadata(tmp_path: Path) -> None:
    _write(tmp_path, build_onnx(nodes=(("Conv", ""),), metadata={"notes": f"harmless{_TAG}"}))
    assert [severity for severity, _ in _findings(tmp_path)] == ["HIGH"]


def test_flags_an_executable_looking_metadata_payload(tmp_path: Path) -> None:
    _write(
        tmp_path,
        build_onnx(
            nodes=(("Conv", ""),),
            metadata={"description": "exec(__import__('base64').b64decode(BLOB))"},
        ),
    )
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["MEDIUM"]
    assert "description" in findings[0][1]


def test_an_unreadable_onnx_file_is_reported_as_unscanned(tmp_path: Path) -> None:
    _write(tmp_path, b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")
    findings = _findings(tmp_path)
    assert [severity for severity, _ in findings] == ["LOW"]
    assert "not scanned" in findings[0][1]
    assert _unread(tmp_path) == [str(tmp_path / "model.onnx")]


def test_a_readable_graph_is_no_shortfall(tmp_path: Path) -> None:
    _write(tmp_path, build_onnx(nodes=(("Conv", ""),)))

    assert _unread(tmp_path) == []


def test_a_graph_too_large_to_walk_is_not_cleared(tmp_path: Path) -> None:
    _write(tmp_path, build_onnx(nodes=tuple(("Conv", "") for _ in range(400))))
    rule = OnnxGraphRule(max_entries=20)
    ctx = RuleContext()
    findings = [f.severity for f in rule.run(ArtifactTarget(tmp_path), ctx)]
    assert findings == [Severity.LOW]
    assert [gap.name for gap in ctx.shortfalls()] == [str(tmp_path / "model.onnx")]


def test_a_lead_found_before_the_budget_ran_out_does_not_hide_the_unread_rest(
    tmp_path: Path,
) -> None:
    """A MEDIUM lead says nothing about a HIGH path traversal past the field budget."""
    nodes = (("Custom", "vendor.custom"), *(("Conv", "") for _ in range(400)))
    _write(tmp_path, build_onnx(nodes=nodes, external_paths=("../../etc/passwd",)))

    findings = list(OnnxGraphRule(max_entries=20).run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.severity for f in findings] == [Severity.MEDIUM, Severity.LOW]
    assert findings[1].title == "ONNX model not scanned"


@pytest.mark.parametrize("carrier", CARRIERS, ids=lambda carrier: carrier.name)
def test_flags_what_a_model_carries_outside_its_top_level_graph(
    tmp_path: Path, carrier: Carrier
) -> None:
    _write(tmp_path, carrier.model)

    findings = _findings(tmp_path)

    if carrier.external_path is not None:
        assert findings == [
            ("HIGH", f"external_data points outside the model directory: '{carrier.external_path}'")
        ]
    if carrier.custom_domain is not None:
        assert [severity for severity, _ in findings] == ["MEDIUM"]
        assert carrier.custom_domain in findings[0][1]


def test_subgraphs_nested_past_the_depth_bound_are_not_cleared(tmp_path: Path) -> None:
    _write(tmp_path, nested_subgraphs(200, node(CUSTOM_DOMAIN)))

    findings = _findings(tmp_path)

    assert [severity for severity, _ in findings] == ["LOW"]
    assert "not scanned" in findings[0][1]
    assert _unread(tmp_path) == [str(tmp_path / "model.onnx")]


def test_a_large_honest_model_is_walked_in_full_and_clean(tmp_path: Path) -> None:
    """60,000 nodes with 3-5 attributes each spend more fields than any fixed floor."""
    _write(tmp_path, large_honest_model(60_000, 300))
    ctx = RuleContext()

    findings = list(OnnxGraphRule().run(ArtifactTarget(tmp_path), ctx))

    assert findings == []
    assert ctx.shortfalls() == ()


def _budgets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rule: OnnxGraphRule) -> list[int]:
    """The field budget the rule hands the reader for `model.onnx`."""
    seen: list[int] = []

    def read(path: Path, *, limits: Limits) -> OnnxSummary:
        seen.append(limits.max_entries)
        return OnnxSummary("", (), (), {}, (), truncated=False)

    monkeypatch.setattr(onnx_graph, "read_onnx_summary", read)
    list(rule.run(ArtifactTarget(tmp_path), RuleContext()))
    return seen


def test_the_default_field_budget_grows_with_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with (tmp_path / "model.onnx").open("wb") as handle:
        handle.truncate(6_000_000)

    assert _budgets(tmp_path, monkeypatch, OnnxGraphRule()) == [3_000_000]


def test_the_default_field_budget_stops_growing_at_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with (tmp_path / "model.onnx").open("wb") as handle:
        handle.truncate(20_000_000)

    assert _budgets(tmp_path, monkeypatch, OnnxGraphRule()) == [8_000_000]


def test_a_small_file_gets_only_the_floor_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path, build_onnx(nodes=(("Conv", ""),)))

    assert _budgets(tmp_path, monkeypatch, OnnxGraphRule()) == [1_000_000]


def test_an_explicit_field_budget_is_used_whatever_the_file_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with (tmp_path / "model.onnx").open("wb") as handle:
        handle.truncate(6_000_000)

    assert _budgets(tmp_path, monkeypatch, OnnxGraphRule(max_entries=20)) == [20]
