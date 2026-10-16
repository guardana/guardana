"""Every row of `docs/conformance-kit.md`, run on the reference pack through the supported surface.

The proof copies this module outside the checkout and runs it with the interpreter that
installed `guardana-cli` and `guardana-reference-pack` from PyPI. It imports nothing from
`guardana.*` outside the surface `docs/compatibility.md` lists; the first test checks that.
A row that cannot be run without such a name is skipped, and the skip names what it needs.
The proof records a skip as not applicable only when its reason starts with
`NOT_APPLICABLE`, which these tests give only after checking, from the pack's own rule
declarations, that the pack ships nothing the row covers; every other skip is not exercised.
"""

import ast
import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from importlib import import_module, metadata
from pathlib import Path
from typing import Any

import pytest
import yaml
from guardana.core import RuleContext
from guardana.core.rule.fixture import DEMANDED_OUTCOMES, FixtureOutcome, materialise
from guardana.core.testing import (
    ScriptedA2aAgent,
    ScriptedMcpServer,
    ScriptedTransport,
    files_target,
    receiver,
    sample_verifications,
)
from guardana.testing import (
    assert_renderer_conforms,
    assert_reporter_conforms,
    assert_target_conforms,
)

PACK = "guardana-reference-pack"
OUTSIDE = "not exercisable through the supported surface: "
NOT_APPLICABLE = "not applicable to this pack: "
ADMIT = ("--plugins", "allowlist", "--allow-plugin", PACK)
# What a rule needs to be run against the MCP or A2A doubles, or against a trace.
SERVED_BY_THE_DOUBLES = {
    "list_tools",
    "call_tools",
    "inspect_authorization",
    "inspect_a2a",
    "registry_entry",
}
TRACE_KIND = "trace"

# Modules the surface covers by their whole `__all__`, and the names it lists one by one
# (the "Extension contract" row of docs/compatibility.md).
WHOLE = (
    "guardana.core",
    "guardana.core.verify",
    "guardana.core.doubles",
    "guardana.core.target.protocols",
    "guardana.core.output",
    "guardana.testing",
    "guardana.core.testing",
)
LISTED = {
    "guardana.core.target": {"WireProtocol"},
    "guardana.core.source": {"PythonSource", "UnreadSource"},
    "guardana.core.report.shortfall": {"CoverageShortfall", "ShortfallKind"},
    "guardana.core.rule.fixture": {
        "RuleFixture",
        "DeclaredFixture",
        "FixtureOutcome",
        "DEMANDED_OUTCOMES",
        "materialise",
    },
}


def surface() -> dict[str, set[str]]:
    """The supported names per module, taken from the installed build."""
    names = {module: set(import_module(module).__all__) for module in WHOLE}
    names["guardana.core"].discard("Runner")
    return {**names, **LISTED}


def entry_point(group: str, name: str) -> metadata.EntryPoint:
    """The pack's entry point, refusing one another distribution registered."""
    found = [
        e for e in metadata.entry_points(group=group, name=name) if e.dist and e.dist.name == PACK
    ]
    assert len(found) == 1, f"{PACK} registers {len(found)} {group} entry points named {name}"
    return found[0]


def outside_surface(source: str, allowed: dict[str, set[str]]) -> list[str]:
    """Every `guardana.*` name `source` imports that `allowed` does not list."""
    outside: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            outside += [a.name for a in node.names if a.name.split(".")[0] == "guardana"]
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "guardana":
            module = node.module or ""
            outside += [
                f"{module}.{a.name}" for a in node.names if a.name not in allowed.get(module, set())
            ]
    return outside


def unpinned_rule() -> Any:  # noqa: ANN401 — the pack's own class, typed by the pack
    """The pack's Python rule, imported from the installed wheel."""
    from guardana_reference_pack.unpinned import UnpinnedRequirementRule  # noqa: PLC0415

    return UnpinnedRequirementRule()


def pack_rule_needs() -> dict[str, tuple[str, set[str]]]:
    """Each pack rule's target kind and capabilities, as the rule itself declares them.

    The rule ids must be exactly the ones `guardana rules` lists for the admitted pack, so a
    rule this function does not read can never make a row look not applicable.
    """
    rule = unpinned_rule()
    meta = rule.meta
    needs = {meta.id: (_value(meta.target_kind), {_value(c) for c in meta.required_capabilities})}
    import guardana_reference_pack  # noqa: PLC0415

    for path in sorted((Path(guardana_reference_pack.__file__).parent / "rules").glob("*.yaml")):
        declared = yaml.safe_load(path.read_text(encoding="utf-8"))
        needs[declared["id"]] = (declared["target_kind"], set(declared.get("requires", [])))
    guardana = shutil.which("guardana", path=str(Path(sys.executable).parent))
    assert guardana is not None
    # S603: the installed `guardana` beside this interpreter, with literal arguments.
    listed = subprocess.run(  # noqa: S603
        [guardana, "rules", "--format", "json", *ADMIT], capture_output=True, text=True, check=True
    )
    ids = {r["id"] for r in json.loads(listed.stdout) if r["id"].startswith("reference.")}
    assert ids == set(needs), f"the pack lists {sorted(ids)}, the kit read {sorted(needs)}"
    return needs


def _value(item: object) -> str:
    return str(getattr(item, "value", item))


def test_this_module_imports_only_the_supported_surface() -> None:
    assert outside_surface(Path(__file__).read_text(encoding="utf-8"), surface()) == []


def test_the_pack_is_the_installed_wheel_from_pypi() -> None:
    import guardana_reference_pack  # noqa: PLC0415

    dist = metadata.distribution(PACK)
    assert dist.read_text("direct_url.json") is None
    assert Path(guardana_reference_pack.__file__).is_relative_to(Path(str(dist.locate_file(""))))


# Row 1: `guardana rule test` and `verify_rule`.


def test_row_1_the_python_rule_concludes_each_declared_sample_through_the_surface() -> None:
    rule = unpinned_rule()
    samples = materialise(rule.fixtures())

    concluded = {}
    for sample in samples:
        findings = list(rule.run(sample.target, RuleContext()))
        declined = [
            f for f in findings if f.verdict is not None and f.verdict.outcome == "inconclusive"
        ]
        if declined:
            concluded[sample.name] = FixtureOutcome.INCONCLUSIVE
        elif findings:
            concluded[sample.name] = FixtureOutcome.FINDING
        else:
            concluded[sample.name] = FixtureOutcome.CLEAN

    assert concluded == {s.name: s.outcome for s in samples}
    assert set(concluded.values()) == set(DEMANDED_OUTCOMES)


def test_row_1_verify_rule() -> None:
    pytest.skip(
        NOT_APPLICABLE + "`guardana rule test`, in the same proof, runs this row's check on every "
        "pack rule; guardana.core.rule.verify.verify_rule itself is not in the surface"
    )


# Row 2: `assert_target_conforms`.


def test_row_2_the_pack_target_keeps_the_target_contract(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "service").mkdir()
    (tmp_path / "service" / "REQUIREMENTS-dev.IN").write_text("pytest\n", encoding="utf-8")
    provided = entry_point("guardana.targets", "reference").load()()
    assert len(provided) == 1

    target = provided[0].from_locator(str(tmp_path), options={})

    assert_target_conforms(target)


# Row 3: `ScriptedMcpServer`, `ScriptedA2aAgent`.

_INITIALIZE = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "proof", "version": "1"},
        },
    }
).encode()
_JSON = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


def test_row_3_the_mcp_double_answers_as_an_enforcing_and_an_open_server() -> None:
    url = "https://mcp.example.test/mcp"
    enforcing = ScriptedMcpServer(url, credential="token-a")
    open_server = ScriptedMcpServer(url, credential="token-a", accepts_any_token=True)

    assert enforcing(url, body=_INITIALIZE, headers=_JSON).status == 401
    assert (
        enforcing(
            url, body=_INITIALIZE, headers={**_JSON, "Authorization": "Bearer token-b"}
        ).status
        == 401
    )
    assert (
        enforcing(
            url, body=_INITIALIZE, headers={**_JSON, "Authorization": "Bearer token-a"}
        ).status
        == 200
    )
    assert (
        open_server(
            url, body=_INITIALIZE, headers={**_JSON, "Authorization": "Bearer token-b"}
        ).status
        == 200
    )


def test_row_3_the_a2a_double_answers_as_an_enforcing_and_an_open_agent() -> None:
    url = "https://agent.example.test/a2a"
    request = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": {"id": "task-1"}}
    ).encode()
    enforcing = ScriptedA2aAgent(url, callers={"token-a": "alice"}, tasks={"alice": ["task-1"]})
    open_agent = ScriptedA2aAgent(
        url, callers={"token-a": "alice"}, tasks={"alice": ["task-1"]}, enforced=False
    )

    assert enforcing(url, body=request, headers=_JSON).status == 401
    assert (
        enforcing(url, body=request, headers={**_JSON, "Authorization": "Bearer token-a"}).status
        == 200
    )
    assert open_agent(url, body=request, headers=_JSON).status == 200


def test_row_3_a_rule_run_against_either_double() -> None:
    needs = pack_rule_needs()
    served = {rule: caps & SERVED_BY_THE_DOUBLES for rule, (_, caps) in needs.items()}
    reason = (
        "pointing a rule at the doubles needs McpServerTarget or A2aAgentTarget "
        "(guardana.core.target), which the surface does not list"
    )
    if any(served.values()):
        pytest.skip(OUTSIDE + f"{reason}; the pack's rules need {served}")
    pytest.skip(
        NOT_APPLICABLE
        + f"no pack rule ({', '.join(sorted(needs))}) needs what the doubles serve; {reason}"
    )


# Row 4: `files_target`, a `Trace` in a `TraceTarget`, the scripted transports.


def test_row_4_files_target_builds_a_finding_and_a_clean_sample_for_the_pack_rule() -> None:
    rule = unpinned_rule()

    unpinned = list(rule.run(files_target({"requirements.txt": "requests>=2.31\n"}), RuleContext()))
    pinned = list(rule.run(files_target({"requirements.txt": "requests==2.32.3\n"}), RuleContext()))

    assert [(f.rule_id, f.verdict) for f in unpinned] == [
        ("reference.supply_chain.unpinned_requirement", None)
    ]
    assert pinned == []


def test_row_4_a_file_past_source_read_limit_is_reported_unread_not_dropped() -> None:
    target = files_target({"app.py": "x = 1\n" * 64}, source_read_limit=16)
    (path,) = target.iter_files((".py",))

    assert target.python_source(path) is None
    assert [u.path.name for u in target.unread_sources()] == ["app.py"]


def test_row_4_a_scripted_transport_replies_in_order_and_repeats_its_last_reply() -> None:
    transport = ScriptedTransport("first", "second")

    replies = [transport.send("https://model.example.test/v1", "model", [], None) for _ in range(3)]

    assert replies == ["first", "second", "second"]


def test_row_4_a_trace_in_a_trace_target() -> None:
    needs = pack_rule_needs()
    reason = (
        "Trace (guardana.core.trace) and TraceTarget (guardana.core.target.trace) "
        "are not in the surface"
    )
    reading = {
        rule for rule, (kind, caps) in needs.items() if kind == TRACE_KIND or "read_trace" in caps
    }
    if reading:
        pytest.skip(OUTSIDE + f"{reason}; the pack's trace rules: {sorted(reading)}")
    pytest.skip(
        NOT_APPLICABLE + f"no pack rule ({', '.join(sorted(needs))}) reads a trace; {reason}"
    )


# Rows 5 and 6: `assert_renderer_conforms`, `assert_reporter_conforms`, over `sample_verifications`.


def test_the_samples_are_the_five_runs_the_page_names_and_only_the_first_passes() -> None:
    samples = sample_verifications()

    assert len(samples) == 5
    assert [s.gate for s in samples[:2]] == ["pass", "fail"]
    assert all(s.gate != "pass" and s.exit_code != 0 for s in samples[2:])


def test_row_5_the_pack_format_keeps_the_output_contract() -> None:
    spec = entry_point("guardana.renderers", "reference-summary").load()()

    assert_renderer_conforms(spec, name="reference-summary")


def test_row_6_the_pack_reporter_keeps_the_output_contract(tmp_path: Path) -> None:
    accepting = tmp_path / "summaries"
    accepting.mkdir()
    refusing = tmp_path / "a-file"
    refusing.write_text("", encoding="utf-8")
    spec = entry_point("guardana.reporters", "reference-file").load()()

    assert_reporter_conforms(
        spec,
        delivered=str(accepting),
        rejected=str(refusing),
        unreachable=str(tmp_path / "absent"),
        name="reference-file",
    )

    assert len(list(accepting.iterdir())) == len(sample_verifications())


def _post(url: str) -> int:
    # S310: a loopback URL the receiver itself serves.
    with urllib.request.urlopen(urllib.request.Request(url, data=b"{}"), timeout=10) as reply:  # noqa: S310
        assert json.load(reply) == {"status": "ok", "duplicate": False, "stored": 0}
        return int(reply.status)


def test_row_6_the_receiver_serves_an_accepting_a_refusing_and_a_closed_url() -> None:
    with receiver() as served:
        assert _post(served.accepting) == 200
        with pytest.raises(urllib.error.HTTPError) as refused:
            _post(served.refusing)
        assert refused.value.code == 403
        with pytest.raises(urllib.error.URLError):
            _post(served.closed)

        assert len(served.received) == 2
