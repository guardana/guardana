"""`threat_classes.yaml` places every rule once; the page names the command that runs it.

The threat coverage page is the reader's way into the rule set, so a rule left out of it
is a check nobody finds, and a command the page names that does not select the rule
sends a reader to a run that never checks what they came for. `plan` is the seam: it is
the selection the runner makes, priced without contacting anything, and each command
the page prints is checked against an invocation `plan` accepted. `plan` has no trace
mode; the runner hands a trace every trace rule, which is all `runs_with` says of one.
"""

import json
import re
from collections.abc import Iterable
from pathlib import Path

import pytest
from guardana.cli.main import app
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, Target, TargetKind
from guardana.rules import provide_rules
from typer.testing import CliRunner

import generate_docs

_REPO = Path(__file__).resolve().parents[2]
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_CHAT = ("probe", "--url", "http://model.invalid", "--model", "m")
_MCP = ("probe", "--mcp", "http://mcp.invalid/mcp")


def _rules() -> list[Rule]:
    return list(provide_rules())


def test_every_built_in_rule_sits_under_exactly_one_threat() -> None:
    placed = [
        rule_id
        for threat in generate_docs.load_threat_classes(_rules())
        for rule_id in threat.rules
    ]
    assert sorted(placed) == sorted(rule.meta.id for rule in _rules())


def test_the_page_lists_every_built_in_rule_in_one_row() -> None:
    page = generate_docs._threats(_rules())
    rows = [line for line in page.splitlines() if line.startswith("| `guardana.")]
    listed = [row.split("`")[1] for row in rows]
    assert sorted(listed) == sorted(rule.meta.id for rule in _rules())


def _planned(*args: str) -> set[str]:
    printed = CliRunner().invoke(app, ["plan", *args, "--format", "json"])
    assert printed.exit_code == 0, printed.output
    return set(json.loads(_ANSI.sub("", printed.output))["rules"])


def _named(command: str, args: tuple[str, ...]) -> set[str]:
    def shape(words: Iterable[str]) -> list[str]:
        return [word for word in words if word.startswith("--")]

    words = command.split()
    assert (words[0], shape(words)) == (args[0], shape(args)), (
        f"the page prints {command!r}, which is not the invocation {args!r} plan accepted"
    )
    named = {rule.meta.id for rule in _rules() if generate_docs.runs_with(rule) == command}
    assert named, f"the page says no rule runs with {command}; this test reads nothing"
    return named


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("scan PATH", ("scan", str(_REPO / "examples" / "vulnerable-model"))),
        ("probe --url URL --model MODEL", _CHAT),
        ("probe --mcp URL", _MCP),
        ("probe --a2a URL", ("probe", "--a2a", "http://a2a.invalid")),
    ],
)
def test_the_command_the_page_names_selects_exactly_those_rules(
    command: str, args: tuple[str, ...]
) -> None:
    assert _named(command, args) == _planned(*args)


def test_fixtures_add_exactly_the_rules_the_page_sends_to_them() -> None:
    fixtures = _REPO / "examples" / "retrieval_pilot" / "guardana-fixtures.yaml"
    seeded = (*_CHAT, "--fixtures", str(fixtures))
    named = _named("probe --url URL --model MODEL --fixtures FILE", seeded)
    assert named == _planned(*seeded) - _planned(*_CHAT)


def test_a_registry_entry_adds_exactly_the_rules_the_page_sends_to_it(tmp_path: Path) -> None:
    entry = tmp_path / "server.json"
    entry.write_text(json.dumps({"name": "io.example/demo", "version": "1.0.0"}), encoding="utf-8")
    published = (*_MCP, "--mcp-registry-entry", str(entry))
    named = _named("probe --mcp URL --mcp-registry-entry FILE", published)
    assert named == _planned(*published) - _planned(*_MCP)


class _EndpointReadingATrace(Rule):
    meta = RuleMeta(
        "guardana.demo.endpoint_reading_a_trace",
        "demo",
        Severity.LOW,
        TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.READ_TRACE}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


def test_a_rule_no_command_can_serve_is_refused_rather_than_listed() -> None:
    with pytest.raises(generate_docs.ThreatClassesError, match="no command is known"):
        generate_docs.runs_with(_EndpointReadingATrace())


_A_RULE = "guardana.supply_chain.code_execution"
_ANOTHER = "guardana.supply_chain.pickle_opcode"


def _class(title: str, *rule_ids: str, summary: str = "Checks for x.") -> str:
    listed = "".join(f"\n    - {rule_id}" for rule_id in rule_ids)
    return f"- title: {title}\n  summary: {summary}\n  rules:{listed or ' []'}\n"


@pytest.mark.parametrize(
    ("text", "names"),
    [
        ("", "non-empty list of classes"),
        ("[]\n", "non-empty list of classes"),
        ("title: x\n", "non-empty list of classes"),
        ("- title: x\n  summary: y\n", "exactly"),
        ("- title: x\n  summary: y\n  rules: []\n  why: z\n", "exactly"),
        ("- x\n", "exactly"),
        (_class("A", _A_RULE, summary="'  '"), "'summary' must be a non-blank"),
        (_class("'  '", _A_RULE), "'title' must be a non-blank"),
        (_class("A", _A_RULE, summary="a | b"), "'|'"),
        (_class("A"), "non-empty list of rule ids"),
        ("- title: A\n  summary: y\n  rules: [1]\n", "non-empty list of rule ids"),
        (_class("A", _A_RULE) + _class("A", _ANOTHER), "titles used more than once: A"),
        (_class("A", "guardana.no_such.rule"), "not built-in rule ids: guardana.no_such.rule"),
        (_class("A", _A_RULE) + _class("B", _A_RULE), f"placed more than once: {_A_RULE}"),
        (_class("A", _A_RULE, _A_RULE), f"placed more than once: {_A_RULE}"),
        (_class("A", _A_RULE), "built-in rules in no class: "),
    ],
)
def test_the_loader_refuses_a_file_that_does_not_place_every_rule_once(
    tmp_path: Path, text: str, names: str
) -> None:
    path = tmp_path / "threat_classes.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(generate_docs.ThreatClassesError, match=re.escape(names)) as raised:
        generate_docs.load_threat_classes(_rules(), path)
    assert str(raised.value).startswith(f"{path}: ")


def test_a_rule_left_out_is_named(tmp_path: Path) -> None:
    path = tmp_path / "threat_classes.yaml"
    path.write_text(_class("A", _A_RULE), encoding="utf-8")
    with pytest.raises(generate_docs.ThreatClassesError) as raised:
        generate_docs.load_threat_classes(_rules(), path)
    assert _ANOTHER in str(raised.value)
    assert _A_RULE not in str(raised.value).split("no class: ", 1)[1]
