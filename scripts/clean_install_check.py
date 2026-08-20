#!/usr/bin/env python3
"""Install the five packages into an empty environment and run the documented commands.

The gate runs in one environment, and it is the one environment a user does not
have: everything is installed, including things nothing declares. That is how
`0.9.0` was tagged with a `guardana` that crashed on **every** command
(`ModuleNotFoundError: click`, because Typer 0.26 vendored Click and stopped
requiring it). Nothing in ruff, mypy, pytest or the dogfood scan could see it.

So this does what a user does: an empty virtual environment, the five
distributions, and then the commands the documentation tells people to type. It
asserts exit codes, not just absence of a crash — a scanner that prints
"No findings" because no rule loaded is the failure this project exists to
prevent, and it exits `0` while doing it.

    uv run python scripts/clean_install_check.py
    uv run python scripts/clean_install_check.py --keep   # leave the venv to poke at

Run it before every tag. CI runs it on every push (`clean-install` job).
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_PACKAGES = [
    "guardana-core",
    "guardana-rules",
    "guardana-report",
    "guardana-cli",
    "guardana-server",
]
_VERSION_RE = re.compile(r'^version = "(?P<v>[^"]+)"', re.MULTILINE)
_TRACEBACK = "Traceback (most recent call last)"
_BIN = "Scripts" if sys.platform == "win32" else "bin"


@dataclass(frozen=True)
class Check:
    """One documented command, and what a working install must answer with."""

    name: str
    argv: list[str]
    exit_code: int
    expect: tuple[str, ...] = ()
    reject: tuple[str, ...] = field(default=())


def _version() -> str:
    pyproject = (_ROOT / "packages" / "guardana-core" / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    match = _VERSION_RE.search(pyproject)
    if match is None:
        raise SystemExit("could not read the version from guardana-core/pyproject.toml")
    return match.group("v")


def _clean_environment(venv: Path) -> dict[str, str]:
    """Build the user's environment, not the developer's.

    Every `GUARDANA_*` variable is dropped: a database URL or a collector token
    exported in this shell would otherwise decide what these commands do.
    """
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GUARDANA_")}
    environment["VIRTUAL_ENV"] = str(venv)
    environment["PATH"] = f"{venv / _BIN}{os.pathsep}{environment.get('PATH', '')}"
    environment.pop("PYTHONPATH", None)
    return environment


def _run(argv: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    # S603: every command is built here from literals and repository paths.
    return subprocess.run(  # noqa: S603
        argv, cwd=_ROOT, check=False, text=True, capture_output=True, env=environment
    )


def _install(venv: Path, environment: dict[str, str]) -> None:
    print(f"creating an empty environment in {venv}")
    _uv(["venv", str(venv)], environment)
    print(f"installing {', '.join(_PACKAGES)} — and nothing else")
    _uv(["pip", "install", *[f"./packages/{name}" for name in _PACKAGES]], environment)


def _uv(arguments: list[str], environment: dict[str, str]) -> None:
    result = _run(["uv", *arguments], environment)
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"uv {' '.join(arguments)} failed with {result.returncode}")


def _checks(venv: Path, clean_directory: Path, trace_file: Path) -> list[Check]:
    guardana = str(venv / _BIN / "guardana")
    collector = str(venv / _BIN / "guardana-collector")
    python = str(venv / _BIN / "python")
    return [
        Check("version", [guardana, "--version"], 0, expect=(_version(),)),
        # A rule catalog reaching the CLI through entry points is what makes every
        # other check meaningful: without it the scanner passes everything.
        Check("rules discovered", [guardana, "rules"], 0, expect=("guardana.",)),
        # Framework catalogues are data files inside the wheel, not Python. If the
        # build ever stopped shipping them, importing the engine would raise and
        # every rule's mapping would fail to load — so a clean install has to read
        # one back, not just start.
        Check(
            "taxonomy catalogues installed",
            [guardana, "taxonomy", "LLM07:2025"],
            0,
            expect=("System Prompt Leakage", "LLM08:2026"),
        ),
        Check("scan of clean input", [guardana, "scan", str(clean_directory)], 0),
        # And the other direction, because "found nothing" must be a result, not a
        # default: the deliberately malicious fixture has to fail the scan.
        Check(
            "scan of the vulnerable fixture",
            [guardana, "scan", str(_ROOT / "examples" / "vulnerable-model")],
            1,
        ),
        Check("unknown flag", [guardana, "scan", "--no-such-flag", "."], 3),
        Check("path that does not exist", [guardana, "scan", "/no/such/path"], 3),
        Check("doctor", [guardana, "doctor"], 0),
        Check("collector help", [collector, "--help"], 0),
        # The collector refuses to guess a storage backend. It must refuse in
        # words, with a code from the table — not with a stack trace.
        Check(
            "collector without storage",
            [collector, "status"],
            3,
            expect=("not told where to keep",),
        ),
        Check("server package imports", [python, "-c", "import guardana.server"], 0),
        # The two subpackages `guardana-core` ships beside `guardana.core`. A wheel
        # that failed to carry one imports fine here, in a checkout, and fails for
        # everybody who installed it — which is the exact shape of the defect that
        # made 0.9.0 unshippable, one namespace along.
        Check(
            "the pytest assertion API imports and refuses a target that is not there",
            [
                python,
                "-c",
                "from guardana.testing import assert_secure\n"
                "try:\n"
                "    assert_secure('/no/such/path')\n"
                "except ValueError as exc:\n"
                "    print('refused:', exc)\n"
                "else:\n"
                "    raise SystemExit('a path that does not exist passed')",
            ],
            0,
            expect=("refused:",),
        ),
        # The conformance kit ships in the package rather than in this repository's
        # tests, precisely so a third party can run it. A wheel that carried the
        # protocols and not the kit would leave the extension contract checkable
        # only by us, which is the state 0.22.0 existed to end.
        Check(
            "the conformance kit refuses a target that lies about what it supports",
            [
                python,
                "-c",
                "from guardana.core.target import Capability, Target, TargetKind\n"
                "from guardana.testing import TargetContractError, assert_target_conforms\n"
                "class Liar(Target):\n"
                "    kind = TargetKind.ARTIFACT\n"
                "    def capabilities(self): return {Capability.READ_FILES}\n"
                "    @property\n"
                "    def ref(self): return 'liar://'\n"
                "try:\n"
                "    assert_target_conforms(Liar())\n"
                "except TargetContractError as exc:\n"
                "    print('refused:', str(exc).splitlines()[-1])\n"
                "else:\n"
                "    raise SystemExit('a target with no surface passed the contract')",
            ],
            0,
            expect=("refused:",),
        ),
        # A dynamic run has to leave a denominator behind. Checked on the installed
        # wheel because the channel crosses four packages — core records it, report
        # renders it, the CLI writes it and diff reads it — and a wheel missing any
        # one of them still imports.
        Check(
            "a graded run records what it measured, passes included",
            [
                python,
                "-c",
                "from guardana.core.assessment import case_id_for, from_verdict\n"
                "from guardana.core.evaluator.base import Verdict\n"
                "from guardana.core.report import ScanResult\n"
                "from guardana.core.report.serialize import assessment_to_dict\n"
                "v = Verdict(outcome='pass', confidence=0.6, rationale='refused', "
                "evaluator_id='keyword')\n"
                "a = from_verdict(v, case_id=case_id_for('r', 'p'), subject_ref='x', "
                "rule_id='r')\n"
                "run = ScanResult(findings=(), rules_run=('r',), rules_skipped=(), "
                "assessments=(a,))\n"
                "assert len(run.measured) == 1\n"
                "assert assessment_to_dict(a)['passed'] is True\n"
                "print('measured:', len(run.measured))",
            ],
            0,
            expect=("measured: 1",),
        ),
        Check(
            "the framework adapter imports without its framework",
            [
                python,
                "-c",
                "import sys\n"
                "from guardana.adapters.langchain import langchain_target\n"
                "assert not [m for m in sys.modules if m.split('.')[0] == 'langchain']\n"
                "print('adapter ready')",
            ],
            0,
            expect=("adapter ready",),
        ),
        # The three translators, and the whole path they exist for: a framework's
        # own run record becomes a trace, the trace becomes a target, and a rule
        # grades it. Each step is fine in a checkout and each is a separate module
        # a wheel could fail to carry.
        Check(
            "the trace translators turn a framework run into a graded finding",
            [python, "-c", _TRANSLATOR_SCRIPT],
            0,
            expect=("cross_tenant_retrieval", "translators ready"),
        ),
        # Both eras of MCP, settled the way a real run settles them. Nothing here
        # reaches the network — the scripted server ships in `guardana.core.testing`
        # — but everything else is the production path, including the decision that
        # records which revision a server agreed to.
        # The writer is a public seam a wheel could fail to carry, and its refusals
        # are the product rather than the ergonomics: an unmapped mutating tool must
        # not be recorded as harmless, a session nobody signed off must not read as
        # finished, and a machine's approval must not satisfy a demand for a person.
        Check(
            "a producer writes a trace, continues it across processes, and refuses a bad span",
            [python, "-c", _WRITER_SCRIPT],
            0,
            expect=("writer ready",),
        ),
        Check(
            "the MCP client speaks both revisions and records the one it agreed to",
            [python, "-c", _MCP_ERAS_SCRIPT],
            0,
            expect=("modern 2026-07-28", "legacy 2025-11-25", "eras ready"),
        ),
        # A security contract crosses both wheels — the schema and its refusals live
        # in `guardana.core.contract`, the checking in `guardana.rules.contract` — so
        # a build that carried one and not the other would load a contract and grade
        # nothing with it. Both halves of the honesty boundary are exercised: an
        # assertion that fires, and one whose dimension the producer does not record,
        # which has to come back as a demand rather than as a clean run.
        Check(
            "a security contract compiles, fires, and refuses what it cannot check",
            [python, "-c", _CONTRACT_SCRIPT],
            0,
            expect=("finding: contract.acme.never-shell", "demanded: approval", "contract ready"),
        ),
        # And the same capability through the command line, on a file, the way the
        # documentation says to run it — because a subcommand group registered in one
        # place and imported in another is exactly what a wheel can drop.
        # The pack manifest is a data file inside the wheel, and `pack validate` is
        # the command 1.0 entry criterion 8 asks a third party to run against a
        # release candidate. A manifest left out of the build makes it answer "no
        # pack declared a manifest" — indistinguishable from a user who wrote none.
        Check(
            "the built-in pack ships its manifest and validates",
            [guardana, "pack", "validate"],
            0,
            expect=("guardana-rules", "extension API implemented by this build: 1"),
        ),
        # The lock is written from installed metadata, which is precisely what an
        # editable checkout and a real wheel disagree about: the distribution behind a
        # module and its version both come from the installed distribution's metadata,
        # and the PEP 420 namespace makes the naive lookup answer with the wrong one
        # of five. A lock that pinned the built-in rules to the wrong package, at a
        # version that could not be read, would look entirely fine until somebody
        # opened the file — so this opens it.
        Check(
            "a lock pins the installed pack by its own distribution and version",
            [python, "-c", _LOCK_SCRIPT],
            0,
            expect=("distribution: guardana-rules", "lock ready"),
        ),
        # A rule's fixtures are data too, and an unsampled rule must never read as
        # a pass — so this asserts the honest verdict rather than a green one.
        Check(
            "rule fixtures ship and an unsampled rule is not a pass",
            [guardana, "rule", "test", "guardana.prompt.system_prompt_leak.canary"],
            0,
            expect=("3 fixture(s) passed", "0 rule(s) not fully sampled"),
        ),
        Check(
            "an unsampled rule is indeterminate rather than green",
            [guardana, "rule", "test", "guardana.supply_chain.pickle_opcode"],
            2,
            expect=("declares no fixtures",),
        ),
        Check(
            "trace inspect prints the evidence matrix and no coverage percentage",
            [guardana, "trace", "inspect", str(trace_file)],
            0,
            expect=("dimension", "declared", "records", "needed by", "unlocks", "effects"),
        ),
    ]


_TRACE_FILE = """\
{"guardana_trace": 2, "instrumented": ["effects"], "producer": {"name": "acme"}, \
"trace_id": "t-1"}
{"kind": "tool_execution", "name": "refund", "span_id": "s1", \
"effects": [{"sink": "payment", "action": "payment.refund", "status": "executed"}]}
"""
"""A native trace, written by hand rather than serialized from the model.

Hand-written on purpose: this file is what a *third party* would produce against the
published `trace-v2` schema, so a reader that quietly stopped accepting the documented
shape would still pass a check that round-tripped Guardana's own writer.
"""

_LOCK_SCRIPT = """
from guardana.core.pack import installed_packs, lock_of
from guardana.core.pack.lock import Installed
from guardana.core.registry import Registry

packs = installed_packs()
assert packs, "no installed pack declares a manifest"
registry = Registry.discover()
lock = lock_of(packs, Installed(rules={r.meta.id: r.digest() for r in registry.rules()}))
(builtin,) = [p for p in lock.packs if p.name == "guardana-rules"]
print("distribution:", builtin.distribution)
assert builtin.version, "the lock recorded no version for the pack shipping the built-ins"
assert builtin.rules, "the lock pinned no rules"
print("lock ready")
"""

_CONTRACT_SCRIPT = """
from guardana.core.contract import contract_from_dict
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.runner import Runner
from guardana.core.target import TraceTarget
from guardana.core.trace import (
    Dimension,
    EffectStatus,
    Provenance,
    SideEffect,
    SinkKind,
    Span,
    SpanKind,
    Trace,
)
from guardana.rules.contract import compile_contracts

contract = contract_from_dict(
    {
        "schema_version": 1,
        "name": "acme",
        "assertions": [
            {"id": "never-shell", "type": "forbidden_sink", "sinks": ["shell"]},
            {"id": "pay-needs-a-human", "type": "approval_required", "actions": ["payment.*"]},
        ],
    },
    source="acme.yaml",
)
compiled = compile_contracts([contract], None)

trace = Trace(
    trace_id="t-1",
    spans=(
        Span(
            span_id="s1",
            kind=SpanKind.TOOL_EXECUTION,
            name="s1",
            effects=(
                SideEffect(sink=SinkKind.SHELL, action="sh", status=EffectStatus.EXECUTED),
                SideEffect(
                    sink=SinkKind.PAYMENT, action="payment.refund", status=EffectStatus.EXECUTED
                ),
            ),
        ),
    ),
    provenance=Provenance(producer="acme", source="acme.jsonl", dialect="guardana"),
    # Effects only: the approval assertion cannot be checked, and must say so.
    instrumented=frozenset({Dimension.EFFECTS}),
)

registry = Registry.discover()
for rule in compiled.rules:
    registry.register_rule(rule)
profile = Profile(name="t", policy=Policy()).demanding(compiled.required_dimensions)
result = Runner(registry=registry, profile=profile).run(TraceTarget(trace))

for finding in result.findings:
    print("finding:", finding.rule_id)
for gap in result.coverage_shortfall:
    print("demanded:", gap.name)
if not result.coverage_shortfall:
    raise SystemExit("an unverifiable contract assertion reported no unmet demand")
print("contract ready")
"""

_MCP_ERAS_SCRIPT = """
from guardana.core.rule import RuleContext
from guardana.core.target import McpServerTarget
from guardana.core.testing import ScriptedMcpServer
from guardana.rules.mcp import McpSessionBindingRule

URL = "https://93.184.215.14/mcp"
TOOLS = [{"name": "read_file", "description": "Read a file."}]
COUNTER = ["mcp-session-1000", "mcp-session-1001", "mcp-session-1002"]


def probe(**settings):
    server = ScriptedMcpServer(URL, tools=TOOLS, credential="t", session_ids=COUNTER, **settings)
    target = McpServerTarget(URL, credential="t", sender=server)
    reported = list(McpSessionBindingRule().run(target, RuleContext()))
    target.list_tools()
    return target.protocols(), reported


modern, silent = probe(protocol_versions=["2026-07-28"])
print("modern", modern["mcp"])
if silent:
    raise SystemExit(f"a server with no sessions was accused: {silent[0].evidence.summary}")

legacy, reported = probe()
print("legacy", legacy["mcp"])
if not reported:
    raise SystemExit("a counter for session ids went unreported on the handshake era")

print("eras ready")
"""


_WRITER_SCRIPT = """
import json
import tempfile
from pathlib import Path

from guardana.core.trace import (
    Approval,
    ApproverKind,
    Dialect,
    Dimension,
    SinkKind,
    SinkMap,
    Span,
    SpanKind,
    ToolExecution,
    ToolStatus,
    TraceTruncation,
    TraceWriteError,
    open_trace,
    read_trace,
    resume_trace,
)

sinks = SinkMap({"refund": SinkKind.PAYMENT}, default=SinkKind.OTHER)
declared = [Dimension.TOOLS, Dimension.APPROVAL, Dimension.EFFECTS]
call = Span(
    span_id="s1",
    kind=SpanKind.TOOL_EXECUTION,
    name="refund",
    tool=ToolExecution(name="refund", status=ToolStatus.SUCCEEDED, mutates=True),
    approvals=(Approval.granted_by_automation("policy", action="refund"),),
)

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "session.jsonl"
    with open_trace(path, trace_id="t", producer="clean-install", instrumented=declared,
                    sinks=sinks) as trace:
        trace.span(call)
    read = read_trace(path, Dialect.GUARDANA).trace
    effect = read.spans[0].effects[0]
    approval = read.spans[0].approvals[0]
    assert read.truncated is None, read.truncated
    assert effect.sink is SinkKind.PAYMENT, effect
    assert approval.approver_kind is ApproverKind.AUTOMATED, approval
    assert approval.approver_ref == "automated:policy", approval
    assert json.loads(path.read_text().splitlines()[-1])["spans"] == 1

    # A second process continuing the same session, and one that never signed off.
    across = Path(directory) / "across.jsonl"
    for step in range(2):
        with resume_trace(across, trace_id="t", producer="clean-install",
                          instrumented=declared, sinks=sinks) as trace:
            trace.span(Span(span_id=f"s{step}", kind=SpanKind.TOOL_EXECUTION, name="refund",
                            tool=ToolExecution(name="refund", mutates=True)))
    unfinished = read_trace(across, Dialect.GUARDANA).trace
    assert len(unfinished.spans) == 2, unfinished.spans
    assert unfinished.truncated is TraceTruncation.UNTERMINATED, unfinished.truncated
    resume_trace(across, trace_id="t", producer="clean-install", instrumented=declared,
                 sinks=sinks).finish()
    assert read_trace(across, Dialect.GUARDANA).trace.truncated is None

    # The refusal the whole writer exists for: a mutating tool nobody mapped.
    refused = Path(directory) / "refused.jsonl"
    try:
        with open_trace(refused, trace_id="t", producer="clean-install",
                        instrumented=declared, sinks=sinks) as trace:
            trace.span(Span(span_id="s1", kind=SpanKind.TOOL_EXECUTION, name="terminal",
                            tool=ToolExecution(name="terminal", mutates=True)))
    except TraceWriteError as exc:
        assert "terminal" in str(exc), exc
    else:
        raise SystemExit("an unmapped mutating tool was recorded as harmless")

print("writer ready")
"""


_TRANSLATOR_SCRIPT = """
import sys

from guardana.adapters.crewai import crewai_trace
from guardana.adapters.llama_index import llama_index_trace
from guardana.adapters.pydantic_ai import pydantic_ai_trace
from guardana.core.target import TraceTarget
from guardana.testing import SecurityAssertionError, assert_secure

loaded = [m for m in sys.modules if m.split(".")[0] in ("crewai", "llama_index", "pydantic_ai")]
assert not loaded, loaded


class Node:
    def __init__(self, node_id, tenant):
        self.node_id = node_id
        self.metadata = {"tenant": tenant}
        self.text = "an invoice"
        self.ref_doc_id = None


class Scored:
    def __init__(self, node):
        self.node = node
        self.node_id = node.node_id
        self.metadata = node.metadata
        self.score = 0.7

    def get_content(self):
        return self.node.text


trace = llama_index_trace(
    [Scored(Node("d1", "acme")), Scored(Node("d2", "globex"))],
    query="invoices",
    tenant="acme",
)
try:
    assert_secure(TraceTarget(trace))
except SecurityAssertionError as exc:
    print("graded:", "cross_tenant_retrieval" in str(exc) and "cross_tenant_retrieval")
else:
    raise SystemExit("a cross-tenant retrieval was not reported")


class Task:
    agent = "Writer"
    raw = "the report"
    description = "write it up"
    name = "write"
    messages = []


class Output:
    raw = "the report"
    tasks_output = [Task()]


assert crewai_trace(Output()).spans[0].agent.name == "Writer"


class Result:
    run_id = "r-1"
    conversation_id = "c-1"

    def all_messages(self):
        return []


assert pydantic_ai_trace(Result()).trace_id == "r-1"
print("translators ready")
"""


def _report(check: Check, result: subprocess.CompletedProcess[str]) -> str | None:
    output = result.stdout + result.stderr
    if result.returncode != check.exit_code:
        return f"exited {result.returncode}, expected {check.exit_code}"
    missing = [text for text in check.expect if text not in output]
    if missing:
        return f"output does not mention {missing}"
    present = [text for text in (*check.reject, _TRACEBACK) if text in output]
    if present:
        return f"output contains {present}"
    return None


def main() -> int:
    """Install into an empty environment, run every check, and report what failed."""
    keep = "--keep" in sys.argv[1:]
    workspace = Path(tempfile.mkdtemp(prefix="guardana-clean-install-"))
    try:
        venv = workspace / ".venv"
        clean_directory = workspace / "clean"
        clean_directory.mkdir()
        (clean_directory / "app.py").write_text("print('hello')\n", encoding="utf-8")
        # Beside the scan input rather than inside it: the clean directory exists to
        # prove a scan of ordinary files finds nothing, and adding material to it
        # would quietly change what that check is checking.
        trace_file = workspace / "trace.jsonl"
        trace_file.write_text(_TRACE_FILE, encoding="utf-8")

        environment = _clean_environment(venv)
        _install(venv, environment)

        failures = 0
        for check in _checks(venv, clean_directory, trace_file):
            result = _run(check.argv, environment)
            problem = _report(check, result)
            if problem is None:
                print(f"  ok    {check.name}")
                continue
            failures += 1
            print(f"  FAIL  {check.name}: {problem}")
            print(f"        $ {' '.join(check.argv)}")
            for line in (result.stdout + result.stderr).splitlines()[:20]:
                print(f"        | {line}")

        if failures:
            print(f"\n{failures} check(s) failed — a clean install does not work")
            return 1
        print("\na clean install works: every documented command answered as documented")
        return 0
    finally:
        if keep:
            print(f"environment kept at {workspace}")
        else:
            shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
