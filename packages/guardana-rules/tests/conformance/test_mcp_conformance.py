"""Every MCP rule graded against servers built on the `mcp` SDK, one test per fixture-table row.

The SDK writes the wire, the era routing, the sessions, the caching hints, the bearer
middleware and the protected-resource metadata, so a reading of the specification
Guardana shares with its own scripted double cannot pass here. Each run goes through
`guardana probe --mcp`, and the saved run is what is read.

Two findings appear on every gated fixture and are the SDK's defaults rather than a
row's policy: its `WWW-Authenticate` challenge names no scope (`scope_breadth`), and the
authorization-server metadata it serves does not advertise RFC 9207 `iss`
(`issuer_identification`). They are pinned as exactly that, so any other finding fails.
"""

import importlib
import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import mcp_servers as mcp
import pytest
from guardana.cli.main import app
from sdk_harness import Factory, serving
from typer.testing import CliRunner

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_VARIABLE = "GUARDANA_CONFORMANCE_MCP_TOKEN"
_MODERN = "2026-07-28"
_SDK_DEFAULTS = {"guardana.mcp.scope_breadth", "guardana.mcp.issuer_identification"}
_TASKS = "guardana.mcp.task_identity"
_REGISTRY = "guardana.mcp.registry_entry"
_REGISTRY_NAME = "io.example.conformance/lookup"

Entry = Callable[[str], dict[str, object]]
"""Build a registry `server.json` from the URL the fixture is served at."""


def _plain(output: str) -> str:
    return " ".join(_ANSI.sub("", output).replace("│", " ").split())


@dataclass(frozen=True)
class Run:
    """One probe of one fixture: its exit code, what it saved, and the URL it reached."""

    code: int
    document: dict[str, Any]
    url: str
    stderr: str

    @property
    def protocols(self) -> dict[str, str]:
        """What the server answered, as the run recorded it."""
        recorded: dict[str, str] = self.document["run"]["coverage"]["protocols"]
        return recorded

    def findings(self, rule_id: str) -> list[dict[str, Any]]:
        """The findings one rule reported."""
        return [f for f in self.document["findings"] if f["rule_id"] == rule_id]

    def unverified(self, rule_id: str) -> list[dict[str, Any]]:
        """The questions one rule could not settle."""
        return [f for f in self.document["unverified"] if f["rule_id"] == rule_id]

    def skipped(self, rule_id: str) -> list[dict[str, Any]]:
        """The skip the run recorded for one rule, if any."""
        skips = self.document["run"]["result_summary"].get("rules_skipped", [])
        return [s for s in skips if s["rule_id"] == rule_id]

    def errors(self, rule_id: str) -> list[dict[str, Any]]:
        """The errors the run recorded against one rule."""
        return [e for e in self.document["errors"] if e["source"] == rule_id]

    def summaries(self, rule_id: str) -> list[str]:
        """Every evidence line one rule wrote, findings first, then any error it raised."""
        reported = self.findings(rule_id) + self.unverified(rule_id)
        return [f["evidence"]["summary"] for f in reported] + [
            e["reason"] for e in self.errors(rule_id)
        ]

    def ran(self, rule_id: str) -> bool:
        """Whether the run lists the rule as run and recorded no error against it."""
        run = self.document["run"]["result_summary"]["rules_run"]
        return rule_id in run and not self.errors(rule_id)

    def silent(self, rule_id: str) -> bool:
        """Whether a rule ran and said nothing: no finding, open question, skip or error."""
        reported = self.findings(rule_id) or self.unverified(rule_id) or self.skipped(rule_id)
        return self.ran(rule_id) and not reported

    @property
    def finding_rules(self) -> set[str]:
        """Every rule that reported a finding."""
        return {f["rule_id"] for f in self.document["findings"]}


def _probe(  # noqa: PLR0913 — the fixture, where to write, and how the run is configured
    factory: Factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    credential: bool,
    entry: Entry | None = None,
    name: str = "run.json",
) -> Run:
    """Probe the fixture through the CLI and read back the run it saved."""
    written = tmp_path / name
    flags = ["--mcp-token-env", _VARIABLE] if credential else []
    monkeypatch.setenv(_VARIABLE, mcp.CREDENTIAL)
    with serving(factory) as origin:
        url = f"{origin.url}{mcp.MCP_PATH}"
        if entry is not None:
            path = tmp_path / "server.json"
            path.write_text(json.dumps(entry(url)), encoding="utf-8")
            flags += ["--mcp-registry-entry", str(path)]
        result = CliRunner().invoke(
            app, ["probe", "--mcp", url, *flags, "--format", "json", "--output", str(written)]
        )
    document = json.loads(written.read_text(encoding="utf-8"))
    return Run(result.exit_code, document, url, _plain(result.stderr))


_GATED = [
    pytest.param(mcp.legacy_only_gated, {"mcp": mcp.LEGACY_REVISION}, id="legacy-only"),
    pytest.param(mcp.modern_only_gated, {"mcp": _MODERN}, id="modern-only"),
    pytest.param(mcp.dual_era_gated, {"mcp": _MODERN}, id="dual-era"),
]


_NOTHING_TO_GRADE: dict[Factory, tuple[str, str]] = {
    mcp.legacy_only_gated: ("guardana.mcp.cache_scope", mcp.LEGACY_REVISION),
    mcp.modern_only_gated: ("guardana.mcp.session_binding", _MODERN),
}
"""The rule each gated fixture's revision leaves nothing to grade, and that revision."""


@pytest.mark.parametrize(("factory", "answered"), _GATED)
def test_a_gated_server_probed_with_its_token_is_graded_in_the_revision_it_answered(
    factory: Factory, answered: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _probe(factory, tmp_path, monkeypatch, credential=True)

    assert run.code == 0, run.stderr
    assert run.protocols == answered
    assert run.finding_rules == _SDK_DEFAULTS
    not_applicable, revision = _NOTHING_TO_GRADE.get(factory, ("", ""))
    for rule_id in (
        "guardana.mcp.unauthenticated_access",
        "guardana.mcp.authorization_discovery",
        "guardana.mcp.token_audience",
        "guardana.mcp.session_binding",
        "guardana.mcp.discovery_target",
        "guardana.mcp.cache_scope",
    ):
        if rule_id == not_applicable:
            (skip,) = run.skipped(rule_id)
            assert skip["reason"] == "not_applicable"
            assert revision in skip["detail"]
            assert not run.ran(rule_id)
        else:
            assert run.silent(rule_id), (rule_id, run.summaries(rule_id))
    # The anonymous tasks/list is refused like every anonymous request here, and a
    # refused listing shows nobody's tasks: silent, never not offered.
    assert run.silent(_TASKS), run.summaries(_TASKS)


@pytest.mark.parametrize(("factory", "answered"), _GATED)
def test_a_gated_server_probed_without_a_credential_leaves_the_credentialed_questions_open(
    factory: Factory, answered: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _probe(factory, tmp_path, monkeypatch, credential=False)

    assert run.code == 2, run.stderr
    assert run.silent("guardana.mcp.unauthenticated_access")
    sessions = run.unverified("guardana.mcp.session_binding")
    assert len(sessions) == 1
    assert "--mcp-token-env" in sessions[0]["evidence"]["summary"]
    # Silence from token_audience means the forged token was refused, which needs no
    # credential of the operator's to observe.
    assert run.silent("guardana.mcp.token_audience")
    assert not run.findings(_TASKS)


def test_a_dual_era_server_whose_legacy_probe_failed_leaves_its_sessions_inconclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _probe(mcp.dual_era_failing_first_handshake, tmp_path, monkeypatch, credential=True)

    assert run.code == 0, run.stderr
    assert run.protocols == {"mcp": _MODERN}
    (said,) = run.unverified("guardana.mcp.session_binding")
    assert "HTTP 503 carrying JSON-RPC error -32603" in said["evidence"]["summary"]


def test_a_rule_that_raised_is_never_read_as_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: object, view: object) -> Iterator[object]:
        raise RuntimeError("examine failed")

    # Looked up now rather than imported at collection: another test may have dropped
    # the rule modules, and the run loads whichever class `sys.modules` holds.
    rules = importlib.import_module("guardana.rules.mcp.task_identity")
    monkeypatch.setattr(rules.McpTaskIdentityRule, "examine", broken)

    run = _probe(mcp.dual_era_gated, tmp_path, monkeypatch, credential=True)

    assert run.errors(_TASKS)
    assert not run.silent(_TASKS)
    assert run.code == 2, run.stderr


def test_an_open_server_is_reported_as_open_on_loopback_and_offers_no_tasks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _probe(mcp.open_server, tmp_path, monkeypatch, credential=False)

    assert run.code == 0, run.stderr
    open_access = run.findings("guardana.mcp.unauthenticated_access")
    assert [f["severity"] for f in open_access] == ["LOW"]
    assert "loopback" in open_access[0]["evidence"]["summary"]
    assert len(run.unverified("guardana.mcp.token_audience")) == 1
    assert [s["reason"] for s in run.skipped(_TASKS)] == ["not_offered"]
    assert run.skipped(_TASKS)[0]["missing"] == ["tasks"]


def test_a_server_accepting_any_token_fails_audience_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _probe(mcp.accepting_any_token, tmp_path, monkeypatch, credential=True)

    assert run.code == 1, run.stderr
    assert [f["severity"] for f in run.findings("guardana.mcp.token_audience")] == ["CRITICAL"]


@pytest.mark.parametrize(
    ("factory", "fires"),
    [
        pytest.param(mcp.modern_public_cache, True, id="modern"),
        pytest.param(mcp.dual_era_public_cache, True, id="dual-era"),
        pytest.param(mcp.legacy_public_cache, False, id="legacy"),
    ],
)
def test_a_public_cache_hint_on_a_gated_listing_fires_only_where_the_revision_carries_it(
    factory: Factory, fires: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _probe(factory, tmp_path, monkeypatch, credential=True)

    assert run.code == 0, run.stderr
    cache = run.findings("guardana.mcp.cache_scope")
    assert [f["severity"] for f in cache] == (["MEDIUM"] if fires else [])
    if not fires:
        assert [s["reason"] for s in run.skipped("guardana.mcp.cache_scope")] == ["not_applicable"]


def test_an_owner_bound_task_listing_refused_to_an_anonymous_caller_is_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _probe(mcp.legacy_tasks_owner_bound, tmp_path, monkeypatch, credential=True)

    assert run.code == 0, run.stderr
    assert run.silent(_TASKS), run.summaries(_TASKS)


def test_an_empty_anonymous_listing_beside_the_operators_task_is_silent_and_withholds_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _probe(mcp.legacy_tasks_listed_by_owner, tmp_path, monkeypatch, credential=True)

    assert run.code == 0, run.stderr
    # Silent only because the operator's own listing held a task: with none it is
    # inconclusive (below), so the task id below was listed to the run.
    assert run.silent(_TASKS), run.summaries(_TASKS)
    assert mcp.OWNED_TASK not in json.dumps(run.document)


def test_an_empty_anonymous_listing_with_no_task_for_the_operator_either_is_inconclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _probe(
        mcp.legacy_tasks_listed_by_owner_none_stored, tmp_path, monkeypatch, credential=True
    )

    assert run.code == 0, run.stderr
    assert not run.findings(_TASKS)
    assert ["until a task exists" in line for line in run.summaries(_TASKS)] == [True]


def test_counting_task_ids_listed_to_anyone_on_an_open_server_are_two_highs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _probe(mcp.legacy_tasks_listed_to_anyone, tmp_path, monkeypatch, credential=False)

    assert run.code == 1, run.stderr
    reported = run.findings(_TASKS)
    assert [f["severity"] for f in reported] == ["HIGH", "HIGH"]
    assert f"lists {len(mcp.COUNTING_TASKS)} task(s)" in reported[0]["evidence"]["summary"]
    assert "task ids are a counter" in reported[1]["evidence"]["summary"]


def test_an_open_task_listing_with_nothing_stored_leaves_the_ids_ungraded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _probe(mcp.legacy_tasks_none_stored, tmp_path, monkeypatch, credential=False)

    assert run.code == 0, run.stderr
    assert not run.findings(_TASKS)
    assert ["cannot be graded" in line for line in run.summaries(_TASKS)] == [True]


def test_the_modern_tasks_extension_is_inconclusive_as_unlisted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _probe(mcp.modern_tasks_extension, tmp_path, monkeypatch, credential=False)

    assert run.code == 0, run.stderr
    assert not run.findings(_TASKS)
    assert run.summaries(_TASKS) == [
        "the server issues task ids only to a tools/call, which guardana never sends"
    ]


@pytest.mark.parametrize(
    ("factory", "said"),
    [
        pytest.param(mcp.issuer_differs, "names issuer", id="differs"),
        pytest.param(mcp.issuer_absent, "names no issuer", id="absent"),
    ],
)
def test_authorization_server_metadata_naming_another_issuer_or_none_fires(
    factory: Factory, said: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _probe(factory, tmp_path, monkeypatch, credential=True)

    assert run.code == 1, run.stderr
    reported = run.findings("guardana.mcp.authorization_discovery")
    assert [f["severity"] for f in reported] == ["HIGH"]
    assert said in reported[0]["evidence"]["summary"]
    assert "must not use" in reported[0]["evidence"]["summary"]


def _entry(*, remotes: Callable[[str], list[str]], version: str = mcp.REPORTED_VERSION) -> Entry:
    def build(url: str) -> dict[str, object]:
        return {
            "name": _REGISTRY_NAME,
            "version": version,
            "remotes": [{"type": "streamable-http", "url": remote} for remote in remotes(url)],
        }

    return build


@pytest.mark.parametrize(
    ("factory", "entry", "severities", "inconclusive"),
    [
        pytest.param(mcp.dual_era_gated, _entry(remotes=lambda url: [url]), [], 0, id="match"),
        pytest.param(
            mcp.dual_era_gated,
            _entry(remotes=lambda url: [url.replace("/mcp", "/{route}/")]),
            [],
            0,
            id="variable",
        ),
        pytest.param(
            mcp.dual_era_gated,
            _entry(remotes=lambda url: ["https://mcp.example.com/mcp"]),
            ["MEDIUM"],
            0,
            id="unlisted-url",
        ),
        pytest.param(
            mcp.legacy_only_gated,
            _entry(remotes=lambda url: [url], version="9.9.9"),
            ["LOW"],
            0,
            id="other-version",
        ),
        pytest.param(
            mcp.reporting_no_version, _entry(remotes=lambda url: [url]), [], 1, id="no-version"
        ),
    ],
)
def test_a_registry_entry_is_compared_with_the_url_and_the_reported_version(  # noqa: PLR0913, PLR0917
    factory: Factory,
    entry: Entry,
    severities: list[str],
    inconclusive: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _probe(factory, tmp_path, monkeypatch, credential=True, entry=entry)

    assert run.code == 0, run.stderr
    assert [f["severity"] for f in run.findings(_REGISTRY)] == severities, run.summaries(_REGISTRY)
    assert len(run.unverified(_REGISTRY)) == inconclusive
    assert not run.skipped(_REGISTRY)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        pytest.param(mcp.legacy_only_gated, mcp.dual_era_gated, id="legacy-then-dual-era"),
        pytest.param(mcp.modern_only_gated, mcp.legacy_only_gated, id="modern-then-legacy"),
    ],
)
def test_diff_reports_a_change_of_revision_between_runs_as_reach_changed(
    first: Factory, second: Factory, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = _probe(first, tmp_path, monkeypatch, credential=True, name="before.json")
    after = _probe(second, tmp_path, monkeypatch, credential=True, name="after.json")

    result = CliRunner().invoke(
        app, ["diff", str(tmp_path / "before.json"), str(tmp_path / "after.json")]
    )

    said = _plain(result.output)
    assert "the two runs did not have the same reach" in said
    assert f"negotiated protocols went from {before.protocols} to {after.protocols}" in said, said
