"""Every run records what it was able to check, not only what it found.

`rules_run` started this promise and kept half of it. A run whose corpus was
trimmed, whose evaluator stopped being installed, whose target lost a capability or
whose server answered an older protocol revision reports fewer findings — and
subtracting two lists reads every one of those as an improvement. The fingerprint is
the other half: one value over all of it, so `diff` can say the reach changed.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from guardana.cli._mcp_run import McpConnection, run_mcp_probe
from guardana.cli._profile import resolve_profile
from guardana.cli.main import app
from guardana.core.manifest.coverage import TaxonomyCatalogRecord, coverage_digest
from guardana.core.manifest.records import EvaluatorRecord, RuleRecord
from guardana.core.profile import Profile
from guardana.core.registry import Registry
from guardana.core.runner import Runner
from guardana.core.taxonomy import catalogs
from typer.testing import CliRunner

runner = CliRunner()

_RULES = (RuleRecord(id="a", digest="d1", trials=4),)
_EVALUATORS = (EvaluatorRecord(id="canary"),)
_CATALOGUES = (TaxonomyCatalogRecord(framework="OWASP-LLM-2026", digest="sha256:aa", entries=10),)


def _digest(**overrides: object) -> str:
    parts: dict[str, object] = {
        "rules": _RULES,
        "evaluators": _EVALUATORS,
        "capabilities": ("read_files",),
        "taxonomies": _CATALOGUES,
        "protocols": {},
    }
    parts.update(overrides)
    return coverage_digest(**parts)  # type: ignore[arg-type]


def test_a_run_pins_every_installed_catalogue_by_digest(tmp_path: Path) -> None:
    document = _scan(tmp_path)

    pinned = {c["framework"]: c for c in document["run"]["coverage"]["taxonomies"]}

    assert {c.framework for c in catalogs()} == set(pinned)
    assert pinned["OWASP-LLM-2025"]["digest"] != pinned["OWASP-LLM-2026"]["digest"]
    assert pinned["OWASP-LLM-2026"]["entries"] == 10
    assert document["run"]["coverage"]["digest"].startswith("sha256:")


def test_a_run_records_what_each_rule_declared_it_would_cost(tmp_path: Path) -> None:
    # A rule trimmed from four prompts to one checks less. Recording only its name
    # would let that read as an unchanged run.
    rules = _scan(tmp_path)["run"]["rules"]

    assert rules
    assert all("trials" in rule for rule in rules)


def test_a_trimmed_corpus_changes_the_fingerprint() -> None:
    assert _digest() != _digest(rules=(RuleRecord(id="a", digest="d1", trials=1),))


def test_an_uninstalled_evaluator_changes_the_fingerprint() -> None:
    assert _digest() != _digest(evaluators=())


def test_a_lost_target_capability_changes_the_fingerprint() -> None:
    assert _digest() != _digest(capabilities=())


def test_a_different_catalogue_edition_changes_the_fingerprint() -> None:
    other = (TaxonomyCatalogRecord(framework="OWASP-LLM-2026", digest="sha256:bb", entries=10),)

    assert _digest() != _digest(taxonomies=other)


def test_an_older_negotiated_protocol_changes_the_fingerprint() -> None:
    # A server that answered with an older MCP revision supports fewer methods, so
    # the run verified less. The handshake is the only place that is knowable.
    assert _digest() != _digest(protocols={"mcp": "2025-03-26"})


def test_the_fingerprint_does_not_move_with_discovery_order() -> None:
    # Rule order depends on entry-point ordering and on which directories a
    # `--rules` flag was given in. A fingerprint that moved with it would report a
    # coverage change on every other run, which is the same as reporting none.
    shuffled = (RuleRecord(id="b", digest="d2"), RuleRecord(id="a", digest="d1", trials=4))
    straight = (RuleRecord(id="a", digest="d1", trials=4), RuleRecord(id="b", digest="d2"))

    assert _digest(rules=shuffled) == _digest(rules=straight)


def test_a_probe_records_the_target_it_reached_and_what_it_could_ask_of_it(
    tmp_path: Path,
) -> None:
    """The half of the fingerprint that only `scan` was keeping.

    `probe` built its manifest without a `TargetIdentity`, so every endpoint run
    recorded no fingerprint and an empty capability list — and two runs of a target
    that had lost `call_tools` in between produced the same coverage digest. The
    test above proves a lost capability moves the digest; this proves the value
    reaching it is the target's rather than a default nobody filled in.
    """
    document = _probe(tmp_path)

    target = document["run"]["target"]
    assert target["capabilities"] == ["inspect_authorization", "list_tools"]
    assert target["fingerprint"] is not None
    assert target["fingerprint_inputs"] == ["kind", "ref"]
    assert document["run"]["coverage"]["digest"].startswith("sha256:")


def test_an_mcp_probe_runs_with_the_concurrency_its_manifest_claims() -> None:
    """Asserted against the runner, not against the document it wrote.

    The obvious test — read `execution.concurrency` back out of the saved run —
    cannot fail: the manifest records the flag whatever the run did with it, which
    is exactly how a probe came to write a four into a document while executing its
    rules one at a time. So the value is read where it has to arrive.
    """
    seen: list[int] = []

    def recording(*, registry: Registry, profile: Profile, concurrency: int) -> Runner:
        seen.append(concurrency)
        return Runner(registry=registry, profile=profile, concurrency=concurrency)

    with pytest.MonkeyPatch.context() as patched:
        patched.setattr("guardana.cli._mcp_run.Runner", recording)
        run_mcp_probe(
            Registry.discover(),
            resolve_profile(None, None),
            McpConnection("http://127.0.0.1:1/mcp"),
            None,
            concurrency=3,
        )

    assert seen == [3]


def _scan(tmp_path: Path) -> dict[str, Any]:
    """Run the documented command and read the document it wrote."""
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    out = tmp_path / "run.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--output", str(out)])
    assert result.exit_code == 0, result.output
    document: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    return document


def _probe(tmp_path: Path, *extra: str) -> dict[str, Any]:
    """Probe an MCP server that is not there, and read the run it still wrote.

    Unreachable on purpose: what is under test is the *manifest*, and a target
    nobody could reach still has a declared identity and declared capabilities —
    which is precisely the run where a missing fingerprint would go unnoticed.
    """
    out = tmp_path / "run.json"
    result = runner.invoke(
        app,
        [
            "probe",
            "--mcp",
            "http://127.0.0.1:1/mcp",
            "--format",
            "json",
            "--output",
            str(out),
            *extra,
        ],
    )
    assert out.is_file(), result.output
    document: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    return document
