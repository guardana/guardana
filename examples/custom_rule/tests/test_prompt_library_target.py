"""The example target is held to the contract the documentation tells others to copy.

0.22.0 made a target that inherits nothing of Guardana's run the built-in artifact
rules — and shipped this example still declaring `READ_FILES` with no `FileReader`
behind it. Every run over it recorded a capability error and went `indeterminate`,
and nothing here noticed, because nothing here ran the `Runner` over it.
"""

from pathlib import Path

from acme_rules.hardcoded_secret import HardcodedAcmeKeyRule
from acme_rules.prompt_library_target import AcmePromptLibraryTarget
from guardana.core.profile import default_profile
from guardana.core.registry import Registry
from guardana.core.rule import RuleContext
from guardana.core.runner import Runner
from guardana.testing import assert_target_conforms


def _library(tmp_path: Path) -> Path:
    (tmp_path / "greeting.txt").write_text("Welcome to Acme support.\n", encoding="utf-8")
    (tmp_path / "settings.env").write_text(
        "ACME_KEY=ACME_LIVE_KEY_9f8a7b6c5d4e3f21\n", encoding="utf-8"
    )
    return tmp_path


def test_the_target_satisfies_the_contract_in_both_directions(tmp_path: Path) -> None:
    assert_target_conforms(AcmePromptLibraryTarget(_library(tmp_path)))


def test_the_engine_runs_the_built_in_artifact_rules_over_it(tmp_path: Path) -> None:
    """The promise from docs/extending.md, proven on the one shipped example."""
    result = Runner(registry=Registry.discover(), profile=default_profile()).run(
        AcmePromptLibraryTarget(_library(tmp_path))
    )

    assert not [e for e in result.errors if e.stage == "capability"], [
        e.reason for e in result.errors
    ]
    assert result.rules_run
    assert "guardana.supply_chain.pickle_opcode" in result.rules_run


def test_an_acme_rule_fires_on_the_acme_target_not_only_on_artifact_target(tmp_path: Path) -> None:
    """The rules used to `isinstance(target, ArtifactTarget)` — and stay silent otherwise."""
    findings = list(
        HardcodedAcmeKeyRule().run(AcmePromptLibraryTarget(_library(tmp_path)), RuleContext())
    )

    assert findings, "a FileReader that is not ArtifactTarget was skipped without a word"
    assert findings[0].rule_id == "acme.supply_chain.hardcoded_key"


def test_a_missing_library_reads_no_files_and_declines_nothing_silently(tmp_path: Path) -> None:
    target = AcmePromptLibraryTarget(tmp_path / "absent")

    assert list(target.iter_files()) == []
    assert target.unread_sources() == ()
