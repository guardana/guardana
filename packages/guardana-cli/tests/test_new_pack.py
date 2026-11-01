"""`guardana new-pack` writes a pack, or it refuses and writes nothing at all.

The manifest checks read the manifest and the catalogue back from disk with
`yaml.safe_load`. Compared against the id list the generator holds in memory they
would agree by construction, and a catalogue file that never reached the tree
would still be a test that passes.
"""

import importlib
import sys
import tomllib
from pathlib import Path

import pytest
import yaml
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core import __version__, taxonomy
from guardana.core.pack import EXTENSION_API_VERSION, load_manifest
from typer.testing import CliRunner

runner = CliRunner()

PACKAGE = Path("src") / "acme_rules"
MANIFEST = PACKAGE / "guardana-pack.yaml"
CATALOG = PACKAGE / "catalog"


def _written(target: Path) -> set[str]:
    return {p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()}


def _catalogue_ids(target: Path) -> set[str]:
    return {
        str(yaml.safe_load(path.read_text())["id"]) for path in (target / CATALOG).glob("*.yaml")
    }


def _declared_ids(target: Path) -> set[str]:
    manifest = yaml.safe_load((target / MANIFEST).read_text())
    return set(manifest["provides"]["rules"])


def test_the_tree_lands_where_dir_says_with_the_files_the_design_lists(tmp_path: Path) -> None:
    result = runner.invoke(app, ["new-pack", "acme-rules", "--dir", str(tmp_path)])

    assert result.exit_code == ExitCode.OK, result.output
    assert _written(tmp_path) == {
        "pyproject.toml",
        "README.md",
        "src/acme_rules/__init__.py",
        "src/acme_rules/py.typed",
        "src/acme_rules/guardana-pack.yaml",
        "src/acme_rules/target.py",
        "src/acme_rules/catalog/__init__.py",
        "src/acme_rules/catalog/prompt_secret_disclosure.yaml",
        "src/acme_rules/catalog/scenario_retrieved_document.yaml",
        "src/acme_rules/catalog/agent_tool_exfiltration.yaml",
        "tests/test_manifest.py",
        "tests/test_rules_are_sampled.py",
        "tests/test_target.py",
    }


def test_the_manifest_claims_exactly_the_ids_the_catalogue_files_on_disk_declare(
    tmp_path: Path,
) -> None:
    runner.invoke(app, ["new-pack", "acme-rules", "--dir", str(tmp_path)])

    catalogue = _catalogue_ids(tmp_path)

    assert len(catalogue) == 3, catalogue
    assert _declared_ids(tmp_path) == catalogue


def test_the_manifest_declares_the_generated_target_and_a_schema_older_builds_read(
    tmp_path: Path,
) -> None:
    runner.invoke(app, ["new-pack", "acme-rules", "--dir", str(tmp_path)])

    manifest = yaml.safe_load((tmp_path / MANIFEST).read_text())

    assert manifest["provides"]["targets"] == ["AcmeRulesTarget"]
    # Schema 2, not this build's newest: a scaffold declares no output, and a
    # schema 2 manifest also loads on builds that predate outputs.
    assert manifest["schema_version"] == 2
    assert "class AcmeRulesTarget(Target)" in (tmp_path / PACKAGE / "target.py").read_text()


def test_the_templates_extension_api_range_still_accepts_this_builds_api(tmp_path: Path) -> None:
    """Without this the scaffold keeps emitting a range that was right once.

    Every pack generated after the extension API moves would then be refused in
    both directions, with nothing in the generator to point at.
    """
    runner.invoke(app, ["new-pack", "acme-rules", "--dir", str(tmp_path)])

    manifest = load_manifest(tmp_path / MANIFEST)

    assert manifest.loadable_by(EXTENSION_API_VERSION)


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("My-Pack", "is not a distribution name"),
        ("2fast", "which is not importable"),
        ("guardana-cli", "reserved for Guardana's own rules"),
        ("trace", "the target scheme would be 'trace', which is reserved"),
        ("typer", "already installed in this environment"),
    ],
)
def test_a_name_that_cannot_produce_a_loadable_pack_is_refused_before_anything_is_written(
    tmp_path: Path, name: str, reason: str
) -> None:
    result = runner.invoke(app, ["new-pack", name, "--dir", str(tmp_path)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert reason in result.stderr
    assert _written(tmp_path) == set()


def test_a_narrowed_shape_narrows_the_catalogue_and_the_manifest_together(
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app, ["new-pack", "acme-rules", "--dir", str(tmp_path), "--shape", "prompt"]
    )

    assert result.exit_code == ExitCode.OK, result.output
    assert _catalogue_ids(tmp_path) == {"acme.prompt.secret_disclosure"}
    assert _declared_ids(tmp_path) == {"acme.prompt.secret_disclosure"}


def test_an_unknown_shape_is_refused_rather_than_written_as_nothing(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["new-pack", "acme-rules", "--dir", str(tmp_path), "--shape", "chat"]
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "unknown shape(s) chat" in result.stderr
    assert _written(tmp_path) == set()


def test_a_directory_holding_only_git_metadata_is_still_empty(tmp_path: Path) -> None:
    """`mkdir mypack && cd mypack && git init && guardana new-pack …` is the likeliest run."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (tmp_path / ".gitignore").write_text("__pycache__/\n")

    result = runner.invoke(app, ["new-pack", "acme-rules", "--dir", str(tmp_path)])

    assert result.exit_code == ExitCode.OK, result.output
    assert (tmp_path / MANIFEST).is_file()


def test_a_directory_holding_a_real_file_is_refused_and_keeps_what_it_had(
    tmp_path: Path,
) -> None:
    (tmp_path / "notes.md").write_text("mine\n")

    result = runner.invoke(app, ["new-pack", "acme-rules", "--dir", str(tmp_path)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "is not empty (notes.md)" in result.stderr
    assert _written(tmp_path) == {"notes.md"}


def test_the_usage_page_states_the_counts_a_real_run_produces(tmp_path: Path) -> None:
    """Every count in the page is a fact about the command, so it is read back here.

    The page quotes what a reader will see: how many files land, how many rules and
    samples `rule test` grades, and how many tests the generated suite runs. A
    template gaining a file or a sample is what makes those numbers a lie, and
    nothing else in the gate reads them.
    """
    page = (Path(__file__).resolve().parents[3] / "docs" / "usage-new-pack.md").read_text()
    runner.invoke(app, ["new-pack", "acme-rules", "--dir", str(tmp_path)])

    files = len([path for path in tmp_path.rglob("*") if path.is_file()])
    catalog = sorted((tmp_path / "src" / "acme_rules" / "catalog").glob("*.yaml"))
    samples = sum(len(yaml.safe_load(path.read_text())["fixtures"]) for path in catalog)
    generated_tests = sum(
        text.count("\ndef test_")
        for text in (path.read_text() for path in (tmp_path / "tests").glob("*.py"))
    )

    assert f"Wrote {files} files" in page
    assert f"{len(catalog)} rule(s); {samples} fixture(s) passed" in page
    assert f"{generated_tests} passed" in page


def test_a_rule_citing_the_packs_own_taxonomy_loads_once_its_taxonomies_are_registered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Discovery registers taxonomies before rules; the generated tests do the same by hand."""
    runner.invoke(app, ["new-pack", "zeta-rules", "--dir", str(tmp_path)])
    package = tmp_path / "src" / "zeta_rules"
    init = package / "__init__.py"
    init.write_text(
        init.read_text() + "\n\ndef provide_taxonomies() -> list[TaxonomyRef]:\n"
        "    return [TaxonomyRef(scheme='ZETA-RMF', id='ZH-02', title='own hazard')]\n"
    )
    rule = package / "catalog" / "prompt_secret_disclosure.yaml"
    rule.write_text(rule.read_text().replace("taxonomy: [", "taxonomy: [ZH-02, ", 1))
    monkeypatch.syspath_prepend(str(tmp_path / "src"))
    for name in [m for m in sys.modules if m == "zeta_rules" or m.startswith("zeta_rules.")]:
        monkeypatch.delitem(sys.modules, name)

    try:
        pack = importlib.import_module("zeta_rules")
        taxonomy.register_all(pack.provide_taxonomies())
        rules = pack.provide_rules()
        cited = {ref.reference for r in rules for ref in r.meta.taxonomy}
    finally:
        taxonomy.unregister("ZH-02")

    assert "ZH-02" in cited


def test_the_pack_requires_the_core_it_was_made_with_up_to_the_next_major(
    tmp_path: Path,
) -> None:
    """Everything the scaffold imports is in the supported surface, which a minor keeps."""
    runner.invoke(app, ["new-pack", "acme-rules", "--dir", str(tmp_path)])
    project = tomllib.loads((tmp_path / "pyproject.toml").read_text())["project"]
    major = int(__version__.split(".")[0])

    assert project["dependencies"] == [f"guardana-core>={__version__},<{major + 1}"]
