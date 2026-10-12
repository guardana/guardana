import importlib.metadata
import io
import json
import os
import pickle
import zipfile
from pathlib import Path

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core import __version__
from typer.testing import CliRunner

runner = CliRunner()


class _Evil:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (os.system, ("x",))


def test_scan_exits_nonzero_on_critical_finding(tmp_path: Path) -> None:
    (tmp_path / "m.pkl").write_bytes(pickle.dumps(_Evil()))
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "pickle_opcode" in result.stdout


def test_scan_clean_tree_exits_zero(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("import os\n")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0


def test_scan_single_file_is_not_a_silent_pass(tmp_path: Path) -> None:
    # A single-file target must scan that file, not walk-nothing and pass clean.
    single = tmp_path / "x.py"
    single.write_text("import torch\ntorch.load('m.pt')\n")
    result = runner.invoke(app, ["scan", str(single)])
    assert result.exit_code == 1
    assert "dependency_risk" in result.stdout


def test_scan_baseline_waives_findings(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    (target / "m.pkl").write_bytes(pickle.dumps(_Evil()))
    baseline = tmp_path / "baseline.yaml"  # kept outside the scanned tree
    generated = runner.invoke(app, ["scan", str(target), "--write-baseline", str(baseline)])
    assert generated.exit_code == 0
    assert baseline.exists()
    # A CRITICAL finding normally fails the gate (exit 1); with it baselined the
    # same scan is green, and the finding is still reported as WAIVED.
    scanned = runner.invoke(app, ["scan", str(target), "--baseline", str(baseline)])
    assert scanned.exit_code == 0
    assert "WAIVED" in scanned.stdout


def test_baseline_survives_a_line_shift(tmp_path: Path) -> None:
    # F-E: an unrelated edit above a waived finding must not un-waive it.
    target = tmp_path / "d"
    target.mkdir()
    (target / "m.py").write_text("import torch\ntorch.load('a.pt')\n")
    baseline = tmp_path / "bl.yaml"
    assert (
        runner.invoke(app, ["scan", str(target), "--write-baseline", str(baseline)]).exit_code == 0
    )
    (target / "m.py").write_text("\n\n\nimport torch\ntorch.load('a.pt')\n")  # shift down 3 lines
    result = runner.invoke(app, ["scan", str(target), "--baseline", str(baseline)])
    assert result.exit_code == 0
    assert "WAIVED" in result.stdout


def test_scan_baseline_and_write_baseline_are_mutually_exclusive(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("import os\n")
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--baseline", "x.yaml", "--write-baseline", "y.yaml"]
    )
    assert result.exit_code != 0


def test_scan_malformed_baseline_is_clean_error_not_traceback(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("import os\n")
    baseline = tmp_path / "bad.yaml"
    baseline.write_text("waivers: not-a-list\n")
    result = runner.invoke(app, ["scan", str(tmp_path), "--baseline", str(baseline)])
    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "Traceback" not in result.output


def test_rules_lists_builtin_rules() -> None:
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "guardana.supply_chain.pickle_opcode" in result.stdout


def test_rules_includes_custom_yaml_pack(tmp_path: Path) -> None:
    (tmp_path / "my_rule.yaml").write_text(
        "id: acme.prompt.demo\n"
        "title: Demo custom rule\n"
        "severity: high\n"
        "target_kind: endpoint\n"
        "requires: [chat]\n"
        "evaluator: keyword\n"
        "prompts:\n"
        '  - "hello"\n'
    )
    result = runner.invoke(app, ["rules", "--rules", str(tmp_path)])
    assert result.exit_code == 0
    assert "acme.prompt.demo" in result.stdout


def test_rules_warns_on_unloadable_custom_pack(tmp_path: Path) -> None:
    (tmp_path / "broken.yaml").write_text("id: acme.broken\ntitle: no prompts\nseverity: high\n")
    result = runner.invoke(app, ["rules", "--rules", str(tmp_path)])
    assert result.exit_code == 0
    assert "warning: could not load rule" in result.output


def test_scan_rejects_invalid_format(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("import os\n")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "bogus"])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "ValueError" not in result.output


def test_version_prints_and_exits_zero() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "guardana" in result.stdout
    # The actual version, not a hardcoded literal, so a release bump doesn't break it.
    assert __version__ in result.stdout


def test_version_names_the_product_first_and_then_every_distribution_it_runs_on() -> None:
    """The four install separately, so one resolved apart from the others shows here."""
    result = runner.invoke(app, ["--version"])

    lines = result.stdout.splitlines()
    assert lines[0] == f"guardana {importlib.metadata.version('guardana-cli')}"
    assert [line.split() for line in lines[1:]] == [
        [name, importlib.metadata.version(name)]
        for name in ("guardana-cli", "guardana-core", "guardana-rules", "guardana-report")
    ]


def test_scan_with_custom_rules_dir_runs_clean(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "demo.yaml").write_text(
        "id: acme.prompt.demo\n"
        "title: demo\n"
        "severity: high\n"
        "target_kind: endpoint\n"
        "evaluator: keyword\n"
        "requires: [chat]\n"
        "prompts: ['hi']\n"
        "expect: {goal: 'complied'}\n"
    )
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    (target_dir / "ok.py").write_text("import os\n")

    result = runner.invoke(app, ["scan", str(target_dir), "--rules", str(rules_dir)])

    assert result.exit_code == 0
    assert "warning: could not load rule" not in result.output


def test_scanning_a_path_that_does_not_exist_is_a_usage_error(tmp_path: Path) -> None:
    """The worst false green there is: a typo'd path in CI, reported as a clean scan.

    `guardana scan /srv/mdoels` printed "✓ No findings", exited 0, and gated a
    build on nothing at all. An excluded scanner is an organisation-level
    fail-open, and a scanner pointed at nothing is the same thing reached by a
    keystroke.
    """
    missing = tmp_path / "not-here"

    result = runner.invoke(app, ["scan", str(missing)])

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "does not exist" in result.output


@pytest.mark.parametrize("preset", [None, "ci", "release"])
def test_scanning_an_empty_directory_is_indeterminate_under_every_preset(
    tmp_path: Path, preset: str | None
) -> None:
    # Nothing to look at is not nothing found: the scan read no file, so it says so
    # instead of passing.
    (tmp_path / "empty").mkdir()
    chosen = [] if preset is None else ["--preset", preset]

    result = runner.invoke(app, ["scan", str(tmp_path / "empty"), *chosen])

    assert result.exit_code == ExitCode.INDETERMINATE
    assert "empty_target" in result.output
    assert "holds no file to scan" in " ".join(result.output.split())


def test_a_directory_holding_only_its_ignore_file_is_indeterminate(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_bytes(b"x")
    (tmp_path / ".guardanaignore").write_text("*.txt\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == ExitCode.INDETERMINATE
    assert "empty_target" in result.output


def test_a_model_file_the_scanned_target_ignores_is_scanned_and_named(tmp_path: Path) -> None:
    (tmp_path / "m.pkl").write_bytes(pickle.dumps(_Evil()))
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".guardanaignore").write_text("*.pkl\n", encoding="utf-8")

    human = runner.invoke(app, ["scan", str(tmp_path)])
    saved = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])

    text = " ".join(human.stdout.split())
    assert human.exit_code == ExitCode.POLICY_FAILED
    assert "pickle_opcode" in text
    assert "excluded by the scanned target's" in text
    assert "*.pkl" in text
    assert "scanned anyway, since only the profile's rules.paths_exclude may exclude" in text
    scope = json.loads(saved.stdout)["scope"]
    assert [kept["pattern"] for kept in scope["kept_models"]] == ["*.pkl"]
    assert scope["kept_models"][0]["path"].endswith("m.pkl")


def test_the_profile_may_still_exclude_a_model_file(tmp_path: Path) -> None:
    (tmp_path / "scanned").mkdir()
    (tmp_path / "scanned" / "m.pkl").write_bytes(pickle.dumps(_Evil()))
    (tmp_path / "scanned" / "app.py").write_text("x = 1\n", encoding="utf-8")
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: t\nrules:\n  paths_exclude: ['*.pkl']\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path / "scanned"), "--profile", str(profile)])

    assert result.exit_code == ExitCode.OK
    assert "scanned anyway" not in " ".join(result.stdout.split())


def test_a_model_file_in_a_skipped_directory_is_noted_and_the_gate_holds(tmp_path: Path) -> None:
    (tmp_path / "env").mkdir()
    (tmp_path / "env" / "model.pkl").write_bytes(pickle.dumps(_Evil()))
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    human = runner.invoke(app, ["scan", str(tmp_path)])
    saved = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])

    text = " ".join(human.stdout.split())
    assert human.exit_code == ExitCode.OK
    assert "model files not scanned, inside directories every scan skips:" in text
    assert f"{tmp_path / 'env'} (1)" in text
    skipped = json.loads(saved.stdout)["scope"]["skipped_models"]
    assert skipped["searched_all"] is True
    assert [(d["path"], d["model_files"]) for d in skipped["directories"]] == [
        (str(tmp_path / "env"), 1)
    ]


def test_a_directory_whose_every_file_the_profile_excludes_is_indeterminate(
    tmp_path: Path,
) -> None:
    (tmp_path / "scanned").mkdir()
    (tmp_path / "scanned" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: t\nrules:\n  paths_exclude: ['*.py']\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path / "scanned"), "--profile", str(profile)])

    assert result.exit_code == ExitCode.INDETERMINATE
    assert "empty_target" in result.output


def test_scanning_a_single_file_still_works(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print('hello')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(target)])

    assert result.exit_code == ExitCode.OK


_ENDPOINT_RULE = (
    "id: acme.prompt.demo\n"
    "title: demo\n"
    "severity: high\n"
    "target_kind: endpoint\n"
    "evaluator: keyword\n"
    "requires: [chat]\n"
    "prompts: ['hi']\n"
    "expect: {goal: 'complied'}\n"
)


def _files_under(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _scan_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("print('hello')\n", encoding="utf-8")
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: audit\n", encoding="utf-8")
    rule = tmp_path / "rule.yaml"
    rule.write_text(_ENDPOINT_RULE, encoding="utf-8")
    return tree, profile, rule


@pytest.mark.parametrize("output_format", ["human", "json"])
def test_write_baseline_refuses_an_output_it_would_never_write(
    tmp_path: Path, output_format: str
) -> None:
    """An earlier run left at `--output` would later be read as this scan's report."""
    tree, _, _ = _scan_inputs(tmp_path)
    earlier_run = tmp_path / "old.json"
    earlier_run.write_text('{"an": "earlier run"}\n', encoding="utf-8")
    earlier_baseline = tmp_path / "b.yaml"
    earlier_baseline.write_text("an earlier baseline\n", encoding="utf-8")
    before = _files_under(tmp_path)

    result = runner.invoke(
        app,
        [
            "scan",
            str(tree),
            "--format",
            output_format,
            "--output",
            str(earlier_run),
            "--write-baseline",
            str(earlier_baseline),
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert (
        f"error: --write-baseline writes no report, so --output {earlier_run} "
        f"would be left as it is — pass one or the other"
    ) in result.output
    assert _files_under(tmp_path) == before


@pytest.mark.parametrize("read", ["scanned file", "profile", "rules file", "hard link"])
def test_write_baseline_refuses_a_file_the_scan_reads(tmp_path: Path, read: str) -> None:
    tree, profile, rule = _scan_inputs(tmp_path)
    scanned = tree / "app.py"
    linked = tmp_path / "linked.yaml"
    linked.hardlink_to(profile)
    written = {
        "scanned file": scanned,
        "profile": profile,
        "rules file": rule,
        "hard link": linked,
    }[read]
    before = _files_under(tmp_path)

    result = runner.invoke(
        app,
        [
            "scan",
            str(scanned),
            "--profile",
            str(profile),
            "--rules",
            str(rule),
            "--write-baseline",
            str(written),
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert f"error: --write-baseline {written} is " in result.output
    assert (
        "which this command reads, and the baseline would replace it — "
        "choose another --write-baseline"
    ) in result.output
    assert _files_under(tmp_path) == before


def test_write_baseline_beside_the_files_it_reads_still_writes(tmp_path: Path) -> None:
    tree, profile, rule = _scan_inputs(tmp_path)
    written = tmp_path / "baseline.yaml"

    result = runner.invoke(
        app,
        [
            "scan",
            str(tree / "app.py"),
            "--profile",
            str(profile),
            "--rules",
            str(rule),
            "--write-baseline",
            str(written),
        ],
    )

    assert result.exit_code == ExitCode.OK, result.output
    assert "wrote baseline waiving 0 finding(s)" in result.output
    assert written.is_file()


@pytest.mark.parametrize("unwritable", ["read-only directory", "directory"])
def test_a_baseline_that_cannot_be_written_is_a_usage_error(
    tmp_path: Path, unwritable: str
) -> None:
    tree, _, _ = _scan_inputs(tmp_path)
    locked = tmp_path / "locked"
    locked.mkdir()
    written = locked / "baseline.yaml" if unwritable == "read-only directory" else locked
    before = _files_under(tmp_path)
    locked.chmod(0o500)
    try:
        result = runner.invoke(app, ["scan", str(tree), "--write-baseline", str(written)])
    finally:
        locked.chmod(0o700)

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert f"error: could not write the baseline to {written}: " in result.output
    assert "Traceback" not in result.output
    assert "wrote baseline" not in result.output
    assert _files_under(tmp_path) == before


def _tree_read_through_profile_and_rules(tmp_path: Path) -> dict[str, Path]:
    """Lay out a scanned tree, a `--rules` directory and a profile naming `rules.paths`."""
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("print('hello')\n", encoding="utf-8")
    ignore = tree / ".guardanaignore"
    ignore.write_text("# nothing excluded yet\n", encoding="utf-8")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule.yaml").write_text(_ENDPOINT_RULE, encoding="utf-8")
    beside = tmp_path / "profile-rules"
    beside.mkdir()
    (beside / "rule.yaml").write_text(_ENDPOINT_RULE.replace("demo", "beside"), encoding="utf-8")
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: audit\nrules:\n  paths: [profile-rules]\n", encoding="utf-8")
    return {
        "tree": tree,
        "profile": profile,
        "rules": rules,
        ".guardanaignore": ignore,
        "--rules directory": rules / "rule.yaml",
        "rules.paths": beside / "rule.yaml",
        "scanned file in the tree": tree / "app.py",
    }


@pytest.mark.parametrize(
    "read", [".guardanaignore", "--rules directory", "rules.paths", "scanned file in the tree"]
)
def test_write_baseline_refuses_a_file_the_scan_reads_inside_a_directory(
    tmp_path: Path, read: str
) -> None:
    laid_out = _tree_read_through_profile_and_rules(tmp_path)
    written = laid_out[read]
    before = _files_under(tmp_path)

    result = runner.invoke(
        app,
        [
            "scan",
            str(laid_out["tree"]),
            "--profile",
            str(laid_out["profile"]),
            "--rules",
            str(laid_out["rules"]),
            "--write-baseline",
            str(written),
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    said = " ".join(result.output.split())
    assert f"error: --write-baseline {written} is " in said
    assert "and the baseline would replace it — choose another --write-baseline" in said
    assert _files_under(tmp_path) == before


def test_the_documented_baseline_snapshot_can_be_taken_again_over_the_last_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    first = runner.invoke(app, ["scan", ".", "--write-baseline", "guardana-baseline.yaml"])
    assert first.exit_code == ExitCode.OK, first.output
    (tmp_path / "guardana-baseline.yaml").write_text("waivers: []\n", encoding="utf-8")

    again = runner.invoke(app, ["scan", ".", "--write-baseline", "guardana-baseline.yaml"])

    assert again.exit_code == ExitCode.OK, again.output
    rewritten = (tmp_path / "guardana-baseline.yaml").read_text(encoding="utf-8")
    assert "Guardana baseline" in rewritten


def test_a_report_never_replaces_a_file_the_scan_read(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    requirements = project / "requirements.txt"
    requirements.write_text("requests==2.0.0\n", encoding="utf-8")

    result = runner.invoke(
        app, ["scan", str(project), "--format", "json", "--output", str(requirements)]
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "which this scan read" in " ".join(result.output.split())
    assert requirements.read_text(encoding="utf-8") == "requests==2.0.0\n"


def test_a_saved_run_inside_the_scanned_tree_is_replaced_on_the_next_run(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("print('hello')\n", encoding="utf-8")
    run = project / "run.json"
    command = ["scan", str(project), "--format", "json", "--output", str(run)]

    first = runner.invoke(app, command)
    second = runner.invoke(app, command)

    assert first.exit_code == ExitCode.OK, first.output
    assert second.exit_code == ExitCode.OK, second.output
    assert run.is_file()


def test_a_baseline_never_replaces_a_scanned_file_that_only_looks_like_one(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    lookalike = project / "waivers.yaml"
    lookalike.write_text("waivers: [the team's own list]\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(project), "--write-baseline", str(lookalike)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert lookalike.read_text(encoding="utf-8") == "waivers: [the team's own list]\n"


def _npz_cut_short() -> bytes:
    header = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    array = b"\x93NUMPY\x01\x00" + len(header).to_bytes(2, "little") + header + pickle.dumps([1])
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("arr_0.npy", array)
    whole = buffer.getvalue()
    return whole[: len(whole) // 2]


def test_a_truncated_npz_is_a_coverage_gap_not_a_pass(tmp_path: Path) -> None:
    (tmp_path / "bundle.npz").write_bytes(_npz_cut_short())

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert "bundle.npz" in " ".join(result.output.split())
