"""The maintainer proofs record what happened, and never call a run passed that proved less.

The scripts run on clean runners against packages from PyPI; here they run against this
checkout's installed build and against crafted records, so every way a proof could read as
passed without having held is pinned: a README parsed to nothing, a canary that crashed,
an install from another index, a missing record, a kit row nobody could run.
"""

import importlib.metadata
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from proofs import __main__ as proofs_cli
from proofs import container, customization, first_run, install, record, summary
from proofs.kit.test_conformance_kit import NOT_APPLICABLE, outside_surface, surface

_ROOT = Path(__file__).resolve().parents[2]
_README = (
    _ROOT / "packages" / "guardana-cli" / "src" / "guardana" / "cli" / "_starter" / "README.md.tmpl"
)
_CHECK = _README.with_name("codename.yaml.tmpl")
_VERSION = importlib.metadata.version("guardana-cli")


def _readme_with(block: str) -> str:
    return f"## 1. Only step\n\n```console\n{block}```\n"


# The README walk.


def test_the_starter_readme_walks_every_step_138_names() -> None:
    items = first_run.walk(_README.read_text(encoding="utf-8"))

    assert first_run.shape(items) == first_run.EXPECTED_SHAPE
    commands = [i for i in items if isinstance(i, first_run.Command)]
    assert [c.expected_exit for c in commands if c.argv[0] == "guardana"] == [1, 0, 1, 0, 0, 0]
    assert commands[-1].argv == ["guardana", "rule", "test", "--rules", "checks", "starter.*"]
    assert commands[-1].section == "7. Change the check"


def test_a_readme_that_parses_to_nothing_does_not_have_the_shape() -> None:
    walked = first_run.shape(first_run.walk("# A starter with no commands\n"))

    assert walked != first_run.EXPECTED_SHAPE
    assert walked == dict.fromkeys(first_run.EXPECTED_SHAPE, 0)


@pytest.mark.parametrize(
    "readme",
    [
        "```python\nprint()\n```\n",
        "```console\noutput before a command\n```\n",
        "```sh-session\n$ guardana scan .\n```\n",
        "```console\n$ guardana scan .\n",
        "```\n$ guardana scan .\n```\n",
    ],
    ids=["unknown-language", "output-first", "sh-session", "unclosed", "no-language"],
)
def test_a_readme_block_the_proof_cannot_run_is_refused(readme: str) -> None:
    with pytest.raises(ValueError, match=r"README|command|block"):
        first_run.walk(readme)


def test_the_readme_edit_adds_the_second_codename_and_its_sample(tmp_path: Path) -> None:
    (edit,) = [
        i
        for i in first_run.walk(_README.read_text(encoding="utf-8"))
        if isinstance(i, first_run.Edit)
    ]
    check = tmp_path / "codename.yaml"
    check.write_text(_CHECK.read_text(encoding="utf-8"), encoding="utf-8")

    assert first_run.apply_edit(check, edit) == []

    edited = yaml.safe_load(check.read_text(encoding="utf-8"))
    assert edited["expect"] == {"contains_none": ["BLUEHARBOR", "REDCOVE"]}
    assert [f["outcome"] for f in edited["fixtures"]] == [
        "finding",
        "clean",
        "inconclusive",
        "finding",
    ]


def test_an_edit_with_nothing_to_edit_is_a_problem(tmp_path: Path) -> None:
    check = tmp_path / "codename.yaml"
    check.write_text("id: x\n", encoding="utf-8")

    problems = first_run.apply_edit(check, first_run.Edit("7", "expect:\n", "  - name: n\n"))

    assert problems == ["codename.yaml has no `expect:` or `fixtures:` section to edit"]


def test_a_shell_line_other_than_rm_or_cp_is_refused_not_run(tmp_path: Path) -> None:
    step = record.Step(name="n", command="curl")

    first_run._shell(step, ["curl", "https://example.test"], tmp_path)

    assert not step.held
    assert step.exit_code is None


def test_the_first_run_walks_this_build_and_is_incomplete_without_isolation(tmp_path: Path) -> None:
    written = tmp_path / "records" / "first-run.json"

    result = first_run.first_run(
        venv=Path(sys.executable).parent.parent,
        project=tmp_path / "project",
        record_path=written,
        version=_VERSION,
        isolation=None,
    )

    assert [s.name for s in result.steps if not s.held] == []
    assert result.verdict() == record.INCOMPLETE
    document = json.loads(written.read_text(encoding="utf-8"))
    assert document["verdict"] == "incomplete"
    exits = [s["exit_code"] for s in document["steps"] if s["command"].startswith("guardana ")]
    assert exits[2:] == [1, 0, 1, 0, 0, 0]
    kept = [json.loads((written.parent / n).read_text("utf-8")) for n in first_run.KEPT_RUNS]
    before, after = (summary.saved_run(document) for document in kept)
    assert before["findings[0].rule_id"] == '"guardana.supply_chain.pickle_opcode"'
    assert before["findings[0].target_ref"] == '"model/weights.pkl"'
    assert after["findings"] == "[]"
    assert before["run.target.ref"] == after["run.target.ref"] == '"model"'
    assert not [path for path in before if path.startswith(tuple(summary.VARYING))]


def test_a_failed_step_does_not_hide_the_steps_after_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(step: record.Step, argv: list[str], **_: object) -> str:
        step.exit_code = 1 if "diff" in argv else step.expected_exit
        if step.exit_code != step.expected_exit:
            step.problems.append("exit 1, expected 0")
        return ""

    monkeypatch.setattr(first_run, "run", fake_run)
    items = first_run.walk(
        _readme_with("$ guardana diff a b  # exit 0\n$ guardana doctor  # exit 0\n")
    )
    proof = record.Record(proof="first-run", version="1")

    first_run._walk(proof, items, tmp_path, tmp_path)

    assert [(s.command.split()[1], s.held, s.ran) for s in proof.steps] == [
        ("diff", False, True),
        ("doctor", True, True),
    ]
    assert proof.verdict() == record.FAILED


# The step runner and the record.


def test_a_step_is_held_to_its_exit_code_and_the_lines_it_must_print(tmp_path: Path) -> None:
    step = record.Step(name="n", command="c", expected_exit=0)

    record.run(
        step,
        [sys.executable, "-c", "print('\\x1b[31mone\\x1b[0m   two'); raise SystemExit(3)"],
        cwd=tmp_path,
        environment=record.clean_environment(None),
        expect_lines=("one two", "three"),
    )

    assert step.exit_code == 3
    assert step.problems == ["exit 3, expected 0", "output lacks: three"]


_README_LINE = "✖ [LEFT THE SCAN · CRITICAL] guardana.supply_chain.pickle_opcode — weights.pkl"


def _shown(tmp_path: Path, output: str) -> record.Step:
    step = record.Step(name="compare", command="c", expected_exit=1)
    record.run(
        step,
        [sys.executable, "-c", f"print({output!r}); raise SystemExit(1)"],
        cwd=tmp_path,
        environment={**record.clean_environment(None), "PYTHONIOENCODING": "utf-8"},
        expect_lines=(_README_LINE,),
    )
    return step


@pytest.mark.parametrize(
    "shown",
    [
        "✖ [LEFT THE SCAN · CRITICAL] guardana.supply_chain.pickle_opcode — model\\weights.pkl",
        "✖ [LEFT THE SCAN · CRITICAL] guardana.supply_chain.pickle_opcode — model/weights.pkl",
    ],
    ids=["windows-path", "posix-path"],
)
def test_a_readme_line_shown_with_a_directory_is_a_problem(tmp_path: Path, shown: str) -> None:
    step = _shown(tmp_path, shown)

    assert step.problems == [f"output lacks: {_README_LINE}"]
    assert not step.held


@pytest.mark.parametrize(
    "shown",
    [
        f"{_README_LINE}.bak",
        f"{_README_LINE} and more",
        f"before {_README_LINE}",
    ],
    ids=["longer-name", "text-after", "text-before"],
)
def test_a_readme_line_is_matched_as_a_whole_output_line(tmp_path: Path, shown: str) -> None:
    step = _shown(tmp_path, shown)

    assert step.problems == [f"output lacks: {_README_LINE}"]


@pytest.mark.parametrize(
    "shown",
    [_README_LINE, f"{_README_LINE}   ", f"other output\n  {_README_LINE}\t\nmore output"],
    ids=["itself", "trailing-whitespace", "among-other-lines"],
)
def test_the_readme_line_itself_holds(tmp_path: Path, shown: str) -> None:
    step = _shown(tmp_path, shown)

    assert step.problems == []
    assert step.held


def test_a_fragment_is_matched_anywhere_in_a_line_and_a_missing_one_is_named(
    tmp_path: Path,
) -> None:
    step = record.Step(name="n", command="c", expected_exit=0)

    record.run(
        step,
        [sys.executable, "-c", "print('migration 0009 rolled back in 2 s')"],
        cwd=tmp_path,
        environment=record.clean_environment(None),
        expect_fragments=("rolled back", "refusing"),
    )

    assert step.problems == ["output lacks: refusing"]


def test_a_command_that_hangs_is_stopped_and_recorded(tmp_path: Path) -> None:
    step = record.Step(name="n", command="c", expected_exit=0)

    record.run(
        step,
        [sys.executable, "-c", "import time; time.sleep(30)"],
        cwd=tmp_path,
        environment=record.clean_environment(None),
        timeout=1,
    )

    assert step.problems == ["did not finish within 1 s"]
    assert not step.held


def test_output_the_runner_cannot_decode_is_recorded_not_raised(tmp_path: Path) -> None:
    step = record.Step(name="n", command="c", expected_exit=0)

    record.run(
        step,
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'caf\\xe9')"],
        cwd=tmp_path,
        environment=record.clean_environment(None),
    )

    assert step.held
    assert step.excerpt == "caf�"


def test_the_maintainers_settings_never_reach_the_commands(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for name in (
        "PYTHONOPTIMIZE",
        "PYTHONIOENCODING",
        "GUARDANA_COLLECTOR_TOKEN",
        "PROOF_COMMIT",
        "VIRTUAL_ENV",
    ):
        monkeypatch.setenv(name, "1")

    environment = record.clean_environment(tmp_path / "venv")

    assert not [
        n for n in environment if n.startswith(("PYTHON", "GUARDANA_", "PROOF_", "PYTEST_"))
    ]
    assert environment["VIRTUAL_ENV"] == str(tmp_path / "venv")
    assert environment["PATH"].startswith(
        str(record.venv_executable(tmp_path / "venv", "python").parent)
    )


@pytest.mark.parametrize(
    ("steps", "not_exercised", "verdict"),
    [
        ([record.Step("a", "c")], [], record.PASSED),
        (
            [record.Step("a", "c"), record.Step("b", "c", problems=["exit 1, expected 0"])],
            [],
            record.FAILED,
        ),
        ([record.not_run("a", "c", "an earlier step failed")], [], record.FAILED),
        ([record.Step("a", "c")], ["a kit row"], record.INCOMPLETE),
        ([], [], record.FAILED),
    ],
    ids=["held", "a-step-failed", "a-step-not-run", "unexercised", "no-steps"],
)
def test_only_a_record_whose_every_step_held_and_nothing_was_left_out_passes(
    steps: list[record.Step], not_exercised: list[str], verdict: str
) -> None:
    proof = record.Record(proof="first-run", version="1", steps=steps, not_exercised=not_exercised)

    assert proof.verdict() == verdict
    assert proof.to_json()["verdict"] == verdict


def _canary_reply(monkeypatch: pytest.MonkeyPatch, exit_code: int, output: str) -> None:
    def fake_run(step: record.Step, argv: list[str], **_: object) -> str:
        step.exit_code = exit_code
        if exit_code != step.expected_exit:
            step.problems.append(f"exit {exit_code}, expected {step.expected_exit}")
        return output

    monkeypatch.setattr(record, "run", fake_run)


_REFUSED = "\n".join(
    json.dumps({"to": f"{h}:{p}", "refused": "OSError: [Errno 101] Network is unreachable"})
    for h, p in record.CANARY_DESTINATIONS
)
_REACHED = "\n".join(
    json.dumps({"to": f"{h}:{p}", "reached": True}) for h, p in record.CANARY_DESTINATIONS
)


@pytest.mark.parametrize(
    ("cut", "exit_code", "output", "held"),
    [
        (True, 1, _REFUSED, True),
        (True, 1, "Traceback (most recent call last):\nImportError", False),
        (True, 0, _REACHED, False),
        (True, 1, _REFUSED.splitlines()[0], False),
        (False, 0, _REACHED, True),
        (False, 1, _REFUSED, False),
    ],
    ids=["cut", "crashed", "reachable", "one-answer-missing", "reachable-before", "outage-before"],
)
def test_the_canary_holds_only_on_an_answer_for_every_destination(  # noqa: PLR0913, PLR0917 — the fixtures and one case
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    cut: bool,
    exit_code: int,
    output: str,
    held: bool,
) -> None:
    _canary_reply(monkeypatch, exit_code, output)

    step = record.canary(Path(sys.executable), tmp_path, {}, cut=cut)

    assert step.held is held


# The install and its provenance.


def test_a_candidate_takes_the_documented_pre_release_flag_and_a_release_does_not(
    tmp_path: Path,
) -> None:
    candidate = install.pip_commands("python", tmp_path, "1.0.0rc3", (), tmp_path / "r.json")[1]
    release = install.pip_commands("python", tmp_path, "1.0.0", (), tmp_path / "r.json")[1]

    assert "--pre" in candidate
    assert "--pre" not in release
    assert install.uv_commands("uv", "python", "1.0.0rc3", ())[1][-3:-1] == [
        "--prerelease",
        "allow",
    ]
    assert "--prerelease" not in install.uv_commands("uv", "python", "1.0.0", ())[1]


def test_both_installers_name_pypi_and_ignore_the_runners_configuration(tmp_path: Path) -> None:
    pip_install = install.pip_commands("python", tmp_path, "1.0.0", (), tmp_path / "r.json")[1]
    uv_init, uv_add = install.uv_commands("uv", "/usr/bin/python3", "1.0.0", ())

    assert pip_install[3:6] == ["install", "--index-url", install.INDEX]
    for argv in (uv_init, uv_add):
        assert {"--no-config", "--no-managed-python", "--no-python-downloads"} <= set(argv)
        assert argv[argv.index("--python") + 1] == "/usr/bin/python3"
    assert uv_add[uv_add.index("--default-index") + 1] == install.INDEX


def test_installer_settings_and_files_are_ignored_before_installing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PIP_INDEX_URL", "https://mirror.example.test/simple")
    monkeypatch.setenv("UV_INDEX_URL", "https://mirror.example.test/simple")
    monkeypatch.setenv("PIP_CONFIG_FILE", "/etc/pip-with-a-mirror.conf")

    environment = install.install_environment()

    assert [n for n in environment if n.startswith(("PIP_", "UV_"))] == ["PIP_CONFIG_FILE"]
    assert environment["PIP_CONFIG_FILE"] == os.devnull


_WHEEL = "https://files.pythonhosted.org/packages/aa/guardana_{}-1.0.0-py3-none-any.whl"


def _pip_report(url: str) -> dict[str, Any]:
    return {
        "install": [
            {
                "metadata": {"name": name},
                "download_info": {
                    "url": url.format(name),
                    "archive_info": {"hashes": {"sha256": "ab" * 32}},
                },
            }
            for name in install.GUARDANA
        ]
    }


def test_pip_downloads_from_pypi_with_a_hash_are_accepted() -> None:
    fetched = install.fetched_from_pip(_pip_report(_WHEEL))

    assert install.fetched_problems(fetched, install.GUARDANA) == []


def test_a_download_from_another_host_is_a_problem() -> None:
    fetched = install.fetched_from_pip(_pip_report("https://mirror.example.test/guardana_{}.whl"))

    assert len(install.fetched_problems(fetched, install.GUARDANA)) == len(install.GUARDANA)


def test_a_pack_beside_guardana_from_another_index_or_missing_is_a_problem() -> None:
    report = _pip_report(_WHEEL)
    report["install"].append(
        {
            "metadata": {"name": "guardana-reference-pack"},
            "download_info": {"url": "https://mirror.example.test/pack.whl", "archive_info": {}},
        }
    )
    fetched = install.fetched_from_pip(report)

    problems = install.fetched_problems(fetched, (*install.GUARDANA, "pytest"))

    assert problems[0] == "the installer reports no download of pytest"
    assert "guardana-reference-pack did not come from" in problems[1]
    assert len(problems) == 2


def test_a_uv_lock_resolved_from_another_index_or_a_path_is_a_problem() -> None:
    lock = {
        "package": [
            {"name": "guardana-cli", "source": {"path": "../packages/guardana-cli"}},
            *(
                {
                    "name": name,
                    "source": {"registry": "https://mirror.example.test/simple"},
                    "wheels": [{"url": _WHEEL.format(name), "hash": "sha256:" + "ab" * 32}],
                }
                for name in install.GUARDANA[1:]
            ),
        ]
    }

    problems = install.fetched_problems(install.fetched_from_uv(lock), install.GUARDANA)

    assert len(problems) == len(install.GUARDANA)
    assert "guardana-cli did not come from" in problems[0]


def _installed(venv: Path, **override: Any) -> dict[str, Any]:  # noqa: ANN401 — JSON values
    dist = {
        "version": "1.0.0",
        "installer": "pip",
        "direct_url": None,
        "location": str(venv / "lib"),
    }
    return {
        "python": ".".join(map(str, sys.version_info[:3])),
        "module": str(venv / "lib" / "guardana" / "core" / "__init__.py"),
        "found": {name: {**dist, **override} for name in install.GUARDANA},
    }


def test_an_install_from_pypi_into_the_project_has_no_provenance_problem(tmp_path: Path) -> None:
    assert install.provenance_problems(_installed(tmp_path), tmp_path, "1.0.0") == []


@pytest.mark.parametrize(
    ("override", "says"),
    [
        ({"version": "0.41.0"}, "is 0.41.0, not 1.0.0"),
        ({"direct_url": '{"url": "file:///src"}'}, "direct URL or path"),
        ({"installer": None}, "records no installer"),
        ({"location": "/elsewhere"}, "outside the project environment"),
    ],
)
def test_an_install_that_is_not_the_published_build_in_the_project_is_named(
    tmp_path: Path, override: dict[str, Any], says: str
) -> None:
    problems = install.provenance_problems(_installed(tmp_path, **override), tmp_path, "1.0.0")

    assert len(problems) == len(install.GUARDANA)
    assert all(says in p for p in problems)


def test_an_environment_on_another_python_is_named(tmp_path: Path) -> None:
    other = f"{sys.version_info.major}.{sys.version_info.minor + 1}.0"
    document = {**_installed(tmp_path), "python": other}

    assert install.provenance_problems(document, tmp_path, "1.0.0") == [
        f"the environment runs Python {other}, not the {sys.version.split()[0]} asked for"
    ]


_PILOT = "guardana-retrieval-pilot"
_LOCAL = {"url": "file:///proof/project/application", "sha256": ""}


def test_the_application_under_test_is_the_one_distribution_from_its_copy() -> None:
    fetched = {
        **{name: {"url": _WHEEL.format(name), "sha256": "ab"} for name in install.GUARDANA},
        _PILOT: _LOCAL,
    }

    assert install.fetched_problems(fetched, (*install.GUARDANA, _PILOT), _PILOT) == []
    assert install.fetched_problems(fetched, install.GUARDANA) != []


@pytest.mark.parametrize(
    ("fetched", "says"),
    [
        ({_PILOT: {"url": _WHEEL.format("pilot"), "sha256": "ab"}}, "not from its copy"),
        ({"guardana-core": _LOCAL}, "did not come from https://files.pythonhosted.org/"),
    ],
)
def test_only_the_named_application_may_come_from_a_local_copy(
    fetched: dict[str, dict[str, str]], says: str
) -> None:
    problems = install.fetched_problems(fetched, (), _PILOT)

    assert [p for p in problems if says in p]


def test_the_installed_application_must_be_the_copy_at_its_declared_version(
    tmp_path: Path,
) -> None:
    copy = tmp_path / "application"
    good = {"version": "0.1.0", "direct_url": json.dumps({"url": copy.resolve().as_uri()})}

    def found(**override: str) -> dict[str, Any]:
        return {"found": {_PILOT: {**good, **override}}}

    assert install.application_problems(found(), _PILOT, "0.1.0", copy) == []
    assert install.application_problems(found(version="0.2.0"), _PILOT, "0.1.0", copy)
    elsewhere = json.dumps({"url": "file:///src/examples/retrieval_pilot"})
    assert install.application_problems(found(direct_url=elsewhere), _PILOT, "0.1.0", copy)
    assert install.application_problems({"found": {}}, _PILOT, "0.1.0", copy) == [
        f"{_PILOT} is not installed"
    ]


def test_an_application_declares_its_normalised_name_and_version(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "Guardana_Retrieval_Pilot"\nversion = "0.1.0"\n', encoding="utf-8"
    )

    assert install.declared_application(tmp_path) == (_PILOT, "0.1.0")


def test_the_checkout_matches_its_tag_only_while_the_files_are_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def git(*args: str) -> None:
        subprocess.run(  # noqa: S603 — git with literal arguments in a temporary repository
            ["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@t", *args],  # noqa: S607
            check=True,
            capture_output=True,
        )

    git("init", "-q")
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "x.py").write_text("x = 1\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-q", "-m", "x")
    git("tag", "v1.0.0")

    assert record.same_as_tag(tmp_path, "v1.0.0", ("app",)).held
    (tmp_path / "app" / "stray.py").write_text("y = 1\n", encoding="utf-8")
    assert record.same_as_tag(tmp_path, "v1.0.0", ("app",)).problems == [
        "not tracked by git: app/stray.py"
    ]
    (tmp_path / "app" / "stray.py").unlink()
    (tmp_path / "app" / "x.py").write_text("x = 2\n", encoding="utf-8")
    changed = record.same_as_tag(tmp_path, "v1.0.0", ("app",))
    assert changed.problems == ["exit 1, expected 0"]
    assert "x.py" in changed.excerpt
    assert not record.same_as_tag(tmp_path, "v9.9.9", ("app",)).held
    monkeypatch.chdir(tmp_path / "app")
    (tmp_path / "app" / "x.py").write_text("x = 1\n", encoding="utf-8")
    assert record.same_as_tag(Path(".."), "v1.0.0", ("app",)).held


# Docker.


def _plan(
    proof: str = "first-run", installer: str = "pip", pack: str | None = None
) -> list[list[str]]:
    return container.plan(
        proof=proof,
        python="3.13",
        installer=installer,
        version="1.0.0rc3",
        out=Path("/out"),
        uv_version="0.12.9",
        pytest_version="8.4.2",
        pack=pack,
    )


def test_only_the_last_container_runs_without_a_network_and_it_runs_the_proof() -> None:
    commands = _plan()
    runs = [c for c in commands if c[:2] == ["docker", "run"]]

    assert ["--network", "none"] not in [r[3:5] for r in runs[:-1]]
    assert runs[-1][3:5] == ["--network", "none"]
    assert runs[-1][runs[-1].index("proofs") + 1] == "first-run"
    assert "--isolation" in runs[-1]


def test_the_customization_fetches_the_sdist_with_the_network_and_pins_the_pack() -> None:
    runs = [c for c in _plan("customization", pack="0.1.2") if c[:2] == ["docker", "run"]]

    assert [r[r.index("proofs") + 1] for r in runs] == ["install", "fetch-sdist", "customization"]
    assert "guardana-reference-pack==0.1.2" in runs[0]
    assert "pytest==8.4.2" in runs[0]


def test_a_uv_cell_installs_the_pinned_uv_before_the_proof() -> None:
    install_run = next(c for c in _plan(installer="uv") if c[:2] == ["docker", "run"])

    assert install_run[-3:-1] == ["sh", "-c"]
    assert "uv==0.12.9" in install_run[-1]
    assert "--uv /proof/tools/bin/uv" in install_run[-1]


def _pilot_plan(proof: str, application: Path | None) -> list[list[str]]:
    return container.plan(
        proof=proof,
        python="3.13",
        installer="pip",
        version="1.0.0rc5",
        out=Path("/out"),
        uv_version="0.12.9",
        pytest_version="8.4.2",
        pack=None,
        application=application,
    )


@pytest.mark.parametrize("proof", container.APPLICATION_PROOFS)
def test_the_pilot_is_mounted_only_where_it_is_installed_and_proven_from_its_copy(
    proof: str,
) -> None:
    runs = [c for c in _pilot_plan(proof, Path("/app")) if c[:2] == ["docker", "run"]]

    install_run, offline = runs
    assert "/app:/application:ro" in install_run
    assert install_run[-2:] == ["--application", "/application"]
    assert not any(":/application" in word for word in offline)
    assert offline[3:5] == ["--network", "none"]
    assert offline[offline.index("proofs") + 1] == proof
    assert offline[-2:] == ["--application", "/proof/project/application"]


@pytest.mark.parametrize(
    ("proof", "application"),
    [("pilot", None), ("regression", None), ("first-run", Path("/app"))],
)
def test_an_application_goes_only_with_a_proof_of_one(proof: str, application: Path | None) -> None:
    with pytest.raises(ValueError, match="application directory"):
        _pilot_plan(proof, application)


def _record_docker(monkeypatch: pytest.MonkeyPatch, digest: str | None) -> list[list[str]]:
    ran: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        ran.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(container, "image_digest", lambda image: digest)
    monkeypatch.delenv("PROOF_IMAGE", raising=False)
    return ran


def test_every_container_after_the_pull_runs_the_digest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    digest = "mirror.gcr.io/library/python@sha256:" + "ab" * 32
    ran = _record_docker(monkeypatch, digest)

    assert container.execute(_plan(), out=tmp_path) == 0

    runs = [c for c in ran if c[:2] == ["docker", "run"]]
    assert len(runs) == 2
    assert all(digest in c and "mirror.gcr.io/library/python:3.13-slim" not in c for c in runs)


def test_an_image_without_a_digest_is_not_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ran = _record_docker(monkeypatch, None)

    assert container.execute(_plan(), out=tmp_path) == 1
    assert [c[:2] for c in ran] == [["docker", "pull"]]


# The customization records and the conformance kit.

_JUNIT = """<testsuites><testsuite name="pytest">
<testcase classname="kit" name="test_row_2"/>
<testcase classname="kit" name="test_row_3">
<skipped message="not exercisable: McpServerTarget"/></testcase>
<testcase classname="kit" name="test_row_5"><failure message="AssertionError: render"/></testcase>
<testcase classname="kit" name="test_row_6"><error message="fixture failed"/></testcase>
</testsuite></testsuites>"""


def test_kit_skips_are_kept_apart_from_passes_and_failures(tmp_path: Path) -> None:
    junit = tmp_path / "kit.xml"
    junit.write_text(_JUNIT, encoding="utf-8")

    passed, failed, skipped = customization.kit_outcomes(junit)

    assert passed == ["test_row_2"]
    assert failed == ["test_row_5: AssertionError: render", "test_row_6: fixture failed"]
    assert skipped == ["test_row_3: not exercisable: McpServerTarget"]


def test_only_a_skip_the_kit_marked_not_applicable_stops_counting_against_the_proof() -> None:
    skipped = [
        f"test_row_1: {NOT_APPLICABLE}rule test covers it",
        "test_row_3: not exercisable through the supported surface: McpServerTarget",
        f"test_row_4: the pack reads traces, so this is not {NOT_APPLICABLE}",
        "test_row_5: Skipped: no reason given",
    ]

    applies, unexercised = customization.classify(skipped)

    assert applies == [skipped[0]]
    assert unexercised == skipped[1:]
    assert customization.NOT_APPLICABLE == NOT_APPLICABLE


def test_a_not_applicable_row_does_not_make_a_record_incomplete() -> None:
    proof = record.Record(
        proof="customization",
        version="1",
        steps=[record.Step("a", "c")],
        not_applicable=["conformance kit: test_row_3: not applicable to this pack: no MCP rule"],
    )

    assert proof.verdict() == record.PASSED


def test_a_defined_test_that_no_outcome_mentions_is_unaccounted(tmp_path: Path) -> None:
    module = tmp_path / "test_kit.py"
    module.write_text(
        "def test_a(): ...\ndef test_b(): ...\nclass TestC:\n    def test_c(self): ...\n",
        encoding="utf-8",
    )
    defined = customization.defined_tests([module])

    deselected: tuple[list[str], list[str], list[str]] = (
        ["test_a[one]", "test_a[two]"],
        [],
        ["test_c: not exercisable"],
    )

    assert defined == {"test_a", "test_b", "test_c"}
    assert customization.unaccounted(defined, deselected) == {"test_b"}


def test_a_pack_installed_at_another_version_than_pinned_is_named(tmp_path: Path) -> None:
    document = _installed(tmp_path)
    document["found"]["guardana-reference-pack"] = {
        **document["found"]["guardana-cli"],
        "version": "0.1.1",
    }

    problems = install.provenance_problems(
        document, tmp_path, "1.0.0", ("guardana-reference-pack==0.1.2",)
    )

    assert problems == ["guardana-reference-pack is 0.1.1, not 0.1.2"]


def _printing(outputs: dict[str, str]) -> Callable[..., str]:
    """Run each step as a command that prints the output named for it and exits as expected."""

    def fake_run(step: record.Step, argv: list[str], **kwargs: Any) -> str:  # noqa: ANN401
        shown = outputs.get(step.name, "").encode()
        code = f"import sys; sys.stdout.buffer.write({shown!r}); sys.exit({step.expected_exit})"
        return record.run(step, [sys.executable, "-c", code], **kwargs)

    return fake_run


_SAMPLED = (
    "{} rule(s); 6 fixture(s) passed, 0 failed, 0 could not run. {} rule(s) not fully sampled.\n"
)
_SCAN = "the pack's target, format and reporter in a scan"
_SUMMARY = (
    "# Guardana run r\n\n## Findings (1)\n\n| Severity | Rule | Title | Location | Evidence |\n"
    "| {} | reference.supply\\_chain.unpinned\\_requirement "
    "| A requirement is not pinned to one version | requirements.txt "
    "| 'requests\\>=2.31' is not pinned: it admits more than one version |\n"
    "delivery: delivered — reference-file to summaries ({})\n"
)


@pytest.mark.parametrize(
    ("name", "output", "held"),
    [
        ("version", "guardana 1.2.0\n  guardana-cli     1.2.0\n  guardana-core  1.2.0\n", True),
        ("version", "guardana 1.2.0rc1\n  guardana-cli     1.2.0rc1\n", False),
        ("the manifest holds", "a\n\n2 pack(s) checked, 0 with problems.\n", True),
        ("the manifest holds", "a\n\n2 pack(s) checked, 10 with problems.\n", False),
        ("the manifest holds", "a\n\n12 pack(s) checked, 0 with problems.\n", False),
        ("every pack rule proves its three samples", _SAMPLED.format(2, 0), True),
        ("every pack rule proves its three samples", _SAMPLED.format(12, 0), False),
        ("every pack rule proves its three samples", _SAMPLED.format(2, 10), False),
        (_SCAN, _SUMMARY.format("MEDIUM", "1 attempt"), True),
        (_SCAN, _SUMMARY.format("LOW", "1 attempt"), False),
        (_SCAN, _SUMMARY.format("MEDIUM", "1 attempt, then lost"), False),
    ],
    ids=[
        "version",
        "candidate",
        "manifest",
        "ten-problems",
        "twelve-packs",
        "sampled",
        "twelve-rules",
        "ten-unsampled",
        "scan",
        "another-severity",
        "delivered-then-lost",
    ],
)
def test_the_customization_expects_its_counts_and_version_as_whole_lines(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str, output: str, held: bool
) -> None:
    monkeypatch.setattr(customization, "run", _printing({name: output}))
    proof = record.Record(proof="customization", version="1.2.0")

    customization._commands(proof, tmp_path / "venv", tmp_path)

    (step,) = [s for s in proof.steps if s.name == name]
    assert bool([p for p in step.problems if p.startswith("output lacks: ")]) is not held


@pytest.mark.parametrize(
    "source",
    [
        "from guardana.core.target import McpServerTarget",
        "from guardana.core.rule.verify import verify_rule",
        "import guardana.core.trace",
        "from guardana.core import Runner",
        "from guardana.core.plugins import normalize_distribution",
    ],
)
def test_the_kit_refuses_an_import_outside_the_supported_surface(source: str) -> None:
    assert outside_surface(source, surface()) != []


def test_the_kit_accepts_the_names_the_surface_lists() -> None:
    source = (
        "from guardana.core.testing import files_target\n"
        "from guardana.core.target import WireProtocol, display_url\n"
        "from guardana.core.plugins import PluginTrust\n"
        "from guardana.core.source import read_source\n"
        "from guardana.core.rule import NotApplicable, NotOffered\n"
        "from guardana.core.rule.fixture import materialise\n"
        "from guardana.testing import assert_target_conforms\n"
    )

    assert outside_surface(source, surface()) == []


def test_the_kits_surface_is_the_generated_surface() -> None:
    generated = json.loads(
        (_ROOT / "docs" / "generated" / "api-surface.json").read_text(encoding="utf-8")
    )
    published = {
        name for section in ("extension", "facade", "kit", "outputs") for name in generated[section]
    }

    kit = {f"{module}.{name}" for module, names in surface().items() for name in names}

    assert kit == published


# The summary.


_CANARY = {"name": record.NETWORK_CUT, "held": True, "ran": True, "problems": []}


def _record(
    proof: str, verdict: str, cell: str, *, steps: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    held = [{"held": True, "ran": True, "problems": []}]
    return {
        "proof": proof,
        "version": "1",
        "verdict": verdict,
        "isolation": "x",
        "steps": [] if steps == [] else [_CANARY, *(held if steps is None else steps)],
        "not_exercised": ["a kit row"] if verdict == "incomplete" else [],
        "cell": cell,
    }


def test_a_summary_passes_only_with_every_expected_record_passed() -> None:
    found = [_record("first-run", "passed", "a"), _record("customization", "passed", "b")]
    needs = {"j": {"result": "success"}}

    assert summary.problems(found, needs, {"first-run": 1, "customization": 1}) == []


_FAILED_STEP = [{"held": False, "ran": True, "problems": ["exit 1, expected 0"]}]


@pytest.mark.parametrize(
    ("found", "needs", "expected", "says"),
    [
        ([_record("first-run", "passed", "a")], {}, {"first-run": 2}, "1 cell(s) left a record, 2"),
        (
            [_record("first-run", "passed", "a"), _record("first-run", "passed", "a")],
            {},
            {"first-run": 2},
            "a: more than one first-run record",
        ),
        (
            [_record("first-run", "passed", "a")],
            {"j": {"result": "cancelled"}},
            {"first-run": 1},
            "ended cancelled",
        ),
        (
            [_record("first-run", "incomplete", "a")],
            {},
            {"first-run": 1},
            "a: first-run incomplete",
        ),
        (
            [_record("first-run", "passed", "a", steps=[])],
            {},
            {"first-run": 1},
            "its steps say failed",
        ),
        (
            [_record("first-run", "passed", "a", steps=_FAILED_STEP)],
            {},
            {"first-run": 1},
            "its steps say failed",
        ),
        ([_record("first-run", "passed", "a")], {}, {}, "no record count was expected"),
        ([], {}, {"first-run": 0}, "no proof record was found"),
        (
            [{**_record("pilot", "passed", "a"), "steps": [{"held": True, "problems": []}]}],
            {},
            {"pilot": 1},
            "a: pilot names an isolation no canary step shows",
        ),
        (
            [{**_record("pilot", "passed", "a"), "steps": [{**_CANARY, "held": False}]}],
            {},
            {"pilot": 1},
            "a: pilot names an isolation no canary step shows",
        ),
    ],
    ids=[
        "missing",
        "duplicate-hides-a-missing-cell",
        "cancelled",
        "incomplete",
        "passed-with-no-steps",
        "passed-with-a-failed-step",
        "no-inventory",
        "nothing",
        "isolated-without-a-canary",
        "isolated-with-a-canary-that-failed",
    ],
)
def test_a_summary_names_every_reason_it_does_not_pass(
    found: list[dict[str, Any]], needs: dict[str, Any], expected: dict[str, int], says: str
) -> None:
    assert [r for r in summary.problems(found, needs, expected) if says in r]


_WINDOWS = {"first-run-windows": "proof-first-run-Windows"}


def test_a_reported_cell_may_fail_without_failing_the_summary() -> None:
    found = [
        _record("first-run", "passed", "proof-first-run-linux-3.13-pip"),
        _record("first-run", "failed", "proof-first-run-Windows-3.13-pip", steps=_FAILED_STEP),
    ]
    needs = {"first-run-linux": {"result": "success"}, "first-run-windows": {"result": "failure"}}

    assert summary.problems(found, needs, {"first-run": 2}, _WINDOWS) == []
    assert "(reported, not required)" in summary.markdown(found, [], _WINDOWS)


def test_a_reported_cell_must_still_leave_its_record_and_others_still_count() -> None:
    found = [_record("first-run", "failed", "proof-first-run-macOS-3.13-pip", steps=_FAILED_STEP)]
    needs = {"first-run-macos": {"result": "failure"}, "first-run-windows": {"result": "failure"}}

    reasons = summary.problems(found, needs, {"first-run": 2}, _WINDOWS)

    assert reasons == [
        "first-run: 1 cell(s) left a record, 2 expected",
        "job first-run-macos ended failure",
        "proof-first-run-macOS-3.13-pip: first-run failed",
    ]


def test_a_run_naming_the_safetensors_file_with_a_backslash_did_not_observe_it(
    tmp_path: Path,
) -> None:
    finding = {"rule_id": "guardana.supply_chain.pickle_opcode", "severity": "CRITICAL"}
    (tmp_path / "before.json").write_text(json.dumps({"findings": [finding]}), encoding="utf-8")
    after = {"findings": [], "errors": [], "observations": [{"ref": "model\\weights.safetensors"}]}
    (tmp_path / "after.json").write_text(json.dumps(after), encoding="utf-8")

    assert first_run.evidence_problems(tmp_path) == [
        "after.json did not observe model/weights.safetensors: ['model\\\\weights.safetensors']"
    ]

    after["observations"] = [{"ref": "elsewhere\\weights.safetensors"}]
    (tmp_path / "after.json").write_text(json.dumps(after), encoding="utf-8")
    assert len(first_run.evidence_problems(tmp_path)) == 1


def test_a_summary_reads_records_by_artifact_and_ignores_other_json(tmp_path: Path) -> None:
    proof = record.Record(proof="first-run", version="1", steps=[record.Step("a", "c")])
    proof.write(tmp_path / "proof-first-run-linux-3.11-pip" / "first-run.json")
    (tmp_path / "proof-first-run-linux-3.11-pip" / "pip-report.json").write_text(
        "{}", encoding="utf-8"
    )
    (tmp_path / "broken.json").write_text("{", encoding="utf-8")

    found = summary.collect(tmp_path)

    assert [(r["cell"], r["verdict"]) for r in found] == [
        ("proof-first-run-linux-3.11-pip", "passed")
    ]


# The saved runs, compared across cells.

_LINUX = "proof-first-run-linux-3.13-uv"
_MACOS = "proof-first-run-macOS-3.13-uv"
_WINDOWS_CELL = "proof-first-run-Windows-3.13-uv"
_PICKLE = "guardana.supply_chain.pickle_opcode"


def _saved_run(  # noqa: PLR0913 — one keyword per field a cell could spell differently
    *,
    target_ref: str = "model",
    target_fingerprint: str = "sha256:0d4b",
    finding_ref: str | None = "model/weights.pkl",
    summary_text: str = "unpickling imports builtins.print",
    observed: str = "model/weights.pkl",
    listed: str = "model/weights.pkl",
) -> dict[str, Any]:
    finding = {
        "rule_id": _PICKLE,
        "severity": "CRITICAL",
        "target_ref": finding_ref,
        "evidence": {"summary": summary_text, "detail": ""},
    }
    return {
        "schema_version": 19,
        "run": {
            "run_id": "00000000-0000-4000-8000-000000000001",
            "created_at": "2026-01-01T00:00:01Z",
            "started_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:00:01Z",
            "source": {"kind": "local", "provider": "local", "run_url": None},
            "deployment": {"commit_sha": None, "model_name": None},
            "usage": {"requests": 0, "wall_time_seconds": 0.1},
            "target": {"type": "artifact", "ref": target_ref, "fingerprint": target_fingerprint},
        },
        "scope": {"files": [listed]},
        "observations": [{"kind": "model", "ref": observed}],
        "findings": [] if finding_ref is None else [finding],
        "errors": [],
    }


def _cell(
    records: Path,
    cell: str,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> None:
    """Write one first-run cell: its passing record and the two runs it kept."""
    proof = record.Record(
        proof="first-run", version="1", isolation="x", steps=[record.Step(record.NETWORK_CUT, "c")]
    )
    proof.write(records / cell / "first-run.json")
    for name, document in zip(first_run.KEPT_RUNS, (before, after), strict=True):
        if document is not None:
            (records / cell / name).write_text(json.dumps(document), encoding="utf-8")


def _compared(records: Path, report_only: dict[str, str] | None = None) -> list[str]:
    return summary.compare_saved_runs(records, summary.collect(records), report_only)


def _three_cells(records: Path, **windows: Any) -> None:  # noqa: ANN401 — the fields to change
    same = _saved_run()
    clean = _saved_run(finding_ref=None, observed="model/weights.safetensors")
    _cell(records, _LINUX, same, clean)
    _cell(records, _MACOS, same, clean)
    _cell(records, _WINDOWS_CELL, _saved_run(**windows), clean)


def test_cells_that_kept_the_same_refs_and_fingerprints_compare_clean(tmp_path: Path) -> None:
    _three_cells(tmp_path)

    assert _compared(tmp_path) == []
    out = tmp_path / "out"
    assert summary.summarise(tmp_path, out, {}, {"first-run": 3}) == 0


@pytest.mark.parametrize(
    ("windows", "field", "theirs", "ours"),
    [
        (
            {"summary_text": "unpickling imports builtins.exec"},
            "findings[0].evidence.summary",
            "builtins.exec",
            "builtins.print",
        ),
        (
            {"finding_ref": "model\\weights.pkl"},
            "findings[0].target_ref",
            '"model\\\\weights.pkl"',
            '"model/weights.pkl"',
        ),
        ({"target_ref": "model\\"}, "run.target.ref", '"model\\\\"', '"model"'),
        ({"target_fingerprint": "sha256:ffff"}, "run.target.fingerprint", "ffff", "0d4b"),
        ({"observed": "model\\weights.pkl"}, "observations[0].ref", "model\\\\weights", "model/"),
        ({"listed": "model\\weights.pkl"}, "scope.files[0]", "model\\\\weights.pkl", "model/"),
    ],
    ids=["summary", "finding-ref", "target-ref", "target-fingerprint", "observed", "listed"],
)
def test_a_cell_whose_saved_run_differs_names_both_cells_and_the_difference(
    tmp_path: Path, windows: dict[str, str], field: str, theirs: str, ours: str
) -> None:
    _three_cells(tmp_path, **windows)

    (reason,) = _compared(tmp_path)

    assert reason.startswith(f"first-run-before.json: {_WINDOWS_CELL} differs from {_LINUX} ")
    assert f" in {field}: " in reason
    head, _, tail = reason.partition(f", {_LINUX} has ")
    assert theirs in head
    assert ours in tail
    assert summary.summarise(tmp_path, tmp_path / "out", {}, {"first-run": 3}) == 1


def _usage_spelled_as_one_key(document: dict[str, Any]) -> None:
    del document["run"]["usage"]
    document["run"]["usage.requests"] = 0


def _schema_version_under_an_empty_key(document: dict[str, Any]) -> None:
    document[""] = {"schema_version": document.pop("schema_version")}


@pytest.mark.parametrize(
    ("change", "field", "theirs", "ours"),
    [
        (
            lambda d: d["findings"][0].update(verdict="unverified"),
            "findings[0].verdict",
            '"unverified"',
            "nothing",
        ),
        (
            lambda d: d.update(waived=[{"rule_id": _PICKLE}]),
            "waived[0].rule_id",
            _PICKLE,
            "nothing",
        ),
        (lambda d: d.pop("errors"), "errors", "nothing", "[]"),
        (lambda d: d["run"]["usage"].update(requests=3), "run.usage.requests", "3", "0"),
        (lambda d: d["run"]["usage"].update(requests=False), "run.usage.requests", "false", "0"),
        (
            lambda d: d["run"]["deployment"].update(model_name="m"),
            "run.deployment.model_name",
            '"m"',
            "null",
        ),
        (_usage_spelled_as_one_key, "run.usage.requests", "nothing", "0"),
        (_schema_version_under_an_empty_key, "schema_version", "nothing", "19"),
    ],
    ids=[
        "new-key-in-one-cell",
        "new-section-in-one-cell",
        "key-left-out",
        "beside-a-timing",
        "false-is-not-zero",
        "beside-the-commit",
        "dotted-key-is-not-a-path",
        "empty-key-is-not-the-top-level",
    ],
)
def test_any_key_a_cell_holds_differently_is_named_with_its_path(
    tmp_path: Path, change: Callable[[dict[str, Any]], object], field: str, theirs: str, ours: str
) -> None:
    windows = _saved_run()
    change(windows)
    _cell(tmp_path, _LINUX, _saved_run(), _saved_run())
    _cell(tmp_path, _MACOS, _saved_run(), _saved_run())
    _cell(tmp_path, _WINDOWS_CELL, windows, _saved_run())

    (reason,) = _compared(tmp_path)

    assert reason.startswith(f"first-run-before.json: {_WINDOWS_CELL} differs from {_LINUX} ")
    assert f" in {field}: " in reason
    head, _, tail = reason.partition(f", {_LINUX} has ")
    assert theirs in head.partition(f" in {field}: ")[2]
    assert ours in tail


def test_the_same_items_in_another_order_are_a_difference(tmp_path: Path) -> None:
    files = ["model/a.pkl", "model/b.pkl"]
    for cell, listed in ((_LINUX, files), (_MACOS, files), (_WINDOWS_CELL, files[::-1])):
        document = _saved_run()
        document["scope"]["files"] = listed
        _cell(tmp_path, cell, document, _saved_run())

    (reason,) = _compared(tmp_path)

    assert reason.startswith(f"first-run-before.json: {_WINDOWS_CELL} differs from {_LINUX} ")
    assert " in scope.files[0]: " in reason
    assert reason.endswith("; 1 other key path(s) differ too")


def test_a_cell_that_differs_in_several_key_paths_says_how_many_more(tmp_path: Path) -> None:
    _three_cells(tmp_path, target_ref="elsewhere", observed="model\\weights.pkl")

    (reason,) = _compared(tmp_path)

    assert " in run.target.ref: " in reason
    assert reason.endswith('has "model"; 1 other key path(s) differ too')


def test_keys_that_vary_from_cell_to_cell_by_design_are_not_compared(tmp_path: Path) -> None:
    for n, cell in enumerate((_LINUX, _MACOS, _WINDOWS_CELL)):
        document = _saved_run()
        document["run"].update(
            run_id=f"00000000-0000-4000-8000-00000000000{n}",
            created_at=f"2026-01-0{n + 1}T00:00:01Z",
            started_at=f"2026-01-0{n + 1}T00:00:00Z",
            completed_at=f"2026-01-0{n + 1}T00:00:01Z",
        )
        document["run"]["usage"]["wall_time_seconds"] = n + 0.5
        if n:
            document["run"]["source"] = {"kind": "ci", "provider": "github", "run_url": f"u{n}"}
            document["run"]["deployment"]["commit_sha"] = "0" * 40
        _cell(tmp_path, cell, document, document)

    assert _compared(tmp_path) == []
    assert sorted(summary.VARYING) == [
        "run.completed_at",
        "run.created_at",
        "run.deployment.commit_sha",
        "run.run_id",
        "run.source",
        "run.started_at",
        "run.usage.wall_time_seconds",
    ]


@pytest.mark.parametrize("key", ["source_kind", "run_id_note", "started_at_offset"])
def test_a_key_named_like_a_varying_one_is_still_compared(tmp_path: Path, key: str) -> None:
    for n, cell in enumerate((_LINUX, _MACOS, _WINDOWS_CELL)):
        document = _saved_run()
        document["run"][key] = "ci" if n else "local"
        _cell(tmp_path, cell, document, document)

    assert any(f"run.{key}" in problem for problem in _compared(tmp_path))


def test_a_directory_named_like_a_record_is_a_problem_naming_its_cell(tmp_path: Path) -> None:
    _three_cells(tmp_path)
    (tmp_path / _MACOS / "notes.json").mkdir()
    out = tmp_path / "out"

    assert len(summary.collect(tmp_path)) == 3
    assert summary.summarise(tmp_path, out, {}, {"first-run": 3}) == 1
    written = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert written["problems"] == [f"{_MACOS}: notes.json is a directory, not a file"]
    assert written["passed"] is False


def test_a_directory_named_like_a_saved_run_is_named_once(tmp_path: Path) -> None:
    _three_cells(tmp_path)
    (tmp_path / _MACOS / "first-run-before.json").unlink()
    (tmp_path / _MACOS / "first-run-before.json").mkdir()
    out = tmp_path / "out"

    assert summary.summarise(tmp_path, out, {}, {"first-run": 3}) == 1
    written = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert written["problems"] == [f"{_MACOS}: first-run-before.json is a directory, not a file"]


def test_a_cell_that_kept_no_saved_run_is_a_problem_not_a_skip(tmp_path: Path) -> None:
    _cell(tmp_path, _LINUX, _saved_run(), _saved_run())
    _cell(tmp_path, _WINDOWS_CELL, _saved_run(), None)

    assert _compared(tmp_path) == [f"{_WINDOWS_CELL}: first-run left no first-run-after.json"]


def test_a_single_cell_that_kept_nothing_is_a_problem(tmp_path: Path) -> None:
    _cell(tmp_path, _LINUX)

    assert _compared(tmp_path) == [
        f"{_LINUX}: first-run left no first-run-before.json",
        f"{_LINUX}: first-run left no first-run-after.json",
    ]


@pytest.mark.parametrize(
    ("written", "says"),
    [
        ("{", "is not JSON"),
        ("[]", "holds no run"),
        (json.dumps({**_saved_run(), "run": {"target": {}}}), "holds no run.target.ref"),
        (json.dumps({**_saved_run(), "findings": [{"rule_id": _PICKLE}]}), "target_ref"),
        (json.dumps({**_saved_run(), "observations": [{"kind": "model"}]}), "holds no ref"),
        (json.dumps({**_saved_run(), "scope": {"files": [1]}}), "scope.files"),
        (json.dumps({**_saved_run(), "run": {"target": {"ref": None}}}), "is not a string"),
        (json.dumps({**_saved_run(), "findings": {}}), "its findings is not a list"),
    ],
    ids=[
        "broken",
        "not-an-object",
        "no-target-ref",
        "finding-no-ref",
        "no-observed-ref",
        "listing",
        "null-target-ref",
        "findings-not-a-list",
    ],
)
def test_a_saved_run_the_summary_cannot_read_is_a_problem(
    tmp_path: Path, written: str, says: str
) -> None:
    _cell(tmp_path, _LINUX, _saved_run(), _saved_run())
    _cell(tmp_path, _WINDOWS_CELL, _saved_run(), _saved_run())
    (tmp_path / _WINDOWS_CELL / "first-run-before.json").write_text(written, encoding="utf-8")

    (reason,) = _compared(tmp_path)

    assert reason.startswith(f"{_WINDOWS_CELL}: first-run-before.json cannot be compared: ")
    assert says in reason


def test_a_saved_run_that_cannot_be_opened_is_a_problem(tmp_path: Path) -> None:
    _cell(tmp_path, _LINUX, _saved_run(), _saved_run())
    _cell(tmp_path, _WINDOWS_CELL, None, _saved_run())
    found = summary.collect(tmp_path)
    (tmp_path / _WINDOWS_CELL / "first-run-before.json").mkdir()

    (reason,) = summary.compare_saved_runs(tmp_path, found)

    assert reason.startswith(f"{_WINDOWS_CELL}: first-run-before.json cannot be compared: ")
    assert "cannot be read" in reason


def test_a_reported_cell_is_left_out_of_the_comparison(tmp_path: Path) -> None:
    _three_cells(tmp_path, target_ref="elsewhere")
    (tmp_path / _WINDOWS_CELL / "first-run-after.json").unlink()

    assert _compared(tmp_path, _WINDOWS) == []
    assert len(_compared(tmp_path)) == 2


# The command line.

_OFFLINE = ["--venv", "v", "--project", "p", "--version", "1", "--record", "r"]
_MINIMAL = {
    "install": ["--installer", "pip", "--version", "1", "--project", "p", "--record", "r"],
    "first-run": _OFFLINE,
    "fetch-sdist": ["--venv", "v", "--into", "i", "--record", "r"],
    "customization": [*_OFFLINE, "--sdist", "s"],
    "container": ["--proof", "first-run", "--python", "3.13", "--installer", "pip",
                  "--version", "1", "--out", "o", "--uv-version", "1", "--pytest-version", "1"],
    "summary": ["--records", "r", "--out", "o"],
    "pilot": [*_OFFLINE, "--application", "a"],
    "regression": [*_OFFLINE, "--application", "a"],
    "recovery": ["--version", "1", "--old-version", "0", "--repository", "r", "--work", "w",
                 "--record", "r"],
    "same-as-tag": ["--repository", "r", "--version", "1", "--path", "p", "--record", "r"],
}  # fmt: skip
_COMMANDS = list(_MINIMAL)


@pytest.mark.parametrize("command", _COMMANDS)
def test_help_prints_usage_and_does_nothing(
    command: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(subprocess, "run", pytest.fail)

    with pytest.raises(SystemExit) as exit_info:
        proofs_cli.main([command, "--help"])

    assert exit_info.value.code == 0
    assert "usage:" in capsys.readouterr().out


@pytest.mark.parametrize("command", _COMMANDS)
def test_an_unknown_flag_is_refused_before_anything_runs(
    command: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(subprocess, "run", pytest.fail)

    with pytest.raises(SystemExit) as exit_info:
        proofs_cli.main([command, *_MINIMAL[command], "--no-such-flag"])

    assert exit_info.value.code == 2
    assert "--no-such-flag" in capsys.readouterr().err


def test_a_dry_run_prints_the_docker_commands_and_runs_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(subprocess, "run", pytest.fail)

    code = proofs_cli.main(
        ["container", "--proof", "first-run", "--python", "3.13", "--installer", "pip",
         "--version", "1.0.0rc3", "--out", str(tmp_path / "out"), "--uv-version", "0.12.9",
         "--pytest-version", "8.4.2", "--dry-run"]
    )  # fmt: skip

    assert code == 0
    assert "--network none" in capsys.readouterr().out
    assert not (tmp_path / "out").exists()


# The workflow.


def _workflow() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(
        (_ROOT / ".github" / "workflows" / "proofs.yml").read_text(encoding="utf-8")
    )
    return loaded


def _cells(job: dict[str, Any]) -> int:
    count = 1
    for values in job["strategy"]["matrix"].values():
        count *= len(values)
    return count


def test_the_summary_expects_one_record_per_matrix_cell() -> None:
    jobs = _workflow()["jobs"]
    (step,) = [s for s in jobs["summary"]["steps"] if "proofs summary" in str(s.get("run", ""))]

    first_runs = [name for name in jobs if name.startswith("first-run-")]
    assert first_runs == ["first-run-linux", "first-run-macos", "first-run-windows"]
    assert f"--expect first-run={sum(_cells(jobs[name]) for name in first_runs)}" in step["run"]
    assert "--expect customization=1" in step["run"]
    for proof in ("pilot", "regression", "recovery"):
        assert f"--expect {proof}=1" in step["run"]
    compared = [n for n, job in jobs.items() if "proofs same-as-tag" in str(job["steps"])]
    assert compared == ["retrieval-pilot", "regression-loop"]
    assert f"--expect same-as-tag={len(compared)}" in step["run"]
    assert jobs["summary"]["if"] == "always()"
    assert set(jobs["summary"]["needs"]) == {
        name for name in jobs if name not in {"inputs", "summary"}
    }


def test_the_summary_collects_a_record_of_every_proof_it_expects(tmp_path: Path) -> None:
    jobs = _workflow()["jobs"]
    (step,) = [s for s in jobs["summary"]["steps"] if "proofs summary" in str(s.get("run", ""))]
    expected = [word.partition("=")[0] for word in step["run"].split() if "=" in word and
                word.partition("=")[2].isdigit()]  # fmt: skip
    for proof in expected:
        written = record.Record(proof=proof, version="1", steps=[record.Step("s", "c")])
        written.write(tmp_path / f"proof-{proof}" / f"{proof}.json")

    assert sorted(r["proof"] for r in summary.collect(tmp_path)) == sorted(expected)
    assert len(expected) == 6


def test_every_proof_job_uploads_its_records_whatever_happened() -> None:
    for name, job in _workflow()["jobs"].items():
        if name in {"inputs", "summary"}:
            continue
        uploads = [s for s in job["steps"] if "upload-artifact" in str(s.get("uses", ""))]
        assert len(uploads) == 1, name
        assert uploads[0]["if"] == "always()", name
        assert uploads[0]["with"]["if-no-files-found"] == "error", name
        assert str(uploads[0]["with"]["name"]).startswith("proof-"), name
        assert job.get("strategy", {}).get("fail-fast", False) is False, name


def test_the_summary_receives_each_cells_saved_runs_in_a_directory_of_its_own() -> None:
    jobs = _workflow()["jobs"]
    (download,) = [s for s in jobs["summary"]["steps"] if "download" in str(s.get("uses"))]

    assert download["with"]["pattern"] == "proof-*"
    assert "merge-multiple" not in download["with"]
    # The saved runs are kept beside the record, so the uploaded directory must hold it:
    # the container writes it under `<out>/records`, the other runners where `--record` says.
    writes = {
        "first-run-linux": '--proof first-run --python "$PY" --installer "$INSTALLER"',
        "first-run-macos": '--record "$RUNNER_TEMP/proof/records/first-run.json"',
        "first-run-windows": '--record "$RUNNER_TEMP/proof/records/first-run.json"',
    }
    for name, written in writes.items():
        (upload,) = [s for s in jobs[name]["steps"] if "upload" in str(s.get("uses"))]
        assert upload["with"]["path"] == "${{ runner.temp }}/proof/records", name
        assert written in str(jobs[name]["steps"]), name
    assert '--out "$RUNNER_TEMP/proof"' in str(jobs["first-run-linux"]["steps"])


def test_the_pilot_jobs_prove_even_when_the_tag_comparison_fails() -> None:
    jobs = _workflow()["jobs"]
    for name, proof in (("retrieval-pilot", "pilot"), ("regression-loop", "regression")):
        (proving,) = [s for s in jobs[name]["steps"] if f"--proof {proof}" in str(s.get("run"))]
        assert proving["if"] == "${{ !cancelled() }}", name
        assert "--application ../examples/retrieval_pilot" in proving["run"], name


def test_the_recovery_proof_upgrades_a_database_the_pinned_release_created() -> None:
    workflow = _workflow()
    (step,) = [
        s
        for s in workflow["jobs"]["recovery-runbooks"]["steps"]
        if "proofs recovery" in str(s.get("run"))
    ]

    assert '--old-version "$RECOVERY_FROM"' in step["run"]
    assert workflow["env"]["RECOVERY_FROM"] == "0.41.0"
    assert "refs/tags/v$VERSION" in step["run"]


def test_the_proofs_run_only_when_a_maintainer_dispatches_them() -> None:
    raw: dict[object, Any] = yaml.safe_load(
        (_ROOT / ".github" / "workflows" / "proofs.yml").read_text(encoding="utf-8")
    )
    triggers = raw[True]  # PyYAML reads the bare key `on` as the boolean True

    assert set(triggers) == {"workflow_dispatch"}
    assert set(triggers["workflow_dispatch"]["inputs"]) == {"version", "pack"}


def test_a_dispatched_value_reaches_a_shell_only_through_the_environment() -> None:
    workflow = _workflow()
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            assert "inputs." not in str(step.get("run", "")), step.get("name")
            assert "needs.inputs" not in str(step.get("run", "")), step.get("name")
    assert workflow["permissions"] == {"contents": "read"}


def test_no_proof_runs_on_a_python_outside_the_supported_range() -> None:
    jobs = _workflow()["jobs"]

    assert jobs["first-run-linux"]["strategy"]["matrix"]["python"] == ["3.11", "3.13"]
    assert jobs["first-run-macos"]["strategy"]["matrix"]["python"] == ["3.11", "3.13"]
    assert jobs["first-run-windows"]["strategy"]["matrix"]["python"] == ["3.11", "3.13"]


def test_every_first_run_cell_is_required_and_windows_still_uploads_its_record() -> None:
    jobs = _workflow()["jobs"]
    (step,) = [s for s in jobs["summary"]["steps"] if "proofs summary" in str(s.get("run", ""))]
    (upload,) = [s for s in jobs["first-run-windows"]["steps"] if "upload" in str(s.get("uses"))]

    assert "--report-only" not in step["run"]
    assert [n for n, job in jobs.items() if "continue-on-error" in job] == []
    assert str(upload["with"]["name"]).startswith("proof-first-run-Windows-")
