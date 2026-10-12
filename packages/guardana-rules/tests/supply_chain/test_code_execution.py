from pathlib import Path

import pytest
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.code_execution import CodeExecutionRule


def _scan(tmp_path: Path) -> list[str]:
    rule = CodeExecutionRule()
    return [f.evidence.summary for f in rule.run(ArtifactTarget(tmp_path), RuleContext())]


def test_flags_aliased_os_system(tmp_path: Path) -> None:
    (tmp_path / "al.py").write_text("import os as o\no.system('rm -rf /')\n", encoding="utf-8")
    assert any("os.system" in s for s in _scan(tmp_path))


def test_flags_os_system(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("import os\nos.system('rm -rf /')\n", encoding="utf-8")
    assert any("os.system" in s for s in _scan(tmp_path))


def test_flags_subprocess_shell_true(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import subprocess\nsubprocess.run(cmd, shell=True)\n", encoding="utf-8"
    )
    assert any("shell=True" in s for s in _scan(tmp_path))


def test_flags_builtin_eval_and_exec(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("eval(user_input)\nexec(payload)\n", encoding="utf-8")
    summaries = _scan(tmp_path)
    assert any("eval(" in s for s in summaries)
    assert any("exec(" in s for s in summaries)


def test_ignores_method_named_eval(tmp_path: Path) -> None:
    # `df.eval(...)` (pandas) and `self.exec(...)` are attribute calls, not the
    # dangerous builtins. Flagging them would be false-positive theater.
    (tmp_path / "a.py").write_text(
        "df.eval('col_a + col_b')\nengine.exec(statement)\n", encoding="utf-8"
    )
    assert _scan(tmp_path) == []


def test_ignores_subprocess_without_shell(tmp_path: Path) -> None:
    # A list argument with no shell=True is the safe form — no shell to inject into.
    (tmp_path / "a.py").write_text(
        "import subprocess\nsubprocess.run(['ls', '-l'])\n", encoding="utf-8"
    )
    assert _scan(tmp_path) == []


def test_a_syntax_error_is_declined_as_not_scanned(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def (:\n", encoding="utf-8")
    assert [s.split(":")[0] for s in _scan(tmp_path)] == ["Python file not scanned"]


def _findings(tmp_path: Path, source: str) -> list[tuple[str, float | None]]:
    """Each finding as (summary, verdict confidence) for one `.py` file of `source`."""
    (tmp_path / "loader.py").write_text(source, encoding="utf-8")
    return [
        (f.evidence.summary, f.verdict.confidence if f.verdict else None)
        for f in CodeExecutionRule().run(ArtifactTarget(tmp_path), RuleContext())
    ]


@pytest.mark.parametrize(
    "source",
    [
        "__import__('os').system('id')\n",
        "__import__('os.path').system('id')\n",
        "getattr(__import__('os'), 'system')('id')\n",
        "import importlib\nimportlib.import_module('os').system('id')\n",
        "import importlib as il\nil.import_module('os').system('id')\n",
        "from importlib import import_module\nimport_module('os').system('id')\n",
        "import builtins\nbuiltins.__import__('os').system('id')\n",
        "__import__('builtins').__import__('os').system('id')\n",
        "shell = __import__('os')\nshell.system('id')\n",
    ],
)
def test_a_dynamic_import_with_a_literal_name_resolves_like_a_static_one(
    tmp_path: Path, source: str
) -> None:
    assert _findings(tmp_path, source) == [("os.system(...) runs a shell command", None)]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import builtins\nbuiltins.eval(payload)\n", "builtins.eval(...) runs a string as code"),
        ("__import__('builtins').exec(payload)\n", "builtins.exec(...) runs a string as code"),
    ],
)
def test_the_code_builtins_reached_through_the_builtins_module_are_flagged(
    tmp_path: Path, source: str, expected: str
) -> None:
    assert _findings(tmp_path, source) == [(expected, None)]


@pytest.mark.parametrize(
    "source",
    [
        "__import__(name).system('id')\n",
        "import importlib\nimportlib.import_module(name).run('id')\n",
        "getattr(__import__(name), 'system')('id')\n",
    ],
)
def test_a_call_through_a_computed_import_is_a_lead(tmp_path: Path, source: str) -> None:
    findings = _findings(tmp_path, source)
    assert len(findings) == 1
    assert "computed" in findings[0][0]
    assert findings[0][1] is not None
    assert findings[0][1] < 1.0


@pytest.mark.parametrize(
    "source",
    [
        "import importlib\nimportlib.import_module('json').loads('{}')\n",
        "__import__('json').dumps({})\n",
        "import importlib\nplugin = importlib.import_module(name)\n",
        "__import__('os.path', fromlist=['join']).join('a', 'b')\n",
        "import os\nos.path.join('a', 'b')\n",
    ],
)
def test_a_harmless_dynamic_import_is_clean(tmp_path: Path, source: str) -> None:
    assert _findings(tmp_path, source) == []


@pytest.mark.parametrize(
    "source",
    [
        "\n".join(
            [
                "import os",
                "",
                "",
                "def helper():",
                "    os = __import__('json')",
                "    return os",
                "",
                "",
                "os.system('id')",
                "",
            ]
        ),
        "os = __import__('json')\nimport os\nos.system('id')\n",
        "import os as shell\nshell = __import__('json')\nshell.system('id')\n",
    ],
)
def test_an_assignment_never_hides_a_module_an_import_bound(tmp_path: Path, source: str) -> None:
    assert _findings(tmp_path, source) == [("os.system(...) runs a shell command", None)]


def test_a_name_two_assignments_bind_to_different_modules_is_a_lead(tmp_path: Path) -> None:
    source = (
        "def first():\n    tool = __import__('json')\n    return tool\n\n\n"
        "tool = __import__('os')\ntool.system('id')\n"
    )
    findings = _findings(tmp_path, source)
    assert len(findings) == 1
    assert findings[0][1] is not None
    assert findings[0][1] < 1.0
