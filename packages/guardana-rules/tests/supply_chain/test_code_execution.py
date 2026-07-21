from pathlib import Path

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


def test_does_not_crash_on_a_syntax_error(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def (:\n", encoding="utf-8")
    assert _scan(tmp_path) == []
