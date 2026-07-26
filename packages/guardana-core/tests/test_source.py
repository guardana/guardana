"""Guards for `guardana.core.source` — the shared, cached read of a Python file.

Every static rule used to parse and walk the same file for itself: measured on
this repo, 211 source files cost 1477 `ast.parse` calls and ~870k `ast.walk`
visits. The index below exists to make that cost linear in the target, so these
tests pin both halves of the deal — the data is right, and it is computed once.
"""

import ast
from pathlib import Path

import pytest
from guardana.core.source import PythonSource, read_python_source
from guardana.core.target import ArtifactTarget

# Inert fixture text, never executed: it is parsed into a tree so the index can be
# compared against `ast.walk`. The `os.system`/`eval` calls are here precisely
# because they are what the static rules look for.
_SAMPLE = """\
import os
import numpy as np
from pathlib import Path

def run(cmd):
    os.system(cmd)
    eval("2 + 2")
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_nodes_returns_every_node_of_a_type_in_document_order(tmp_path: Path) -> None:
    source = read_python_source(_write(tmp_path, "sample.py", _SAMPLE))
    assert source is not None
    calls = source.nodes(ast.Call)
    assert [call.lineno for call in calls] == [6, 7]


def test_nodes_of_an_absent_type_is_empty_not_an_error(tmp_path: Path) -> None:
    source = read_python_source(_write(tmp_path, "sample.py", "x = 1\n"))
    assert source is not None
    assert source.nodes(ast.Call) == ()


def test_nodes_matches_ast_walk_exactly(tmp_path: Path) -> None:
    # The index replaces `ast.walk` in every rule, so any node it misses is a
    # check that silently stops firing — a fail-open dressed as an optimisation.
    source = read_python_source(_write(tmp_path, "sample.py", _SAMPLE))
    assert source is not None
    for node_type in (ast.Call, ast.Import, ast.ImportFrom, ast.FunctionDef, ast.Attribute):
        walked = [n for n in ast.walk(source.tree) if type(n) is node_type]
        assert list(source.nodes(node_type)) == walked


def test_unreadable_file_is_none(tmp_path: Path) -> None:
    assert read_python_source(tmp_path / "missing.py") is None


def test_unparseable_file_is_none_not_an_exception(tmp_path: Path) -> None:
    assert read_python_source(_write(tmp_path, "broken.py", "def (:\n")) is None


def test_a_directory_is_none(tmp_path: Path) -> None:
    # `iter_files` never yields one, but a rule may pass any path; a blocking
    # open or a raised OSError here would take down the whole scan.
    assert read_python_source(tmp_path) is None


def test_undecodable_file_is_none(tmp_path: Path) -> None:
    path = tmp_path / "latin.py"
    path.write_bytes(b"# \xff\xfe not utf-8\nx = 1\n")
    assert read_python_source(path) is None


def test_target_parses_a_file_once_across_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path, "sample.py", _SAMPLE)
    target = ArtifactTarget(tmp_path)
    parses = 0
    real_parse = ast.parse

    def counting_parse(source: str, *args: object, **kwargs: object) -> ast.Module:
        nonlocal parses
        parses += 1
        return real_parse(source)

    monkeypatch.setattr(ast, "parse", counting_parse)
    first = target.python_source(path)
    second = target.python_source(path)
    assert first is not None
    assert second is first
    assert parses == 1


def test_target_caches_an_unreadable_file_as_the_same_answer(tmp_path: Path) -> None:
    # A failure must be as sticky as a success: if one rule got None and the next
    # re-read a file that had meanwhile appeared, two rules would disagree about
    # the same scan — and the report would depend on rule ordering.
    target = ArtifactTarget(tmp_path)
    missing = tmp_path / "later.py"
    assert target.python_source(missing) is None
    missing.write_text("x = 1\n", encoding="utf-8")
    assert target.python_source(missing) is None


def test_each_target_has_its_own_cache(tmp_path: Path) -> None:
    path = _write(tmp_path, "sample.py", _SAMPLE)
    first = ArtifactTarget(tmp_path).python_source(path)
    second = ArtifactTarget(tmp_path).python_source(path)
    assert first is not None
    assert second is not None
    assert first is not second


def test_cache_stops_growing_past_its_budget_but_still_answers(tmp_path: Path) -> None:
    # The tree is the expensive part: measured at ~9.3x the size of the source it
    # came from. Past the budget the cache must degrade to today's behaviour —
    # recomputing — never to a wrong or missing answer.
    target = ArtifactTarget(tmp_path, source_cache_bytes=len(_SAMPLE))
    first = _write(tmp_path, "a.py", _SAMPLE)
    second = _write(tmp_path, "b.py", _SAMPLE)
    assert target.python_source(first) is target.python_source(first)
    uncached = target.python_source(second)
    assert uncached is not None
    assert uncached.nodes(ast.Call)
    assert target.python_source(second) is not uncached


def test_source_carries_its_text_and_path(tmp_path: Path) -> None:
    path = _write(tmp_path, "sample.py", _SAMPLE)
    source = read_python_source(path)
    assert source is not None
    assert source.path == path
    assert source.text == _SAMPLE


def test_oversized_file_is_refused_rather_than_read_whole(tmp_path: Path) -> None:
    # A crafted multi-GB `.py` must not be read into memory. Refusing beats
    # truncating: a half-parsed file yields findings about code nobody wrote.
    path = _write(tmp_path, "huge.py", "x = 1\n")
    assert read_python_source(path, limit=4) is None


def test_python_source_is_reusable_without_a_target(tmp_path: Path) -> None:
    # Third-party rules get the same entry point the built-ins use.
    source = read_python_source(_write(tmp_path, "sample.py", _SAMPLE))
    assert isinstance(source, PythonSource)
