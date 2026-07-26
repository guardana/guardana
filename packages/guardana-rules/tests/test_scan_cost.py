"""The cost of a scan must grow with the target, not with the number of rules.

This is a gate, not a benchmark: it counts operations rather than measuring time,
so it means the same thing on a busy CI runner as on a laptop. Wall-clock is what
users feel, but a timing assertion is either flaky or so loose it catches nothing.

What it protects: every build-time rule used to walk the tree, read each file and
parse it for itself. Measured on this repo that was 26 full tree walks, 2025 file
opens for 422 files, and 1477 `ast.parse` calls for 211 sources — cost multiplied
by knowledge, so each new rule made every scan slower. A scan nobody waits for is
one that gets switched off, and a switched-off scanner fails open at a level no
rule can defend.
"""

import ast
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from guardana.core.profile.model import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.runner import Runner
from guardana.core.target import ArtifactTarget

_SOURCE_FILES = 6
# One walk belongs to the target. The second is `_declared_deps`, which reads the
# repo's requirements/pyproject to tell a real dependency from a hallucinated one;
# it looks for two filenames, not for every file, and runs once per scan.
_MAX_TREE_WALKS = 2

# Inert fixture text, never imported or executed: `verify=False` and `os.system`
# are here because they are what `insecure_transport` and `code_execution` must
# still find once the reads are shared.
_MODULE = """\
import os
import requests

def go(url):
    requests.get(url, verify=False)
    os.system("echo hi")
"""


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    for index in range(_SOURCE_FILES):
        (tmp_path / f"mod{index}.py").write_text(_MODULE, encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    return tmp_path


def _run(root: Path) -> int:
    result = Runner(registry=Registry.discover(), profile=Profile(name="t", policy=Policy())).run(
        ArtifactTarget(root)
    )
    return result.rules_run


def test_a_source_file_is_parsed_once_however_many_rules_read_it(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parses = 0
    real_parse = ast.parse

    def counting_parse(source: str, *args: object, **kwargs: object) -> ast.Module:
        nonlocal parses
        parses += 1
        return real_parse(source)

    monkeypatch.setattr(ast, "parse", counting_parse)
    assert _run(repo) > 0
    assert parses <= _SOURCE_FILES, (
        f"{parses} parses for {_SOURCE_FILES} files — a rule is parsing for itself "
        f"instead of asking `target.python_source()`"
    )


def test_the_tree_is_walked_a_bounded_number_of_times(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    walks = 0
    real_walk = os.walk

    def counting_walk(top: str | Path, *args: object, **kwargs: object) -> Iterator[object]:
        nonlocal walks
        walks += 1
        return real_walk(top)

    monkeypatch.setattr(os, "walk", counting_walk)
    assert _run(repo) > 0
    assert walks <= _MAX_TREE_WALKS, (
        f"{walks} tree walks — a rule is walking the target itself instead of "
        f"filtering `target.iter_files()`"
    )


def test_findings_survive_the_shared_read(repo: Path) -> None:
    # The cheapest way to make the counters above look good would be to stop
    # reading things. The fixture contains a TLS-off fetch and an `os.system`
    # call in every module, so the rules must still fire on all of them.
    result = Runner(registry=Registry.discover(), profile=Profile(name="t", policy=Policy())).run(
        ArtifactTarget(repo)
    )
    rules_fired = {finding.rule_id for finding in result.findings}
    assert "guardana.supply_chain.code_execution" in rules_fired
    assert "guardana.supply_chain.insecure_transport" in rules_fired
    assert not result.errors
