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
import collections
import gzip
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from types import FrameType
from typing import Any

import pytest
from guardana.core import inventory
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile.model import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.runner import Runner
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import _ast_names, keras_lambda, pickle_opcode

_SOURCE_FILES = 6
# The one walk belongs to the target; every rule filters its listing.
_MAX_TREE_WALKS = 1

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


def _runner() -> Runner:
    return Runner(
        registry=Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
        profile=Profile(name="t", policy=Policy()),
    )


def _run(root: Path) -> int:
    return _runner().run(ArtifactTarget(root)).rules_run_count


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


def test_each_directory_is_listed_once_per_scan(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Every directory listing goes through `os.scandir` or `os.listdir`, whichever
    # spelling a rule's hand-rolled walk uses on this Python.
    (repo / "pkg" / "sub").mkdir(parents=True)
    (repo / "pkg" / "sub" / "notes.txt").write_text("text\n", encoding="utf-8")
    directories = 1 + sum(1 for path in repo.rglob("*") if path.is_dir())
    runner = _runner()
    listings = 0
    real_scandir = os.scandir
    real_listdir = os.listdir

    def counting_scandir(path: str | Path = ".") -> object:
        nonlocal listings
        listings += 1
        return real_scandir(path)

    def counting_listdir(path: str | Path = ".") -> list[str]:
        nonlocal listings
        listings += 1
        return real_listdir(path)

    monkeypatch.setattr(os, "scandir", counting_scandir)
    monkeypatch.setattr(os, "listdir", counting_listdir)
    assert runner.run(ArtifactTarget(repo)).rules_run_count > 0
    assert listings <= directories, (
        f"{listings} directory listings for {directories} directories — a rule is "
        f"listing the tree itself instead of filtering `target.iter_files()`"
    )


def test_findings_survive_the_shared_read(repo: Path) -> None:
    # The cheapest way to make the counters above look good would be to stop
    # reading things. The fixture contains a TLS-off fetch and an `os.system`
    # call in every module, so the rules must still fire on all of them.
    result = Runner(
        registry=Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
        profile=Profile(name="t", policy=Policy()),
    ).run(ArtifactTarget(repo))
    rules_fired = {finding.rule_id for finding in result.findings}
    assert "guardana.supply_chain.code_execution" in rules_fired
    assert "guardana.supply_chain.insecure_transport" in rules_fired
    assert not result.errors


def _name_resolution_calls(root: Path, links: int) -> int:
    """Count the calls into the shared name resolver while a scan reads one method chain."""
    (root / "fluent.py").write_text(
        "q = db" + "".join(f".step{i}(x)" for i in range(links)) + "\n", encoding="utf-8"
    )
    resolver_file = _ast_names.__file__
    calls = 0

    def count(frame: FrameType, event: str, _arg: object) -> None:
        nonlocal calls
        if event == "call" and frame.f_code.co_filename == resolver_file:
            calls += 1

    sys.setprofile(count)
    try:
        _run(root)
    finally:
        sys.setprofile(None)
    return calls


def test_name_resolution_grows_linearly_with_a_method_chain(tmp_path: Path) -> None:
    # Fluent chains (`df.where(...).groupby(...)...`) are ordinary code; a resolver that
    # revisits a receiver once per call above it, or twice per link, turns one long
    # line into a scan that never finishes.
    short_root, long_root = tmp_path / "short", tmp_path / "long"
    short_root.mkdir()
    long_root.mkdir()
    short = _name_resolution_calls(short_root, 8)
    long = _name_resolution_calls(long_root, 16)
    assert short > 0, "the resolver was never called, so this measures nothing"
    assert long <= 3 * short, (
        f"{short} resolver calls for 8 links but {long} for 16 — name resolution is not "
        f"linear in the chain"
    )


def _opens_by_reader(
    monkeypatch: pytest.MonkeyPatch, watched: set[str]
) -> collections.Counter[tuple[str, str]]:
    """Count each open of a watched file name by the module that asked for it."""
    readers = {
        Path(module.__file__).name: name
        for name, module in (
            ("pickle_opcode", pickle_opcode),
            ("keras_lambda", keras_lambda),
            ("inventory", inventory),
        )
        if module.__file__ is not None
    }
    opens: collections.Counter[tuple[str, str]] = collections.Counter()
    real_path_open = Path.open
    real_os_open = os.open

    def note(name: str) -> None:
        if name not in watched:
            return
        frame = sys._getframe(2)
        while frame is not None and Path(frame.f_code.co_filename).name not in readers:
            frame = frame.f_back  # type: ignore[assignment]
        reader = "other" if frame is None else readers[Path(frame.f_code.co_filename).name]
        opens[name, reader] += 1

    def path_open(self: Path, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        note(self.name)
        return real_path_open(self, *args, **kwargs)

    def os_open(path: Any, *args: Any, **kwargs: Any) -> int:  # noqa: ANN401
        note(Path(path).name)
        return real_os_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", path_open)
    monkeypatch.setattr(os, "open", os_open)
    return opens


def test_a_file_whose_name_says_nothing_costs_each_reader_one_read(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A file with no suffix, or a `.dat`, may be a pickle or an HDF5 model a loader opens
    # by its content; finding out that it is neither must cost one bounded read, or every
    # LICENSE and data file in a repository is read in full by each rule that asks.
    honest = {
        "LICENSE": b"x" * 200_000,
        "table.dat": bytes(range(256)) * 800,
        "values.dat.gz": gzip.compress(b"1.0 2.0\n" * 50_000),
    }
    for name, content in honest.items():
        (repo / name).write_bytes(content)
    (repo / "model").write_bytes(b"\x80\x02cos\nsystem\nX\x02\x00\x00\x00id\x85R.")
    opens = _opens_by_reader(monkeypatch, set(honest))
    result = _runner().run(ArtifactTarget(repo))
    assert "guardana.supply_chain.pickle_opcode" in {f.rule_id for f in result.findings}, (
        "the pickle under no suffix was not read, so the counts measure nothing"
    )
    readers = {reader for _name, reader in opens}
    assert {"pickle_opcode", "inventory"} <= readers
    assert all(count <= 1 for count in opens.values()), (
        f"opens per file and reader: {dict(opens)} — a reader opens a file whose name says "
        f"nothing more than once to find out it is no model"
    )
