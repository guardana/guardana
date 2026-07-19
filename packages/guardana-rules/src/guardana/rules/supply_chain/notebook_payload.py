import ast
import json
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.evaluator.base import Verdict
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import NIST_SUPPLY_CHAIN, OWASP_LLM03
from guardana.rules.supply_chain._code_sinks import code_sinks
from guardana.rules.supply_chain._leads import lead_verdict
from guardana.rules.supply_chain._reading import read_text_bounded

# Fetching a script and piping it straight into a shell (`curl … | sh`) is the
# classic notebook payload — a channel the `.py` AST scanners never see.
_PIPE_TO_SHELL = re.compile(r"\|\s*(sudo\s+)?(ba)?sh\b")
_SHELL_CELL_MAGIC = ("%%bash", "%%sh", "%%script")
# IPython shell forms that are not Python: a `!` line escape, and `var = !cmd`.
_ASSIGN_SHELL = re.compile(r"^\s*[\w.]+\s*=\s*!(.*)$")


def _cell_source(cell: object) -> str | None:
    """Return a code cell's source (str or list-of-lines joined), else None."""
    if not isinstance(cell, dict) or cell.get("cell_type") != "code":
        return None
    source = cell.get("source")
    if isinstance(source, list):
        return "".join(s for s in source if isinstance(s, str))
    return source if isinstance(source, str) else None


def _split_shell_and_python(source: str) -> tuple[str, list[str]]:
    """Separate a cell into (Python source, shell command lines).

    `!` escapes, `var = !cmd`, and `%%bash`-style cell magics run a shell, not
    Python; line magics (`%…`) are dropped so the remaining Python parses. Removed
    lines are blanked, not deleted, so a reported line still maps to the cell.
    """
    lines = source.splitlines()
    if lines and lines[0].lstrip().startswith(_SHELL_CELL_MAGIC):
        return "", lines
    python: list[str] = []
    shell: list[str] = []
    for line in lines:
        stripped = line.lstrip()
        assign = _ASSIGN_SHELL.match(line)
        if stripped.startswith("!"):
            shell.append(stripped[1:])
            python.append("")
        elif assign:
            shell.append(assign.group(1))
            python.append("")
        elif stripped.startswith("%"):
            python.append("")
        else:
            python.append(line)
    return "\n".join(python), shell


class NotebookPayloadRule(Rule):
    """Flags dangerous code and shell payloads inside Jupyter notebook (`.ipynb`) cells.

    Notebooks are a primary ML distribution format, yet the `.py` scanners never
    see inside them. This applies the shared code-sink detection to each code
    cell, and catches the notebook-only channels — a `!curl … | sh` escape or a
    `%%bash` cell. A cell whose Python cannot be parsed is surfaced as a lead,
    never silently skipped: an un-analyzable cell is not a proven-clean one.
    """

    meta = RuleMeta(
        id="guardana.supply_chain.notebook_payload",
        title="Dangerous payload in a notebook cell",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM03, NIST_SUPPLY_CHAIN),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every `.ipynb` for code-execution sinks and shell payloads."""
        if not isinstance(target, ArtifactTarget):
            return
        for path in target.iter_files((".ipynb",)):
            yield from self._scan(path)

    def _scan(self, path: Path) -> Iterator[Finding]:
        raw = read_text_bounded(path, errors="ignore")
        if raw is None:
            return
        try:
            doc = json.loads(raw)
        except ValueError:
            return
        cells = doc.get("cells") if isinstance(doc, dict) else None
        if not isinstance(cells, list):
            return
        for index, cell in enumerate(cells):
            source = _cell_source(cell)
            if source is not None:
                yield from self._scan_cell(path, index, source)

    def _scan_cell(self, path: Path, index: int, source: str) -> Iterator[Finding]:
        python, shell = _split_shell_and_python(source)
        for line in shell:
            if _PIPE_TO_SHELL.search(line):
                yield self._finding(
                    path, index, Severity.HIGH, "shell escape pipes a download into a shell"
                )
        try:
            tree = ast.parse(python)
        except SyntaxError:
            yield self._finding(
                path,
                index,
                Severity.LOW,
                "notebook cell could not be parsed as Python; not analyzed",
                lead_verdict("unparsed notebook cell"),
            )
            return
        for _lineno, why in code_sinks(tree):
            yield self._finding(path, index, Severity.HIGH, why)

    def _finding(
        self,
        path: Path,
        index: int,
        severity: Severity,
        summary: str,
        verdict: Verdict | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=f"{path}:cell{index}",
            evidence=Evidence(summary=summary, detail=f"{path.name} cell {index}"),
            verdict=verdict,
        )
