"""Read a Jupyter code cell the way IPython runs it.

A cell is Python interleaved with IPython syntax that is not Python: `!` shell
escapes, `%` line magics, `%%` cell magics, automagic lines, `{…}` expansions and
calls on the IPython object. This module separates what a cell runs into Python,
shell commands and the parts it cannot read, carrying the notebook-wide state
(aliases, magic aliases, names bound so far) from one cell to the next.
"""

import ast
import builtins
import contextlib
import keyword
import re
import shlex
import string
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

# Fetching a script and piping it straight into a shell (`curl … | sh`) is the
# classic notebook payload — a channel the `.py` AST scanners never see.
PIPE_TO_SHELL = re.compile(r"\|\s*(sudo\s+)?(ba)?sh\b")
# IPython forms that are not Python: a `!` line escape, and `target = !cmd` or
# `target = %magic` assigning one, whatever the target.
_ASSIGN_ESCAPE = re.compile(
    r"^\s*(?P<target>[^=\s][^=]*?)(?<![=!<>:+\-*/%&|^@~])=\s*(?P<kind>[!%])(?P<rest>.*)$"
)
# IPython's own split of a line into escape, function part and the rest.
_LINE_SPLIT = re.compile(r"^(\s*)([,;/%]|!!?|\?\??)?\s*(%{0,2}[\w\.\*]*)(.*?$|$)")
# The line magics IPython and its kernel define at start-up; with automagic on, a
# single-line cell that starts with one of these names runs it.
_DEFAULT_LINE_MAGICS = frozenset(
    {
        "alias", "alias_magic", "autoawait", "autocall", "automagic", "bookmark", "cat", "cd",
        "clear", "code_wrap", "colors", "conda", "config", "connect_info", "cp", "debug",
        "dhist", "dirs", "doctest_mode", "ed", "edit", "env", "gui", "hist", "history",
        "killbgscripts", "ldir", "less", "lf", "lk", "ll", "load", "load_ext", "loadpy",
        "logoff", "logon", "logstart", "logstate", "logstop", "ls", "lsmagic", "lx", "macro",
        "magic", "mamba", "man", "matplotlib", "micromamba", "mkdir", "more", "mv", "notebook",
        "page", "pastebin", "pdb", "pdef", "pdoc", "pfile", "pinfo", "pinfo2", "pip", "popd",
        "pprint", "precision", "prun", "psearch", "psource", "pushd", "pwd", "pycat", "pylab",
        "qtconsole", "quickref", "recall", "rehashx", "reload_ext", "rep", "rerun", "reset",
        "reset_selective", "rm", "rmdir", "run", "save", "sc", "set_env", "store", "sx",
        "system", "tb", "time", "timeit", "unalias", "unload_ext", "uv", "who", "who_ls",
        "whos", "xdel", "xmode",
    }
)  # fmt: skip
# Names a line magic never shadows: IPython's builtin namespace and the names it puts
# in every user namespace.
_SHADOWING_BUILTINS = frozenset(dir(builtins)) | {
    "In", "Out", "_", "__", "___", "_dh", "_i", "_ih", "_ii", "_iii", "_oh", "exit",
    "get_ipython", "quit",
}  # fmt: skip
_SHELL_LINE_MAGICS = frozenset({"system", "sx", "sc"})
_OPTION_WORD = re.compile(r"\S+")
# A shell reads the next line as part of the command after a trailing `|`, `&&` or `||`.
_CONTINUING_OPERATOR = re.compile(r"(\|\||&&|\|&?)\s*$")
_SHELL_CELL_MAGICS = frozenset({"bash", "sh", "sx", "system", "!"})
_SHELL_INTERPRETERS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash"})
_PYTHON_INTERPRETER = re.compile(r"(python|pypy)[\d.]*")
_SCRIPT_VALUED_OPTIONS = frozenset({"--proc", "--out", "--err"})
# Cell magics whose body IPython runs, or writes out, as Python source.
_PYTHON_BODY_CELL_MAGICS = frozenset(
    {"time", "capture", "writefile", "file", "python", "python2", "python3", "pypy"}
)
# Line magics that only change or show interpreter state; none runs code or input from
# outside the cell.
_STATE_LINE_MAGICS = frozenset(
    {
        "aimport", "autoawait", "autocall", "autoindent", "automagic", "autoreload",
        "autosave", "bookmark", "cd", "colors", "config", "dhist", "dirs", "doctest_mode",
        "env", "gui", "hist", "history", "killbgscripts", "logoff", "logon", "logstart",
        "logstate", "logstop", "lsmagic", "magic", "matplotlib", "notebook", "page", "pdb",
        "pdef", "pdoc", "pfile", "pinfo", "pinfo2", "popd", "pprint", "precision", "psearch",
        "psource", "pushd", "pwd", "pycat", "pylab", "quickref", "recall", "rep", "reset",
        "reset_selective", "save", "set_env", "tb", "unload_ext", "who", "who_ls", "whos",
        "xdel", "xmode",
    }
)  # fmt: skip
_EXTENSION_LINE_MAGICS = frozenset({"load_ext", "reload_ext"})
# Extensions IPython resolves inside its own package before anything on `sys.path`.
_BUNDLED_EXTENSIONS = frozenset({"autoreload", "storemagic"})
# The shell aliases IPython defines at start-up on POSIX.
_DEFAULT_ALIASES = {
    name: name
    for name in (
        "cat", "clear", "cp", "ldir", "less", "lf", "lk", "ll", "ls", "lx", "man", "mkdir",
        "more", "mv", "rm", "rmdir",
    )
}  # fmt: skip


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


# How many magic aliases resolve in a row before the chain counts as a loop.
_MAX_ALIAS_HOPS = 8
_MAGIC_ALIAS_NAMES = 2
_DEFINING_LINE_MAGICS = frozenset({"alias", "unalias", "alias_magic", "rehashx"})
# `get_ipython()` methods that run their string argument as a shell command or as Python.
_IPYTHON_SHELL_METHODS = frozenset({"system", "getoutput", "system_raw", "system_piped"})
_IPYTHON_CODE_METHODS = frozenset({"run_cell", "run_cell_async", "ex", "ev"})
# Uses of the IPython object that run nothing: its namespaces and counters, history and
# display data, `events` (which only registers callables the cell itself defines), and
# methods that set variables or the next input without running them.
_IPYTHON_INERT = frozenset(
    {
        "display_formatter", "del_var", "events", "execution_count", "history_manager",
        "push", "set_next_input", "user_global_ns", "user_ns",
    }
)  # fmt: skip
# Methods that return a magic function; calling the result runs that magic.
_MAGIC_FINDERS = frozenset({"find_line_magic", "find_cell_magic", "find_magic"})
# Builtins that only inspect, compare or print an object, so handing them the IPython
# object runs none of its methods.
_INSPECTING_BUILTINS = frozenset(
    {
        "bool",
        "callable",
        "dir",
        "hasattr",
        "id",
        "isinstance",
        "issubclass",
        "print",
        "repr",
        "str",
        "type",
    }
)
HANDED_OUT = "code handed the IPython object"
"""The label of a call given the IPython object, whose use of it is not followed."""
_CELL_MAGIC_ARGUMENTS = 2


@dataclass
class CellReading:
    """What one cell runs: its Python, its shell commands and the magics left unread."""

    python: str = ""
    shell: list[str] = field(default_factory=list)
    unread: list[str] = field(default_factory=list)
    too_complex: bool = False
    bound: set[str] = field(default_factory=set)


@dataclass
class NotebookState:
    """What earlier cells defined that changes how a later cell runs."""

    aliases: dict[str, str] = field(default_factory=lambda: dict(_DEFAULT_ALIASES))
    line_magic_aliases: dict[str, tuple[str, str]] = field(default_factory=dict)
    cell_magic_aliases: dict[str, tuple[str, str]] = field(default_factory=dict)
    bound: set[str] = field(default_factory=set)
    ipython_names: set[str] = field(default_factory=set)
    get_ipython_names: set[str] = field(default_factory=lambda: {"get_ipython"})
    rehashed: bool = False


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


def _shell_commands(lines: list[str]) -> list[str]:
    """Join a shell cell's physical lines into the commands a shell would run.

    A trailing backslash joins the next line; a trailing `|`, `&&` or `||` carries
    the command on past blank and comment lines.
    """
    commands: list[str] = []
    pending: str | None = None
    after_operator = False
    for line in lines:
        if pending is not None and after_operator and line.strip()[:1] in ("", "#"):
            continue
        text = line if pending is None else f"{pending} {line}"
        if text.endswith("\\"):
            pending, after_operator = text[:-1], False
        elif _CONTINUING_OPERATOR.search(text):
            pending, after_operator = text, True
        else:
            commands.append(text)
            pending = None
    if pending is not None:
        commands.append(pending)
    return commands


def _escaped_line_end(lines: list[str], start: int) -> int:
    """Return the last physical line of an IPython escape, which a trailing backslash extends."""
    end = start
    while end + 1 < len(lines) and lines[end].rstrip().endswith("\\"):
        end += 1
    return end


def _join_escaped(lines: list[str]) -> str:
    """Join backslash-continued lines the way IPython assembles an escaped command."""
    return " ".join([part.rstrip()[:-1] for part in lines[:-1]] + [lines[-1].rstrip()])


def _alias_command(command: str, rest: str) -> str:
    """Return the shell command a call of an alias runs, substituting `%l` and `%s`."""
    if "%l" in command:
        command, rest = command.replace("%l", rest), ""
    count = command.count("%s") - command.count("%%s")
    if count <= 0:
        return f"{command.replace('%%s', '%s')} {rest}"
    words = rest.split(None, count)
    try:
        return f"{command % tuple(words[:count])} {' '.join(words[count:])}"
    except (TypeError, ValueError):
        return f"{command} {rest}"


def _script_interpreter(args: str) -> str:
    """Return the program a `%%script` cell names, past the options it accepts."""
    words = args.split()
    index = 0
    while index < len(words):
        word = words[index]
        if not word.startswith("-"):
            return word.rsplit("/", 1)[-1]
        index += 2 if word in _SCRIPT_VALUED_OPTIONS else 1
    return ""


def _expansions(text: str) -> list[str]:
    """Return the Python expressions IPython evaluates when it expands `{…}` in `text`.

    IPython parses the text as a format string (`{{` and `}}` are literal braces)
    and evaluates each field, its format spec rejoined to it, until a field fails to
    parse; the fields before that failure have already run. A field that is not a
    Python expression evaluates nothing: IPython runs the command unexpanded instead.
    """
    expressions: list[str] = []
    with contextlib.suppress(ValueError):
        for _literal, name, spec, _conversion in string.Formatter().parse(text):
            expression = f"{name}:{spec}" if spec else name
            if expression is not None and expression.strip():
                expressions.append(expression)
    return expressions


def _expansion_python(text: str, cell: CellReading) -> str:
    """Return the Python expressions `text` expands as statements on one logical line.

    Each expression is parenthesised across lines of its own, so a trailing comment in
    it cannot swallow the closing parenthesis.
    """
    statements: list[str] = []
    for expression in _expansions(text):
        try:
            ast.parse(expression.strip(), mode="eval")
        except (SyntaxError, ValueError):
            continue
        except (MemoryError, RecursionError):
            cell.too_complex = True
            continue
        statements.append(f"(\n{expression.strip()}\n)")
    return "; ".join(statements)


def _resolve_magic_alias(
    name: str, args: str, aliases: dict[str, tuple[str, str]]
) -> tuple[str, str] | None:
    """Follow `%alias_magic` definitions to the magic they run; None for a loop."""
    for _ in range(_MAX_ALIAS_HOPS):
        if name not in aliases:
            return name, args
        target, params = aliases[name]
        name, args = target, f"{params} {args}".strip()
    return None


def _line_magic(name: str, args: str, state: NotebookState, cell: CellReading) -> str | None:
    """Read one line magic into `cell`; return the Python it runs, or None for none.

    Every magic but the ones that run their argument as Python has its argument
    expanded first, so the expressions in it run too.
    """
    resolved = _resolve_magic_alias(name, args, state.line_magic_aliases)
    if resolved is None:
        cell.unread.append(f"%{name}")
        return None
    name, args = resolved
    if name in _PYTHON_LINE_MAGICS:
        return _magic_statement(args, _PYTHON_LINE_MAGICS[name])
    expanded = _expansion_python(args, cell)
    _classify_line_magic(name, args, state, cell)
    return expanded or None


def _classify_line_magic(name: str, args: str, state: NotebookState, cell: CellReading) -> None:
    """Record what a line magic that is not Python runs: a shell command, or nothing read."""
    if name in _SHELL_LINE_MAGICS:
        cell.shell.append(args)
    elif name in _DEFINING_LINE_MAGICS:
        _define(name, args, state, cell)
    elif name in state.aliases:
        cell.shell.append(_alias_command(state.aliases[name], args))
    elif name in _EXTENSION_LINE_MAGICS and args.strip() in _BUNDLED_EXTENSIONS:
        pass
    elif name not in _STATE_LINE_MAGICS:
        cell.unread.append(f"%{name}")


def _define(name: str, args: str, state: NotebookState, cell: CellReading) -> None:
    """Apply a magic that changes what later lines run: an alias, or the executable aliases."""
    if name == "alias":
        alias, _, command = args.strip().partition(" ")
        if command.strip():
            state.aliases[alias] = command.strip()
            cell.shell.append(command)
    elif name == "unalias":
        state.aliases.pop(args.strip(), None)
    elif name == "rehashx":
        state.rehashed = True
    elif not _define_magic_alias(args, state):
        cell.unread.append("%alias_magic")


def _magic_alias_words(words: list[str]) -> tuple[bool, bool, str, list[str]] | None:
    """Parse `%alias_magic` words into (line, cell, params, names); None for an unknown option."""
    line = cell = False
    params = ""
    names: list[str] = []
    index = 0
    while index < len(words):
        word = words[index]
        if word in ("-p", "--params"):
            params = words[index + 1] if index + 1 < len(words) else ""
            index += 1
        elif word.startswith("--params="):
            params = word.partition("=")[2]
        elif word in ("--line", "--cell"):
            line, cell = line or word == "--line", cell or word == "--cell"
        elif word.startswith("-") and len(word) > 1 and set(word[1:]) <= {"l", "c"}:
            line, cell = line or "l" in word, cell or "c" in word
        elif word.startswith("-"):
            return None
        else:
            names.append(word.lstrip("%"))
        index += 1
    return line, cell, params, names


def _define_magic_alias(args: str, state: NotebookState) -> bool:
    """Record an `%alias_magic [-l] [-c] [-p PARAMS] name target`; False if unreadable."""
    try:
        parsed = _magic_alias_words(shlex.split(args))
    except ValueError:
        return False
    if parsed is None:
        return False
    line, cell, params, names = parsed
    if len(names) != _MAGIC_ALIAS_NAMES:
        # With no names it only lists the aliases; any other count is an error.
        return not names
    if not line and not cell:
        line = cell = True
    if line:
        state.line_magic_aliases[names[0]] = (names[1], params)
    if cell:
        state.cell_magic_aliases[names[0]] = (names[1], params)
    return True


def _cell_magic(head: str, state: NotebookState) -> tuple[str, str]:
    """Return a cell magic's name and arguments, aliases followed.

    `%%script <program>` is named for the kind of program it runs: `sh`, `python`,
    or `script <program>`.
    """
    name, _, args = head.lstrip()[2:].partition(" ")
    resolved = _resolve_magic_alias(name, args, state.cell_magic_aliases)
    if resolved is None:
        return f"{name} (an alias loop)", args
    name, args = resolved
    if name != "script":
        return name, args
    interpreter = _script_interpreter(args)
    if interpreter in _SHELL_INTERPRETERS:
        return "sh", args
    if _PYTHON_INTERPRETER.fullmatch(interpreter):
        return "python", args
    return f"script {interpreter}".rstrip(), args


def _assigned_names(target: str) -> set[str]:
    """Return the names an assignment target such as `a, b` binds; empty if it is not one."""
    try:
        tree = ast.parse(f"{target} = None")
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return set()
    return {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}


def _escaped_python(joined: str, state: NotebookState, cell: CellReading) -> str | None:
    """Read one `!`, `var = !` or `%` line into `cell`; return the Python it runs, or None."""
    stripped = joined.lstrip()
    if not stripped.startswith(("!", "%")):
        assign = _ASSIGN_ESCAPE.match(joined)
        if assign is None:
            return None
        cell.bound |= _assigned_names(assign.group("target"))
        stripped = assign.group("kind") + assign.group("rest")
    if stripped.startswith("!"):
        cell.shell.append(stripped[1:])
        return _expansion_python(stripped[1:], cell) or None
    if not stripped.startswith("%%"):
        # IPython takes the magic's name up to the first space, exactly.
        name, _, args = stripped[1:].partition(" ")
        return _line_magic(name, args, state, cell)
    return None


def _automagic(source: str, state: NotebookState) -> str | None:
    """Return the `%magic` line a cell runs through automagic, or None when it runs none.

    IPython applies automagic only to a cell that is one line once leading blank lines
    and indentation are removed: its first word must be a line magic, the rest must not
    start with `=` or `,`, and no name the notebook bound, no builtin and no keyword
    may shadow it. After `%rehashx` any word can name an executable alias.
    """
    lines = source.splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    line = lines[0].lstrip() if len(lines) == 1 else ""
    match = _LINE_SPLIT.match(line)
    if not line or line.startswith(("!", "%")) or _ASSIGN_ESCAPE.match(line) or match is None:
        return None
    function, rest = match.group(3), match.group(4).lstrip()
    head = function.split(".", 1)[0]
    shadowed = head in state.bound or head in _SHADOWING_BUILTINS or keyword.iskeyword(head)
    if match.group(2) or not function or rest[:1] in ("=", ",") or shadowed:
        return None
    known = (
        function in _DEFAULT_LINE_MAGICS
        or function in state.aliases
        or function in state.line_magic_aliases
    )
    if not known and not (state.rehashed and function.isidentifier()):
        return None
    return f"%{function} {rest}".rstrip()


def _python_lines(
    lines: list[str],
    head: tuple[int, str] | None,
    cell_options: _MagicOptions | None,
    state: NotebookState,
    cell: CellReading,
) -> Iterator[str]:
    """Yield one line of Python per physical line, escapes and magics read into `cell`."""
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.lstrip()
        if head is not None and index == head[0]:
            if cell_options is None:
                yield _expansion_python(head[1], cell)
            else:
                yield _magic_python(head[1], cell_options, "")
            index += 1
        elif stripped.startswith(("!", "%")) or _ASSIGN_ESCAPE.match(line):
            end = _escaped_line_end(lines, index)
            statement = _escaped_python(_join_escaped(lines[index : end + 1]), state, cell)
            yield line[: len(line) - len(stripped)] + statement if statement else ""
            yield from ("" for _ in range(index + 1, end + 1))
            index = end + 1
        else:
            yield line
            index += 1


def read_cell(source: str, state: NotebookState | None = None) -> CellReading:
    """Separate a cell into the Python it runs, its shell commands and the magics left unread.

    `!` escapes, `var = !cmd`, `%system`/`%sx`, `%alias` definitions and calls, and
    shell cell magics run a shell, not Python; a shell cell is read as the shell
    joins its lines. A magic that runs Python (`%time`, `%timeit`, `%prun`,
    `%debug`, and the first line of `%%timeit`, `%%prun`, `%%debug`) keeps its
    statement in place of the magic. A magic that only changes interpreter state is
    dropped so the remaining Python parses; every other magic, and any cell magic
    that runs another language, is named in `unread` and its input is never read as
    Python. Removed lines are blanked, not deleted, so a reported line still maps
    to the cell. `state` carries what earlier cells defined, and this cell's
    definitions are added to it.
    """
    state = NotebookState() if state is None else state
    automagic = _automagic(source, state)
    if automagic is not None:
        source = automagic
    lines = source.splitlines()
    cell = CellReading()
    # IPython drops leading blank lines before it looks for a cell magic.
    first = next((index for index, line in enumerate(lines) if line.strip()), None)
    head: tuple[int, str] | None = None
    cell_options: _MagicOptions | None = None
    if first is not None and lines[first].lstrip().startswith("%%"):
        name, args = _cell_magic(lines[first], state)
        if name in _SHELL_CELL_MAGICS or (
            name not in _PYTHON_CELL_MAGICS and name not in _PYTHON_BODY_CELL_MAGICS
        ):
            # The body is not Python, but the magic's own line is expanded before it runs.
            cell.python = "\n" * first + _expansion_python(args, cell)
            if name in _SHELL_CELL_MAGICS:
                cell.shell = _shell_commands(lines[first + 1 :])
            else:
                cell.unread.append(f"%%{name}")
            return cell
        head = (first, args)
        cell_options = _PYTHON_CELL_MAGICS.get(name)
    cell.python = "\n".join(_python_lines(lines, head, cell_options, state, cell))
    return cell


def read_shell_command(command: str) -> CellReading:
    """Read a command string the IPython object runs in a shell, as a `!` line is read."""
    cell = CellReading(shell=_shell_commands(command.splitlines()))
    cell.python = _expansion_python(command, cell)
    return cell


def bind_names(tree: ast.Module, state: NotebookState) -> None:
    """Add the names a parsed cell binds in the notebook's namespace to `state`.

    Function, class, lambda and comprehension bodies have scopes of their own, so
    the names bound inside them are not followed.
    """
    stack: list[ast.AST] = list(tree.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            state.bound.add(node.name)
            stack.extend(node.decorator_list)
            continue
        if isinstance(
            node, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            state.bound.update(
                alias.asname or alias.name.split(".")[0]
                for alias in node.names
                if alias.name != "*"
            )
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            state.bound.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            state.bound.add(node.name)
        if isinstance(node, ast.ImportFrom):
            state.get_ipython_names.update(
                alias.asname or alias.name for alias in node.names if alias.name == "get_ipython"
            )
        stack.extend(ast.iter_child_nodes(node))
    _bind_ipython_names(tree, state)


def _bind_ipython_names(tree: ast.Module, state: NotebookState) -> None:
    """Record names bound to `get_ipython` itself and to the object it returns, in order."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        names = {target.id for target in node.targets if isinstance(target, ast.Name)}
        if _is_ipython_object(node.value, state):
            state.ipython_names |= names
        elif isinstance(node.value, ast.Name) and node.value.id in state.get_ipython_names:
            state.get_ipython_names |= names


def _is_ipython_object(node: ast.expr, state: NotebookState) -> bool:
    """Whether `node` evaluates to the IPython shell: `get_ipython()` or a name bound to it.

    `get_ipython` is recognised under any name an import or an assignment gave it, and
    as an attribute of any module (`IPython.get_ipython()`).
    """
    if isinstance(node, ast.Name):
        return node.id in state.ipython_names
    if not isinstance(node, ast.Call) or node.args or node.keywords:
        return False
    function = node.func
    if isinstance(function, ast.Name):
        return function.id in state.get_ipython_names
    return isinstance(function, ast.Attribute) and function.attr == "get_ipython"


def _literal(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _shell(texts: list[str]) -> tuple[str, str]:
    return "shell", texts[0]


def _code(texts: list[str]) -> tuple[str, str]:
    return "cell", texts[0]


# What each IPython-object method runs, built from its leading literal arguments: how
# many it needs, and the shell command or cell source they make.
_IPYTHON_CALLS: dict[str, tuple[int, Callable[[list[str]], tuple[str, str]]]] = {
    **dict.fromkeys(_IPYTHON_SHELL_METHODS, (1, _shell)),
    **dict.fromkeys(_IPYTHON_CODE_METHODS, (1, _code)),
    "magic": (1, lambda texts: ("cell", "%" + texts[0].replace("\n", " "))),
    "run_line_magic": (2, lambda texts: ("cell", f"%{texts[0]} {texts[1]}".replace("\n", " "))),
    "run_cell_magic": (3, lambda texts: ("cell", f"%%{texts[0]} {texts[1]}\n{texts[2]}")),
}


def _ipython_method(method: str, args: list[ast.expr]) -> tuple[str, str | None] | None:
    """Return what calling one IPython-object method runs; None for an inert method.

    A method outside the read list, or one whose arguments are not literals, is
    returned as its label with no text, so it is reported unread.
    """
    label = f"get_ipython().{method}"
    if method in _IPYTHON_INERT:
        return None
    if method not in _IPYTHON_CALLS:
        return label, None
    arity, build = _IPYTHON_CALLS[method]
    literals = [text for text in (_literal(arg) for arg in args[:arity]) if text is not None]
    return build(literals) if len(literals) == arity else (label, None)


def _found_magic_call(finder: ast.Call, args: list[ast.expr]) -> tuple[str, str | None]:
    """Return what calling the magic a `find_*_magic(name)` call returned runs."""
    method = finder.func.attr if isinstance(finder.func, ast.Attribute) else ""
    label = f"get_ipython().{method}"
    name = _literal(finder.args[0]) if finder.args else None
    kind_node = finder.args[1] if len(finder.args) > 1 else None
    kind_node = next((kw.value for kw in finder.keywords if kw.arg == "magic_kind"), kind_node)
    kind = "cell" if method == "find_cell_magic" else (_literal(kind_node) or "line")
    texts = [_literal(arg) for arg in args]
    if name is None or None in texts:
        return label, None
    if kind == "cell" and len(texts) == _CELL_MAGIC_ARGUMENTS:
        return "cell", f"%%{name} {texts[0]}\n{texts[1]}"
    if kind == "line" and len(texts) == 1:
        return "cell", f"%{name} {texts[0]}".replace("\n", " ")
    return label, None


def _ipython_method_target(
    node: ast.expr, state: NotebookState
) -> tuple[str | None, ast.AST] | None:
    """Return `(method, consumed node)` when `node` names a method of the IPython object.

    `ip.name` and `getattr(ip, 'name')` both name it; a `getattr` with a computed name
    names no method this rule can read, given as None.
    """
    if isinstance(node, ast.Attribute) and _is_ipython_object(node.value, state):
        return node.attr, node
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and node.args
        and _is_ipython_object(node.args[0], state)
    ):
        name = _literal(node.args[1]) if len(node.args) > 1 else None
        return name, node
    return None


def ipython_calls(tree: ast.Module, state: NotebookState) -> Iterator[tuple[str, str | None]]:
    """Yield what each use of the IPython object runs, as `(kind, text)`.

    `kind` is `shell` (a command) or `cell` (cell source to read). A use the rule does
    not read — a method outside its list, a computed argument, a method taken without
    being called — is yielded as a label with `text` None.
    """
    consumed: set[int] = set()
    for node in ast.walk(tree):
        if id(node) in consumed:
            continue
        if isinstance(node, ast.Call):
            call = _call_on_ipython(node, state, consumed)
            if call is not None:
                yield call
            elif id(node) not in consumed and _hands_out_ipython(node, state):
                yield HANDED_OUT, None
            continue
        target = _ipython_method_target(node, state) if isinstance(node, ast.expr) else None
        if target is not None and target[0] not in _IPYTHON_INERT:
            yield f"get_ipython().{target[0] or 'getattr'}", None


def _hands_out_ipython(node: ast.Call, state: NotebookState) -> bool:
    """Whether a call is given the IPython object, or `get_ipython` itself, as an argument.

    What the callee does with it is not followed. A builtin that only inspects or prints
    its argument is no such call unless the notebook rebound its name.
    """
    function = node.func
    if (
        isinstance(function, ast.Name)
        and function.id in _INSPECTING_BUILTINS
        and function.id not in state.bound
    ):
        return False
    values = [*node.args, *(kw.value for kw in node.keywords)]
    return any(
        _is_ipython_object(value, state) or _is_ipython_getter(value, state)
        for value in (each.value if isinstance(each, ast.Starred) else each for each in values)
    )


def _is_ipython_getter(node: ast.expr, state: NotebookState) -> bool:
    """Whether `node` is `get_ipython` itself, under any name it was given, uncalled."""
    if isinstance(node, ast.Name):
        return node.id in state.get_ipython_names
    return isinstance(node, ast.Attribute) and node.attr == "get_ipython"


def _call_on_ipython(
    node: ast.Call, state: NotebookState, consumed: set[int]
) -> tuple[str, str | None] | None:
    """Read one call that may be on the IPython object; mark the nodes it accounts for."""
    target = _ipython_method_target(node.func, state)
    if target is not None:
        consumed.add(id(target[1]))
        if target[0] is None:
            return "get_ipython().getattr", None
        return _ipython_method(target[0], node.args)
    if isinstance(node.func, ast.Call):
        finder = _ipython_method_target(node.func.func, state)
        if finder is not None and finder[0] in _MAGIC_FINDERS:
            consumed.update({id(node.func), id(finder[1])})
            return _found_magic_call(node.func, node.args)
    handed_out = _ipython_method_target(node, state)
    if handed_out is not None:
        # A `getattr(ip, ...)` that is not called still hands the method out.
        consumed.add(id(node))
        if handed_out[0] not in _IPYTHON_INERT:
            return f"get_ipython().{handed_out[0] or 'getattr'}", None
    return None


_COMMAND_SEPARATORS = frozenset({";", ";;", "&", "&&", "|", "||", "|&", "(", ")"})
_COMMAND_WRAPPERS = frozenset(
    {"builtin", "command", "env", "exec", "nice", "nohup", "sudo", "time"}
)
_WRAPPER_VALUED_OPTIONS = frozenset({"-u", "-g", "-n"})
_SOURCE_COMMANDS = frozenset({"source", "."})
_SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh", ".py")
_ASSIGNMENT = re.compile(r"[A-Za-z_]\w*=")
_SHELL_VALUED_OPTIONS = frozenset({"-o", "+o", "-O", "+O", "--rcfile", "--init-file"})
_PYTHON_VALUED_OPTIONS = frozenset({"-W", "-X", "--check-hash-based-pycs"})
_STDIN = "<"
_MAX_INLINE_DEPTH = 4
"""How deep `sh -c` programs nested in one another are read for scripts."""


def _shell_words(command: str) -> list[str]:
    """Split a shell command into words and operators as a POSIX shell tokenises it."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError:
        return command.split()


def _simple_commands(words: list[str]) -> Iterator[tuple[list[str], str | None]]:
    """Yield each simple command's words, without redirections, and the file it reads as stdin."""
    current: list[str] = []
    stdin: str | None = None
    redirect: str | None = None
    for word in words:
        if redirect is not None:
            stdin = word if redirect == _STDIN else stdin
            redirect = None
        elif word in _COMMAND_SEPARATORS:
            yield current, stdin
            current, stdin = [], None
        elif word and set(word) <= set("<>&|"):
            redirect = word
        else:
            current.append(word)
    yield current, stdin


def _unwrapped(words: list[str]) -> list[str]:
    """Drop leading assignments and the wrappers that run the command after them."""
    index = 0
    while index < len(words):
        word = words[index]
        if _ASSIGNMENT.match(word):
            index += 1
        elif word.rsplit("/", 1)[-1] in _COMMAND_WRAPPERS:
            index += 1
            while index < len(words) and words[index].startswith("-"):
                index += 2 if words[index] in _WRAPPER_VALUED_OPTIONS else 1
        else:
            break
    return words[index:]


@dataclass(frozen=True)
class _Invocation:
    """What an interpreter's arguments say it runs."""

    script: str | None = None
    inline: str | None = None
    """The program given as text (`sh -c '...'`), read for scripts in turn."""

    named: bool = False
    """Whether the arguments name what it runs, so it does not read its standard input."""


def _interpreter_run(words: list[str], valued: frozenset[str], inline: str) -> _Invocation:
    """Read an interpreter's arguments: the script it runs, or the program it is given.

    An option letter in `inline` takes the program as text (`-c`) or names a module
    (`-m`), so there is no script file.
    """
    index = 0
    while index < len(words):
        word = words[index]
        following = words[index + 1] if index + 1 < len(words) else None
        if word == "--":
            return _Invocation(script=following, named=following is not None)
        if word in ("-", "+"):
            return _Invocation()
        if not word.startswith(("-", "+")):
            return _Invocation(script=word, named=True)
        letters = set(word[1:]) if not word.startswith("--") else set()
        if letters & set(inline):
            return _Invocation(inline=following if "c" in letters else None, named=True)
        index += 2 if word in valued else 1
    return _Invocation()


def _names_a_script(word: str) -> bool:
    """Whether a command word is a file run as a program rather than a tool on the path.

    A relative path is a local file; a bare name or an absolute path counts only with a
    script suffix, since system tools are run by both.
    """
    if word.lower().endswith(_SCRIPT_SUFFIXES):
        return True
    return "/" in word and not word.startswith("/")


def local_scripts(command: str, depth: int = 0) -> list[str]:
    """Return the local script files a shell command runs, as they are written in it.

    A script is the file a shell or Python interpreter is given to run, by argument or as
    its standard input, a file sourced into the shell, or a path run as the command
    itself. A tool run by name, `python -m` and an interpreter given its program inline
    name none; the program given inline is read for scripts in turn.
    """
    scripts: list[str] = []
    for raw, stdin in _simple_commands(_shell_words(command)):
        words = _unwrapped(raw)
        if not words:
            continue
        program, arguments = words[0], words[1:]
        name = program.rsplit("/", 1)[-1]
        inline = None
        if name in _SHELL_INTERPRETERS or _PYTHON_INTERPRETER.fullmatch(name):
            shell = name in _SHELL_INTERPRETERS
            run = _interpreter_run(
                arguments,
                _SHELL_VALUED_OPTIONS if shell else _PYTHON_VALUED_OPTIONS,
                "c" if shell else "cm",
            )
            script = run.script if run.named else stdin
            inline = run.inline
        elif name in _SOURCE_COMMANDS:
            script = arguments[0] if arguments else None
        else:
            script = program if _names_a_script(program) else None
        if script is not None:
            scripts.append(script)
        if inline is not None and depth < _MAX_INLINE_DEPTH:
            scripts.extend(local_scripts(inline, depth + 1))
    return scripts
