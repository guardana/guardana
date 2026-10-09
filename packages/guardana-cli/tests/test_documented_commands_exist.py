"""Every `guardana …` command line in the docs or a note names a real command and real flags.

The command trees come from the parsers themselves — the Typer app and the collector's
argparse parser — so a flag renamed or removed in code turns the page that still shows it red.
A flag named on its own in prose (`--max-requests`) must be one some command accepts.
"""

import argparse
import re
import shlex
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, cast

import pytest
import typer
from guardana.cli.main import app
from guardana.server.cli.main import build_parser

_REPO = Path(__file__).resolve().parents[3]
_EXCLUDED_DOC_DIRS = ("design", "work", "generated")
# Maintainer pages name the flags of the repository's own scripts, not of the product.
_SCRIPT_DOC_DIRS = ("maintainers",)
_SHELL_FENCES = frozenset({"", "bash", "sh", "shell", "zsh", "console", "text", "yaml", "yml"})
_FENCE = re.compile(r"^\s*(`{3,}|~{3,})\s*([\w+-]*)")
_INLINE_CODE = re.compile(r"(`+)([^`]+?)\1")
_ANGLE_PLACEHOLDER = re.compile(r"<[^\s<>][^<>\n]*>")
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_YAML_COMMAND_KEY = re.compile(r"^(?:-\s+)?(?:(?:run|script|command):\s*)?")
_ALL_CAPS = re.compile(r"^[A-Z][A-Z0-9_]*$")
_OPERATOR = re.compile(r"^[();<>|&]+$")
_IMAGE = re.compile(r"^ghcr\.io/guardana/(guardana|guardana-collector)(?::\S*)?$")
_PROGRAMS = ("guardana", "guardana-collector")
_COMPOSE_COLLECTOR = "collector"
"""The service in `deploy/docker-compose.yml` whose image runs `guardana-collector`."""
_PLACEHOLDER = "PLACEHOLDER"
_BARE_FLAG = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]*")


_RAG_NOTE = "notes/tenant-leaks-and-poisoned-documents.md"
_FOREIGN_OR_ABSENT_FLAGS: Mapping[tuple[str, str], str] = {
    ("docs/usage-collector.md", "--api-key"): "named as the flag probe deliberately does not take",
    ("docs/usage-collector.md", "--with"): "a uv run flag",
    ("docs/usage-new-pack.md", "--force"): "named as the flag new-pack deliberately does not take",
    ("docs/usage-recipe.md", "--prefix"): "a pip install flag",
    (_RAG_NOTE, "--break-tenant-filter"): "a switch of the reference application",
    (_RAG_NOTE, "--obey-documents"): "a switch of the reference application",
}
"""Flags named alone in prose that belong to another tool or are named as absent: (page, flag)."""


@dataclass(frozen=True)
class _Spec:
    """One command of a parser tree: the options it accepts and the commands under it."""

    options: frozenset[str]
    valued: frozenset[str]
    subcommands: Mapping[str, "_Spec"] = field(default_factory=dict)


@dataclass(frozen=True)
class _Invocation:
    """A command line found in a document: where it starts, which program, what follows."""

    line: int
    program: str
    args: tuple[str, ...]


class _ClickParam(Protocol):
    opts: list[str]
    secondary_opts: list[str]
    param_type_name: str


class _ClickCommand(Protocol):
    context_class: Callable[..., object]
    context_settings: dict[str, object]

    def get_params(self, ctx: object) -> list[_ClickParam]:
        """Return the command's parameters as Click resolves them for `ctx`."""


def _from_click(command: object) -> _Spec:
    """Walk the Click tree Typer builds; duck-typed, as Typer ships its own copy of Click."""
    typed = cast("_ClickCommand", command)
    context = typed.context_class(typed, **(typed.context_settings or {}))
    options: set[str] = set()
    valued: set[str] = set()
    for param in typed.get_params(context):
        if param.param_type_name != "option":
            continue
        names = [*param.opts, *param.secondary_opts]
        options.update(names)
        if not getattr(param, "is_flag", False) and not getattr(param, "count", False):
            valued.update(names)
    children = cast("dict[str, object]", getattr(command, "commands", {}))
    return _Spec(
        frozenset(options),
        frozenset(valued),
        {name: _from_click(child) for name, child in children.items()},
    )


def _from_argparse(parser: argparse.ArgumentParser) -> _Spec:
    """Walk an argparse parser and the subparsers under it."""
    options: set[str] = set()
    valued: set[str] = set()
    subcommands: dict[str, _Spec] = {}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, child in action.choices.items():
                subcommands[name] = _from_argparse(child)
            continue
        options.update(action.option_strings)
        if action.option_strings and action.nargs != 0:
            valued.update(action.option_strings)
    return _Spec(frozenset(options), frozenset(valued), subcommands)


_TREES: Mapping[str, _Spec] = {
    "guardana": _from_click(typer.main.get_command(app)),
    # The parser is assembled without touching storage; only `main` opens a connection.
    "guardana-collector": _from_argparse(build_parser()),
}


def _is_placeholder(token: str) -> bool:
    bare = token.strip("[]{}'\"").lstrip("-").split("=", 1)[0]
    return (
        not bare
        or "…" in token
        or "..." in token
        or _PLACEHOLDER in token
        or _ALL_CAPS.match(bare) is not None
    )


def _tokens(line: str) -> list[str]:
    lexer = shlex.shlex(
        _ANGLE_PLACEHOLDER.sub(_PLACEHOLDER, line), posix=True, punctuation_chars=True
    )
    lexer.commenters = ""
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError:
        return line.split()


def _segments(tokens: list[str]) -> Iterator[list[str]]:
    """Split a tokenised line at shell operators and stop at a comment."""
    current: list[str] = []
    for token in tokens:
        if token.startswith("#"):
            break
        if _OPERATOR.match(token):
            yield current
            current = []
            continue
        current.append(token)
    yield current


def _invocation(tokens: list[str]) -> tuple[str, list[str]] | None:
    """Strip the prompt, environment and launcher in front of the program, if it is ours."""
    rest = list(tokens)
    if rest[:1] == ["$"]:
        rest = rest[1:]
    while rest and _ENV_ASSIGNMENT.match(rest[0]):
        rest = rest[1:]
    if rest[:2] == ["docker", "run"]:
        return _image_invocation(rest)
    if rest[:2] == ["docker", "compose"]:
        return _compose_invocation(rest)
    if rest[:2] == ["uv", "run"] or rest[:1] == ["uvx"]:
        return _launched_invocation(rest)
    if rest and rest[0] in _PROGRAMS:
        return rest[0], rest[1:]
    return None


def _image_invocation(rest: list[str]) -> tuple[str, list[str]] | None:
    """`docker run … ghcr.io/guardana/<image>:<tag> …` runs that image's entrypoint."""
    for index, token in enumerate(rest):
        image = _IMAGE.match(token)
        if image:
            return image.group(1), rest[index + 1 :]
    return None


def _launched_invocation(rest: list[str]) -> tuple[str, list[str]] | None:
    """`uv run …` or `uvx …` runs the first of our programs it names."""
    for index, token in enumerate(rest):
        if token in _PROGRAMS:
            return token, rest[index + 1 :]
    return None


def _compose_invocation(rest: list[str]) -> tuple[str, list[str]] | None:
    """`docker compose … run [--rm] collector …` runs the collector image's entrypoint."""
    if "run" not in rest:
        return None
    after = rest[rest.index("run") + 1 :]
    while after and after[0].startswith("-"):
        after = after[1:]
    if after[:1] == [_COMPOSE_COLLECTOR]:
        return "guardana-collector", after[1:]
    return None


def _invocations_in_line(line: str, number: int) -> Iterator[_Invocation]:
    for segment in _segments(_tokens(line)):
        found = _invocation(segment)
        if found:
            yield _Invocation(number, found[0], tuple(found[1]))


def _joined(lines: list[tuple[int, str]]) -> Iterator[tuple[int, str]]:
    """Join backslash-continued lines, numbering each command by its first line."""
    start: int | None = None
    parts: list[str] = []
    for number, line in lines:
        if start is None:
            start = number
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            parts.append(stripped[:-1])
            continue
        parts.append(stripped)
        yield start, " ".join(part.strip() for part in parts)
        start, parts = None, []
    if start is not None:
        yield start, " ".join(part.strip() for part in parts)


def _block_invocations(language: str, lines: list[tuple[int, str]]) -> Iterator[_Invocation]:
    for number, line in _joined(lines):
        text = line.strip()
        if language == "console" and not text.startswith("$ "):
            continue
        if language in ("yaml", "yml"):
            text = _YAML_COMMAND_KEY.sub("", text, count=1)
        yield from _invocations_in_line(text, number)


def _invocations(markdown: str) -> list[_Invocation]:
    """Every command line in the shell-like fenced blocks and inline code spans of a page."""
    found: list[_Invocation] = []
    fence: str | None = None
    language = ""
    block: list[tuple[int, str]] = []
    for number, line in enumerate(markdown.splitlines(), start=1):
        opening = _FENCE.match(line)
        if fence is None:
            if opening:
                fence, language, block = opening.group(1), opening.group(2).lower(), []
                continue
            for span in _INLINE_CODE.finditer(line):
                found.extend(_invocations_in_line(span.group(2).strip(), number))
            continue
        if opening and opening.group(1).startswith(fence) and not opening.group(2):
            if language in _SHELL_FENCES:
                found.extend(_block_invocations(language, block))
            fence = None
            continue
        block.append((number, line))
    return found


def _problems(invocation: _Invocation) -> list[str]:
    """What is wrong with one command line against the real parser tree; empty when nothing."""
    node = _TREES[invocation.program]
    path = [invocation.program]
    args = list(invocation.args)
    problems: list[str] = []
    index = 0
    skip_value = False
    while node.subcommands and index < len(args):
        word = args[index]
        index += 1
        if skip_value:
            skip_value = False
            continue
        if word.startswith("-"):
            skip_value = _check_option(word, node, path, problems)
            continue
        if _is_placeholder(word):
            return problems
        child = node.subcommands.get(word)
        if child is None:
            return [*problems, f"{' '.join([*path, word])}: no such command"]
        node = child
        path.append(word)
    for word in args[index:]:
        if skip_value:
            skip_value = False
            continue
        if word == "--":
            break
        if word.startswith("-"):
            skip_value = _check_option(word, node, path, problems)
    return problems


def _check_option(word: str, node: _Spec, path: list[str], problems: list[str]) -> bool:
    """Record an option the command does not accept; return whether the next word is its value."""
    if word == "-" or re.match(r"^-\d", word) or _is_placeholder(word):
        return False
    name, has_value = (
        (word.split("=", 1)[0], "=" in word) if word.startswith("--") else (word, False)
    )
    if name not in node.options:
        problems.append(f"{' '.join(path)} has no option {name}")
        return False
    return name in node.valued and not has_value


def _every_option(spec: _Spec) -> frozenset[str]:
    return spec.options.union(*(_every_option(child) for child in spec.subcommands.values()))


_ANY_COMMAND_OPTIONS: frozenset[str] = frozenset().union(
    *(_every_option(tree) for tree in _TREES.values())
)


def _unknown_bare_flags(markdown: str, page: str) -> list[tuple[int, str]]:
    """Flags written alone in an inline code span that no command of either program accepts."""
    found: list[tuple[int, str]] = []
    fence: str | None = None
    for number, line in enumerate(markdown.splitlines(), start=1):
        opening = _FENCE.match(line)
        if opening:
            if fence is None:
                fence = opening.group(1)
            elif opening.group(1).startswith(fence) and not opening.group(2):
                fence = None
            continue
        if fence is not None:
            continue
        for span in _INLINE_CODE.finditer(line):
            text = span.group(2).strip()
            if not text.startswith("--"):
                continue
            found.extend(
                (number, f"no command takes {flag}")
                for flag in _BARE_FLAG.findall(text)
                if flag not in _ANY_COMMAND_OPTIONS and (page, flag) not in _FOREIGN_OR_ABSENT_FLAGS
            )
    return found


def _documents(repo: Path = _REPO) -> list[Path]:
    """The README, FEATURES, the published docs pages and every note under `notes/`."""
    docs = repo / "docs"
    pages = [
        page
        for page in sorted(docs.rglob("*.md"))
        if page.relative_to(docs).parts[0] not in _EXCLUDED_DOC_DIRS
    ]
    notes = sorted((repo / "notes").glob("*.md")) if (repo / "notes").is_dir() else []
    return [repo / "README.md", repo / "FEATURES.md", *pages, *notes]


def _failures(markdown: str, page: str = "docs/page.md") -> list[tuple[int, str]]:
    """Every problem on a page, by line; `page` is its path relative to the repository."""
    command_lines = [(i.line, problem) for i in _invocations(markdown) for problem in _problems(i)]
    if Path(page).parts[:2] in {("docs", directory) for directory in _SCRIPT_DOC_DIRS}:
        return command_lines
    return sorted([*command_lines, *_unknown_bare_flags(markdown, page)])


_DOCUMENTS = _documents()
_IDS = [page.relative_to(_REPO).as_posix() for page in _DOCUMENTS]


@pytest.mark.parametrize("page", _DOCUMENTS, ids=_IDS)
def test_every_documented_command_line_names_a_real_command_and_real_flags(page: Path) -> None:
    relative = page.relative_to(_REPO).as_posix()
    failures = [
        f"{relative}:{line}: {problem}"
        for line, problem in _failures(page.read_text(encoding="utf-8"), relative)
    ]

    assert not failures, "\n".join(failures)


def test_the_walk_finds_nested_commands_and_which_options_take_a_value() -> None:
    guardana, collector = _TREES["guardana"], _TREES["guardana-collector"]
    probe = guardana.subcommands["probe"]

    assert {"inspect", "migrate"} <= set(guardana.subcommands["run"].subcommands)
    assert {"--help", "--max-requests", "--allow-destructive"} <= probe.options
    assert "--max-requests" in probe.valued
    assert "--allow-destructive" not in probe.valued
    assert "--host" in collector.subcommands["serve"].valued
    assert "create" in collector.subcommands["key"].subcommands


def test_a_flag_named_alone_that_no_command_takes_is_reported() -> None:
    snippet = "Budgets are hard ceilings: `--max-requests`, `--max-cost` and `--max-duration`.\n"

    assert _failures(snippet) == [(1, "no command takes --max-cost")]


def test_a_flag_the_command_does_not_have_is_reported_with_its_line() -> None:
    snippet = "Some prose.\n\n```bash\nguardana probe --max-cost 5 --url http://x\n```\n"

    assert _failures(snippet) == [(4, "guardana probe has no option --max-cost")]


def test_a_valid_command_line_reports_nothing() -> None:
    snippet = (
        "Run `guardana probe --url http://x --max-requests=5`, or:\n\n"
        "```console\n"
        "$ uv run guardana run inspect \\\n"
        "    --help | head\n"
        "```\n"
    )

    assert _failures(snippet) == []
    assert [i.args for i in _invocations(snippet)] == [
        ("probe", "--url", "http://x", "--max-requests=5"),
        ("run", "inspect", "--help"),
    ]


def test_an_unknown_subcommand_is_reported() -> None:
    snippet = "```sh\nguardana run frobnicate --help\n```\n"

    assert _failures(snippet) == [(2, "guardana run frobnicate: no such command")]


def test_a_collector_flag_the_command_does_not_have_is_reported() -> None:
    snippet = (
        "```bash\ndocker run --rm ghcr.io/guardana/guardana-collector:0.41 serve --hots 0\n```\n"
    )

    assert _failures(snippet) == [(2, "guardana-collector serve has no option --hots")]


def test_a_collector_run_through_compose_is_read_as_the_collector() -> None:
    snippet = (
        "```bash\ndocker compose -f deploy/docker-compose.yml run --rm collector \\\n"
        "  key create --project acme/web --scopes ingest\n```\n"
    )

    assert _failures(snippet) == [(2, "guardana-collector key create has no option --scopes")]


def test_launchers_prompts_and_placeholders_are_not_read_as_flags() -> None:
    snippet = (
        "```bash\n"
        "$ GUARDANA_X=1 uvx --from guardana-cli guardana scan <path> --profile FILE  # --nope\n"
        'docker run --rm -v "$PWD:/work:ro" ghcr.io/guardana/guardana:<tag> scan /work ...\n'
        "guardana <command> --whatever\n"
        "```\n"
    )

    assert _failures(snippet) == []
    assert [i.args[0] for i in _invocations(snippet)] == ["scan", "scan", _PLACEHOLDER]


def test_a_note_is_checked_like_a_documentation_page(tmp_path: Path) -> None:
    for name in ("README.md", "FEATURES.md", "docs/index.md"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("# Page\n", encoding="utf-8")
    (tmp_path / "notes").mkdir()
    (tmp_path / "notes" / "a-note.md").write_text(
        "---\ntitle: A\n---\n```bash\nguardana frobnicate\nguardana probe --max-cost 5\n```\n"
        "Then pass `--no-such-flag`.\n",
        encoding="utf-8",
    )

    failures = [
        f"{page.relative_to(tmp_path).as_posix()}:{line}: {problem}"
        for page in _documents(tmp_path)
        for line, problem in _failures(
            page.read_text(encoding="utf-8"), page.relative_to(tmp_path).as_posix()
        )
    ]

    assert failures == [
        "notes/a-note.md:5: guardana frobnicate: no such command",
        "notes/a-note.md:6: guardana probe has no option --max-cost",
        "notes/a-note.md:8: no command takes --no-such-flag",
    ]


def test_without_a_notes_directory_only_the_documentation_is_read(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()

    assert _documents(tmp_path) == [tmp_path / "README.md", tmp_path / "FEATURES.md"]


def test_the_pages_carry_enough_command_lines_for_the_check_to_mean_something() -> None:
    total = sum(len(_invocations(page.read_text(encoding="utf-8"))) for page in _DOCUMENTS)

    assert total >= 100
