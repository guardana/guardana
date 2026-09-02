"""A third-party `Target`: the extension point with an entry-point group and no example.

`guardana.targets` has been in the contract table since 0.1 and nothing in this
repository ever registered one — which meant `Registry.targets()` came back empty in
every install, and the path a third party would use was never exercised end to end.
It surfaced as a false red: `pack validate` built its "what is registered" set from
rules and evaluators only, so any pack shipping a target was accused of not
registering it. Nothing caught that, because no pack shipped one.

This is the smallest honest target: Acme keeps its approved prompts in a directory,
and a rule wants to read them the way it reads any other artifact. It performs no
network I/O and invents no capability — a target that cannot answer a question
declares it cannot, and the runner skips the rules that need it.
"""

from collections.abc import Iterator
from pathlib import Path

from guardana.core.source import PythonSource, UnreadSource, read_source
from guardana.core.target import Capability, Target, TargetKind


class AcmePromptLibraryTarget(Target):
    """A directory of Acme's approved prompt templates, read as artifacts.

    Declares `READ_FILES` and implements `FileReader` — both halves, because a
    declaration the runner selects rules by must have a surface behind it, and
    `guardana.testing.assert_target_conforms` refuses one that does not.
    """

    kind = TargetKind.ARTIFACT

    def __init__(self, root: Path | str) -> None:
        """Point the target at a directory of prompt templates."""
        self._root = Path(root)
        self._sources: dict[Path, PythonSource | None] = {}
        self._unread: list[UnreadSource] = []

    def capabilities(self) -> set[Capability]:
        """Files, and only files."""
        return {Capability.READ_FILES}

    @property
    def ref(self) -> str:
        """How this target appears in a finding and in a run manifest."""
        return f"acme-prompts:{self._root}"

    def iter_files(self, suffixes: tuple[str, ...] | None = None) -> Iterator[Path]:
        """Walk the library in a stable order, optionally by suffix; nothing when absent."""
        if not self._root.is_dir():
            return
        for path in sorted(p for p in self._root.rglob("*") if p.is_file()):
            if suffixes is None or path.suffix in suffixes:
                yield path

    def python_source(self, path: Path) -> PythonSource | None:
        """Read and index a Python file once; every rule asks through here."""
        if path.suffix != ".py":
            return None
        if path not in self._sources:
            result = read_source(path)
            if isinstance(result, UnreadSource):
                self._unread.append(result)
                self._sources[path] = None
            else:
                self._sources[path] = result
        return self._sources[path]

    def unread_sources(self) -> tuple[UnreadSource, ...]:
        """Every file this target could not read — a check that did not run."""
        return tuple(self._unread)

    def templates(self) -> list[Path]:
        """Every template in the library, sorted, or nothing when the directory is absent."""
        return list(self.iter_files((".txt",)))
