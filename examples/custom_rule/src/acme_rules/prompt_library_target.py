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

from pathlib import Path

from guardana.core.target import Capability, Target, TargetKind


class AcmePromptLibraryTarget(Target):
    """A directory of Acme's approved prompt templates, read as artifacts.

    Declares `READ_FILES` and nothing else. Declaring more would make the runner
    select rules this target cannot serve, and a rule handed a target it cannot use
    is a check that errors rather than one that ran — which is worse than the
    coverage it was reaching for.
    """

    kind = TargetKind.ARTIFACT

    def __init__(self, root: Path | str) -> None:
        """Point the target at a directory of prompt templates."""
        self._root = Path(root)

    def capabilities(self) -> set[Capability]:
        """Files, and only files."""
        return {Capability.READ_FILES}

    @property
    def ref(self) -> str:
        """How this target appears in a finding and in a run manifest."""
        return f"acme-prompts:{self._root}"

    def templates(self) -> list[Path]:
        """Every template in the library, sorted, or nothing when the directory is absent.

        Absent is not an error here: a repository with no prompt library has none to
        check. What the rules must not do is read that as "the templates are fine",
        which is why a rule over this target declines rather than passing when it
        finds nothing — the same distinction the engine draws everywhere else.
        """
        if not self._root.is_dir():
            return []
        return sorted(p for p in self._root.rglob("*.txt") if p.is_file())
