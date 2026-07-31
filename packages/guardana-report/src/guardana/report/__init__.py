from collections.abc import Callable

from guardana.core.report.run import RunMeta
from guardana.report.base import DiffRenderer, Renderer
from guardana.report.diff_human import DiffHumanRenderer
from guardana.report.diff_json import DiffJsonRenderer
from guardana.report.human import HumanRenderer
from guardana.report.json_report import JsonRenderer
from guardana.report.junit import JUnitRenderer
from guardana.report.sarif import SarifRenderer

_RENDERERS: dict[str, Callable[[RunMeta | None], Renderer]] = {
    JsonRenderer.name: JsonRenderer,
    HumanRenderer.name: lambda _run: HumanRenderer(),
    SarifRenderer.name: lambda _run: SarifRenderer(),
    JUnitRenderer.name: lambda _run: JUnitRenderer(),
}


_DIFF_RENDERERS: dict[str, DiffRenderer] = {
    r.name: r for r in (DiffHumanRenderer(), DiffJsonRenderer())
}


def get_diff_renderer(name: str) -> DiffRenderer:
    """Look up a comparison renderer by the name `guardana diff --format` takes."""
    try:
        return _DIFF_RENDERERS[name]
    except KeyError as exc:
        raise ValueError(f"unknown diff renderer: {name!r}") from exc


def get_renderer(name: str, *, run: RunMeta | None = None) -> Renderer:
    """Look up a renderer by the name the CLI's `--format` takes.

    Renderers are built per call rather than shared, because one of them takes the
    run's metadata. Only the JSON document is read back, so only it needs to carry
    what the run was; the rest accept the argument and ignore it, which is a
    contract being honoured rather than a smell.
    """
    try:
        return _RENDERERS[name](run)
    except KeyError as exc:
        raise ValueError(f"unknown renderer: {name!r}") from exc


__all__ = [
    "DiffHumanRenderer",
    "DiffJsonRenderer",
    "DiffRenderer",
    "HumanRenderer",
    "JUnitRenderer",
    "JsonRenderer",
    "Renderer",
    "SarifRenderer",
    "get_diff_renderer",
    "get_renderer",
]
