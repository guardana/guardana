from guardana.report.base import Renderer
from guardana.report.human import HumanRenderer
from guardana.report.json_report import JsonRenderer
from guardana.report.junit import JUnitRenderer
from guardana.report.sarif import SarifRenderer

_RENDERERS: dict[str, Renderer] = {
    r.name: r for r in (JsonRenderer(), HumanRenderer(), SarifRenderer(), JUnitRenderer())
}


def get_renderer(name: str) -> Renderer:
    """Look up a renderer by the name the CLI's `--format` takes."""
    try:
        return _RENDERERS[name]
    except KeyError as exc:
        raise ValueError(f"unknown renderer: {name!r}") from exc


__all__ = [
    "HumanRenderer",
    "JUnitRenderer",
    "JsonRenderer",
    "Renderer",
    "SarifRenderer",
    "get_renderer",
]
