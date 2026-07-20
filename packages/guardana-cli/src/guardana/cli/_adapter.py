import os
import re
from pathlib import Path

import typer
import yaml
from guardana.core.target import AdapterConfig

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_ALLOWED_KEYS = frozenset({"url", "method", "headers", "body", "response_path"})


def _expand_env(value: str) -> str:
    """Replace `${VAR}` with the environment value, failing loudly if it is unset.

    A header that silently expands to an empty auth token would send unauthenticated
    probes that look like refusals — a false all-clear. So a missing var is an error.
    """

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        env = os.environ.get(name)
        if env is None:
            raise typer.BadParameter(f"adapter references ${{{name}}} but it is not set")
        return env

    return _ENV_REF.sub(replace, value)


def load_adapter_config(path: Path, fallback_url: str) -> AdapterConfig:
    """Parse an endpoint adapter file into an `AdapterConfig`, rejecting bad input loudly."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise typer.BadParameter(f"cannot read adapter {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise typer.BadParameter(f"invalid adapter {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise typer.BadParameter(f"invalid adapter {path}: the top level must be a mapping")
    unknown = sorted(set(raw) - _ALLOWED_KEYS)
    if unknown:
        raise typer.BadParameter(f"invalid adapter {path}: unknown key(s): {', '.join(unknown)}")
    if "body" not in raw:
        raise typer.BadParameter(f"invalid adapter {path}: 'body' is required")
    response_path = raw.get("response_path")
    if not isinstance(response_path, str) or not response_path:
        raise typer.BadParameter(f"invalid adapter {path}: 'response_path' must be a non-empty str")
    raw_headers = raw.get("headers", {})
    if not isinstance(raw_headers, dict):
        raise typer.BadParameter(f"invalid adapter {path}: 'headers' must be a mapping")
    headers = {str(key): _expand_env(str(value)) for key, value in raw_headers.items()}
    return AdapterConfig(
        url=str(raw.get("url") or fallback_url),
        body=raw["body"],
        response_path=response_path,
        headers=headers,
    )
