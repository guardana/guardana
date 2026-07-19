"""Loads the human-readable rule catalog the dashboard shows instead of bare ids.

The catalog is a plain JSON file (`catalog/en.json`) — English for now, structured
so a translation (`catalog/pl.json`, …) can slot in later. It is bundled with the
server so the collector stays self-sufficient; a rule id it doesn't know about
(a custom, third-party rule) simply falls back to the id and the finding's own
title on the page.
"""

import json
from functools import cache
from importlib.resources import files

_DEFAULT_LANGUAGE = "en"


@cache
def rule_catalog(language: str = _DEFAULT_LANGUAGE) -> dict[str, dict[str, str]]:
    """Return `{rule_id: {"name", "description"}}` for the given language (English by default)."""
    resource = files("guardana.server.catalog").joinpath(f"{language}.json")
    if not resource.is_file():
        return {}
    data = json.loads(resource.read_text(encoding="utf-8"))
    rules = data.get("rules", {})
    return rules if isinstance(rules, dict) else {}
