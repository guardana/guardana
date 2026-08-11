"""The rule explorer: one page per rule, one per filter, no script anywhere.

This is the page a competitor cannot copy without also having the rules, and it is
the reason the site is worth building at all. A reader arrives with one of four
questions — does it cover this framework entry, what runs with no model and no
network, what will this cost and what does it send, and what does this rule
actually check — and none of them is answerable today without reading a fifty-one
row table.

**Filtering is navigation.** `site/_headers` ships `script-src 'none'`, and that is
a claim a visitor can check in devtools rather than a default nobody chose. With
fifty-one rules the filter space is small and finite, so every view is rendered
ahead of time and a filter is a link. What this cannot do is free-text search over
prose; that is the one thing worth relaxing the policy for, and it is not this.
"""

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any

from sitegen.errors import SiteBuildError

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
_CHEAP = 4
"""The upper end of the cheap band, in model requests a rule declares."""


@dataclass(frozen=True, slots=True)
class Facet:
    """One question a reader arrives with, and the field that answers it."""

    key: str
    heading: str
    blurb: str


FACETS = (
    Facet("family", "Family", "What area of the system a rule is about."),
    Facet("surface", "Surface", "Build-time checks need no model and no network."),
    Facet("severity", "Severity", "What a finding from this rule means for a gate."),
    Facet("impact", "Impact", "What running the rule does to the target."),
    Facet("cost", "Cost", "Model requests the rule declares up front, as an upper bound."),
    Facet("framework", "Framework", "Which public catalogue a rule answers to."),
    Facet("reference", "Framework entry", "The exact control, edition included."),
)

_COST_LABELS = {
    "undeclared": "no model requests declared",
    "1-4": "1 to 4 requests",
    "5-plus": "5 or more requests",
}


def load_rules(path: Path) -> list[dict[str, Any]]:
    """Read `docs/generated/rules.json`, refusing a shape this build cannot render."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SiteBuildError(f"cannot read {path}: {exc}") from exc
    rules = document.get("rules")
    if not isinstance(rules, list) or not rules:
        raise SiteBuildError(
            f"{path} lists no rules — run `uv run python scripts/generate_docs.py` "
            f"rather than publishing an explorer that says this project ships none"
        )
    return sorted(rules, key=lambda rule: str(rule["id"]))


def cost_bucket(rule: dict[str, Any]) -> str:
    """Which cost band a rule falls in, from the bound it declares.

    `None` is *undeclared*, never zero. A rule that cannot say what it will spend
    and a rule that spends nothing are different facts, and only one of them lets
    somebody set a budget — which is why `estimated_requests` is nullable in the
    first place.
    """
    declared = rule.get("estimated_requests")
    if declared is None:
        return "undeclared"
    return "1-4" if int(declared) <= _CHEAP else "5-plus"


def facet_values(rule: dict[str, Any], key: str) -> list[str]:
    """Every value of one facet a rule carries — several, for the framework facets."""
    if key == "cost":
        return [cost_bucket(rule)]
    if key == "framework":
        return sorted({str(ref["framework"]) for ref in rule["taxonomy"]})
    if key == "reference":
        return [str(ref["reference"]) for ref in rule["taxonomy"]]
    return [str(rule[key])]


def index_facets(rules: list[dict[str, Any]]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """Group the rules by every facet, once, so no page walks the list a second time."""
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for facet in FACETS:
        buckets: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for rule in rules:
            for value in facet_values(rule, facet.key):
                buckets[value].append(rule)
        grouped[facet.key] = dict(sorted(buckets.items()))
    return grouped


def filter_href(facet: str, value: str) -> str:
    """Where the pre-rendered view for one filter lives, relative to `site/docs/`."""
    return f"rules/by/{facet}-{_UNSAFE.sub('-', value)}.html"


def rule_href(rule_id: str) -> str:
    """Where one rule's page lives, relative to `site/docs/`."""
    return f"rules/{_UNSAFE.sub('-', rule_id)}.html"


def label_for(facet: str, value: str) -> str:
    """Spell out a facet value where the stored form is not what a reader wants to read."""
    return _COST_LABELS.get(value, value) if facet == "cost" else value


def table(rules: list[dict[str, Any]], up: str) -> str:
    """Render the rule table, identical on the index and on every filtered view."""
    rows = []
    for rule in rules:
        maps_to = " ".join(
            f'<a class="pill" href="{up}{filter_href("reference", str(ref["reference"]))}">'
            f"{escape(str(ref['reference']))}</a>"
            for ref in rule["taxonomy"]
        )
        declared = rule.get("estimated_requests")
        rows.append(
            "<tr>"
            f'<td><a class="rid" href="{up}{rule_href(str(rule["id"]))}">'
            f"{escape(str(rule['id']))}</a><br>{escape(str(rule['title']))}</td>"
            f'<td><span class="sev {escape(str(rule["severity"]))}">'
            f"{escape(str(rule['severity']))}</span></td>"
            f"<td>{escape(str(rule['surface']))}</td>"
            f"<td>{'—' if declared is None else escape(str(declared))}</td>"
            f"<td>{maps_to}</td>"
            "</tr>"
        )
    return (
        '<div class="table-wrap"><table><thead><tr>'
        "<th>Rule</th><th>Severity</th><th>Surface</th><th>Requests</th><th>Maps to</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


_WIDE = 12
"""Values above which a facet takes the full row and sets in columns.

The framework-entry facet has fifty-odd values; in a card sized for eight it is a
column of links beside an acre of nothing, which reads as a layout bug rather than
as the most useful filter on the page.
"""


def facet_panels(grouped: dict[str, dict[str, list[dict[str, Any]]]], up: str) -> str:
    """Render the filter grid: every value of every facet, with how many rules it holds."""
    panels = []
    for facet in FACETS:
        values = grouped[facet.key]
        items = "".join(
            f'<li><a href="{up}{filter_href(facet.key, value)}">'
            f'{escape(label_for(facet.key, value))}</a><span class="n">{len(rules)}</span></li>'
            for value, rules in values.items()
        )
        wide = " wide" if len(values) > _WIDE else ""
        panels.append(
            f'<div class="facet{wide}"><h3>{escape(facet.heading)}</h3><ul>{items}</ul></div>'
        )
    return f'<div class="facets">{"".join(panels)}</div>'


def summary_line(rules: list[dict[str, Any]]) -> str:
    """State the totals, from the registry rather than from memory.

    The landing page advertised twenty-five rules across three releases that took
    the real number to thirty-two. Every count on this site is counted here.
    """
    surfaces = Counter(str(rule["surface"]) for rule in rules)
    entries = {str(ref["reference"]) for rule in rules for ref in rule["taxonomy"]}
    frameworks = {str(ref["framework"]) for rule in rules for ref in rule["taxonomy"]}
    return (
        f"{len(rules)} built-in rules — {surfaces['build']} that read artifacts with no "
        f"model and no network, and {surfaces['runtime']} that question a live system or "
        f"a run it already performed. Between them they map to {len(entries)} entries "
        f"across {len(frameworks)} public catalogues."
    )


def rule_properties(rule: dict[str, Any], up: str) -> str:
    """Lay out the declaration a policy selects on, as the facts they are."""
    declared = rule.get("estimated_requests")
    requires = ", ".join(str(capability) for capability in rule["requires"]) or "nothing"
    fields = [
        (
            "Severity",
            f'<a class="sev {escape(str(rule["severity"]))}" '
            f'href="{up}{filter_href("severity", str(rule["severity"]))}">'
            f"{escape(str(rule['severity']))}</a>",
        ),
        ("Surface", _linked(rule, "surface", up)),
        ("Family", _linked(rule, "family", up)),
        ("Impact", _linked(rule, "impact", up)),
        ("Target", escape(str(rule["target_kind"]))),
        ("Requests", "not declared" if declared is None else f"at most {declared}"),
        ("Evaluator", escape(str(rule["evaluator"])) if rule["evaluator"] else "graded in code"),
        ("Maturity", escape(str(rule["maturity"]))),
        ("Destructive", "yes" if rule["destructive"] else "no"),
        ("Needs", escape(requires)),
    ]
    return (
        '<ul class="props">'
        + "".join(f"<li><b>{name}</b>{value}</li>" for name, value in fields)
        + "</ul>"
    )


def _linked(rule: dict[str, Any], facet: str, up: str) -> str:
    value = str(rule[facet])
    return f'<a href="{up}{filter_href(facet, value)}">{escape(value)}</a>'


def rule_taxonomy(rule: dict[str, Any], up: str) -> str:
    """Render what the rule answers to, with the edition spelled out.

    `LLM07` is System Prompt Leakage in the 2025 edition and Misinformation in the
    2026 one, so a reference without its edition would send a reader to the wrong
    control while looking correct.
    """
    rows = "".join(
        f'<tr><td><a class="rid" href="{up}'
        f'{filter_href("reference", str(ref["reference"]))}">'
        f"{escape(str(ref['reference']))}</a></td>"
        f"<td>{escape(str(ref['title']))}</td>"
        f'<td><a href="{up}{filter_href("framework", str(ref["framework"]))}">'
        f"{escape(str(ref['framework']))}</a></td></tr>"
        for ref in rule["taxonomy"]
    )
    if not rows:
        raise SiteBuildError(
            f"{rule['id']} maps to no framework, which no built-in rule is allowed to do"
        )
    return (
        '<div class="table-wrap"><table><thead><tr>'
        "<th>Reference</th><th>Control</th><th>Catalogue</th>"
        "</tr></thead><tbody>" + rows + "</tbody></table></div>"
    )
