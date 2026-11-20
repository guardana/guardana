"""Rewrite the landing page's factual claims from the registry, and its diagrams from the docs.

`bump_version.py` keeps the page's *version* correct on every release. Everything
beside it was hand-maintained, which is how `site/index.html` advertised 25 rules
through three releases that took the real number to 32 — automation covering one
number and nothing else makes the stale prose next to it look maintained.

What it writes into `site/index.html`, and from where:

- the rule counts (in total, per surface, and the invariant rules), from the registry;
- the framework coverage between `<!-- coverage -->` and `<!-- /coverage -->`, from
  the registry and the installed taxonomy catalogues, entries no rule maps to included;
- every maturity label (`<span class="st" data-maturity="…">`), from the table in
  `docs/product-status.md`;
- every diagram region, from the `mermaid` block of the docs page it names.

Two ways to run it, and both matter:

    python scripts/sync_site.py            # rewrite the page from the registry
    python scripts/sync_site.py --check    # exit 1 if it is out of date, change nothing

`release.py` runs the first so a release never ships a stale page. `--check` is
for anyone who wants the answer without a diff; the same claims are pinned by
`test_landing_page.py`, so a rule added between releases turns the suite red
immediately rather than waiting for someone to cut one. It needs the workspace
installed (`uv sync`) and contacts nothing.
"""

import argparse
import html
import re
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_PAGE = _REPO / "site" / "index.html"
_STATUS_PAGE = _REPO / "docs" / "product-status.md"

sys.path.insert(0, str(_REPO / "packages" / "guardana-core" / "src"))
sys.path.insert(0, str(_REPO / "packages" / "guardana-rules" / "src"))

from guardana.core.safety import Detection  # noqa: E402
from guardana.core.surface import Surface  # noqa: E402
from guardana.core.taxonomy import TaxonomyCatalog, catalogs  # noqa: E402
from guardana.rules import provide_rules  # noqa: E402

from sitegen.diagram import figure  # noqa: E402
from sitegen.errors import SiteBuildError  # noqa: E402
from sitegen.explorer import filter_href  # noqa: E402
from sitegen.page import served_path  # noqa: E402
from sitegen.render import parser  # noqa: E402

_RUNTIME_LABEL = "served systems; recorded runs support checks only where exchanges were captured"

# Each claim is (pattern with the number captured, template, what it counts).
# Kept next to each other so adding a claim to the page means adding one line
# here — the alternative is a fourth number nobody rewrites.
_CLAIMS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r">(\d+) rules · two surfaces<"), ">{n} rules · two surfaces<", "total"),
    (re.compile(r">(\d+) rules · your laptop"), ">{n} rules · your laptop", "build"),
    (
        re.compile(r">(\d+) rules · " + re.escape(_RUNTIME_LABEL) + "<"),
        ">{n} rules · " + _RUNTIME_LABEL + "<",
        "runtime",
    ),
    (re.compile(r"(\d+) rule\(s\) run, 0 skipped"), "{n} rule(s) run, 0 skipped", "build"),
    (
        re.compile(r'<b data-count="invariant">(\d+)</b>'),
        '<b data-count="invariant">{n}</b>',
        "invariant",
    ),
)

_EVERY_OCCURRENCE: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(\d+)( security)? check(s?)\b"), "total"),
)
"""Claims the page states in prose, wherever it states them.

The eyebrows above were rewritten from the registry while the meta description, the
`og:description`, the hero and the threat-model section all still said 47 — four
sentences one element away from a number this script had just corrected. That is the
same failure the docstring opens with, one layer in: automation covering the labels
makes the prose beside them look maintained.
"""


_DIAGRAM = re.compile(
    r"(?P<open><!-- diagram: (?P<path>\S+) (?P<n>[1-9][0-9]*) -->)"
    r"(?P<body>.*?)(?P<close><!-- /diagram -->)",
    re.DOTALL,
)
"""A diagram drawn from the n-th `mermaid` block of a docs page, which stays its only source."""


def _diagram(path: str, number: int, index: int) -> str:
    source = _REPO / path
    if not source.is_file():
        sys.exit(f"error: site/index.html draws a diagram from {path}, which does not exist")
    blocks = [
        token.content
        for token in parser().parse(source.read_text(encoding="utf-8"))
        if token.type == "fence" and token.info.strip() == "mermaid"
    ]
    if number > len(blocks):
        sys.exit(f"error: {path} has {len(blocks)} mermaid block(s); the page asks for #{number}")
    try:
        return figure(blocks[number - 1], 100 + index)
    except SiteBuildError as exc:
        sys.exit(f"error: {path} mermaid block #{number}: {exc}")


def _rewrite_diagrams(text: str) -> tuple[str, list[str]]:
    matches = list(_DIAGRAM.finditer(text))
    opened, closed = text.count("<!-- diagram:"), text.count("<!-- /diagram -->")
    if not opened == closed == len(matches) or any("<!-- diagram:" in m["body"] for m in matches):
        sys.exit(
            f"error: site/index.html has {opened} diagram marker(s), {closed} closing "
            f"marker(s) and {len(matches)} well-formed pair(s); write each as "
            f"`<!-- diagram: docs/<page>.md <n> -->…<!-- /diagram -->`"
        )
    changed: list[str] = []
    index = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal index
        drawn = f"\n{_diagram(match['path'], int(match['n']), index)}\n"
        index += 1
        if match["body"] != drawn:
            changed.append(f"diagram from {match['path']} #{match['n']}")
        return f"{match['open']}{drawn}{match['close']}"

    return _DIAGRAM.sub(replace, text), changed


_COVERAGE = re.compile(
    r"(?P<open><!-- coverage -->)(?P<body>.*?)(?P<close><!-- /coverage -->)", re.DOTALL
)

_GRIDS = ("OWASP-LLM-2025", "OWASP-LLM-2026", "OWASP-ASI-2026", "OWASP-MCP-2025")
"""Ranked lists the page draws whole, so an entry no built-in rule maps to shows as one."""

_COUNTED = {
    "MITRE-ATLAS": "{n} techniques",
    "NIST-AI-100-2": "{n} attack classes",
    "OWASP-ML-2023": "{n} entries",
}
"""Catalogues installed in part or without ranks: the page states what rules map to, no total."""

_MAPPED = "{mapped} of {total} entries mapped"
_ONE_RULE = "One rule"
_RULES = "{n} rules"
_NO_RULE = "No built-in rule"
_OTHER = "Other framework mappings"


def _explorer(facet: str, value: str) -> str:
    return served_path("docs/" + filter_href(facet, value))


def _grid(catalog: TaxonomyCatalog, rules_per_entry: Counter[tuple[str, str]]) -> str:
    entries = sorted(catalog.refs, key=lambda ref: ref.rank or 0)
    if [ref.rank for ref in entries] != list(range(1, len(entries) + 1)):
        sys.exit(
            f"error: {catalog.framework} is not a ranked list from 1 to {len(entries)}; the "
            f"page draws it whole, so move it to _COUNTED in this script"
        )
    cells = []
    for ref in entries:
        count = rules_per_entry[(catalog.framework, ref.id)]
        name = f"<code>{html.escape(ref.reference)}</code><span>{html.escape(ref.title)}</span>"
        if count:
            rules = _ONE_RULE if count == 1 else _RULES.format(n=count)
            href = _explorer("reference", ref.reference)
            cells.append(f'<li><a href="{href}">{name}<small>{rules}</small></a></li>')
        else:
            cells.append(f'<li><span class="x">{name}<small>{_NO_RULE}</small></span></li>')
    mapped = sum(1 for ref in entries if rules_per_entry[(catalog.framework, ref.id)])
    summary = _MAPPED.format(mapped=f"<b>{mapped}</b>", total=f"<b>{len(entries)}</b>")
    title = html.escape(catalog.title)
    edition = html.escape(catalog.edition or catalog.version or "")
    return (
        f'<article class="fw"><h3><a href="{_explorer("framework", catalog.framework)}">'
        f'{title}</a> <span class="ed">{edition}</span></h3>\n<p class="mapped">{summary}</p>\n'
        f'<ol class="cells">\n' + "\n".join(cells) + "\n</ol></article>"
    )


def _coverage() -> str:
    """Draw every ranked framework entry and the count of the others rules map to."""
    installed = {catalog.framework: catalog for catalog in catalogs()}
    rules_per_entry: Counter[tuple[str, str]] = Counter()
    for rule in provide_rules():
        for entry in {(ref.framework, ref.id) for ref in rule.meta.taxonomy}:
            rules_per_entry[entry] += 1
    drawn = set(_GRIDS) | set(_COUNTED)
    unplaced = sorted({framework for framework, _ in rules_per_entry} - drawn)
    absent = sorted(drawn - set(installed))
    if unplaced or absent:
        sys.exit(
            f"error: built-in rules map to {unplaced} the page does not show, and the page "
            f"shows {absent} nothing installs; update _GRIDS and _COUNTED in this script"
        )
    others = []
    for framework, template in _COUNTED.items():
        catalog = installed[framework]
        count = sum(1 for mapped, _ in rules_per_entry if mapped == framework)
        edition = catalog.edition or catalog.version
        pill = f' <span class="ed">{html.escape(edition)}</span>' if edition else ""
        others.append(
            f'<li><a href="{_explorer("framework", framework)}">{html.escape(catalog.title)}'
            f"</a>{pill} <span>{template.format(n=count)}</span></li>"
        )
    grids = "\n".join(_grid(installed[framework], rules_per_entry) for framework in _GRIDS)
    return (
        f'<div class="fws">\n{grids}\n</div>\n'
        f'<div class="also"><b>{_OTHER}</b><ul>\n' + "\n".join(others) + "\n</ul></div>"
    )


def _rewrite_coverage(text: str) -> tuple[str, list[str]]:
    matches = list(_COVERAGE.finditer(text))
    if len(matches) != 1 or text.count("<!-- coverage -->") != 1:
        sys.exit(
            f"error: site/index.html holds {len(matches)} well-formed coverage region(s); "
            f"write exactly one as `<!-- coverage -->…<!-- /coverage -->`"
        )
    match = matches[0]
    drawn = f"\n{_coverage()}\n"
    changed = [] if match["body"] == drawn else ["framework coverage"]
    return text[: match.start("body")] + drawn + text[match.end("body") :], changed


_MATURITY = re.compile(
    r'<span class="st(?: [a-z]+)?" data-maturity="(?P<component>[^"]+)">(?P<label>[a-z]+)</span>'
)
"""A component's maturity label; its word is copied from `docs/product-status.md`."""

_STATUS_ROW = re.compile(
    r"^\| (?P<component>[^|]+?) \| \*\*(?P<maturity>[a-z]+)\*\* \|", re.MULTILINE
)


def _maturities() -> dict[str, str]:
    page = _STATUS_PAGE.read_text(encoding="utf-8")
    _, heading, section = page.partition("\n## Maturity by component\n")
    rows = _STATUS_ROW.finditer(section.split("\n## ", 1)[0]) if heading else ()
    table = {row["component"].replace("`", ""): row["maturity"] for row in rows}
    if not table:
        sys.exit(
            "error: docs/product-status.md has no `## Maturity by component` table with rows "
            "`| Component | **maturity** |`; the page copies its labels from it"
        )
    return table


def _rewrite_maturity(text: str) -> tuple[str, list[str]]:
    table = _maturities()
    labels = list(_MATURITY.finditer(text))
    named = {html.unescape(label["component"]) for label in labels}
    if not labels or named - set(table):
        sys.exit(
            f"error: site/index.html labels {sorted(named - set(table)) or 'no component'}; "
            f"each label names a component of the table in docs/product-status.md"
        )
    changed: list[str] = []

    def replace(match: re.Match[str]) -> str:
        component = html.unescape(match["component"])
        want = table[component]
        drawn = f'<span class="st {want}" data-maturity="{match["component"]}">{want}</span>'
        if match[0] != drawn:
            moved = f": {match['label']} -> {want}" if match["label"] != want else ""
            changed.append(f"maturity label of {component}{moved}")
        return drawn

    return _MATURITY.sub(replace, text), changed


def _counts() -> dict[str, int]:
    rules = list(provide_rules())
    return {
        "total": len(rules),
        "build": sum(1 for r in rules if r.meta.surface is Surface.BUILD),
        "runtime": sum(1 for r in rules if r.meta.surface is Surface.RUNTIME),
        "invariant": sum(1 for r in rules if r.meta.detection is Detection.INVARIANT),
    }


def _replacement(want: int) -> Callable[[re.Match[str]], str]:
    """Rewrite one "N checks" occurrence, keeping the wording it was written with."""

    def replace(match: re.Match[str]) -> str:
        return f"{want}{match.group(2) or ''} check{match.group(3)}"

    return replace


def _rewrite(text: str, counts: dict[str, int]) -> tuple[str, list[str]]:
    """Return the page with every claim corrected, and a note per claim that moved."""
    changed: list[str] = []
    for pattern, template, kind in _CLAIMS:
        match = pattern.search(text)
        if match is None:
            # Loud, never a silent skip: a claim the page stopped stating in the
            # form this script recognises is a claim nothing is checking any more.
            sys.exit(
                f"error: site/index.html no longer states its {kind} count as "
                f"{pattern.pattern!r} — the page was reworded, so update this script "
                f"with it rather than letting the claim go unchecked"
            )
        want = counts[kind]
        if int(match.group(1)) != want:
            changed.append(f"{kind}: {match.group(1)} -> {want}")
        text = pattern.sub(template.format(n=want), text, count=1)
    for pattern, kind in _EVERY_OCCURRENCE:
        want = counts[kind]
        stale = {m.group(1) for m in pattern.finditer(text) if int(m.group(1)) != want}
        if stale:
            changed.append(f"{kind} in prose: {', '.join(sorted(stale))} -> {want}")
        text = pattern.sub(_replacement(want), text)
    return text, changed


def main() -> int:
    """Rewrite the page from the registry, or report that it is stale."""
    parser = argparse.ArgumentParser(description="Sync the landing page with the rule registry.")
    parser.add_argument(
        "--check", action="store_true", help="exit 1 if the page is stale; write nothing"
    )
    args = parser.parse_args()

    original = _PAGE.read_text(encoding="utf-8")
    updated, changed = _rewrite(original, _counts())
    for step in (_rewrite_maturity, _rewrite_coverage, _rewrite_diagrams):
        updated, moved = step(updated)
        changed += moved

    if not changed:
        print("site/index.html is current")
        return 0
    if args.check:
        print("site/index.html is out of date:")
        for note in changed:
            print(f"  {note}")
        print("run `python scripts/sync_site.py` to fix it")
        return 1
    _PAGE.write_text(updated, encoding="utf-8")
    print("updated site/index.html:")
    for note in changed:
        print(f"  {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
