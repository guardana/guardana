"""Generate `site/llms.txt` from the documentation map, so it cannot list a page nobody wrote.

[llms.txt](https://llmstxt.org) is a file at the site root that tells a model which
documents matter and what each one is for, instead of leaving it to infer that from
rendered HTML. For this project the interesting question is not the format — it is
where the list comes from.

**It comes from `docs/index.md`.** That file is already the curated map, already
describes every page in a sentence, and every link in it is already checked against
the filesystem by `test_docs_consistency.py`. Deriving llms.txt from it means a page
added to the docs appears here for free, a page removed disappears, and a
hand-written second list — which is what every stale claim in this repository has
been — never exists.

    python scripts/generate_llms_txt.py            # write it
    python scripts/generate_llms_txt.py --check    # exit 1 if stale, write nothing

`release.py` runs the first and `test_docs_consistency.py` runs the second, which is
the same pair of guards `sync_site.py` and `generate_docs.py` already have.
"""

import argparse
import re
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_INDEX = _REPO / "docs" / "index.md"
_OUT = _REPO / "site" / "llms.txt"

_RAW = "https://raw.githubusercontent.com/guardana/guardana/refs/heads/main"

sys.path.insert(0, str(_REPO / "packages" / "guardana-core" / "src"))
sys.path.insert(0, str(_REPO / "packages" / "guardana-rules" / "src"))

from guardana.core import __version__  # noqa: E402
from guardana.core.surface import Surface  # noqa: E402
from guardana.rules import provide_rules  # noqa: E402

_HEADING = re.compile(r"^## (.+)$")
_ENTRY = re.compile(r"^- \[`?([^\]`]+)`?\]\(([^)]+)\)\s*(?:—|-)?\s*(.*)$")

_OPTIONAL_SECTIONS = frozenset({"Design documents", "Maintainers", "Governance"})
"""Sections a model may skip when its context is short, per the llms.txt spec.

Design documents argue about rejected alternatives, and governance is about people.
Both are worth having on the site and neither is what somebody asking "how do I gate
a build on this" needs first.
"""


def _counts() -> dict[str, int]:
    rules = list(provide_rules())
    return {
        "total": len(rules),
        "build": sum(1 for r in rules if r.meta.surface is Surface.BUILD),
        "runtime": sum(1 for r in rules if r.meta.surface is Surface.RUNTIME),
    }


def _url(target: str) -> str:
    """Turn a link relative to `docs/` into an absolute raw-markdown URL.

    Raw rather than the rendered GitHub page on purpose: what arrives is the markdown
    somebody wrote, not a page of navigation chrome with the document inside it.
    """
    resolved = (_INDEX.parent / target).resolve()
    return f"{_RAW}/{resolved.relative_to(_REPO).as_posix()}"


def _sections() -> list[tuple[str, list[tuple[str, str, str]]]]:
    """Read `docs/index.md` into (heading, [(name, url, description)]).

    A bullet wrapped over two lines is joined first: `usage-probe.md` is written that
    way, and reading line by line would have silently dropped half its description.
    """
    lines = _INDEX.read_text(encoding="utf-8").splitlines()
    joined: list[str] = []
    for line in lines:
        if joined and line.startswith("  ") and joined[-1].startswith("- "):
            joined[-1] = f"{joined[-1]} {line.strip()}"
        else:
            joined.append(line)

    sections: list[tuple[str, list[tuple[str, str, str]]]] = []
    current: list[tuple[str, str, str]] = []
    heading = ""
    for line in joined:
        title = _HEADING.match(line)
        if title is not None:
            if heading and current:
                sections.append((heading, current))
            heading, current = title.group(1), []
            continue
        entry = _ENTRY.match(line)
        if entry is None or entry.group(2).startswith(("http", "#", "mailto:")):
            continue
        current.append((entry.group(1), _url(entry.group(2)), entry.group(3).strip()))
    if heading and current:
        sections.append((heading, current))

    if not sections:
        sys.exit(
            "error: docs/index.md yielded no entries — its bullet format changed, so "
            "update this script with it rather than publishing an empty llms.txt"
        )
    return sections


def _render() -> str:
    counts = _counts()
    out = [
        "# Guardana",
        "",
        "> Open-source AI security verification. One rule engine scans model artifacts, "
        "probes live endpoints and MCP servers, and grades agent executions that already "
        "happened — on a laptop, in CI, and next to a served model. It runs offline, needs "
        "no account, and sends nothing anywhere except to the target you name.",
        "",
        f"Version {__version__}, Apache-2.0. {counts['total']} built-in rules: "
        f"{counts['build']} static ones that need no model and no network, and "
        f"{counts['runtime']} that grade a live system or a recorded run. Every rule maps "
        "to a public framework (OWASP LLM Top 10 in both editions, OWASP ASI, OWASP MCP, "
        "OWASP ML, MITRE ATLAS, NIST AI 100-2e2025).",
        "",
        "The distinguishing property is what happens when a check cannot reach a verdict. "
        "Guardana reports four separate outcomes — a finding, an unverified check, a check "
        "that errored, and evidence that was demanded and not available — and none of them "
        "is silently a pass. A run that could not establish something says so and exits "
        "non-zero.",
        "",
        "This file is generated from the documentation map; do not edit it by hand.",
        "",
    ]
    optional: list[tuple[str, list[tuple[str, str, str]]]] = []
    for heading, entries in _sections():
        if heading in _OPTIONAL_SECTIONS:
            optional.append((heading, entries))
            continue
        out.append(f"## {heading}")
        out.append("")
        out.extend(_bullet(entry) for entry in entries)
        out.append("")
    if optional:
        out.append("## Optional")
        out.append("")
        out.extend(_bullet(entry) for _heading, entries in optional for entry in entries)
        out.append("")
    return "\n".join(out)


def _bullet(entry: tuple[str, str, str]) -> str:
    name, url, description = entry
    return f"- [{name}]({url}): {description}" if description else f"- [{name}]({url})"


def main() -> int:
    """Write `site/llms.txt`, or report that the one on disk is stale."""
    parser = argparse.ArgumentParser(description="Generate site/llms.txt from docs/index.md.")
    parser.add_argument(
        "--check", action="store_true", help="exit 1 if it is out of date; write nothing"
    )
    args = parser.parse_args()

    rendered = _render()
    current = _OUT.read_text(encoding="utf-8") if _OUT.exists() else None
    if current == rendered:
        print("site/llms.txt is current")
        return 0
    if args.check:
        print("site/llms.txt is out of date — run `python scripts/generate_llms_txt.py`")
        return 1
    _OUT.write_text(rendered, encoding="utf-8")
    print(f"{'updated' if current else 'wrote'} site/llms.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
