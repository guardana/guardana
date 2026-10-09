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

Published notes follow the documentation sections, listed from their own front
matter at the URL the site serves them on; with no note, the section is absent.

    python scripts/generate_llms_txt.py            # write it
    python scripts/generate_llms_txt.py --check    # exit 1 if stale, write nothing

`release.py` runs the first and `test_docs_consistency.py` runs the second, which is
the same pair of guards `sync_site.py` and `generate_docs.py` already have.
"""

import argparse
import json
import re
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_INDEX = _REPO / "docs" / "index.md"
_OUT = _REPO / "site" / "llms.txt"
_NOTES = _REPO / "notes"

_RAW = "https://raw.githubusercontent.com/guardana/guardana/refs/heads/main"
_SCHEMAS = _REPO / "schemas"
_SCHEMA_FILE = re.compile(r"^(?P<kind>[a-z][a-z0-9-]*)-v(?P<version>[1-9][0-9]*)\.schema\.json$")
_CONTROL_README = "https://raw.githubusercontent.com/guardana/control/refs/heads/main/README.md"
_CONTROL_SUMMARY = (
    "Watch, decide, enforce and record the tool calls your AI agents make. Status: alpha."
)
"""Quoted from Control's README, which owns how Control describes itself."""

sys.path.insert(0, str(_REPO / "scripts"))
sys.path.insert(0, str(_REPO / "packages" / "guardana-core" / "src"))
sys.path.insert(0, str(_REPO / "packages" / "guardana-rules" / "src"))

from guardana.core import __version__  # noqa: E402
from guardana.core.surface import Surface  # noqa: E402
from guardana.rules import provide_rules  # noqa: E402

from sitegen import SiteBuildError  # noqa: E402
from sitegen.notes import read_notes  # noqa: E402
from sitegen.render import inline_text  # noqa: E402

_HEADING = re.compile(r"^## (.+)$")
_ENTRY = re.compile(r"^- \[`?([^\]`]+)`?\]\(([^)]+)\)\s*(?:—|-)?\s*(.*)$")

_OPTIONAL_SECTIONS = frozenset({"Studies", "Maintainers", "Governance"})
"""Sections a model may skip when its context is short, per the llms.txt spec.

Studies say how the published measures are collected, and governance is about people.
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


def _current_schemas() -> list[tuple[str, str, str]]:
    """Return the newest schema of each document kind as (title, `$id`, first sentence)."""
    newest: dict[str, tuple[int, Path]] = {}
    for path in _SCHEMAS.glob("*.schema.json"):
        match = _SCHEMA_FILE.match(path.name)
        if match is None:
            sys.exit(f"error: schemas/{path.name} is not named <kind>-v<N>.schema.json")
        version = int(match["version"])
        if version > newest.get(match["kind"], (0, path))[0]:
            newest[match["kind"]] = (version, path)
    entries = []
    for _version, path in sorted(newest.values(), key=lambda item: item[1].name):
        schema = json.loads(path.read_text(encoding="utf-8"))
        sentence = str(schema.get("description", "")).split(". ", 1)[0].rstrip(".")
        entries.append((str(schema["title"]), str(schema["$id"]), f"{sentence}."))
    if not entries:
        sys.exit("error: schemas/ holds no *.schema.json to list")
    return entries


def _notes(notes: Path) -> list[tuple[str, str, str]]:
    """List every published note, newest first, as (title, served URL, summary).

    A note that would not build stops this script too, rather than being left out
    of a list that then disagrees with the site.
    """
    try:
        return [(note.title, note.url, inline_text(note.summary)) for note in read_notes(notes)]
    except SiteBuildError as exc:
        raise SystemExit(f"error: {exc}") from exc


def _render() -> str:
    counts = _counts()
    out = [
        "# Guardana",
        "",
        "> Guardana is open-source AI security verification. Its rule engine scans model "
        + "artifacts, probes live endpoints and MCP servers, and grades completed agent "
        + "runs. Use it on a laptop, in CI, or beside a served model. It runs offline, "
        + "needs no account, and sends nothing anywhere except to the target you name.",
        "",
        f"Version {__version__}, Apache-2.0. {counts['total']} built-in rules: "
        + f"{counts['build']} static ones that need no model and no network, and "
        + f"{counts['runtime']} that grade a live system or a recorded run. Every rule maps "
        + "to a public framework (OWASP LLM Top 10 in both editions, OWASP ASI, OWASP MCP, "
        + "OWASP ML, MITRE ATLAS, NIST AI 100-2e2025).",
        "",
        "Guardana reports four separate outcomes: a finding, an unverified check, a check "
        + "that errored, and required evidence that was unavailable. None silently counts "
        + "as a pass. If a run cannot establish something, it says so and exits non-zero.",
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
    notes = _notes(_NOTES)
    if notes:
        out.append("## Notes")
        out.append("")
        out.extend(_bullet(entry) for entry in notes)
        out.append("")
    out.append("## Schemas")
    out.append("")
    out.extend(_bullet(entry) for entry in _current_schemas())
    out.append("")
    out.append("## Related project")
    out.append("")
    out.append(_bullet(("Guardana Control", _CONTROL_README, _CONTROL_SUMMARY)))
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
