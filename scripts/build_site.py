"""Render the documentation site into `site/docs/`, from the prose and the registry.

    uv run python scripts/build_site.py            # write site/docs/
    uv run python scripts/build_site.py --check    # exit 1 if stale; write nothing

The same pair of guards `generate_docs.py`, `sync_site.py` and
`generate_llms_txt.py` already have: `release.py` runs the first and
`test_documentation_site.py` runs the second, so a page edited without rebuilding
turns the suite red rather than waiting for somebody to cut a release.

`wrangler.jsonc` stays a static-assets-only Worker with no build command — what
Cloudflare serves is what is committed here, which is also what a reviewer can
read in a diff. Two things follow, and both are deliberate:

- **Nothing under `site/docs/` is edited by hand.** The whole tree is deleted and
  rewritten, so a hand-edit is silently lost — which is the honest outcome, since
  the markdown is the source.
- **No script is emitted anywhere.** `site/_headers` ships `script-src 'none'`,
  and that is a claim a visitor checks in devtools rather than a default nobody
  chose. Filtering the rules is navigation between pre-rendered pages.
"""

import argparse
import shutil
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_OUT = _REPO / "site" / "docs"

sys.path.insert(0, str(_REPO / "scripts"))
sys.path.insert(0, str(_REPO / "packages" / "guardana-core" / "src"))
sys.path.insert(0, str(_REPO / "packages" / "guardana-rules" / "src"))

from guardana.core import __version__  # noqa: E402

from sitegen import SiteBuildError, build  # noqa: E402

_NAMED = 8
"""How many stale paths `--check` prints before it stops listing them."""


def _on_disk() -> dict[str, str]:
    if not _OUT.is_dir():
        return {}
    return {
        path.relative_to(_OUT).as_posix(): path.read_text(encoding="utf-8")
        for path in _OUT.rglob("*")
        if path.is_file()
    }


def _write(files: dict[str, str]) -> None:
    """Replace the tree wholesale, so a renamed page cannot leave its old URL live.

    A page deleted from `docs/` but left in `site/docs/` would keep answering, and
    stale documentation that still loads is worse than a 404: nothing tells the
    reader they are looking at something that no longer describes the product.
    """
    if _OUT.exists():
        shutil.rmtree(_OUT)
    for relative, content in files.items():
        destination = _OUT / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")


def main() -> int:
    """Build the site, or report which pages on disk no longer match the sources."""
    parser = argparse.ArgumentParser(description="Render docs/ into site/docs/.")
    parser.add_argument("--check", action="store_true", help="exit 1 if stale; write nothing")
    args = parser.parse_args()

    try:
        files = build(_REPO, __version__)
    except SiteBuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    current = _on_disk()
    if current == files:
        print(f"site/docs is current ({len(files)} files)")
        return 0
    if args.check:
        stale = sorted(set(files) ^ set(current)) or sorted(
            name for name, body in files.items() if current.get(name) != body
        )
        named = ", ".join(stale[:_NAMED])
        print(f"site/docs is out of date: {named}{' …' if len(stale) > _NAMED else ''}")
        print("run `uv run python scripts/build_site.py` to rebuild it")
        return 1
    _write(files)
    print(f"wrote {len(files)} files to site/docs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
