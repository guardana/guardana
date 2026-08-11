"""Render `docs/**.md` and the rule registry into the static site at `site/docs/`.

Split across small modules for the reason the engine is: one concept per file, so
a change to how links are rewritten does not sit in the same file as the palette.

`build.py` is the only entry point anybody outside this package needs.
"""

from sitegen.build import build
from sitegen.errors import SiteBuildError

__all__ = ["SiteBuildError", "build"]
