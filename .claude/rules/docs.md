---
paths:
  - "docs/**"
  - "*.md"
  - "site/**"
---
# Documentation and the site

Procedure: the `docs` skill.

- **Five places for every user-visible change, in the same commit**: `CHANGELOG.md` under
  `[Unreleased]` (why, not only what) · `FEATURES.md` · the `docs/` page plus `docs/index.md` ·
  `site/index.html` for a headline claim · the affected GitHub issue or milestone when the
  direction moved, with durable limits reconciled in `docs/product-status.md`. Each is an
  edit or an explicit "not applicable".
- **No public claim without generated or cited evidence.** Counts come from the registry
  (`scripts/generate_docs.py`, `scripts/sync_site.py`); a statistic names its source and what
  it measured; a capability claim is testable.
- **No promise about the future.** `**vX.Y` and "coming in vX.Y" are refused by
  `test_docs_consistency.py` once that version has shipped; `CLAUDE.md` is not exempt.
  `CHANGELOG.md` is a record and may say what was true when written.
- **Every `docs/**/*.md` carries front matter** (`title`, unique `nav_order`, `summary`,
  `status`) and an entry in `docs/index.md`; the build refuses otherwise. Plans and notes go to
  `.work/`, which git ignores; nothing internal goes under `docs/`.
- **A diagram is a `mermaid` block** in the subset `scripts/sitegen/diagram.py` draws, with
  `accTitle:` and `accDescr:`; the site and the landing page render it, GitHub shows it as
  is. Never hand-edit the SVG `sync_site.py` writes into `site/index.html`.
- **Generated trees are never edited by hand**: `docs/generated/`, `site/docs/`,
  `site/llms.txt`. Regenerate; `--check` is the gate.
- **A push to `main` deploys `site/`** through Cloudflare before CI runs; the pre-push hook
  refuses when the four `--check` scripts report drift.
- Every local link points at a file that exists; renaming a page is not done until the test
  says so. English everywhere; a user page holds no history, no incident, no measurement —
  those go to `CHANGELOG.md` or the commit message.
