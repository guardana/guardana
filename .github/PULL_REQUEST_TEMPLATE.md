## Summary

<!-- What does this change do, and why? One or two sentences. -->

## Type

<!-- Pick one; the PR title should be a conventional commit of this type. -->
- [ ] feat
- [ ] fix
- [ ] docs
- [ ] refactor
- [ ] test
- [ ] chore

## Checklist

- [ ] **This PR is a single commit.** (Multi-commit PRs are not accepted —
      squash before pushing: see `CONTRIBUTING.md` § Commits and pull
      requests.)
- [ ] PR title is a specific, conventional-commit style message
      (`feat: …`, `fix: …`, `docs: …`, `refactor: …`, `test: …`,
      `chore: …`) — not `wip` / `fixes`.
- [ ] All gates pass (or: `git push` and let the pre-push hooks run them):
      ```
      uv run ruff check . && uv run ruff format --check .
      uv run mypy --strict .
      uv run lint-imports
      uv run pytest --cov
      uv run guardana scan packages
      ```
- [ ] Docs updated alongside the code change (`CLAUDE.md`, `CONTRIBUTING.md`,
      or `docs/`, as applicable) — not deferred to a follow-up.
- [ ] If this PR adds/changes a **Rule**: it has a taxonomy mapping
      (OWASP/MITRE ATLAS/NIST tags) and a positive **and** negative test
      fixture (`guardana.core.testing` has the model doubles).
- [ ] If this PR adds/changes an **Evaluator** or **Target**: it has docs
      and tests.
- [ ] `guardana-core` still does not import `guardana-server` (the
      commercialization boundary — `uv run lint-imports` proves it).

## Notes for reviewers

<!-- Anything a reviewer should know: tradeoffs, follow-ups, out-of-scope items. -->
