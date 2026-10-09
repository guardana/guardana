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

## Issue and release impact

<!-- Link the issue this PR completes. Use Closes #N only if all acceptance
     criteria are met; otherwise link it without a closing keyword. -->
Issue:

<!-- Propose one using docs/compatibility.md#versioning; the maintainer confirms
     the version when grouping a release. Before stable 1.0, rc2 takes fixes
     only. A merge does not publish a package. -->
- [ ] No package release needed (tests, docs, or maintainer tooling only)
- [ ] Patch: compatible correction to documented behavior
- [ ] Minor: compatible opt-in functionality or deprecation
- [ ] Major: supported contract break or stricter default

<!-- If a previously passing gate can fail after this change, explain which
     check changes and whether this is a correction or a new default. -->
Gate impact:

## Checklist

- [ ] This PR contains one logical change. Multiple branch commits are fine;
      a maintainer will squash-merge after all CI checks pass and review is
      complete.
- [ ] PR title is a specific, conventional-commit style message
      (`feat: …`, `fix: …`, `docs: …`, `refactor: …`, `test: …`,
      `chore: …`) — not `wip` / `fixes`. A maintainer confirms the squash
      commit title.
- [ ] All gates pass (or: `git push` and let the pre-push hooks run them):
      ```
      uv run ruff check . && uv run ruff format --check .
      uv run mypy --strict .
      uv run lint-imports
      uv run pytest --cov
      uv run guardana scan packages --profile scripts/dogfood.yaml
      ```
- [ ] The change keeps the project principles (`CONTRIBUTING.md` § Principles).
- [ ] Docs updated alongside the code change (`README.md`, `CONTRIBUTING.md`
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
