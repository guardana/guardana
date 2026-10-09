---
name: ship
description: Commit and push a finished change the way this repo requires — explicit paths, one commit per logical change, no attribution, the five documentation places answered, the site checks before a push (a push to main deploys guardana.dev), CI watched after it, work file closed. Use when the gate is green and the review is settled.
argument-hint: "[commit | push — default: both]"
---
# Ship

Tree right now:

```!
git status --short | head -40
```

## 1. Commit

- The full gate was green on THIS tree (`/gate`), verdict lines read. If something is red for a
  reason that is not yours, the commit message says so.
- Stage **explicit paths** only — never `git add .` / `-A`; the tree may hold changes that are
  not yours. Never stage an `.env*` file or anything from `.work/`.
- One commit per logical change. A maintainer session commits on `main`; a contributor's PR is
  squash-merged by a maintainer after CI and review, so its branch may hold several. Message in English,
  conventional prefix (`feat|fix|refactor|docs|test|chore(scope): …`), the subject says what is
  now true. The body carries the WHY, the measurements and the history that must not go into
  code comments.
- No attribution of any kind: no `Co-Authored-By`, no "generated with", no session links. Check
  the last line of the message rather than assuming.
- The five documentation places are answered in this same commit — `CHANGELOG.md` under
  `[Unreleased]` (why, not only what), `FEATURES.md`, the `docs/` page plus `docs/index.md`,
  `site/index.html` for a headline claim, the affected GitHub issue or milestone when the
  direction moved, with durable limits in `docs/product-status.md` — and
  `docs/generated/` was regenerated, never edited (`/docs` has the checklist).
- M/L work: delete the work file; open leftovers as issues; move durable knowledge to its home
  (a `docs/` page, a rule, the commit message).
- An issue: `Closes #N` only when every acceptance box in the work file is ticked with its
  evidence; otherwise `Refs #N`, and what remains stays open. Confirm the release impact
  against `docs/compatibility.md#versioning`; a merge never publishes packages, and the
  version and the tag are the release checklist's.

## 2. Push — a push to `main` deploys guardana.dev

Cloudflare deploys `site/` from the tree on every push to `main`, before CI has run, so a stale
`site/docs/` or `site/llms.txt` goes live. The PreToolUse hook runs the four `--check` scripts
(`generate_docs`, `sync_site`, `build_site`, `generate_llms_txt`) before it lets the push through
and refuses on drift; if it could not check, it asks. Regenerate, commit, push again.

Then `git push`. If the user asked only for a commit, stop before this step. A version tag is
never pushed here — tags are a maintainer's release step, and the hook asks before any tag push.

## 3. After the push

- `gh run list --limit 3`, then `gh run watch <id> --exit-status` when you can wait. Read the
  failing **step**, not the job: a cache-cleanup step has gone red while every test step passed.
  Red CI is yours to fix now.
- A change to the landing page or the docs: open the live page once it deployed (`site-check`
  with `browser`) and read what a visitor reads.
- A change to what a command writes: run the documented command against a real or faked target
  and read the artifact. A green suite answers a narrower question than "does it work".

## 4. Close — one minute of retro

If a missing rule or skill line cost a detour on this task, add that ONE line now — a code trap
to the matching `.claude/rules/*.md`, a procedure to the skill that owns it. The story behind it
belongs in the commit message. Do not grow `CLAUDE.md`: it holds only what every session needs.

## 5. Report

What shipped (commit hashes), what was verified and how, what was NOT verified.
