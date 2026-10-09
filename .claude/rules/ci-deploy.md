---
paths:
  - ".github/**"
  - "action.yml"
  - ".pre-commit-config.yaml"
  - "wrangler.jsonc"
---
# CI, the release pipeline and the site deploy

- **Every action is pinned by commit SHA** with a version comment, and every workflow declares
  least-privilege `permissions`. A too-wide token never fails a build, which is why it is
  written down instead of defaulted.
- **`ci.yml` runs on every push and PR**: the gate on three Python versions against a real
  PostgreSQL (`GUARDANA_REQUIRE_POSTGRES=1` — the skip is a failure there), `uv audit`, the
  dogfood scan, the two container images, the clean-install check, the SBOM check and one
  isolated suite per example package. `scripts/ci_local.sh` mirrors it; keep them in step in the
  same change.
- **`release.yml` runs on `v*.*.*` tags only**: clean install → build the five distributions →
  SBOM per distribution → provenance → PyPI for the five through the `pypi` environment's
  approval click → the GitHub Release from the changelog section → both images (amd64, arm64).
  CI and the clean-install check in `publish` build and check the reference pack before
  anything is published, so a broken pack stops the release there. Its own build, attestation
  and upload to the Release run afterwards in `reference-pack` (after `publish`);
  `publish-reference-pack` (after it) puts the pack on PyPI only while
  `vars.REFERENCE_PACK_PYPI` is `true`, and the images wait on neither. The moving `vX.Y` tag is for the Marketplace Action and never
  re-triggers a publish.
- **A squash merge is not a release.** CI runs on the PR and on main; a maintainer groups
  completed issues, chooses the version under `docs/compatibility.md#versioning`, and uses
  `scripts/release.py` to gate, push main, wait for green CI, then tag. Do not publish
  packages from a pull_request or main-push workflow.
- **A push to `main` deploys `site/`** through Cloudflare's `npx wrangler deploy`, from the
  tree, before CI has run: `wrangler.jsonc` is a static-assets Worker with no build step,
  `workers_dev` and previews off. The pre-push hook refuses a push while the generated site is
  stale.
- **`action.yml` is a public contract**: its inputs and its `version` default (rewritten by
  `bump_version.py`) are pinned by `test_release_tooling.py`; it installs `guardana-cli` from
  PyPI at run time and uploads SARIF to code scanning.
- **`.pre-commit-config.yaml` is CI's local twin**: fast checks on commit, the slow ones on
  push, conventional-commit messages enforced on `commit-msg`. A hook added to CI gets its
  local counterpart in the same change.
- A workflow's job conclusion is not the verdict: read the failing **step**. A cache-cleanup
  step has gone red while every test step passed.
