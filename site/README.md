# `site/` — the guardana.dev landing page

One static page. No build step, no framework, no JavaScript — just `index.html`
plus `_headers` (Cloudflare Pages reads that file for the security headers).

Preview locally:

```bash
open site/index.html          # macOS; or just drag it into a browser
```

## Deploy to Cloudflare Pages

**Connect the repo. Every push to `main` then publishes itself.**

1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Pages** → **Connect to Git**.
2. Pick `guardana/guardana`.
3. Build settings:
   - **Framework preset:** None
   - **Build command:** *(leave empty)*
   - **Build output directory:** `site`
4. **Save and Deploy.** You get `guardana.pages.dev` within a minute.

There is a one-off upload path (`npx wrangler pages deploy site --project-name=guardana`)
but prefer the connected repo: a manual deploy is one more thing that can be
forgotten, and the whole point below is that nothing here should need remembering.

## Point guardana.dev at it

1. In Cloudflare, **Add a site** → `guardana.dev`. The free plan is enough.
2. Cloudflare gives you two nameservers; set them at the registrar in place of
   the current ones.
3. Wait for the domain to show as **Active** in Cloudflare — usually minutes.
4. **Workers & Pages → guardana → Custom domains → Set up a custom domain** →
   `guardana.dev`, and `www.guardana.dev` if you want it.

Cloudflare issues the TLS certificate itself.

`_headers` is applied automatically. It sets a deliberately closed Content
Security Policy — `script-src 'none'`, `connect-src 'none'` — because the page
runs no script and makes no request. That is the no-telemetry product principle
being true of the website too, not only the engine. Worth a check at
[securityheaders.com](https://securityheaders.com) once it is live.

## How the page stays current

Two mechanisms, because the page has two kinds of claim that go stale in
different ways.

**Version markers** — the `v0.6.0` in the header and the `guardana/guardana@v0.6`
Action pin — are rewritten by `scripts/bump_version.py` on every release, and the
bump **refuses to run** if either marker has gone missing.

**Factual claims** — the rule total and the build/runtime split — come from the
registry, not from memory:

```bash
uv run python scripts/sync_site.py           # rewrite them from the registry
uv run python scripts/sync_site.py --check   # exit 1 if stale, change nothing
```

`release.py` runs the first automatically, so a release cannot ship a page
claiming last quarter's numbers. Between releases, `test_landing_page.py` pins the
same three counts to the registry, so adding a rule without touching the page
turns the suite red immediately rather than waiting for someone to cut a release.

Both scripts fail loudly if a claim disappears from the page rather than skipping
it quietly: a claim nothing checks is exactly how this drifted in the first place
— the page advertised **25 rules** across three releases that took the real number
to **32**, one element below a version the tooling faithfully rewrote every time.

If you reword a claim, update the pattern in `scripts/sync_site.py` and
`test_landing_page.py` in the same change. That is the moment the check either
survives or silently stops existing.

## What is still hand-maintained

The illustrative rule list, the terminal demo's finding lines, and the prose. A
landing page may show six checks out of thirty-two — it may not state a total that
is not the total, which is the part that is now pinned. `test_landing_page.py`
does refuse a rule *name* the project does not ship, so the list cannot advertise
something that was renamed or removed.

The **Docs** link in the header still points at the GitHub README, from when the
domain was parked. Point it at the documentation site when there is one.
