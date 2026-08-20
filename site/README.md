# `site/` — guardana.dev

The landing page and the documentation site. No framework and no JavaScript
anywhere: `index.html` is hand-written, `docs/` is generated, and `_headers` —
which Cloudflare reads for the security headers — applies to both.

| File | What it is | Where it comes from |
|---|---|---|
| `index.html` | the landing page | hand-written; its counts are rewritten by `scripts/sync_site.py` |
| `docs/` | the documentation site: every page of `docs/`, plus a page per rule and per filter | **generated** by `scripts/build_site.py` — never edit it, the whole tree is deleted and rewritten |
| `llms.txt` | the [llms.txt](https://llmstxt.org) documentation map, so a model asking what this project is gets the docs rather than this page's markup | **generated** by `scripts/generate_llms_txt.py` from `docs/index.md` — never edit it |
| `og.png` | the 1200×630 card a link preview shows in Slack, X and LinkedIn | rendered from `scripts/og_card.html`, deliberately and by hand (see below) |

Preview locally:

```bash
open site/index.html                    # macOS; or drag it into a browser
python3 -m http.server -d site 8099     # if you want it over HTTP
```

## Deploy: connect the repo once, then every push to `main` publishes itself

The deployment is described by [`wrangler.jsonc`](../wrangler.jsonc) at the
repository root rather than by dashboard settings, because a deployment that
lives in a console is one nobody can review, diff or restore. It declares a
**static-assets-only Worker**: no script, no build, `site/` served as it is.

1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Import a repository**
2. Pick `guardana/guardana`
3. On **Set up your application**:
   - **Project name:** `guardana` — it must match `name` in `wrangler.jsonc`
   - **Build command:** *(leave empty — there is nothing to build)*
   - **Deploy command:** `npx wrangler deploy` *(the default)*
   - **Path:** `/` — the config is at the repository root, not in `site/`
   - **API token:** *Create new token*; leave the variable fields empty
4. **Deploy.** It is live on the custom domain within a minute — not on
   `guardana.dev.workers.dev`, because `workers_dev` is off in the config (see below).
   Until the domain resolves, check the deployment from the Cloudflare dashboard
   rather than by guessing a `workers.dev` address that will not answer.

`_headers` is applied by Workers static assets exactly as it was by Pages —
verified after the first deploy, and all five headers are live. Check it once at
[securityheaders.com](https://securityheaders.com) too: a header file nobody
verified is a policy nobody has.

**This file is not published.** Wrangler uploads everything in the assets
directory, so the first deploy served it at `/README.md`; `site/.assetsignore`
keeps maintainer files out of the site, and a test keeps that true. The config
also pins **one** public hostname — `workers_dev` and `preview_urls` are off, so
the page lives at `guardana.dev` and nowhere else.

There is a one-off path (`npx wrangler deploy` from a laptop) but prefer the
connected repo: a manual deploy is one more thing that can be forgotten, and the
whole point below is that nothing here should need remembering.

> **Pages instead of Workers?** It still works — *Create → Pages → Connect to
> Git*, build command empty, output directory `site` — and needs no file in the
> repository. Workers is the path Cloudflare is steering new projects to, and it
> is the one where the deployment is written down.

## Point guardana.dev at it

1. In Cloudflare, **Add a site** → `guardana.dev`. The free plan is enough.
2. Cloudflare gives you two nameservers; set them at the registrar in place of
   the current ones.
3. Wait for the domain to show as **Active** in Cloudflare — usually minutes.
4. **Workers & Pages → guardana → Settings → Domains & Routes → Add → Custom
   domain** → `guardana.dev`, and `www.guardana.dev` if you want it.

Cloudflare issues the TLS certificate itself.

`_headers` is applied automatically. It sets a deliberately closed Content
Security Policy — `script-src 'none'`, `connect-src 'none'` — because the page
runs no script and makes no request. That is the no-telemetry product principle
being true of the website too, not only the engine. Worth a check at
[securityheaders.com](https://securityheaders.com) once it is live.

## How the page stays current

Two mechanisms, because the page has two kinds of claim that go stale in
different ways.

**Version markers** — the `vX.Y.Z` in the header and the `guardana/guardana@vX.Y`
Action pin — are rewritten by `scripts/bump_version.py` on every release, and the
bump **refuses to run** if either marker has gone missing. Written as placeholders
on purpose: a literal number in a sentence *explaining* how numbers stay current is
one more number to forget, and this one sat eight releases behind while the marker
it described was rewritten every time.

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

## Re-rendering the share card

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless \
  --disable-gpu --screenshot=site/og.png --window-size=1200,630 --hide-scrollbars \
  scripts/og_card.html
```

Deliberately **not** wired into `release.py`: a browser is a build dependency nobody
should need in order to cut a release, and the card has no reason to change on a
release schedule. Re-render it when the wording changes.

**The card states no rule count, and that is the point.** A number rendered into a
PNG is a claim no gate in this repository can read — which is how the number went
stale on this page, in the README and in the GitHub repository description. So the
image carries the four verbs and the licence, and
`test_site_sharing_and_llms_txt.py` refuses a count in `og_card.html` rather than
waiting to discover one in the pixels. The same test reads the PNG's own header, so
a card re-rendered at a different size cannot sit beside meta tags claiming the old
one.

## What is still hand-maintained on the landing page

The illustrative rule list, the terminal demo's finding lines, and the prose. A
landing page may show six checks out of forty — it may not state a total that is
not the total, which is the part that is pinned. `test_landing_page.py` refuses a
rule *name* the project does not ship, so the list cannot advertise something that
was renamed or removed, and it now also runs `guardana plan probe` and compares the
transcript in the page against what the command actually prints — that transcript
had drifted to numbers no build produced, which is this file's own warning happening
one element over.

## The documentation site

```bash
uv run python scripts/build_site.py            # rewrite site/docs/
uv run python scripts/build_site.py --check    # exit 1 if stale, change nothing
```

`docs/**.md` plus `docs/generated/rules.json` become `site/docs/**.html`.
`release.py` runs the build; `test_documentation_site.py` runs `--check` and reads
the rendered pages, so a page edited without rebuilding turns the suite red rather
than waiting for a release. Reasoning and the alternatives that lost:
[`docs/design/documentation-site.md`](../docs/design/documentation-site.md).

**Nothing in `site/docs/` is hand-edited.** The tree is deleted and rewritten on
every build, so an edit there is silently lost — which is the honest outcome, since
the markdown is the source. Prose lives in `docs/`, and every page carries four
lines of YAML frontmatter (`title`, `nav_order`, `summary`, `status`) that the build
**refuses to guess**: a title inferred from a filename reorders the navigation the
day somebody retitles a page, and nothing would notice.

**The rule explorer is the reason this exists.** Every rule gets a page, and every
filter — family, surface, severity, impact, cost, framework, framework entry — is a
*pre-rendered page* rather than a script, because the `script-src 'none'` above is a
claim a visitor can check rather than a default nobody chose. It is generated from
the registry, so it cannot go stale the way this page's rule count did.

Two consequences worth stating, because both are choices:

- **Free-text search over the prose is the one thing this cannot do.** It would
  need `script-src 'self'` under `/docs/*`. The design document says that is the
  only reason worth taking it, and that `connect-src 'none'` stays either way —
  which `test_documentation_site.py` now pins.
- **`/docs/*` loads no font from Google, unlike the landing page.** One request on
  one page is a trade; the same request on a hundred and ninety pages is a security
  project's documentation telling a third party who is reading it. The documentation
  uses system fonts and carries the identity in its palette and layout instead.
