# `site/` — the guardana.dev landing page

One static page. No build step, no framework, no JavaScript — just `index.html`
plus `_headers` (Cloudflare Pages reads that file for the security headers).

Preview locally:

```bash
open site/index.html          # macOS; or just drag it into a browser
```

## Deploy to Cloudflare Pages

**Option A — connect the repo (recommended; auto-deploys on every push).**

1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Pages** → **Connect to Git**.
2. Pick `guardana/guardana`.
3. Build settings:
   - **Framework preset:** None
   - **Build command:** *(leave empty)*
   - **Build output directory:** `site`
4. **Save and Deploy.** You get `guardana.pages.dev` immediately.

**Option B — direct upload from your machine.**

```bash
npx wrangler pages deploy site --project-name=guardana
```

## Point the domain at it

`guardana.dev` is registered at GoDaddy, so its DNS has to reach Cloudflare:

1. In Cloudflare, add the site (**Add a site** → `guardana.dev`) — the free plan is enough.
2. Cloudflare gives you two nameservers; set them at GoDaddy
   (*My Products → Domains → DNS → Nameservers → Change → I'll use my own*).
3. Once the domain is active in Cloudflare: **Workers & Pages → guardana → Custom domains
   → Set up a custom domain** → `guardana.dev` (and `www.guardana.dev` if you want it).

Cloudflare issues the TLS certificate automatically. Propagation is usually minutes,
occasionally a few hours.

## After it's live

Point the packaging metadata at the real site — `Homepage`/`Documentation` in each
`packages/*/pyproject.toml` currently reference the domain while it is parked.
