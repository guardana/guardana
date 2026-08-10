# A documentation site on guardana.dev, and what "interactive" is allowed to mean

**Status:** proposed · **Written:** 2026-08-10

`site/README.md` ends with an open item: *"The **Docs** link in the header still
points at the GitHub README, from when the domain was parked. Point it at the
documentation site when there is one."* This is the design for that site.

It is written as a decision document rather than a plan because the interesting
part is not the tooling — every static-site generator would work — but a
collision nobody would predict from the outside: **this site's Content Security
Policy forbids JavaScript on purpose**, and interactivity is the thing being
asked for.

## What is actually being asked for

"Interactive documentation" is two different products, and only one of them is
worth building here.

**The one everyone means first — a docs theme.** Sidebar, search box, dark mode,
copy-to-clipboard, anchor links. Real value, entirely commodity: every competitor
has it, and none of it makes a verdict more honest. Nothing about Guardana's
subject matter is expressed by it.

**The one this project alone can build — a rule explorer.** 51 rules, each with a
severity, a surface, a target kind, a set of required capabilities, an impact, a
cost declaration and a mapping into six framework catalogues across two editions.
A reader arrives with one of four questions:

- *Does it cover LLM03 in the 2026 edition?* — filter by framework reference
- *What runs in CI with no model and no network?* — filter by surface
- *What will this cost me and what does it send?* — filter by impact and cost
- *What does this rule actually flag, and how do I fix it?* — the rule page

None of those is answerable today without reading a 51-row generated markdown
table. All of them are answerable from data the registry already holds, which is
the point: **the explorer is generated, so it cannot rot, and it is the one page
on the site that a competitor cannot copy without also having the rules.**

Recommendation: build the explorer first and the theme around it, not the other
way round. A docs theme with a stale rule list would be this project's own
principle-9 failure with better typography.

## The constraint: `script-src 'none'` is a product claim, not a default

`site/_headers` ships:

```
Content-Security-Policy: default-src 'none'; style-src 'self' 'unsafe-inline' …;
  img-src 'self' data:; connect-src 'none'; script-src 'none'; …
```

`site/README.md` states why: *"the page runs no script and makes no request. That
is the no-telemetry product principle being true of the website too, not only the
engine."* A visitor can open devtools and confirm that a security vendor's own
site cannot phone home, because it cannot execute anything.

That is a real asset and it is directly in the way. Three honest responses:

**A. Keep `script-src 'none'` everywhere; pre-render every view.** With 51 rules
the filter space is small and finite: one page per family (8), per severity (4),
per surface (2), per framework entry (~40), plus one per rule. A few hundred tiny
static pages, all generated. Filtering becomes navigation; `<details>` gives
collapsible sections and `:target` gives tabs, both without script. Free-text
search is the one thing this cannot do — it would have to link out to GitHub's.

**B. Relax to `script-src 'self'` under `/docs/*` only, and keep
`connect-src 'none'`.** `_headers` matches by path, so the landing page keeps its
absolute policy and the docs subtree gets one self-hosted script with no network
reachability at all — a client-side index over ~31 documents is a few hundred
kilobytes and needs no server. The claim weakens from *"runs no script"* to
*"runs no script it did not ship, and can reach nothing"*, which is still a
stronger statement than any comparable site makes.

**C. Relax globally.** Rejected. The landing page is where the claim is read, and
trading it for a copy-to-clipboard button is the exact shape of trade this project
refuses elsewhere.

Recommendation: **A for the first release, B only when search is the thing being
asked for**, and if B is taken, `connect-src 'none'` is non-negotiable and gets a
test. A pre-rendered explorer answers all four reader questions above; only
free-text prose search needs B. Shipping A first also means the fallback exists if
B is ever regretted.

## Decision: prose stays markdown, facts become JSON, and nothing moves to YAML

The question that prompted this — *should docs live in YAML?* — deserves a direct
answer: **no for the prose, and the facts are already structured.**

`docs/` is 31 hand-written markdown files and 4 generated ones. The hand-written
ones are arguments and instructions: `threat-model.md`, `safe-testing.md`,
`writing-rules.md`. Prose in YAML is prose in a worse container — it loses diff
readability in review, it invites indentation bugs in a file nobody executes, and
it buys exactly one thing a site generator needs and markdown already has a
convention for: metadata.

So the split:

| Content | Source of truth | Format |
|---|---|---|
| Guides, references, arguments | hand-written, reviewed in PRs | markdown + **YAML frontmatter** (`title`, `nav_order`, `summary`, `status`) |
| Rules, evaluators, taxonomy entries, capability surface | `Registry`, at build time | **JSON**, emitted by `scripts/generate_docs.py` |
| Counts stated in prose | the registry | already pinned by tests; unchanged |

Frontmatter is the only new authoring burden and it is four lines per file. It
replaces what a generator would otherwise infer from filenames and first
headings — inference that silently reorders a nav when somebody retitles a page.

**`generate_docs.py` gains a JSON emitter beside its markdown one.** It already
walks the registry to produce `rule-catalog.md`, `rule-summary.md`,
`evaluator-catalog.md` and `taxonomy-coverage.md`; the same walk emits
`docs/generated/rules.json` with the fields the explorer filters on. One walk, two
renderings, and `docs/generated/` stays the thing nobody edits by hand. A third
party's installed rules appear in a local build for free, which is what makes the
explorer honest about what *your* installation ships rather than about ours.

## The build, and what it costs the dependency surface

`wrangler.jsonc` declares a static-assets-only Worker with no build command. That
stays true — the build happens in CI and commits or uploads plain HTML.

```
scripts/build_site.py            # markdown + frontmatter + rules.json -> site/docs/**.html
  reads   docs/*.md              (prose, frontmatter for nav)
  reads   docs/generated/*.json  (facts, from the registry)
  writes  site/docs/             (plain HTML, one CSS file, no script under plan A)
```

**Principle 6 applies to the build as well.** A markdown renderer is a new
dependency; it belongs in a `docs` extra that neither `guardana-core` nor any
shipped package depends on, so a user installing the scanner never acquires it.
`markdown-it-py` is the smallest credible option with the CommonMark guarantees
this needs. A generator like MkDocs or Docusaurus would bring a framework, a
theme, a plugin ecosystem and — in Docusaurus's case — a Node toolchain, to
produce pages this repository can emit in a script it can read end to end. For 35
files that is the wrong trade; it stops being the wrong trade somewhere north of a
few hundred.

## What gets a test, because otherwise this rots like everything else did

The site's existing gates are the model — `test_landing_page.py` pins its counts,
`sync_site.py --check` fails a stale claim, `.assetsignore` is enforced by a test.
The docs site needs the same, and the list is short because most of it already
exists:

1. **Every `docs/*.md` has frontmatter with a title**, or the nav silently drops a
   page. Fail the build, do not guess from the filename.
2. **Every internal link resolves after rendering**, not only in markdown —
   `test_docs_consistency.py` checks `.md` targets today, and rewriting them to
   `.html` is exactly where a link breaks.
3. **`rules.json` and `rule-catalog.md` describe the same registry** — one walk,
   so this is a cheap equality check, and it is what stops the explorer drifting
   from the catalog the way the landing page drifted from the registry.
4. **`connect-src 'none'` survives**, under plan A and B alike. If the docs site
   ever needs to reach a host, that is a decision with a design document, not a
   CSP edit.
5. **The header's Docs link points at the docs site**, once there is one — the
   open item this document closes.

## Rejected

| Option | Why not |
|---|---|
| **MkDocs Material / Docusaurus** | a framework, a theme system and (for Docusaurus) a Node toolchain to render 35 files. The generated half — the part with actual value — would still need custom work, and the custom half is most of the value |
| **Publish `docs/` to GitHub Pages and link that** | free, and it gives the docs a different origin, a different CSP and a different security posture from the product's own page. The claim "this site runs nothing" stops being checkable in one place |
| **Prose in YAML** | see above: a worse container for prose, and the facts that deserve structure are already generated from the registry rather than authored anywhere |
| **A live "try a rule against your text" widget** | it would need `connect-src` to something, and that something would be a service holding other people's prompts. The engine's proposition is that it runs on your machine; a hosted demo contradicts it more loudly than it demonstrates it |
| **Versioned docs (one tree per release)** | worth doing after 1.0, when the compatibility contract makes "the 1.2 docs" a meaningful thing to read. Before then every version's docs describe a moving API and a version switcher offers a reader a choice with no right answer |

## Open question for whoever implements this

Whether the explorer is generated from **this repository's** registry at CI time
or from a **user's local install** by a `guardana docs` command. The first is a
website; the second is a feature — a team with private rule packs could render an
explorer covering their own rules under the same evidence semantics, which is the
extension story told one more way. They are not exclusive, and the second is
cheap once `rules.json` exists, but it is scope this document deliberately does
not decide.
