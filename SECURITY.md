# Security Policy

## Reporting a vulnerability

**Please do not open a public GitHub issue for a suspected vulnerability.**
Report it privately so it can be assessed and fixed before details are
public.

**Preferred: open a private [GitHub Security Advisory](https://github.com/guardana/guardana/security/advisories/new).**
This keeps the report, discussion, and fix coordination in one private
place tied directly to the repository.

If you'd rather not use GitHub, email **security@guardana.io** instead.

Either way, include:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal artifact, rule, or profile that triggers it).
- The Guardana version / commit and which package(s) are affected
  (`guardana-core`, `guardana-rules`, `guardana-cli`, `guardana-report`,
  `guardana-server`).

We aim to acknowledge reports promptly and to coordinate a disclosure
timeline with the reporter once a fix is available. Please give us
reasonable time to ship a fix before any public disclosure.

## Scope

This covers the Guardana engine, built-in rules, CLI, report renderers, and
the optional collector server in this repository. It does not cover
vulnerabilities in third-party rule/evaluator/target packages you install —
report those to the package's own maintainers (see the trust model below).

## The plugin trust model

Guardana's extensibility is entry-point based: **any installed package that
registers under the `guardana.rules`, `guardana.evaluators`, or
`guardana.targets` entry-point groups is discovered and its code is
executed** when the registry runs `Registry.discover()` (used by `guardana
scan`, `probe`, and `monitor` by default). This is intentional — it's what
lets a company or contributor ship a private rule package that plugs in
exactly like a built-in — but it means:

- **A third-party rule, evaluator, or target package runs arbitrary Python
  in your process.** Installing an untrusted package and letting Guardana
  discover it is equivalent to running that package's code directly. Treat
  `pip install`/`uv add` of a Guardana plugin with the same scrutiny you'd
  give any other dependency with import-time side effects.
- Guardana's own built-in rules (`guardana-rules`) are reviewed as part of
  this repository and held to the same code-quality and test bar as the
  engine. A third-party plugin is not — it's outside this project's
  supply chain the moment it's a separate package.

### `--no-plugins`: the safe mode

For untrusted or locked-down environments, run with entry-point discovery
disabled entirely:

```bash
guardana scan . --no-plugins
```

This constructs an empty `Registry()` instead of calling
`Registry.discover()` — **no code plugin, built-in or third-party, is
imported.** Combine it with YAML rule directories you've reviewed yourself
if you need checks beyond the engine's core behavior: YAML rules are parsed
data (via `yaml.safe_load`), not executed code, so they don't carry the same
risk as a `guardana.rules` entry-point package.

Use `--no-plugins` whenever you're running Guardana against a codebase or in
a pipeline where you haven't audited every installed plugin package, e.g.
shared CI runners, third-party contribution checks, or any environment where
"whatever happens to be pip-installed" isn't a trust boundary you control.

## Running the collector (`guardana-server`)

The optional collector requires a **scoped API key** on every route that carries a
finding, keeps keys hashed at rest, and shows a key exactly once. Keys live in the
database, so a collector with nowhere to keep one refuses to serve rather than
serving openly. Each key is bound to one **project** and optionally to one
**environment**, and every storage query is scoped to it — a cross-tenant read
returns nothing.

Two switches, both of which have to be typed, produce a collector that
authenticates nobody: `GUARDANA_STORAGE=memory` together with
`GUARDANA_ALLOW_UNAUTHENTICATED=1`. That configuration exists for evaluating
Guardana on a laptop. **Do not expose it to an untrusted network**, and note that
its store is bounded and lost on restart.

The optional dashboard (`GUARDANA_DASHBOARD=1`, off by default) is **read-only**
and signs in with a **read-scoped API key**, kept in an `HttpOnly`,
`SameSite=Strict` cookie the page cannot read. `key revoke` ends the session.
**The cookie authenticates reads and nothing else**: ingest accepts a bearer
header only, so a page on another origin cannot make a signed-in browser submit
findings — enforced in the guard rather than left to one browser flag.

Two limits bound what one caller can do: a request-body ceiling
(`GUARDANA_MAX_BODY_BYTES`, 8 MiB, `413` over it) and a per-caller rate limit
(`GUARDANA_RATE_LIMIT_PER_MINUTE`, 120, `429` with `Retry-After`). Both refuse a
value that is not a number at start-up rather than treating a typo as "no limit",
and the rate limiter is **per worker process** — put a proxy in front for a global
one.

Every submission is validated and a malformed one is rejected with a 422 rather
than stored — input hardening, which is a different thing from access control and
does not replace running the service inside your own perimeter.

## How we hold ourselves to this

A security tool that doesn't scan itself is a marketing exercise. On every push,
CI runs the bandit rule set over our own source (`ruff`'s `S` family), audits
our dependencies (`uv audit`), and runs `guardana scan packages` — Guardana
against Guardana, which must stay at zero findings. The pre-commit gate refuses
a commit that contains a private key (`detect-private-key`) before it ever
leaves a contributor's machine.

## What a release publishes, and how to check it yourself

Every release publishes, alongside the five distributions:

- a **CycloneDX SBOM per distribution**, attached to the GitHub Release as
  `guardana-<package>-<version>.cdx.json` — `guardana-cli`'s bill of materials is
  not `guardana-server`'s, and one merged document would tell a collector
  operator they had installed Typer;
- **build provenance** for the distributions, signed keylessly through Sigstore,
  plus PyPI's own PEP 740 attestation from the trusted-publishing upload;
- **an SBOM and provenance attestation for each container image**, pushed into
  the registry beside it.

Check them without trusting this document:

```bash
gh attestation verify ./guardana_cli-<version>-py3-none-any.whl --repo guardana/guardana
gh attestation verify oci://ghcr.io/guardana/guardana:0.15 --repo guardana/guardana
docker buildx imagetools inspect ghcr.io/guardana/guardana:0.15 --format '{{ json .SBOM }}'
```

The SBOMs are generated by `uv export` from the same `uv.lock` the tests and the
release run against — one resolver, so the bill of materials cannot disagree with
what was built — and `scripts/generate_sbom.py` reads each file back and checks it
against that package's own metadata before the release keeps it. CI generates and
verifies them on every push, so a tag is never the first time they are produced.

## Supported versions

Guardana is pre-1.0 (0.15.x). Security fixes land on the latest released
version; there is no separate LTS branch yet.

## Plugin trust (0.7)

Installed plugins are code Guardana imports, and importing code is trusting it.
Until 0.7 the only control was `--no-plugins`, which refused *everything* —
Guardana's own rules included. A safe mode that costs all your coverage is one
people switch off, and a control people switch off is not a control.

```bash
guardana scan .                              # all: every installed entry point
guardana scan . --plugins builtins           # only Guardana's own distributions
guardana scan . --plugins allowlist --allow-plugin acme-rules
guardana scan . --plugins disabled           # nothing; YAML rules still load from disk
```

`builtins` is the setting most `--no-plugins` pipelines actually wanted: the
reviewed rules run, nothing else is imported.

Trust is decided by **distribution name** — what pip installed and what a lockfile
pins — not by entry-point name or module path. A third party can name their entry
point `builtin` and their module `guardana_rules`; neither is a claim anybody
checked. An entry point that cannot name its origin is treated as third-party,
because reading an unnamed origin as trusted would make the allowlist bypassable
by anything that fails to record where it came from.

A plugin that is refused is **recorded** in the run's `errors` channel, not
silently dropped: a rule pack you installed and this run declined to load is
coverage you think you have, and `errors` fails the gate by default.

`--no-plugins` still works and still means "import nothing".
