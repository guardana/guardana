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

The optional collector is a plain FastAPI service with **no authentication**
and an in-memory store (bounded, and lost on restart). It validates every
submission and rejects a malformed one with a 422 rather than storing it, but
that is input hardening — not access control.

**Do not expose it to an untrusted network.** Run it inside your own perimeter,
behind whatever authentication your infrastructure already provides. Durable,
authenticated storage is the seam a hosted backend replaces.

The optional dashboard (`GUARDANA_DASHBOARD=1`, off by default) is **read-only**
— it adds no write endpoints — but it is equally unauthenticated and displays the
collected findings, so the same rule applies: it belongs inside your perimeter,
never on an untrusted network.

## How we hold ourselves to this

A security tool that doesn't scan itself is a marketing exercise. On every push,
CI runs the bandit rule set over our own source (`ruff`'s `S` family), audits
our dependencies (`uv audit`), and runs `guardana scan packages` — Guardana
against Guardana, which must stay at zero findings. The pre-commit gate refuses
a commit that contains a private key (`detect-private-key`) before it ever
leaves a contributor's machine.

## Supported versions

Guardana is pre-1.0 (v0.1). Security fixes land on the latest released
version; there is no separate LTS branch yet.
