# Security Policy

## Reporting a vulnerability

**Please do not open a public GitHub issue for a suspected vulnerability.**
Report it privately so it can be assessed and fixed before details are
public.

**Preferred: open a private [GitHub Security Advisory](https://github.com/guardana/guardana/security/advisories/new).**
This keeps the report, discussion, and fix coordination in one private
place tied directly to the repository.

If you'd rather not use GitHub, email **contact@guardana.dev** or use
[karauda.com/contact](https://karauda.com/contact) instead.

Either way, include:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal artifact, rule, or profile that triggers it).
- The Guardana version / commit and which package(s) are affected
  (`guardana-core`, `guardana-rules`, `guardana-cli`, `guardana-report`,
  `guardana-server`).

We will send a first response to every vulnerability report within 14 days
of receiving it. Once a fix is available, we will coordinate a disclosure
timeline with the reporter. Please allow us reasonable time to ship a fix
before public disclosure.

The default disclosure window is 90 days: the advisory is published when the fix ships, and at the latest 90 days after the report, unless the reporter agrees otherwise.

- An emailed report is moved into a draft GitHub advisory. The fix is prepared on the advisory's private fork; nothing about it appears in a public branch, issue or PR before the release.
- The advisory is published once all five distributions are on PyPI. It lists the affected distributions, affected versions (`<= X.Y.Z`) and patched version.
- A CVE is requested when the severity warrants one. The reporter is credited if they want to be.
- `CHANGELOG.md` gets a `### Security` entry linking the advisory.

## Scope

This covers the Guardana engine, built-in rules, CLI, report renderers, and
the optional collector server in this repository. It does not cover
vulnerabilities in third-party rule/evaluator/target packages you install —
report those to the package's own maintainers (see the trust model below).

## The plugin trust model

Guardana supports plugins through entry points. An installed package can register under `guardana.rules`, `guardana.evaluators`, `guardana.targets` or `guardana.taxonomies`, and add an output under `guardana.renderers` or `guardana.reporters`. Once Guardana loads it, it works like a built-in and its code runs. This lets a company ship a private rule package. It also means:

- **A third-party rule, evaluator, target or output package runs arbitrary Python in your process once it is admitted.** Review `pip install`/`uv add` of a Guardana plugin as you would any dependency that can run code when imported.
- Guardana's built-in rules (`guardana-rules`) are reviewed in this repository and meet the same code quality and test standards as the engine. A third-party plugin is a separate package outside this project's supply chain.

### Every command starts with built-in trust

Every CLI command loads Guardana's own distributions (`guardana-core`, `guardana-rules`, `guardana-report`). It refuses other installed entry points before importing them unless you admit them. Guardana records each refusal as an error. While any installed pack is refused, every run whose gate fails on errors (the default) is `indeterminate`, whether or not it would have used the pack: `scan` and `probe` exit `2`, and `monitor` raises a gate-failed alert every cycle. The command prints the refused distributions and how to admit them on stderr. Admit the pack, or uninstall it. `guardana doctor` lists every third-party Guardana entry point, the module it would import, and whether the current trust setting would load it. It does this without importing the entry point.

An installed format or reporter is different: no run imports it unless `--format` or `--reporter` names it, so an unselected one is never refused and never an error. When a command names a refused one, the command exits `3` before it sends anything ([installed outputs](docs/outputs.md)).

```bash
guardana scan .                              # builtins: Guardana's own distributions only
guardana scan . --plugins allowlist --allow-plugin acme-rules
guardana scan . --plugins all                # every installed entry point
guardana scan . --plugins disabled           # nothing; YAML rules still load from disk
```

A profile sets trust for every command given that profile with `--profile` (`plugins: {mode: allowlist, allow: [acme-rules]}`, see [profiles](docs/profiles.md#plugin-trust-plugins)). A flag takes precedence over the profile. A pipeline that checks untrusted contributions should pass `--plugins builtins` as a flag. A `guardana.yaml` changed in the same pull request can widen a profile, but it cannot change that flag. `doctor` warns when a profile widens trust beyond the built-ins.

Guardana decides trust by **distribution name**: the name pip installed and a lockfile pins. It does not use the entry-point name or module path. It compares names the way pip does (`Acme_Rules` is `acme-rules`). A third party can name an entry point `builtin` and a module `guardana_rules`; neither name means anyone checked it. Guardana treats an entry point with no recorded origin as third-party. Otherwise, an entry point could bypass the allowlist by omitting its origin.

Trust controls which **Guardana entry points** Guardana imports. It does not control a package's dependencies or `.pth` startup hooks; those run when Python starts, before Guardana makes a trust decision. An admitted pack runs with your privileges. A Python caller states trust the same way: `Registry.discover(trust)` and `Verifier(trust=...)` take a `PluginTrust` and have no default.

`Registry.discover(trust)` runs in every mode, including `disabled`. There is no "empty registry" shortcut. Guardana never imports a refused entry point. It records the refusal in `registry.load_errors` and `registry.refused`. If you need checks beyond the engine's core behavior, you can combine any mode with YAML rule directories you have reviewed. YAML rules are parsed as data (via `yaml.safe_load`), not executed as code, so they do not carry the same risk as a `guardana.rules` entry-point package.

A restricted run reports what it refused as well as what it ran. `scan`, `probe`, `monitor`, `analyze-trace`, and `baseline create`/`update` put `registry.load_errors` in the run's `errors` channel. A refused rule pack therefore appears in the run report and fails the gate by default. `plan scan`, `plan probe`, `rule test`, `rules`, `taxonomy`, `calibrate`, `target inspect`, `trace inspect`, `pack validate`, and `pack lock` have no run report for a refusal, so they print it on stderr. You can verify what a trust restriction refused.

A restrictive mode affects exit codes too. `rules` and `taxonomy
<reference>` exit `2` (indeterminate) rather than `0` when a restrictive `--plugins` mode leaves an empty rule list or a reference that no *loaded* catalogue defines. Neither is a clean result. `pack validate` and `pack lock` refuse before reading any manifest if plugin trust refused anything, an installed format or reporter included, or if two distributions install one output name. Reading a manifest imports its package, and both commands check or pin this build's *own* registrations. A registry that omitted extensions cannot determine that a pack "does not register" something it was not allowed to load. In CI, check the exit code when you restrict trust; do not rely only on a warning on stderr.

`--no-plugins` remains as a deprecated alias for `--plugins disabled` on `scan` and `plan scan` only.

### What trust and a lock do not do

Trust is per distribution: admitting one for its output also admits every rule, evaluator and target it ships. Pack manifests and locks are not signed. A pack lock detects a changed rule declaration or version, but does not authenticate the publisher or pin the Python behind an evaluator, target or output. Code installed editable or from a direct URL can change under one version; only a recipe lock pins it by file digests. To pin installed code, use hash-checked installs (`pip --require-hashes`, `uv.lock`).

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
findings — enforced in the guard rather than left to one browser flag. The page
is served with a Content-Security-Policy that runs only its own script and
stylesheet, by hash, and it escapes every submitted value it renders
([threat model](docs/threat-model.md), T7).

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
  the registry beside it, and from 0.33.0 a provenance statement per image digest
  signed keylessly through Sigstore, which is what `gh attestation verify oci://…`
  checks. Images before 0.33.0 carry the unsigned attestations only.

Check them without trusting this document:

```bash
gh attestation verify ./guardana_cli-<version>-py3-none-any.whl --repo guardana/guardana
gh attestation verify oci://ghcr.io/guardana/guardana:0.41 --repo guardana/guardana
docker buildx imagetools inspect ghcr.io/guardana/guardana:0.41 --format '{{ json .SBOM }}'
```

The SBOMs are generated by `uv export` from the same `uv.lock` the tests and the
release run against — one resolver, so the bill of materials cannot disagree with
what was built — and `scripts/generate_sbom.py` reads each file back and checks it
against that package's own metadata before the release keeps it. CI generates and
verifies them on every push, so a tag is never the first time they are produced.

The release controls are described in [the threat model](docs/threat-model.md#t10--a-compromised-guardana-release).

## If a release is withdrawn

- All five PyPI distributions are yanked, not deleted. An exact pin still installs the yanked release; a version range no longer picks it.
- The ghcr image versions of both images are deleted, breaking digest pins to them. The moving `X.Y` image tag points back to the last good release.
- The moving `vX.Y` Action tag moves back. `vX.Y.Z` never moves.
- The GitHub Release is marked pre-release with the reason. A security advisory is published when the cause was a vulnerability or an artifact the project did not build.

## Supported versions

Guardana is pre-1.0 (0.41.x) and on the 1.0 release candidate line. Security fixes
ship in the next candidate, installed with `pip install --upgrade --pre`; a plain
install selects the last stable release, 0.41.x, which receives no further release. After 1.0, security
fixes land on the latest release; there is no LTS branch. Which versions stay
compatible, how long a Python version is supported and how a name is deprecated
before it is removed is stated in the [compatibility policy](docs/compatibility.md).
